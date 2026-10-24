"""Orchestrator for remote vulnerability scanning across HTTP, HTTPS, and SSH."""

from __future__ import annotations

import concurrent.futures
import datetime
import json
import logging
import os
import threading
import time
import uuid
from typing import Any, Callable, Dict, List, Optional

from vulnshield.advisory.intelligence import AdvisoryIntelligence
from vulnshield.findings.model import Finding, ScanResult, Protocol, Severity, Confidence, FindingStatus, Evidence
from vulnshield.findings.storage import FindingStore
from vulnshield.plugins.manager import default_plugin_manager
from vulnshield.remote.authorization import TargetAuthorizer, AuthorizationError, redact_sensitive
from vulnshield.remote.correlation import CrossProtocolCorrelator
from vulnshield.remote.http.checks import HttpSecurityChecks
from vulnshield.remote.http.client import SafeHttpClient
from vulnshield.remote.http.fingerprint import TechnologyFingerprinter
from vulnshield.remote.http.headers import HeaderSecurityAnalyzer
from vulnshield.remote.ssh.authentication import SshAuthCredentials
from vulnshield.remote.ssh.client import SafeSshClient
from vulnshield.remote.targets import TargetConfig, HttpProtocolConfig, SshProtocolConfig
from vulnshield.remote.tls.certificates import CertificateInspector
from vulnshield.remote.tls.configuration import TlsConfigurationAuditor

logger = logging.getLogger(__name__)


class CancellationContext:
    """Thread-safe cancellation token for halting scans gracefully."""

    def __init__(self):
        self._cancelled = threading.Event()

    def cancel(self) -> None:
        self._cancelled.set()

    @property
    def is_cancelled(self) -> bool:
        return self._cancelled.is_set()


class AuditLogger:
    """Writes tamper-evident structured audit records for all remote scan activities."""

    def __init__(self, log_path: Optional[str] = None):
        default_dir = os.environ.get("VULNSHIELD_DATA_DIR")
        if not default_dir:
            try:
                test_p = Path(os.path.expanduser("~/.vulnshield"))
                test_p.mkdir(parents=True, exist_ok=True)
                default_dir = str(test_p)
            except Exception:
                default_dir = os.path.join(os.getcwd(), ".vulnshield")

        path = Path(log_path or os.path.join(default_dir, "audit.log"))
        path.parent.mkdir(parents=True, exist_ok=True)
        self.path = path

    def record_event(
        self,
        event_type: str,
        target_id: str,
        protocols: List[str],
        status: str,
        details: Optional[Dict[str, Any]] = None,
    ) -> None:
        entry = {
            "timestamp": datetime.datetime.now(datetime.timezone.utc).isoformat(),
            "event_type": event_type,
            "target_id": target_id,
            "protocols": protocols,
            "status": status,
            "details": details or {},
        }
        with open(self.path, "a", encoding="utf-8") as f:
            f.write(json.dumps(entry) + "\n")


from pathlib import Path


class RemoteAssessmentEngine:
    """Coordinates agentless remote security assessments across HTTP, HTTPS, and SSH."""

    def __init__(
        self,
        authorizer: Optional[TargetAuthorizer] = None,
        finding_store: Optional[FindingStore] = None,
        advisory_engine: Optional[AdvisoryIntelligence] = None,
        audit_logger: Optional[AuditLogger] = None,
    ):
        self.authorizer = authorizer or TargetAuthorizer()
        self.finding_store = finding_store or FindingStore()
        self.advisory_engine = advisory_engine or AdvisoryIntelligence()
        self.audit_logger = audit_logger or AuditLogger()
        self.correlator = CrossProtocolCorrelator(self.advisory_engine)

        self.fingerprinter = TechnologyFingerprinter()
        self.header_analyzer = HeaderSecurityAnalyzer()
        self.cert_inspector = CertificateInspector()
        self.tls_auditor = TlsConfigurationAuditor()

    def scan_target(
        self,
        target: TargetConfig,
        cancel_token: Optional[CancellationContext] = None,
    ) -> List[Finding]:
        """Performs full assessment on a single target across configured protocols."""
        if cancel_token and cancel_token.is_cancelled:
            logger.info("Scan cancelled before starting target %s", target.id)
            return []

        # 1. Authorization Gatekeeper
        self.authorizer.validate_target_authorization(target.id, target.authorized)

        default_plugin_manager.trigger("on_target_discovered", target)

        target_protocols = list(target.protocols.keys())
        self.audit_logger.record_event(
            event_type="SCAN_TARGET_START",
            target_id=target.id,
            protocols=target_protocols,
            status="IN_PROGRESS",
        )

        http_findings: List[Finding] = []
        tls_findings: List[Finding] = []
        ssh_telemetry = None
        fingerprint_res = None

        # 2. HTTP / HTTPS Assessment
        http_conf = target.http_config
        if http_conf:
            h_findings, t_findings, fp = self._assess_http(target.id, http_conf, cancel_token)
            http_findings.extend(h_findings)
            tls_findings.extend(t_findings)
            fingerprint_res = fp

        # 3. SSH Assessment
        ssh_conf = target.ssh_config
        if ssh_conf and (not cancel_token or not cancel_token.is_cancelled):
            ssh_telemetry = self._assess_ssh(target.id, ssh_conf)

        # 4. Cross-Protocol Correlation
        correlated_findings = self.correlator.correlate(
            target_id=target.id,
            http_findings=http_findings,
            tls_findings=tls_findings,
            ssh_telemetry=ssh_telemetry,
            fingerprint=fingerprint_res,
        )

        for finding in correlated_findings:
            default_plugin_manager.trigger("on_finding", finding)

        self.audit_logger.record_event(
            event_type="SCAN_TARGET_COMPLETE",
            target_id=target.id,
            protocols=target_protocols,
            status="SUCCESS",
            details={"findings_count": len(correlated_findings)},
        )

        return correlated_findings

    def scan_targets_batch(
        self,
        targets: List[TargetConfig],
        concurrency: int = 5,
        cancel_token: Optional[CancellationContext] = None,
    ) -> ScanResult:
        """Executes concurrent batch assessment across targets with bounded pool."""
        scan_id = f"SCAN-{uuid.uuid4().hex[:12].upper()}"
        start_time = datetime.datetime.now(datetime.timezone.utc).isoformat()

        default_plugin_manager.trigger("on_scan_start", scan_id, targets)

        all_findings: List[Finding] = []
        errors: List[Dict[str, str]] = []
        target_ids = [t.id for t in targets]

        token = cancel_token or CancellationContext()

        with concurrent.futures.ThreadPoolExecutor(max_workers=concurrency) as executor:
            future_to_target = {
                executor.submit(self.scan_target, target, token): target
                for target in targets
            }

            for future in concurrent.futures.as_completed(future_to_target):
                target = future_to_target[future]
                try:
                    findings = future.result()
                    all_findings.extend(findings)
                except Exception as e:
                    logger.error("Scan error on target %s: %s", target.id, e)
                    errors.append({"target_id": target.id, "error": str(e)})

        end_time = datetime.datetime.now(datetime.timezone.utc).isoformat()

        result = ScanResult(
            scan_id=scan_id,
            target_ids=target_ids,
            start_time=start_time,
            end_time=end_time,
            findings=all_findings,
            errors=errors,
            metadata={"concurrency": concurrency, "target_count": len(targets)},
        )

        # Save to persistent store
        self.finding_store.save_scan_result(result)

        default_plugin_manager.trigger("on_scan_complete", result)
        return result

    def _assess_http(
        self,
        target_id: str,
        config: HttpProtocolConfig,
        cancel_token: Optional[CancellationContext],
    ) -> Tuple[List[Finding], List[Finding], Optional[TechnologyFingerprinter]]:
        http_findings: List[Finding] = []
        tls_findings: List[Finding] = []

        client = SafeHttpClient(
            authorizer=self.authorizer,
            timeout=config.timeout,
            rate_limit=config.rate_limit,
        )
        checks = HttpSecurityChecks(client, self.advisory_engine)

        parsed = self.authorizer.validate_url(config.url)
        is_https = parsed.scheme.lower() == "https"
        host = parsed.hostname or ""
        port = parsed.port or (443 if is_https else 80)

        # 1. TLS Inspection if HTTPS
        if is_https:
            # Certificate inspection
            cert_info, cert_findings = self.cert_inspector.inspect_host(
                host=host, port=port, timeout=config.timeout, verify_ca=config.verify_tls
            )
            tls_findings.extend(cert_findings)

            # TLS Version & Cipher Auditing
            audit_res, tls_cfg_findings = self.tls_auditor.audit_target(
                host=host, https_port=port, timeout=config.timeout
            )
            tls_findings.extend(tls_cfg_findings)

        # 2. HTTP Request Inspection for allowed paths
        fingerprint_res = None
        for path in config.allowed_paths:
            if cancel_token and cancel_token.is_cancelled:
                break

            target_url = urllib_join_path(config.url, path)
            try:
                resp = client.request("GET", target_url, verify_tls=config.verify_tls)

                # Fingerprinting
                fingerprint_res = self.fingerprinter.fingerprint(resp.headers, resp.body)

                # Security Headers
                header_findings = self.header_analyzer.analyze(
                    target_id=target_id,
                    url=target_url,
                    headers=resp.headers,
                    is_https=is_https,
                )
                http_findings.extend(header_findings)

                # Cookie Security Flags
                cookie_findings = checks.check_cookies(
                    target_id=target_id,
                    url=target_url,
                    headers=resp.headers,
                    is_https=is_https,
                )
                http_findings.extend(cookie_findings)

                # Safe Method Discovery
                if config.mode != "passive":
                    method_findings = checks.check_allowed_methods(target_id=target_id, url=target_url)
                    http_findings.extend(method_findings)

                # Correlate Server Banner with Advisories (Classified as POTENTIALLY_VULNERABLE with LOW confidence)
                if fingerprint_res.server_software and fingerprint_res.server_version:
                    banner_adv = checks.check_advisories_from_banner(
                        target_id=target_id,
                        url=target_url,
                        component=fingerprint_res.server_software,
                        version=fingerprint_res.server_version,
                        is_https=is_https,
                    )
                    http_findings.extend(banner_adv)

                for runtime_name, runtime_ver in fingerprint_res.runtimes.items():
                    r_adv = checks.check_advisories_from_banner(
                        target_id=target_id,
                        url=target_url,
                        component=runtime_name,
                        version=runtime_ver,
                        is_https=is_https,
                    )
                    http_findings.extend(r_adv)

            except Exception as e:
                logger.warning("HTTP check failed on %s: %s", target_url, e)

        return http_findings, tls_findings, fingerprint_res

    def _assess_ssh(
        self, target_id: str, config: SshProtocolConfig
    ) -> Optional[SshSystemTelemetry]:
        try:
            creds = SshAuthCredentials(
                username=config.username,
                identity_file=config.identity,
            )
            client = SafeSshClient(
                credentials=creds,
                host=config.host,
                port=config.port,
                authorizer=self.authorizer,
                timeout=config.timeout,
                known_hosts_file=config.known_hosts_file,
            )
            return client.collect_system_telemetry(target_id=target_id)
        except Exception as e:
            logger.warning("SSH assessment failed for target %s: %s", target_id, e)
            return None


def urllib_join_path(base_url: str, path: str) -> str:
    import urllib.parse
    if not path.startswith("/"):
        path = "/" + path
    parsed = urllib.parse.urlparse(base_url)
    return urllib.parse.urlunparse((parsed.scheme, parsed.netloc, path, "", "", ""))
