"""Cross-protocol evidence correlation engine combining HTTP, HTTPS, and SSH signals."""

from __future__ import annotations

import logging
from typing import Any, Dict, List, Optional, Set

from vulnshield.advisory.intelligence import AdvisoryIntelligence
from vulnshield.findings.model import (
    Finding,
    Evidence,
    Protocol,
    Severity,
    Confidence,
    FindingStatus,
)
from vulnshield.remote.http.fingerprint import FingerprintResult
from vulnshield.remote.ssh.collectors import SshSystemTelemetry
from vulnshield.remote.ssh.platforms import PlatformType

logger = logging.getLogger(__name__)


class CrossProtocolCorrelator:
    """Correlates evidence across HTTP, TLS, and SSH to produce authoritative findings."""

    def __init__(self, advisory_engine: Optional[AdvisoryIntelligence] = None):
        self.advisory_engine = advisory_engine or AdvisoryIntelligence()

    def correlate(
        self,
        target_id: str,
        http_findings: List[Finding],
        tls_findings: List[Finding],
        ssh_telemetry: Optional[SshSystemTelemetry] = None,
        fingerprint: Optional[FingerprintResult] = None,
    ) -> List[Finding]:
        correlated: List[Finding] = []
        seen_keys: Set[str] = set()

        # 1. Process TLS findings (cert validity, deprecated versions, weak ciphers)
        for f in tls_findings:
            key = f"{f.target_id}:{f.id}"
            if key not in seen_keys:
                correlated.append(f)
                seen_keys.add(key)

        # 2. Correlate HTTP findings
        for f in http_findings:
            # If not an advisory finding (e.g. missing security header), keep as is
            if not f.cve or not f.affected_component:
                key = f"{f.target_id}:{f.id}"
                if key not in seen_keys:
                    correlated.append(f)
                    seen_keys.add(key)
                continue

            # Advisory finding from banner
            component = f.affected_component.lower()
            detected_ver = f.detected_version or ""

            if ssh_telemetry:
                # Find matching package or runtime in SSH telemetry
                pkg_ver = self._resolve_package_version_for_service(
                    component, ssh_telemetry
                )

                if pkg_ver:
                    # Authoritative host package found! Query advisory with package string
                    advisory_results = self.advisory_engine.query(
                        component, detected_ver, package_version=pkg_ver
                    )

                    matching_adv = next((item for item in advisory_results if item[0].cve == f.cve), None)
                    if matching_adv:
                        adv, status, confidence, note = matching_adv
                        # Build cross-protocol correlated finding
                        f.confidence = confidence
                        f.status = status
                        f.protocols = list(set(f.protocols + [Protocol.SSH]))
                        f.description = (
                            f"{adv.description}\n\n"
                            f"Cross-Protocol Correlation:\n"
                            f"- HTTP Banner indicated {component} {detected_ver}.\n"
                            f"- SSH Host Evidence identified installed package {component}={pkg_ver}.\n"
                            f"- Result: {note}"
                        )
                        f.evidence.append(
                            Evidence(
                                protocol=Protocol.SSH,
                                collector="ssh_package_correlation",
                                raw_data=f"Installed package: {pkg_ver}. {note}",
                                extracted_value=pkg_ver,
                                source_command_or_uri="host_package_manager",
                            )
                        )
                    else:
                        # Version not affected according to authoritative package
                        f.status = FindingStatus.NOT_AFFECTED
                        f.confidence = Confidence.HIGH
                        f.protocols = list(set(f.protocols + [Protocol.SSH]))
                        f.evidence.append(
                            Evidence(
                                protocol=Protocol.SSH,
                                collector="ssh_package_correlation",
                                raw_data=f"Host package {pkg_ver} is not affected by {f.cve}.",
                                extracted_value=pkg_ver,
                            )
                        )
                else:
                    # Conflicting or unmapped runtime
                    f.confidence = Confidence.MEDIUM
                    f.description += (
                        "\n\nNote: SSH telemetry collected, but matching package was not found in package inventory."
                    )
            else:
                # No SSH evidence: remains POTENTIALLY_VULNERABLE with LOW confidence
                f.confidence = Confidence.LOW
                f.status = FindingStatus.POTENTIALLY_VULNERABLE

            key = f"{f.target_id}:{f.cve or f.id}"
            if key not in seen_keys:
                correlated.append(f)
                seen_keys.add(key)

        # 3. Add SSH-exclusive package and system findings
        if ssh_telemetry:
            ssh_findings = self._evaluate_ssh_findings(target_id, ssh_telemetry)
            for sf in ssh_findings:
                key = f"{sf.target_id}:{sf.cve or sf.id}"
                if key not in seen_keys:
                    correlated.append(sf)
                    seen_keys.add(key)

        return correlated

    def _resolve_package_version_for_service(
        self, component: str, telemetry: SshSystemTelemetry
    ) -> Optional[str]:
        """Resolves package string accounting for multi-version PHP / Nginx / Apache / OpenSSH."""
        # 1. If listening ports identify a specific daemon (e.g. php-fpm8.3), match the daemon
        active_daemons = [
            lp["process_name"].lower() for lp in telemetry.listening_ports if lp.get("process_name")
        ]

        if component == "php":
            # Check for FPM daemons in listening ports
            fpm_daemon = next((d for d in active_daemons if "php" in d or "fpm" in d), None)
            if fpm_daemon:
                # E.g. php-fpm8.3 -> match package containing '8.3' and 'fpm'
                for pkg_name, pkg_ver in telemetry.packages.items():
                    p_lower = pkg_name.lower()
                    if "fpm" in p_lower:
                        if any(token in p_lower for token in fpm_daemon.split("-")):
                            return pkg_ver
                # Fallback to any fpm package
                for pkg_name, pkg_ver in telemetry.packages.items():
                    if "fpm" in pkg_name.lower():
                        return pkg_ver

        # 2. Prefer package matching runtime version if available
        runtime_ver = telemetry.runtime_versions.get(component)
        if runtime_ver:
            major_minor = ".".join(runtime_ver.split(".")[:2])
            for pkg_name, pkg_ver in telemetry.packages.items():
                if component in pkg_name.lower() and major_minor in pkg_name.lower():
                    return pkg_ver

        # 3. Standard package lookup
        for pkg_name, pkg_ver in telemetry.packages.items():
            name_lower = pkg_name.lower()
            if component == "php" and ("php" in name_lower or "fpm" in name_lower):
                return pkg_ver
            if component in ("httpd", "apache") and ("apache2" in name_lower or "httpd" in name_lower):
                return pkg_ver
            if component == "nginx" and "nginx" in name_lower:
                return pkg_ver
            if component in ("openssh", "ssh") and "openssh" in name_lower:
                return pkg_ver
            if component == "openssl" and "openssl" in name_lower:
                return pkg_ver

        # Check runtime versions directly
        if component in telemetry.runtime_versions:
            return telemetry.runtime_versions[component]

        return None

    def _evaluate_ssh_findings(
        self, target_id: str, telemetry: SshSystemTelemetry
    ) -> List[Finding]:
        findings: List[Finding] = []

        # Check Linux packages
        for pkg_name, pkg_ver in telemetry.packages.items():
            comp_norm = self.advisory_engine._normalize_component(pkg_name)
            adv_results = self.advisory_engine.query(comp_norm, pkg_ver, package_version=pkg_ver)

            for adv, status, confidence, note in adv_results:
                findings.append(
                    Finding(
                        id=f"SSH-ADVISORY-{adv.cve}-{target_id}-{pkg_name}",
                        target_id=target_id,
                        title=f"{adv.cve}: {adv.title} ({pkg_name})",
                        description=f"{adv.description}\n\nEvidence: {note}",
                        severity=adv.severity,
                        confidence=confidence,
                        status=status,
                        cve=adv.cve,
                        cvss_score=adv.cvss_score,
                        affected_component=pkg_name,
                        detected_version=pkg_ver,
                        fixed_version=adv.fixed_version,
                        protocols=[Protocol.SSH],
                        evidence=[
                            Evidence(
                                protocol=Protocol.SSH,
                                collector="ssh_package_scanner",
                                raw_data=f"{pkg_name} {pkg_ver}. {note}",
                                extracted_value=pkg_ver,
                                source_command_or_uri="package_inventory",
                            )
                        ],
                        remediation_advice=adv.remediation,
                        references=adv.references,
                    )
                )

        # Check Network Appliances
        if telemetry.platform.is_appliance:
            os_ver = telemetry.platform.os_version
            os_name = telemetry.platform.os_name
            comp_name = "cisco-ios-xe" if "cisco" in os_name.lower() else (
                "fortinet-fortios" if "fortinet" in os_name.lower() else (
                    "f5-bigip" if "big-ip" in os_name.lower() else "appliance"
                )
            )

            adv_results = self.advisory_engine.query(comp_name, os_ver)
            for adv, status, confidence, note in adv_results:
                findings.append(
                    Finding(
                        id=f"APPLIANCE-{adv.cve}-{target_id}",
                        target_id=target_id,
                        title=f"{adv.cve}: {adv.title} ({os_name})",
                        description=f"{adv.description}\n\nAppliance Firmware: {os_ver}",
                        severity=adv.severity,
                        confidence=Confidence.HIGH,
                        status=FindingStatus.CONFIRMED_VULNERABLE,
                        cve=adv.cve,
                        cvss_score=adv.cvss_score,
                        affected_component=os_name,
                        detected_version=os_ver,
                        fixed_version=adv.fixed_version,
                        protocols=[Protocol.SSH],
                        evidence=[
                            Evidence(
                                protocol=Protocol.SSH,
                                collector="appliance_diagnostic_collector",
                                raw_data=f"{os_name} Version {os_ver}",
                                extracted_value=os_ver,
                            )
                        ],
                        remediation_advice=adv.remediation,
                        references=adv.references,
                    )
                )

        return findings
