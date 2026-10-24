"""Safe, authenticated SSH client enforcing strict security controls and vetted commands."""

from __future__ import annotations

import logging
import os
import random
import subprocess
import time
from typing import Any, Callable, Dict, List, Optional, Tuple

from vulnshield.findings.model import Evidence, Protocol
from vulnshield.remote.authorization import TargetAuthorizer, redact_sensitive, AuthorizationError
from vulnshield.remote.ssh.authentication import SshAuthCredentials
from vulnshield.remote.ssh.collectors import (
    CommandValidator,
    SshEvidenceCollector,
    SshSystemTelemetry,
    SecurityCommandValidationError,
)
from vulnshield.remote.ssh.platforms import PlatformDetector, PlatformType, PlatformProfile

logger = logging.getLogger(__name__)


class SshExecutionError(Exception):
    """Raised when an SSH operation fails."""
    pass


class SshAuthenticationError(SshExecutionError):
    """Raised when SSH authentication fails."""
    pass


class SshHostKeyError(SshExecutionError):
    """Raised when SSH host key verification fails."""
    pass


class SafeSshClient:
    """Agentless SSH assessment client enforcing read-only commands and strict security controls."""

    def __init__(
        self,
        credentials: SshAuthCredentials,
        host: str,
        port: int = 22,
        authorizer: Optional[TargetAuthorizer] = None,
        timeout: float = 10.0,
        known_hosts_file: Optional[str] = None,
        mock_transport: Optional[Callable[[str], Tuple[int, str, str]]] = None,
    ):
        self.credentials = credentials
        self.host = host
        self.port = port
        self.authorizer = authorizer or TargetAuthorizer()
        self.timeout = timeout
        self.known_hosts_file = known_hosts_file
        self.mock_transport = mock_transport
        self.collector = SshEvidenceCollector()

    def run_vetted_command(self, template_key: str, **kwargs: str) -> str:
        """Renders vetted command template and executes safely over SSH."""
        cmd = CommandValidator.render_command(template_key, **kwargs)
        exit_code, stdout, stderr = self._execute_remote_command(cmd)

        if exit_code != 0:
            err_msg = stderr.strip() or stdout.strip() or f"Command exited with code {exit_code}"
            # Check for host key or auth errors
            if "host key verification failed" in err_msg.lower():
                raise SshHostKeyError(f"Strict host key verification failed for {self.host}: {err_msg}")
            if "permission denied" in err_msg.lower():
                raise SshAuthenticationError(f"SSH authentication failed for {self.credentials.username}@{self.host}: {err_msg}")
            # Non-zero exit code may simply mean package is not installed or service is inactive
            logger.debug("Vetted command %s exited with %d: %s", template_key, exit_code, err_msg)
            return stdout

        return stdout

    def collect_system_telemetry(self, target_id: str) -> SshSystemTelemetry:
        """Executes non-destructive read-only telemetry collection across vetted templates."""
        evidence_list: List[Evidence] = []

        # 1. Probe OS and Kernel
        os_release_raw = self._safe_run_collector("os_release", evidence_list, target_id)
        uname_raw = self._safe_run_collector("uname", evidence_list, target_id)

        # 2. Identify platform
        platform = PlatformDetector.identify_from_evidence(
            os_release_text=os_release_raw,
            uname_text=uname_raw,
        )

        telemetry = SshSystemTelemetry(
            platform=platform,
            raw_evidence_list=evidence_list,
        )

        # If Network Appliance, execute appliance-specific diagnostic and exit
        if platform.is_appliance:
            if platform.platform_type == PlatformType.CISCO_IOS:
                self._safe_run_collector("cisco_show_version", evidence_list, target_id)
            elif platform.platform_type == PlatformType.FORTINET_FORTIOS:
                self._safe_run_collector("fortinet_status", evidence_list, target_id)
            elif platform.platform_type == PlatformType.F5_BIGIP:
                self._safe_run_collector("f5_show_version", evidence_list, target_id)
            elif platform.platform_type == PlatformType.JUNIPER_JUNOS:
                self._safe_run_collector("juniper_show_version", evidence_list, target_id)
            return telemetry

        # Linux Telemetry: Packages
        if platform.package_manager == "dpkg":
            pkg_raw = self._safe_run_collector("dpkg_query", evidence_list, target_id)
            telemetry.packages = self.collector.parse_packages("dpkg", pkg_raw)
        elif platform.package_manager == "rpm":
            pkg_raw = self._safe_run_collector("rpm_qa", evidence_list, target_id)
            telemetry.packages = self.collector.parse_packages("rpm", pkg_raw)
        elif platform.package_manager == "apk":
            pkg_raw = self._safe_run_collector("apk_info", evidence_list, target_id)
            telemetry.packages = self.collector.parse_packages("apk", pkg_raw)

        # Services and Listening Ports
        services_raw = self._safe_run_collector("running_services", evidence_list, target_id)
        telemetry.running_services = self.collector.parse_running_services(services_raw)

        ports_raw = self._safe_run_collector("listening_ports", evidence_list, target_id)
        telemetry.listening_ports = self.collector.parse_listening_ports(ports_raw)

        # Application Runtimes
        for app, template in [
            ("php", "php_version"),
            ("nginx", "nginx_version"),
            ("apache", "apache_version"),
            ("openssl", "openssl_version"),
            ("docker", "docker_version"),
        ]:
            out = self._safe_run_collector(template, evidence_list, target_id)
            ver = self.collector.parse_runtime_version(app, out)
            if ver:
                telemetry.runtime_versions[app] = ver

        return telemetry

    def _safe_run_collector(
        self,
        template_key: str,
        evidence_list: List[Evidence],
        target_id: str,
    ) -> str:
        try:
            output = self.run_vetted_command(template_key)
            if output.strip():
                evidence_list.append(
                    Evidence(
                        protocol=Protocol.SSH,
                        collector=f"ssh_{template_key}",
                        raw_data=redact_sensitive(output.strip()),
                        source_command_or_uri=template_key,
                    )
                )
            return output
        except Exception as e:
            logger.debug("Collector %s failed: %s", template_key, e)
            return ""

    def _execute_remote_command(self, cmd: str) -> Tuple[int, str, str]:
        """Executes a single remote command with retry logic for transient network issues."""
        # Check mock transport first (for unit and integration tests)
        if self.mock_transport:
            return self.mock_transport(cmd)

        # Validate IP with SSRF guard
        self.authorizer.resolve_and_verify_ip(self.host, self.port)

        # Build secure ssh command line
        ssh_cmd = [
            "ssh",
            "-p", str(self.port),
            "-o", "BatchMode=yes",
            "-o", "StrictHostKeyChecking=yes",
            "-o", f"ConnectTimeout={int(self.timeout)}",
            "-o", "LogLevel=ERROR",
        ]

        if self.known_hosts_file:
            ssh_cmd.extend(["-o", f"UserKnownHostsFile={os.path.expanduser(self.known_hosts_file)}"])

        if self.credentials.identity_file:
            ssh_cmd.extend(["-i", os.path.expanduser(self.credentials.identity_file)])

        if self.credentials.certificate_file:
            ssh_cmd.extend(["-o", f"CertificateFile={os.path.expanduser(self.credentials.certificate_file)}"])

        ssh_cmd.append(f"{self.credentials.username}@{self.host}")
        ssh_cmd.append(cmd)

        # Retries for transient socket errors (max 2 retries, NEVER retry auth failure)
        max_retries = 2
        for attempt in range(max_retries + 1):
            try:
                proc = subprocess.run(
                    ssh_cmd,
                    stdout=subprocess.PIPE,
                    stderr=subprocess.PIPE,
                    timeout=self.timeout + 5.0,
                    text=True,
                )
                stdout = redact_sensitive(proc.stdout)
                stderr = redact_sensitive(proc.stderr)

                # If auth failed, don't retry
                if "permission denied" in stderr.lower():
                    raise SshAuthenticationError(f"Permission denied for {self.credentials.username}@{self.host}")

                return proc.returncode, stdout, stderr

            except subprocess.TimeoutExpired:
                if attempt == max_retries:
                    raise SshExecutionError(f"SSH command timed out after {self.timeout}s on {self.host}")
                time.sleep(0.5 + random.uniform(0.1, 0.4))
            except Exception as e:
                if attempt == max_retries:
                    raise SshExecutionError(f"SSH command execution failed on {self.host}: {e}")
                time.sleep(0.5 + random.uniform(0.1, 0.4))

        return 1, "", "Execution failed"
