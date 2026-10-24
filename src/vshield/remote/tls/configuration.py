"""TLS configuration auditing: protocol version negotiation, cipher suite analysis, and redirect enforcement."""

from __future__ import annotations

import http.client
import socket
import ssl
from dataclasses import dataclass, field
from typing import Dict, List, Optional, Tuple

from vshield.findings.model import Finding, Evidence, Protocol, Severity, Confidence, FindingStatus


# Cipher patterns considered weak
WEAK_CIPHER_PATTERNS = ["NULL", "EXPORT", "RC4", "3DES", "DES", "MD5", "CBC"]


@dataclass
class TlsAuditResult:
    supported_protocols: List[str] = field(default_factory=list)
    deprecated_protocols_found: List[str] = field(default_factory=list)
    negotiated_cipher: Optional[str] = None
    negotiated_protocol: Optional[str] = None
    enforces_https_redirect: bool = False


class TlsConfigurationAuditor:
    """Audits TLS protocol versions, weak cipher suites, and HTTPS redirect policies."""

    def audit_target(
        self,
        host: str,
        https_port: int = 443,
        http_port: int = 80,
        timeout: float = 5.0,
    ) -> Tuple[TlsAuditResult, List[Finding]]:
        findings: List[Finding] = []
        result = TlsAuditResult()

        # 1. Test supported TLS protocol versions
        self._test_tls_versions(host, https_port, timeout, result, findings)

        # 2. Inspect negotiated cipher and check for weak cipher families
        self._test_ciphers(host, https_port, timeout, result, findings)

        # 3. Check HTTP -> HTTPS redirect enforcement
        self._test_https_redirect(host, http_port, https_port, timeout, result, findings)

        return result, findings

    def _test_tls_versions(
        self,
        host: str,
        port: int,
        timeout: float,
        result: TlsAuditResult,
        findings: List[Finding],
    ) -> None:
        # Check standard versions
        versions_to_test = [
            ("TLSv1.0", getattr(ssl, "TLSVersion", None) and ssl.TLSVersion.TLSv1),
            ("TLSv1.1", getattr(ssl, "TLSVersion", None) and ssl.TLSVersion.TLSv1_1),
            ("TLSv1.2", getattr(ssl, "TLSVersion", None) and ssl.TLSVersion.TLSv1_2),
            ("TLSv1.3", getattr(ssl, "TLSVersion", None) and hasattr(ssl.TLSVersion, "TLSv1_3") and ssl.TLSVersion.TLSv1_3),
        ]

        for ver_name, ver_const in versions_to_test:
            if ver_const is None:
                continue

            try:
                context = ssl.SSLContext(ssl.PROTOCOL_TLS_CLIENT)
                context.check_hostname = False
                context.verify_mode = ssl.CERT_NONE
                context.minimum_version = ver_const
                context.maximum_version = ver_const

                with socket.create_connection((host, port), timeout=timeout) as sock:
                    with context.wrap_socket(sock, server_hostname=host) as ssock:
                        result.supported_protocols.append(ver_name)
                        if ver_name in ("TLSv1.0", "TLSv1.1"):
                            result.deprecated_protocols_found.append(ver_name)
            except Exception:
                # Connection or handshake failed for this version -> Not supported
                pass

        if result.deprecated_protocols_found:
            findings.append(
                Finding(
                    id=f"TLS-DEPRECATED-PROTOCOLS-{host}-{port}",
                    target_id=host,
                    title=f"Deprecated TLS Protocols Supported: {', '.join(result.deprecated_protocols_found)}",
                    description=(
                        f"The server negotiates deprecated TLS protocol versions ({', '.join(result.deprecated_protocols_found)}). "
                        "These protocols have known cryptographic vulnerabilities (BEAST, POODLE) and are formally deprecated by RFC 8996."
                    ),
                    severity=Severity.HIGH,
                    confidence=Confidence.HIGH,
                    status=FindingStatus.CONFIRMED_VULNERABLE,
                    protocols=[Protocol.HTTPS],
                    evidence=[
                        Evidence(
                            protocol=Protocol.HTTPS,
                            collector="tls_configuration_auditor",
                            raw_data=f"Supported deprecated protocols: {', '.join(result.deprecated_protocols_found)}",
                            source_command_or_uri=f"{host}:{port}",
                        )
                    ],
                    remediation_advice="Disable TLS 1.0 and TLS 1.1 in server SSL configuration. Enforce TLS 1.2 and TLS 1.3 only.",
                    references=["https://datatracker.ietf.org/doc/html/rfc8996"],
                )
            )

    def _test_ciphers(
        self,
        host: str,
        port: int,
        timeout: float,
        result: TlsAuditResult,
        findings: List[Finding],
    ) -> None:
        try:
            context = ssl.create_default_context()
            context.check_hostname = False
            context.verify_mode = ssl.CERT_NONE

            with socket.create_connection((host, port), timeout=timeout) as sock:
                with context.wrap_socket(sock, server_hostname=host) as ssock:
                    cipher_info = ssock.cipher()
                    if cipher_info:
                        result.negotiated_cipher = cipher_info[0]
                        result.negotiated_protocol = cipher_info[1]

                        # Check if negotiated cipher is weak
                        cipher_name = cipher_info[0].upper()
                        matched_weak = [p for p in WEAK_CIPHER_PATTERNS if p in cipher_name]
                        if matched_weak:
                            findings.append(
                                Finding(
                                    id=f"TLS-WEAK-CIPHER-{host}-{port}",
                                    target_id=host,
                                    title=f"Weak Cipher Suite Negotiated: {cipher_name}",
                                    description=f"The server negotiated cipher '{cipher_name}', which belongs to weak cipher family: {', '.join(matched_weak)}.",
                                    severity=Severity.MEDIUM,
                                    confidence=Confidence.HIGH,
                                    status=FindingStatus.CONFIRMED_VULNERABLE,
                                    protocols=[Protocol.HTTPS],
                                    evidence=[
                                        Evidence(
                                            protocol=Protocol.HTTPS,
                                            collector="tls_configuration_auditor",
                                            raw_data=f"Negotiated Cipher: {cipher_name}, Protocol: {cipher_info[1]}",
                                            source_command_or_uri=f"{host}:{port}",
                                        )
                                    ],
                                    remediation_advice="Configure server to use strong AEAD cipher suites (e.g. ECDHE-ECDSA-AES256-GCM-SHA384, ECDHE-RSA-AES256-GCM-SHA384).",
                                )
                            )
        except Exception:
            pass

    def _test_https_redirect(
        self,
        host: str,
        http_port: int,
        https_port: int,
        timeout: float,
        result: TlsAuditResult,
        findings: List[Finding],
    ) -> None:
        """Verifies if HTTP (port 80) enforces redirection to HTTPS (port 443)."""
        try:
            conn = http.client.HTTPConnection(host, port=http_port, timeout=timeout)
            conn.request("GET", "/")
            res = conn.getresponse()
            headers = {k.lower(): v for k, v in res.getheaders()}
            conn.close()

            loc = headers.get("location", "")
            if res.status in (301, 302, 307, 308) and loc.startswith("https://"):
                result.enforces_https_redirect = True
            else:
                findings.append(
                    Finding(
                        id=f"HTTP-NO-HTTPS-REDIRECT-{host}",
                        target_id=host,
                        title=f"Insecure HTTP Service Does Not Enforce HTTPS Redirection",
                        description=f"HTTP service on {host}:{http_port} returned HTTP status {res.status} without redirecting to https://.",
                        severity=Severity.MEDIUM,
                        confidence=Confidence.HIGH,
                        status=FindingStatus.CONFIRMED_VULNERABLE,
                        protocols=[Protocol.HTTP],
                        evidence=[
                            Evidence(
                                protocol=Protocol.HTTP,
                                collector="tls_redirect_enforcer",
                                raw_data=f"HTTP Status: {res.status}, Location: '{loc}'",
                                source_command_or_uri=f"http://{host}:{http_port}/",
                            )
                        ],
                        remediation_advice="Configure HTTP server on port 80 to permanently redirect (301) all requests to https://.",
                    )
                )
        except Exception:
            # HTTP port not open or not reachable - not an error
            pass
