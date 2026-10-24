"""TLS certificate inspection, validation, expiration, and inventory auditing."""

from __future__ import annotations

import datetime
import socket
import ssl
from dataclasses import dataclass, field
from typing import Any, Dict, List, Optional, Tuple

from vshield.findings.model import Finding, Evidence, Protocol, Severity, Confidence, FindingStatus


@dataclass
class CertificateInfo:
    subject_cn: Optional[str] = None
    issuer_cn: Optional[str] = None
    sans: List[str] = field(default_factory=list)
    serial_number: Optional[str] = None
    not_before: Optional[str] = None
    not_after: Optional[str] = None
    days_until_expiration: Optional[int] = None
    is_expired: bool = False
    is_self_signed: bool = False
    validation_error: Optional[str] = None
    raw_dict: Dict[str, Any] = field(default_factory=dict)


class CertificateInspector:
    """Inspects X.509 certificates and reports cryptographic and validity findings."""

    def inspect_host(
        self,
        host: str,
        port: int = 443,
        timeout: float = 10.0,
        verify_ca: bool = True,
    ) -> Tuple[Optional[CertificateInfo], List[Finding]]:
        """
        Connects via TLS and analyzes server certificate.
        Preserves certificate validation by default, producing diagnostic findings on failure.
        """
        findings: List[Finding] = []
        cert_info = CertificateInfo()

        # Step 1: Attempt standard verified connection
        context = ssl.create_default_context()
        validation_error: Optional[str] = None
        verified = True

        try:
            with socket.create_connection((host, port), timeout=timeout) as sock:
                with context.wrap_socket(sock, server_hostname=host) as ssock:
                    cert_dict = ssock.getpeercert()
                    if cert_dict:
                        self._populate_cert_info(cert_dict, cert_info)
        except ssl.SSLCertVerificationError as e:
            verified = False
            validation_error = str(e)
            cert_info.validation_error = validation_error
        except Exception as e:
            # Other socket/SSL error
            return None, [
                Finding(
                    id=f"TLS-CONNECT-FAIL-{host}-{port}",
                    target_id=host,
                    title=f"TLS Connection Error on {host}:{port}",
                    description=f"Could not establish TLS session: {e}",
                    severity=Severity.HIGH,
                    confidence=Confidence.HIGH,
                    status=FindingStatus.UNABLE_TO_ASSESS,
                    protocols=[Protocol.HTTPS],
                    evidence=[
                        Evidence(
                            protocol=Protocol.HTTPS,
                            collector="tls_certificate_inspector",
                            raw_data=str(e),
                            source_command_or_uri=f"{host}:{port}",
                        )
                    ],
                )
            ]

        # Step 2: If verification failed, connect unverified ONLY to extract diagnostic metadata
        # without trusting it for application traffic!
        if not verified:
            try:
                unverified_context = ssl._create_unverified_context()
                with socket.create_connection((host, port), timeout=timeout) as sock:
                    with unverified_context.wrap_socket(sock, server_hostname=host) as ssock:
                        cert_dict = ssock.getpeercert()
                        # When unverified, getpeercert() returns empty dict without binary form in standard stdlib
                        # but ssock.getpeercert(binary_form=True) can be extracted or binary DER inspected
                        if cert_dict:
                            self._populate_cert_info(cert_dict, cert_info)
            except Exception:
                pass

            # Generate diagnostic finding for verification failure
            finding_type = "Certificate Verification Failure"
            sev = Severity.HIGH
            if "certificate has expired" in (validation_error or "").lower():
                finding_type = "Expired TLS Certificate"
                cert_info.is_expired = True
            elif "self-signed" in (validation_error or "").lower() or "self signed" in (validation_error or "").lower():
                finding_type = "Self-Signed TLS Certificate"
                cert_info.is_self_signed = True
            elif "hostname" in (validation_error or "").lower():
                finding_type = "TLS Certificate Hostname Mismatch"

            findings.append(
                Finding(
                    id=f"TLS-CERT-INVALID-{host}-{port}",
                    target_id=host,
                    title=f"{finding_type} on {host}:{port}",
                    description=f"TLS certificate validation failed: {validation_error}",
                    severity=sev,
                    confidence=Confidence.HIGH,
                    status=FindingStatus.CONFIRMED_VULNERABLE,
                    protocols=[Protocol.HTTPS],
                    evidence=[
                        Evidence(
                            protocol=Protocol.HTTPS,
                            collector="tls_certificate_inspector",
                            raw_data=f"Verification Error: {validation_error}",
                            source_command_or_uri=f"{host}:{port}",
                        )
                    ],
                    remediation_advice="Deploy a valid, CA-signed TLS certificate matching the target domain.",
                )
            )

        # Step 3: Check certificate expiration warnings if certificate parsed
        if cert_info.days_until_expiration is not None:
            if cert_info.days_until_expiration <= 0:
                findings.append(
                    Finding(
                        id=f"TLS-CERT-EXPIRED-{host}-{port}",
                        target_id=host,
                        title=f"Expired TLS Certificate on {host}:{port}",
                        description=f"Certificate expired {abs(cert_info.days_until_expiration)} days ago (Not After: {cert_info.not_after}).",
                        severity=Severity.HIGH,
                        confidence=Confidence.HIGH,
                        status=FindingStatus.CONFIRMED_VULNERABLE,
                        protocols=[Protocol.HTTPS],
                        evidence=[
                            Evidence(
                                protocol=Protocol.HTTPS,
                                collector="tls_certificate_inspector",
                                raw_data=f"Not After: {cert_info.not_after}, Days Remaining: {cert_info.days_until_expiration}",
                                source_command_or_uri=f"{host}:{port}",
                            )
                        ],
                        remediation_advice="Renew and replace the expired TLS certificate immediately.",
                    )
                )
            elif cert_info.days_until_expiration <= 30:
                findings.append(
                    Finding(
                        id=f"TLS-CERT-EXPIRING-SOON-{host}-{port}",
                        target_id=host,
                        title=f"TLS Certificate Expiring Soon on {host}:{port}",
                        description=f"Certificate will expire in {cert_info.days_until_expiration} days on {cert_info.not_after}.",
                        severity=Severity.MEDIUM,
                        confidence=Confidence.HIGH,
                        status=FindingStatus.CONFIRMED_VULNERABLE,
                        protocols=[Protocol.HTTPS],
                        evidence=[
                            Evidence(
                                protocol=Protocol.HTTPS,
                                collector="tls_certificate_inspector",
                                raw_data=f"Days Remaining: {cert_info.days_until_expiration}",
                                source_command_or_uri=f"{host}:{port}",
                            )
                        ],
                        remediation_advice="Initiate certificate renewal before expiration.",
                    )
                )

        return cert_info, findings

    def _populate_cert_info(self, cert: Dict[str, Any], info: CertificateInfo) -> None:
        info.raw_dict = cert

        # Subject
        for item in cert.get("subject", ()):
            for k, v in item:
                if k == "commonName":
                    info.subject_cn = v

        # Issuer
        for item in cert.get("issuer", ()):
            for k, v in item:
                if k == "commonName":
                    info.issuer_cn = v

        if info.subject_cn and info.subject_cn == info.issuer_cn:
            info.is_self_signed = True

        # SANs
        sans = []
        for san_type, san_val in cert.get("subjectAltName", ()):
            if san_type == "DNS":
                sans.append(san_val)
        info.sans = sans

        # Serial
        info.serial_number = cert.get("serialNumber")

        # Expiry
        info.not_before = cert.get("notBefore")
        info.not_after = cert.get("notAfter")

        if info.not_after:
            try:
                # Format: "May 24 12:00:00 2025 GMT"
                expiry_dt = datetime.datetime.strptime(info.not_after, "%b %d %H:%M:%S %Y %Z")
                now = datetime.datetime.utcnow()
                diff = (expiry_dt - now).days
                info.days_until_expiration = diff
                info.is_expired = diff < 0
            except Exception:
                pass
