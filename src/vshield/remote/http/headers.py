"""HTTP security header analyzer and version disclosure auditor."""

from __future__ import annotations

from typing import Dict, List, Optional
from vshield.findings.model import Finding, Evidence, Protocol, Severity, Confidence, FindingStatus


class HeaderSecurityAnalyzer:
    """Audits HTTP response headers for missing security controls and information disclosures."""

    def analyze(
        self,
        target_id: str,
        url: str,
        headers: Dict[str, str],
        is_https: bool = False,
    ) -> List[Finding]:
        findings: List[Finding] = []

        # 1. HSTS Check (Only relevant for HTTPS)
        if is_https:
            hsts = headers.get("strict-transport-security")
            if not hsts:
                findings.append(
                    Finding(
                        id=f"HTTP-HEADER-HSTS-MISSING-{target_id}",
                        target_id=target_id,
                        title="Missing HTTP Strict Transport Security (HSTS) Header",
                        description="The server does not enforce HTTPS connections using the Strict-Transport-Security header, allowing potential SSL-stripping attacks.",
                        severity=Severity.MEDIUM,
                        confidence=Confidence.HIGH,
                        status=FindingStatus.CONFIRMED_VULNERABLE,
                        protocols=[Protocol.HTTPS],
                        evidence=[
                            Evidence(
                                protocol=Protocol.HTTPS,
                                collector="http_header_analyzer",
                                raw_data="Header Strict-Transport-Security absent in response headers",
                                source_command_or_uri=url,
                            )
                        ],
                        remediation_advice="Configure 'Strict-Transport-Security: max-age=31536000; includeSubDomains; preload' on HTTPS web server.",
                        references=["https://cheatsheetseries.owasp.org/cheatsheets/HTTP_Strict_Transport_Security_Cheat_Sheet.html"],
                    )
                )

        # 2. Content-Security-Policy (CSP) Check
        csp = headers.get("content-security-policy")
        if not csp:
            findings.append(
                Finding(
                    id=f"HTTP-HEADER-CSP-MISSING-{target_id}",
                    target_id=target_id,
                    title="Missing Content-Security-Policy (CSP) Header",
                    description="The web application does not specify a Content-Security-Policy header to mitigate Cross-Site Scripting (XSS) and data injection attacks.",
                    severity=Severity.LOW,
                    confidence=Confidence.HIGH,
                    status=FindingStatus.CONFIRMED_VULNERABLE,
                    protocols=[Protocol.HTTPS if is_https else Protocol.HTTP],
                    evidence=[
                        Evidence(
                            protocol=Protocol.HTTPS if is_https else Protocol.HTTP,
                            collector="http_header_analyzer",
                            raw_data="Header Content-Security-Policy absent in response",
                            source_command_or_uri=url,
                        )
                    ],
                    remediation_advice="Deploy an appropriate Content-Security-Policy header restricting script and object sources.",
                )
            )

        # 3. X-Content-Type-Options
        xcto = headers.get("x-content-type-options", "").lower()
        if xcto != "nosniff":
            findings.append(
                Finding(
                    id=f"HTTP-HEADER-XCTO-MISSING-{target_id}",
                    target_id=target_id,
                    title="Missing or Insecure X-Content-Type-Options Header",
                    description="The server did not send 'X-Content-Type-Options: nosniff', which protects against MIME-type sniffing vulnerabilities.",
                    severity=Severity.LOW,
                    confidence=Confidence.HIGH,
                    status=FindingStatus.CONFIRMED_VULNERABLE,
                    protocols=[Protocol.HTTPS if is_https else Protocol.HTTP],
                    evidence=[
                        Evidence(
                            protocol=Protocol.HTTPS if is_https else Protocol.HTTP,
                            collector="http_header_analyzer",
                            raw_data=f"X-Content-Type-Options: '{xcto or 'absent'}'",
                            source_command_or_uri=url,
                        )
                    ],
                    remediation_advice="Set 'X-Content-Type-Options: nosniff' on all responses.",
                )
            )

        # 4. X-Frame-Options
        xfo = headers.get("x-frame-options", "").lower()
        if not xfo and not csp:
            findings.append(
                Finding(
                    id=f"HTTP-HEADER-XFO-MISSING-{target_id}",
                    target_id=target_id,
                    title="Missing Anti-Clickjacking Header (X-Frame-Options)",
                    description="The server is missing the X-Frame-Options header and frame-ancestors CSP directive, leaving pages vulnerable to framing / clickjacking.",
                    severity=Severity.LOW,
                    confidence=Confidence.HIGH,
                    status=FindingStatus.CONFIRMED_VULNERABLE,
                    protocols=[Protocol.HTTPS if is_https else Protocol.HTTP],
                    evidence=[
                        Evidence(
                            protocol=Protocol.HTTPS if is_https else Protocol.HTTP,
                            collector="http_header_analyzer",
                            raw_data="Neither X-Frame-Options nor CSP frame-ancestors present",
                            source_command_or_uri=url,
                        )
                    ],
                    remediation_advice="Add 'X-Frame-Options: DENY' or 'X-Frame-Options: SAMEORIGIN'.",
                )
            )

        # 5. Server Version Disclosure
        server = headers.get("server", "")
        if any(c.isdigit() for c in server):
            findings.append(
                Finding(
                    id=f"HTTP-DISCLOSURE-SERVER-VERSION-{target_id}",
                    target_id=target_id,
                    title=f"Server Header Version Disclosure: {server}",
                    description=f"The HTTP server banner discloses detailed software and version information: '{server}'.",
                    severity=Severity.INFO,
                    confidence=Confidence.HIGH,
                    status=FindingStatus.CONFIRMED_VULNERABLE,
                    protocols=[Protocol.HTTPS if is_https else Protocol.HTTP],
                    evidence=[
                        Evidence(
                            protocol=Protocol.HTTPS if is_https else Protocol.HTTP,
                            collector="http_header_analyzer",
                            raw_data=f"Server: {server}",
                            extracted_value=server,
                            source_command_or_uri=url,
                        )
                    ],
                    remediation_advice="Configure web server to suppress granular version information (e.g. 'ServerTokens Prod' in Apache or 'server_tokens off;' in Nginx).",
                )
            )

        # 6. X-Powered-By Disclosure
        powered_by = headers.get("x-powered-by", "")
        if powered_by:
            findings.append(
                Finding(
                    id=f"HTTP-DISCLOSURE-X-POWERED-BY-{target_id}",
                    target_id=target_id,
                    title=f"X-Powered-By Technology Disclosure: {powered_by}",
                    description=f"The application leaks underlying runtime technology in the X-Powered-By header: '{powered_by}'.",
                    severity=Severity.INFO,
                    confidence=Confidence.HIGH,
                    status=FindingStatus.CONFIRMED_VULNERABLE,
                    protocols=[Protocol.HTTPS if is_https else Protocol.HTTP],
                    evidence=[
                        Evidence(
                            protocol=Protocol.HTTPS if is_https else Protocol.HTTP,
                            collector="http_header_analyzer",
                            raw_data=f"X-Powered-By: {powered_by}",
                            extracted_value=powered_by,
                            source_command_or_uri=url,
                        )
                    ],
                    remediation_advice="Disable X-Powered-By header (e.g. 'expose_php = Off' in php.ini).",
                )
            )

        return findings
