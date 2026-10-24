"""Non-invasive HTTP checks: safe method discovery, cookie security, and advisory correlation."""

from __future__ import annotations

import re
import urllib.parse
from typing import Dict, List, Optional, Tuple

from vulnshield.advisory.intelligence import AdvisoryIntelligence
from vulnshield.findings.model import Finding, Evidence, Protocol, Severity, Confidence, FindingStatus
from vulnshield.remote.http.client import SafeHttpClient, HttpResponse


class HttpSecurityChecks:
    """Performs safe, non-invasive active/passive HTTP assessments."""

    def __init__(
        self,
        client: SafeHttpClient,
        advisory_engine: Optional[AdvisoryIntelligence] = None,
    ):
        self.client = client
        self.advisory_engine = advisory_engine or AdvisoryIntelligence()

    def check_cookies(
        self, target_id: str, url: str, headers: Dict[str, str], is_https: bool = False
    ) -> List[Finding]:
        """Audits Set-Cookie headers for missing Secure, HttpOnly, and SameSite attributes."""
        findings: List[Finding] = []
        set_cookie_raw = headers.get("set-cookie")
        if not set_cookie_raw:
            return findings

        # In case multiple cookies are separated
        cookies = set_cookie_raw.split("\n") if "\n" in set_cookie_raw else [set_cookie_raw]

        for cookie in cookies:
            parts = [p.strip() for p in cookie.split(";")]
            if not parts:
                continue
            name_val = parts[0]
            cookie_name = name_val.split("=")[0].strip()
            attr_keys = [p.split("=")[0].strip().lower() for p in parts[1:]]

            # Secure attribute on HTTPS
            if is_https and "secure" not in attr_keys:
                findings.append(
                    Finding(
                        id=f"COOKIE-MISSING-SECURE-{target_id}-{cookie_name}",
                        target_id=target_id,
                        title=f"Cookie Without Secure Flag: '{cookie_name}'",
                        description=f"The cookie '{cookie_name}' was transmitted over HTTPS without the 'Secure' attribute, risking transmission over unencrypted connections.",
                        severity=Severity.MEDIUM,
                        confidence=Confidence.HIGH,
                        status=FindingStatus.CONFIRMED_VULNERABLE,
                        protocols=[Protocol.HTTPS],
                        evidence=[
                            Evidence(
                                protocol=Protocol.HTTPS,
                                collector="http_cookie_check",
                                raw_data=cookie,
                                extracted_value=cookie_name,
                                source_command_or_uri=url,
                            )
                        ],
                        remediation_advice=f"Add '; Secure' attribute to '{cookie_name}' cookie.",
                    )
                )

            # HttpOnly attribute for session-like cookies
            is_session = any(k in cookie_name.lower() for k in ["sess", "token", "auth", "jwt", "id"])
            if is_session and "httponly" not in attr_keys:
                findings.append(
                    Finding(
                        id=f"COOKIE-MISSING-HTTPONLY-{target_id}-{cookie_name}",
                        target_id=target_id,
                        title=f"Session Cookie Without HttpOnly Flag: '{cookie_name}'",
                        description=f"The session-related cookie '{cookie_name}' lacks the 'HttpOnly' flag, making it accessible to client-side scripts in case of XSS.",
                        severity=Severity.MEDIUM,
                        confidence=Confidence.HIGH,
                        status=FindingStatus.CONFIRMED_VULNERABLE,
                        protocols=[Protocol.HTTPS if is_https else Protocol.HTTP],
                        evidence=[
                            Evidence(
                                protocol=Protocol.HTTPS if is_https else Protocol.HTTP,
                                collector="http_cookie_check",
                                raw_data=cookie,
                                extracted_value=cookie_name,
                                source_command_or_uri=url,
                            )
                        ],
                        remediation_advice=f"Set '; HttpOnly' attribute on cookie '{cookie_name}'.",
                    )
                )

            # SameSite attribute
            has_samesite = any("samesite" in a for a in attr_keys)
            if not has_samesite:
                findings.append(
                    Finding(
                        id=f"COOKIE-MISSING-SAMESITE-{target_id}-{cookie_name}",
                        target_id=target_id,
                        title=f"Cookie Without SameSite Attribute: '{cookie_name}'",
                        description=f"Cookie '{cookie_name}' does not specify a SameSite attribute (Lax/Strict), increasing exposure to Cross-Site Request Forgery (CSRF).",
                        severity=Severity.LOW,
                        confidence=Confidence.HIGH,
                        status=FindingStatus.CONFIRMED_VULNERABLE,
                        protocols=[Protocol.HTTPS if is_https else Protocol.HTTP],
                        evidence=[
                            Evidence(
                                protocol=Protocol.HTTPS if is_https else Protocol.HTTP,
                                collector="http_cookie_check",
                                raw_data=cookie,
                                extracted_value=cookie_name,
                                source_command_or_uri=url,
                            )
                        ],
                        remediation_advice=f"Set '; SameSite=Lax' or '; SameSite=Strict' on cookie '{cookie_name}'.",
                    )
                )

        return findings

    def check_allowed_methods(self, target_id: str, url: str) -> List[Finding]:
        """Safely probes OPTIONS to discover allowed methods and detects dangerous verbs (e.g. TRACE)."""
        findings: List[Finding] = []
        try:
            resp = self.client.request("OPTIONS", url)
            allow_header = resp.headers.get("allow", "") or resp.headers.get("public", "")
            if not allow_header:
                return findings

            methods = [m.strip().upper() for m in allow_header.split(",")]
            proto = Protocol.HTTPS if url.startswith("https") else Protocol.HTTP

            if "TRACE" in methods:
                findings.append(
                    Finding(
                        id=f"HTTP-METHOD-TRACE-ENABLED-{target_id}",
                        target_id=target_id,
                        title="HTTP TRACE / TRACK Method Enabled",
                        description="The web server permits HTTP TRACE requests, enabling Cross-Site Tracing (XST) and potential credential theft.",
                        severity=Severity.MEDIUM,
                        confidence=Confidence.HIGH,
                        status=FindingStatus.CONFIRMED_VULNERABLE,
                        protocols=[proto],
                        evidence=[
                            Evidence(
                                protocol=proto,
                                collector="http_method_discovery",
                                raw_data=f"Allow: {allow_header}",
                                source_command_or_uri=f"OPTIONS {url}",
                            )
                        ],
                        remediation_advice="Disable HTTP TRACE in web server configuration (e.g. 'TraceEnable Off' in Apache).",
                    )
                )

            dangerous_methods = {"PUT", "DELETE"}.intersection(methods)
            if dangerous_methods:
                findings.append(
                    Finding(
                        id=f"HTTP-METHOD-DANGEROUS-ENABLED-{target_id}",
                        target_id=target_id,
                        title=f"Insecure HTTP Methods Advertised: {', '.join(dangerous_methods)}",
                        description=f"The server advertises support for modifying HTTP methods ({', '.join(dangerous_methods)}) on the root endpoint.",
                        severity=Severity.LOW,
                        confidence=Confidence.MEDIUM,
                        status=FindingStatus.POTENTIALLY_VULNERABLE,
                        protocols=[proto],
                        evidence=[
                            Evidence(
                                protocol=proto,
                                collector="http_method_discovery",
                                raw_data=f"Allow: {allow_header}",
                                source_command_or_uri=f"OPTIONS {url}",
                            )
                        ],
                        remediation_advice="Ensure state-altering HTTP methods require authentication and restrict unneeded verbs.",
                    )
                )
        except Exception:
            pass

        return findings

    def check_advisories_from_banner(
        self,
        target_id: str,
        url: str,
        component: str,
        version: str,
        is_https: bool = False,
    ) -> List[Finding]:
        """
        Correlates banner-detected version against advisory database.
        Marks findings as POTENTIALLY_VULNERABLE with LOW confidence.
        """
        findings: List[Finding] = []
        proto = Protocol.HTTPS if is_https else Protocol.HTTP

        advisory_hits = self.advisory_engine.query(component, version)
        for adv, status, confidence, note in advisory_hits:
            findings.append(
                Finding(
                    id=f"HTTP-ADVISORY-{adv.cve}-{target_id}",
                    target_id=target_id,
                    title=f"{adv.cve}: {adv.title}",
                    description=(
                        f"{adv.description}\n\n"
                        f"Note: Detected via HTTP banner '{component} {version}'. "
                        f"Classified as POTENTIALLY_VULNERABLE with LOW confidence because "
                        f"vendor security backports may be present on the host without changing the banner."
                    ),
                    severity=adv.severity,
                    confidence=Confidence.LOW,  # Explicitly LOW for banner-only
                    status=FindingStatus.POTENTIALLY_VULNERABLE,
                    cve=adv.cve,
                    cvss_score=adv.cvss_score,
                    affected_component=component,
                    detected_version=version,
                    fixed_version=adv.fixed_version,
                    protocols=[proto],
                    evidence=[
                        Evidence(
                            protocol=proto,
                            collector="http_banner_advisory_check",
                            raw_data=f"Banner match: {component} {version}. {note}",
                            source_command_or_uri=url,
                        )
                    ],
                    remediation_advice=adv.remediation,
                    references=adv.references,
                )
            )

        return findings
