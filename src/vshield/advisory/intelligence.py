"""Advisory and CVE Intelligence Engine for vShield."""

from __future__ import annotations

import re
from dataclasses import dataclass, field
from typing import Any, Dict, List, Optional, Tuple

from vshield.advisory.backports import VendorBackportDetector
from vshield.findings.model import Severity, Confidence, FindingStatus


@dataclass
class AdvisoryEntry:
    cve: str
    component: str
    affected_versions: List[str]
    fixed_version: str
    severity: Severity
    cvss_score: float
    title: str
    description: str
    remediation: str
    references: List[str] = field(default_factory=list)
    vendor_fixes: Dict[str, str] = field(default_factory=dict)  # vendor -> fixed_package_string


# Curated known security advisories for network services, runtimes, and appliances
BUILTIN_ADVISORIES: List[AdvisoryEntry] = [
    AdvisoryEntry(
        cve="CVE-2024-2756",
        component="php",
        affected_versions=["8.3.0", "8.3.1", "8.3.2", "8.3.3", "8.3.4"],
        fixed_version="8.3.5",
        severity=Severity.HIGH,
        cvss_score=7.5,
        title="PHP __Host-/__Secure- Cookie Bypass",
        description="In PHP version 8.3 prior to 8.3.5, cookie name validation flaw allows __Host- prefix bypass.",
        remediation="Upgrade PHP package to 8.3.5 or apply vendor security backport.",
        references=["https://nvd.nist.gov/vuln/detail/CVE-2024-2756"],
        vendor_fixes={
            "ubuntu": "8.3.6-0ubuntu0.24.04.1",
            "debian": "8.3.5-1~deb12u1",
            "rhel": "8.3.5-1.el9",
        },
    ),
    AdvisoryEntry(
        cve="CVE-2024-4577",
        component="php",
        affected_versions=["8.1.0-8.1.28", "8.2.0-8.2.19", "8.3.0-8.3.7"],
        fixed_version="8.3.8",
        severity=Severity.CRITICAL,
        cvss_score=9.8,
        title="PHP CGI Argument Injection (Best-Fit Mapping)",
        description="Bypass of CVE-2012-1823 in PHP allows remote code execution when running in CGI mode on Windows or misconfigured servers.",
        remediation="Upgrade PHP to 8.3.8, 8.2.20, or 8.1.29.",
        references=["https://nvd.nist.gov/vuln/detail/CVE-2024-4577"],
        vendor_fixes={
            "ubuntu": "8.3.6-0ubuntu0.24.04.1+security1",
            "debian": "8.2.7-1~deb12u2",
        },
    ),
    AdvisoryEntry(
        cve="CVE-2024-6387",
        component="openssh",
        affected_versions=["8.5p1-9.7p1"],
        fixed_version="9.8p1",
        severity=Severity.HIGH,
        cvss_score=8.1,
        title="OpenSSH regreSSHion Signal Handler Race Condition",
        description="Signal handler race condition in OpenSSH's server (sshd) allows remote code execution as root on glibc-based Linux systems.",
        remediation="Update openssh-server to 9.8p1 or apply vendor security backport (e.g. Ubuntu USN-6859-1).",
        references=["https://nvd.nist.gov/vuln/detail/CVE-2024-6387"],
        vendor_fixes={
            "ubuntu": "1:9.6p1-3ubuntu13.3",
            "debian": "1:9.2p1-2+deb12u3",
            "rhel": "8.7p1-38.el9_4.1",
            "alpine": "9.7_p1-r4",
        },
    ),
    AdvisoryEntry(
        cve="CVE-2023-44487",
        component="httpd",
        affected_versions=["2.4.0-2.4.57"],
        fixed_version="2.4.58",
        severity=Severity.HIGH,
        cvss_score=7.5,
        title="HTTP/2 Rapid Reset Denial of Service (Apache)",
        description="HTTP/2 protocol flaw allows rapid stream cancellation causing resource exhaustion.",
        remediation="Update Apache httpd to 2.4.58 or later and configure Protocols appropriately.",
        references=["https://nvd.nist.gov/vuln/detail/CVE-2023-44487"],
        vendor_fixes={
            "ubuntu": "2.4.52-1ubuntu4.7",
            "debian": "2.4.56-1~deb12u2",
            "rhel": "2.4.57-11.el9_4",
        },
    ),
    AdvisoryEntry(
        cve="CVE-2023-44487",
        component="nginx",
        affected_versions=["1.0.0-1.25.2"],
        fixed_version="1.25.3",
        severity=Severity.HIGH,
        cvss_score=7.5,
        title="HTTP/2 Rapid Reset Denial of Service (Nginx)",
        description="Nginx HTTP/2 stream processing vulnerability allowing remote denial of service.",
        remediation="Update Nginx to 1.25.3 or 1.24.1, or configure limit_req and keepalive_requests.",
        references=["https://nvd.nist.gov/vuln/detail/CVE-2023-44487"],
        vendor_fixes={
            "ubuntu": "1.18.0-6ubuntu14.4",
            "debian": "1.22.1-9+deb12u1",
            "rhel": "1.20.1-14.el9_2.1",
        },
    ),
    AdvisoryEntry(
        cve="CVE-2023-38606",
        component="openssl",
        affected_versions=["3.0.0-3.0.9", "3.1.0-3.1.1"],
        fixed_version="3.0.10",
        severity=Severity.MEDIUM,
        cvss_score=5.3,
        title="OpenSSL Excessive Time Spent Checking DH Keys",
        description="Processing excessively long Diffie-Hellman keys may lead to denial of service.",
        remediation="Upgrade OpenSSL to 3.0.10 or 3.1.2 or apply vendor package updates.",
        references=["https://nvd.nist.gov/vuln/detail/CVE-2023-38606"],
        vendor_fixes={
            "ubuntu": "3.0.8-1ubuntu1.2",
            "debian": "3.0.9-1~deb12u1",
            "rhel": "3.0.7-27.el9_2",
        },
    ),
    # Appliance advisories
    AdvisoryEntry(
        cve="CVE-2023-46747",
        component="f5-bigip",
        affected_versions=["17.1.0", "16.1.0-16.1.4", "15.1.0-15.1.10"],
        fixed_version="17.1.0.3",
        severity=Severity.CRITICAL,
        cvss_score=9.8,
        title="F5 BIG-IP TMUI Authentication Bypass",
        description="Undisclosed requests may bypass Traffic Management User Interface (TMUI) authentication.",
        remediation="Apply F5 hotfix or upgrade BIG-IP firmware per vendor advisory K000137353.",
        references=["https://my.f5.com/manage/s/article/K000137353"],
        vendor_fixes={
            "f5": "17.1.0.3",
        },
    ),
    AdvisoryEntry(
        cve="CVE-2023-27997",
        component="fortinet-fortios",
        affected_versions=["7.2.0-7.2.4", "7.0.0-7.0.11", "6.4.0-6.4.12"],
        fixed_version="7.2.5",
        severity=Severity.CRITICAL,
        cvss_score=9.8,
        title="Fortinet FortiOS SSL-VPN Heap-Based Buffer Overflow",
        description="Heap-based buffer overflow vulnerability in FortiOS SSL-VPN allows unauthenticated remote code execution.",
        remediation="Upgrade FortiOS firmware to 7.2.5, 7.0.12, or 6.4.13 immediately.",
        references=["https://www.fortiguard.com/psirt/FG-IR-23-097"],
        vendor_fixes={
            "fortinet": "7.2.5",
        },
    ),
    AdvisoryEntry(
        cve="CVE-2023-20198",
        component="cisco-ios-xe",
        affected_versions=["16.1.1-17.9.4"],
        fixed_version="17.9.4a",
        severity=Severity.CRITICAL,
        cvss_score=10.0,
        title="Cisco IOS XE Web UI Privilege Escalation",
        description="Flaw in web UI feature allows remote unauthenticated attacker to create account with privilege level 15.",
        remediation="Upgrade Cisco IOS XE to fixed release (17.9.4a or later) or disable HTTP/HTTPS Server feature.",
        references=["https://sec.cloudapps.cisco.com/security/center/content/CiscoSecurityAdvisory/cisco-sa-iosxe-webui-privesc-j22SaA4z"],
        vendor_fixes={
            "cisco": "17.9.4a",
        },
    ),
]


class AdvisoryIntelligence:
    """Intelligence engine matching software versions with known security advisories."""

    def __init__(self, advisories: Optional[List[AdvisoryEntry]] = None):
        self.advisories = advisories or BUILTIN_ADVISORIES

    def query(
        self,
        component: str,
        version: str,
        package_version: Optional[str] = None,
    ) -> List[Tuple[AdvisoryEntry, FindingStatus, Confidence, Optional[str]]]:
        """
        Queries known advisories for component and version.
        Returns list of (advisory, status, confidence, note).
        """
        results = []
        normalized_component = self._normalize_component(component)

        for adv in self.advisories:
            if self._normalize_component(adv.component) != normalized_component:
                continue

            # Check if version matches affected versions
            if not self._is_version_affected(version, adv.affected_versions):
                continue

            # Check if vendor package backport resolves it
            if package_version:
                is_patched, backport_note = VendorBackportDetector.is_vendor_patched(
                    normalized_component, package_version, adv.vendor_fixes
                )
                if is_patched:
                    results.append((adv, FindingStatus.PATCHED, Confidence.FIXED, backport_note))
                    continue
                else:
                    # Verified vulnerable installed package with vendor advisory
                    results.append(
                        (
                            adv,
                            FindingStatus.CONFIRMED_VULNERABLE,
                            Confidence.HIGH,
                            f"Verified installed package {package_version} is vulnerable to {adv.cve}",
                        )
                    )
                    continue

            # If only a banner/version was detected without package backport confirmation
            results.append(
                (
                    adv,
                    FindingStatus.POTENTIALLY_VULNERABLE,
                    Confidence.LOW,
                    f"Version {version} matches affected range for {adv.cve}. Needs package/build confirmation.",
                )
            )

        return results

    def _normalize_component(self, name: str) -> str:
        name = name.lower().strip()
        if "apache" in name or "httpd" in name:
            return "httpd"
        if "nginx" in name:
            return "nginx"
        if "php" in name:
            return "php"
        if "openssh" in name or "ssh" in name:
            return "openssh"
        if "openssl" in name:
            return "openssl"
        if "cisco" in name or "ios-xe" in name or "ios" in name:
            return "cisco-ios-xe"
        if "fortinet" in name or "fortios" in name:
            return "fortinet-fortios"
        if "f5" in name or "bigip" in name or "big-ip" in name:
            return "f5-bigip"
        return name

    def _is_version_affected(self, version: str, affected_ranges: List[str]) -> bool:
        """Determines if version string falls in affected range."""
        clean_v = self._extract_clean_version(version)
        if not clean_v:
            return False

        for r in affected_ranges:
            if "-" in r:
                start, end = r.split("-", 1)
                if self._cmp(clean_v, start) >= 0 and self._cmp(clean_v, end) <= 0:
                    return True
            else:
                if clean_v == r or clean_v.startswith(r):
                    return True
        return False

    def _extract_clean_version(self, v_str: str) -> str:
        match = re.search(r"(\d+(\.\d+)+)", v_str)
        return match.group(1) if match else v_str.strip()

    def _cmp(self, v1: str, v2: str) -> int:
        p1 = [int(x) if x.isdigit() else 0 for x in v1.split(".")]
        p2 = [int(x) if x.isdigit() else 0 for x in v2.split(".")]
        # Pad to equal length
        max_len = max(len(p1), len(p2))
        p1 += [0] * (max_len - len(p1))
        p2 += [0] * (max_len - len(p2))
        if p1 < p2:
            return -1
        elif p1 > p2:
            return 1
        return 0
