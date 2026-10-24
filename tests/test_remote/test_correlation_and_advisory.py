"""Unit tests for cross-protocol correlation, vendor backports, and confidence scoring."""

import unittest

from vulnshield.advisory.intelligence import AdvisoryIntelligence, AdvisoryEntry
from vulnshield.advisory.backports import VendorBackportDetector
from vulnshield.findings.model import Finding, Evidence, Protocol, Severity, Confidence, FindingStatus
from vulnshield.remote.correlation import CrossProtocolCorrelator
from vulnshield.remote.ssh.collectors import SshSystemTelemetry
from vulnshield.remote.ssh.platforms import PlatformProfile, PlatformType


class TestCorrelationAndAdvisory(unittest.TestCase):

    def setUp(self):
        self.advisory_engine = AdvisoryIntelligence()
        self.correlator = CrossProtocolCorrelator(self.advisory_engine)

    def test_vendor_backport_detector_ubuntu(self):
        pkg_ver = "8.3.6-0ubuntu0.24.04.1"
        info = VendorBackportDetector.parse_vendor_release(pkg_ver)
        self.assertEqual(info["vendor"], "ubuntu")

        fixed_versions = {"ubuntu": "8.3.6-0ubuntu0.24.04.1"}
        is_patched, note = VendorBackportDetector.is_vendor_patched("php", pkg_ver, fixed_versions)
        self.assertTrue(is_patched)
        self.assertIn("Vendor backport", note)

    def test_vendor_backport_detector_debian(self):
        pkg_ver = "8.2.7-1~deb12u2"
        info = VendorBackportDetector.parse_vendor_release(pkg_ver)
        self.assertEqual(info["vendor"], "debian")

        fixed_versions = {"debian": "8.2.7-1~deb12u1"}
        is_patched, note = VendorBackportDetector.is_vendor_patched("php", pkg_ver, fixed_versions)
        self.assertTrue(is_patched)

    def test_vendor_backport_detector_rhel(self):
        pkg_ver = "8.2.4-2.el9_4.1"
        info = VendorBackportDetector.parse_vendor_release(pkg_ver)
        self.assertEqual(info["vendor"], "rhel")

    def test_banner_only_confidence_is_low(self):
        """Banner-only findings must be classified as POTENTIALLY_VULNERABLE with LOW confidence."""
        http_finding = Finding(
            id="HTTP-ADVISORY-CVE-2024-2756-target",
            target_id="web-prod",
            title="CVE-2024-2756: PHP __Host- Cookie Bypass",
            description="Banner indicated PHP 8.3.2",
            severity=Severity.HIGH,
            confidence=Confidence.LOW,
            status=FindingStatus.POTENTIALLY_VULNERABLE,
            cve="CVE-2024-2756",
            affected_component="php",
            detected_version="8.3.2",
            protocols=[Protocol.HTTP],
            evidence=[Evidence(protocol=Protocol.HTTP, collector="http_banner", raw_data="Server: Apache PHP/8.3.2")],
        )

        # Correlate with NO SSH evidence available
        results = self.correlator.correlate(
            target_id="web-prod",
            http_findings=[http_finding],
            tls_findings=[],
            ssh_telemetry=None,
        )

        self.assertEqual(len(results), 1)
        res = results[0]
        self.assertEqual(res.confidence, Confidence.LOW)
        self.assertEqual(res.status, FindingStatus.POTENTIALLY_VULNERABLE)

    def test_cross_protocol_correlation_vendor_backport_fixed(self):
        """HTTP banner shows vulnerable PHP 8.3.2, but SSH identifies Ubuntu security backport."""
        http_finding = Finding(
            id="HTTP-ADVISORY-CVE-2024-2756-target",
            target_id="web-prod",
            title="CVE-2024-2756: PHP __Host- Cookie Bypass",
            description="Banner indicated PHP 8.3.2",
            severity=Severity.HIGH,
            confidence=Confidence.LOW,
            status=FindingStatus.POTENTIALLY_VULNERABLE,
            cve="CVE-2024-2756",
            affected_component="php",
            detected_version="8.3.2",
            protocols=[Protocol.HTTP],
        )

        # SSH Telemetry identifies package with backport
        telemetry = SshSystemTelemetry(
            platform=PlatformProfile(
                platform_type=PlatformType.LINUX_DEBIAN,
                os_name="Ubuntu Linux",
                os_version="24.04",
                package_manager="dpkg",
            ),
            packages={"php8.3-fpm": "8.3.6-0ubuntu0.24.04.1"},
            listening_ports=[{"port": 9000, "process_name": "php-fpm8.3"}],
        )

        results = self.correlator.correlate(
            target_id="web-prod",
            http_findings=[http_finding],
            tls_findings=[],
            ssh_telemetry=telemetry,
        )

        res = next(f for f in results if f.cve == "CVE-2024-2756")
        # Must be upgraded to FIXED confidence and PATCHED status!
        self.assertEqual(res.confidence, Confidence.FIXED)
        self.assertEqual(res.status, FindingStatus.PATCHED)
        self.assertIn(Protocol.HTTP, res.protocols)
        self.assertIn(Protocol.SSH, res.protocols)
        self.assertTrue(any("Vendor backport" in ev.raw_data for ev in res.evidence))

    def test_cross_protocol_correlation_confirmed_vulnerable(self):
        """HTTP banner shows PHP 8.3.2, and SSH confirms vulnerable unpatched package."""
        http_finding = Finding(
            id="HTTP-ADVISORY-CVE-2024-2756-target",
            target_id="web-prod",
            title="CVE-2024-2756: PHP __Host- Cookie Bypass",
            description="Banner indicated PHP 8.3.2",
            severity=Severity.HIGH,
            confidence=Confidence.LOW,
            status=FindingStatus.POTENTIALLY_VULNERABLE,
            cve="CVE-2024-2756",
            affected_component="php",
            detected_version="8.3.2",
            protocols=[Protocol.HTTP],
        )

        telemetry = SshSystemTelemetry(
            platform=PlatformProfile(
                platform_type=PlatformType.LINUX_DEBIAN,
                os_name="Debian GNU/Linux",
                os_version="12",
                package_manager="dpkg",
            ),
            # Package version 8.3.2 is older than Debian fix 8.3.5-1~deb12u1
            packages={"php8.3-fpm": "8.3.2-1"},
        )

        results = self.correlator.correlate(
            target_id="web-prod",
            http_findings=[http_finding],
            tls_findings=[],
            ssh_telemetry=telemetry,
        )

        res = next(f for f in results if f.cve == "CVE-2024-2756")
        self.assertEqual(res.confidence, Confidence.HIGH)
        self.assertEqual(res.status, FindingStatus.CONFIRMED_VULNERABLE)

    def test_multiple_php_installations_disambiguation(self):
        """Host has multiple PHP packages (e.g. php7.4-cli and php8.3-fpm); active web service mapped to listening socket."""
        telemetry = SshSystemTelemetry(
            platform=PlatformProfile(
                platform_type=PlatformType.LINUX_DEBIAN,
                os_name="Ubuntu Linux",
                os_version="24.04",
                package_manager="dpkg",
            ),
            packages={
                "php7.4-cli": "7.4.3-4ubuntu2.63",
                "php8.3-fpm": "8.3.6-0ubuntu0.24.04.1",
            },
            listening_ports=[{"port": 9000, "process_name": "php-fpm8.3"}],
            runtime_versions={"php": "8.3.6"},
        )

        resolved_pkg = self.correlator._resolve_package_version_for_service("php", telemetry)
        self.assertIn("8.3.6", resolved_pkg)

    def test_unknown_advisory_data_handling(self):
        """Unknown or uncataloged software version produces no crash and maintains graceful status."""
        query_res = self.advisory_engine.query("unknown_custom_daemon", "1.0.0")
        self.assertEqual(len(query_res), 0)


if __name__ == "__main__":
    unittest.main()
