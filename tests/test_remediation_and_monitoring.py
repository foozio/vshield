"""Unit tests for remediation recommendations, patch verification, and differential monitoring."""

import tempfile
import time
import unittest

from vshield.findings.model import Finding, Severity, Confidence, FindingStatus, Protocol
from vshield.findings.storage import FindingStore
from vshield.monitor.tracker import DifferentialTracker
from vshield.remediation.patches import PatchEngine
from vshield.remediation.recommender import RemediationRecommender


class TestRemediationAndMonitoring(unittest.TestCase):

    def setUp(self):
        self.temp_dir = tempfile.TemporaryDirectory()
        self.store = FindingStore(data_dir=self.temp_dir.name)
        self.recommender = RemediationRecommender()
        self.patch_engine = PatchEngine(finding_store=self.store)

    def tearDown(self):
        self.temp_dir.cleanup()

    def test_linux_package_remediation_recommendation(self):
        finding = Finding(
            id="FINDING-PHP-1",
            target_id="linux-web-01",
            title="CVE-2024-2756: PHP __Host- Cookie Bypass",
            description="Vulnerable PHP version",
            severity=Severity.HIGH,
            confidence=Confidence.HIGH,
            status=FindingStatus.CONFIRMED_VULNERABLE,
            cve="CVE-2024-2756",
            affected_component="php8.3",
            protocols=[Protocol.SSH],
        )

        # Ubuntu recommendation
        plan_ubuntu = self.recommender.recommend_for_finding(finding, distro_or_platform="ubuntu")
        self.assertEqual(plan_ubuntu.target_type, "linux")
        self.assertIn("apt-get install --dry-run --only-upgrade php8.3", plan_ubuntu.dry_run_command)
        self.assertIn("apt-get install --only-upgrade -y php8.3", plan_ubuntu.production_command)

        # RHEL recommendation
        plan_rhel = self.recommender.recommend_for_finding(finding, distro_or_platform="rhel")
        self.assertEqual(plan_rhel.target_type, "linux")
        self.assertIn("dnf check-update php8.3", plan_rhel.dry_run_command)
        self.assertIn("dnf update -y php8.3", plan_rhel.production_command)

    def test_network_appliance_remediation_safety(self):
        finding = Finding(
            id="FINDING-CISCO-1",
            target_id="cisco-edge-01",
            title="CVE-2023-20198: Cisco IOS XE Web UI Privilege Escalation",
            description="Privilege escalation flaw in IOS XE Web UI",
            severity=Severity.CRITICAL,
            confidence=Confidence.HIGH,
            status=FindingStatus.CONFIRMED_VULNERABLE,
            cve="CVE-2023-20198",
            affected_component="cisco-ios-xe",
            protocols=[Protocol.SSH],
        )

        plan = self.recommender.recommend_for_finding(finding, distro_or_platform="cisco")
        self.assertEqual(plan.target_type, "appliance")
        # Ensure NO shell / package manager commands are recommended on appliances!
        self.assertIsNone(plan.dry_run_command)
        self.assertIsNone(plan.production_command)
        self.assertIn("cisco.com", plan.documentation_url)
        self.assertTrue(any("Never attempt generic Linux package manager" in note for note in plan.safety_notes))

    def test_patch_verification_workflow(self):
        target_id = "test-target-remediation"

        # Step 1: Save initial vulnerable finding to store
        f1 = Finding(
            id="FIND-1",
            target_id=target_id,
            title="Initial Vulnerability",
            description="Needs patch",
            severity=Severity.HIGH,
            confidence=Confidence.HIGH,
            status=FindingStatus.CONFIRMED_VULNERABLE,
            cve="CVE-2024-2756",
            affected_component="php",
        )
        from vshield.findings.model import ScanResult
        self.store.save_scan_result(
            ScanResult(
                scan_id="SCAN-INITIAL",
                target_ids=[target_id],
                start_time="2026-01-01T00:00:00Z",
                end_time="2026-01-01T00:05:00Z",
                findings=[f1],
            )
        )

        # Step 2: Post-patch scan: finding is resolved (current scan has no active findings)
        verification = self.patch_engine.verify_patch(target_id, current_findings=[])
        self.assertEqual(verification["verification_status"], "PASSED")
        self.assertEqual(verification["verified_remediated_count"], 1)
        self.assertEqual(verification["unremediated_count"], 0)

    def test_differential_tracker_and_alert_suppression(self):
        tracker = DifferentialTracker(suppression_window_seconds=3600)
        target_id = "server-01"

        f = Finding(
            id="ALERT-FINDING-1",
            target_id=target_id,
            title="Heartbleed / Critical Vulnerability",
            description="Testing alert suppression",
            severity=Severity.CRITICAL,
            confidence=Confidence.HIGH,
            status=FindingStatus.CONFIRMED_VULNERABLE,
            cve="CVE-2014-0160",
        )

        # First alert trigger at t=1000
        alerts_1 = tracker.generate_alerts(target_id, [f], now=1000.0)
        self.assertEqual(len(alerts_1), 1)

        # Immediate re-scan at t=1500 (within 3600s suppression window)
        alerts_2 = tracker.generate_alerts(target_id, [f], now=1500.0)
        self.assertEqual(len(alerts_2), 0)  # Suppressed!

        # Scan after suppression window expires at t=5000 (1000 + 4000)
        alerts_3 = tracker.generate_alerts(target_id, [f], now=5000.0)
        self.assertEqual(len(alerts_3), 1)  # Alert re-fires!


if __name__ == "__main__":
    unittest.main()
