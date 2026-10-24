"""Unit tests for batch assessment, concurrency bounding, cancellation, and scheduling."""

import os
import tempfile
import time
import unittest

from vulnshield.findings.storage import FindingStore
from vulnshield.remote.authorization import TargetAuthorizer, AuthorizationError
from vulnshield.remote.scanner import RemoteAssessmentEngine, CancellationContext
from vulnshield.remote.scheduler import ScheduleManager, parse_interval_to_seconds
from vulnshield.remote.targets import (
    TargetConfig,
    parse_targets_file,
    expand_cidr_target,
    MAX_CIDR_HOST_LIMIT,
)


class TestBatchConcurrencyAndCancellation(unittest.TestCase):

    def setUp(self):
        self.temp_dir = tempfile.TemporaryDirectory()
        self.store = FindingStore(data_dir=self.temp_dir.name)
        self.authorizer = TargetAuthorizer(allow_private_ips=True)

    def tearDown(self):
        self.temp_dir.cleanup()

    def test_parse_targets_file_yaml(self):
        yaml_content = """
targets:
  - id: web-prod-01
    authorized: true
    protocols:
      http:
        url: https://web01.example.com
        mode: passive
        allowed_paths:
          - /
      ssh:
        host: web01.example.com
        port: 22
        username: scanner

  - id: web-prod-02
    authorized: true
    protocols:
      https:
        url: https://web02.example.com
"""
        yaml_path = os.path.join(self.temp_dir.name, "targets.yaml")
        with open(yaml_path, "w") as f:
            f.write(yaml_content)

        targets = parse_targets_file(yaml_path)
        self.assertEqual(len(targets), 2)
        self.assertEqual(targets[0].id, "web-prod-01")
        self.assertTrue(targets[0].authorized)
        self.assertIsNotNone(targets[0].http_config)
        self.assertIsNotNone(targets[0].ssh_config)

    def test_cidr_inventory_strict_max_host_limit(self):
        # A /23 subnet has 512 hosts (> MAX_CIDR_HOST_LIMIT = 256)
        oversized_cidr_target = TargetConfig(
            id="oversized-subnet",
            authorized=True,
            cidr="192.168.0.0/23",
        )
        with self.assertRaises(AuthorizationError) as ctx:
            expand_cidr_target(oversized_cidr_target)
        self.assertIn("exceeds strict limit", str(ctx.exception).lower())

        # A /29 subnet has 8 addresses -> allowed
        small_cidr_target = TargetConfig(
            id="small-subnet",
            authorized=True,
            cidr="192.0.2.0/29",
            protocols={"ssh": {"username": "scanner", "port": 22}},
        )
        expanded = expand_cidr_target(small_cidr_target)
        self.assertEqual(len(expanded), 6)  # 6 usable hosts in /29
        self.assertTrue(all(t.authorized for t in expanded))

    def test_cancellation_token(self):
        cancel_token = CancellationContext()
        self.assertFalse(cancel_token.is_cancelled)
        cancel_token.cancel()
        self.assertTrue(cancel_token.is_cancelled)

        engine = RemoteAssessmentEngine(authorizer=self.authorizer, finding_store=self.store)
        target = TargetConfig(
            id="test-cancelled",
            authorized=True,
            protocols={"http": {"url": "http://127.0.0.1:8080"}},
        )

        findings = engine.scan_target(target, cancel_token=cancel_token)
        self.assertEqual(findings, [])

    def test_schedule_interval_parsing(self):
        self.assertEqual(parse_interval_to_seconds("30s"), 30)
        self.assertEqual(parse_interval_to_seconds("15m"), 900)
        self.assertEqual(parse_interval_to_seconds("24h"), 86400)
        self.assertEqual(parse_interval_to_seconds("7d"), 604800)

        with self.assertRaises(ValueError):
            parse_interval_to_seconds("invalid")

    def test_schedule_manager(self):
        manager = ScheduleManager(storage_path=os.path.join(self.temp_dir.name, "schedules.json"))
        dummy_file = os.path.join(self.temp_dir.name, "targets.yaml")
        with open(dummy_file, "w") as f:
            f.write("targets: []")

        job = manager.add_schedule(dummy_file, "12h")
        self.assertEqual(job.interval_seconds, 43200)

        jobs = manager.list_schedules()
        self.assertEqual(len(jobs), 1)
        self.assertEqual(jobs[0].id, job.id)


if __name__ == "__main__":
    unittest.main()
