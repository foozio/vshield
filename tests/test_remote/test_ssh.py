"""Unit tests for SSH assessment capabilities, platform detection, and security controls."""

import unittest

from vulnshield.remote.authorization import TargetAuthorizer
from vulnshield.remote.ssh.authentication import SshAuthCredentials, ProtectedCredentialProvider
from vulnshield.remote.ssh.client import (
    SafeSshClient,
    SshExecutionError,
    SshAuthenticationError,
    SshHostKeyError,
)
from vulnshield.remote.ssh.collectors import (
    CommandValidator,
    SshEvidenceCollector,
    SecurityCommandValidationError,
)
from vulnshield.remote.ssh.platforms import PlatformDetector, PlatformType


class TestSshAssessment(unittest.TestCase):

    def setUp(self):
        self.authorizer = TargetAuthorizer(allow_private_ips=True)
        self.creds = SshAuthCredentials(username="scanner")

    def test_missing_ssh_credentials_validation(self):
        empty_creds = SshAuthCredentials(username="")
        with self.assertRaises(ValueError):
            empty_creds.validate()

        bad_path_creds = SshAuthCredentials(username="test", identity_file="/nonexistent/id_rsa")
        with self.assertRaises(FileNotFoundError):
            bad_path_creds.validate()

    def test_invalid_ssh_host_key_handling(self):
        def host_key_fail_mock(cmd: str):
            return 255, "", "Host key verification failed."

        client = SafeSshClient(
            credentials=self.creds,
            host="127.0.0.1",
            authorizer=self.authorizer,
            mock_transport=host_key_fail_mock,
        )

        with self.assertRaises(SshHostKeyError) as ctx:
            client.run_vetted_command("os_release")
        self.assertIn("host key verification failed", str(ctx.exception).lower())

    def test_ssh_authentication_failure(self):
        def auth_fail_mock(cmd: str):
            return 255, "", "Permission denied (publickey)."

        client = SafeSshClient(
            credentials=self.creds,
            host="127.0.0.1",
            authorizer=self.authorizer,
            mock_transport=auth_fail_mock,
        )

        with self.assertRaises(SshAuthenticationError) as ctx:
            client.run_vetted_command("os_release")
        self.assertIn("authentication failed", str(ctx.exception).lower())

    def test_ssh_timeout_handling(self):
        def timeout_mock(cmd: str):
            raise SshExecutionError("SSH command timed out after 10.0s on 127.0.0.1")

        client = SafeSshClient(
            credentials=self.creds,
            host="127.0.0.1",
            authorizer=self.authorizer,
            mock_transport=timeout_mock,
        )

        with self.assertRaises(SshExecutionError) as ctx:
            client.run_vetted_command("os_release")
        self.assertIn("timed out", str(ctx.exception).lower())

    def test_linux_distribution_detection_ubuntu(self):
        os_release = 'NAME="Ubuntu"\nVERSION_ID="24.04"\nID=ubuntu'
        uname = "6.8.0-31-generic"
        platform = PlatformDetector.identify_from_evidence(os_release_text=os_release, uname_text=uname)
        self.assertEqual(platform.platform_type, PlatformType.LINUX_DEBIAN)
        self.assertEqual(platform.os_name, "Ubuntu Linux")
        self.assertEqual(platform.os_version, "24.04")
        self.assertEqual(platform.package_manager, "dpkg")
        self.assertFalse(platform.is_appliance)

    def test_linux_distribution_detection_rhel(self):
        os_release = 'NAME="Red Hat Enterprise Linux"\nVERSION_ID="9.4"\nID="rhel"'
        uname = "5.14.0-427.el9.x86_64"
        platform = PlatformDetector.identify_from_evidence(os_release_text=os_release, uname_text=uname)
        self.assertEqual(platform.platform_type, PlatformType.LINUX_RHEL)
        self.assertEqual(platform.package_manager, "rpm")
        self.assertFalse(platform.is_appliance)

    def test_linux_distribution_detection_alpine(self):
        os_release = 'NAME="Alpine Linux"\nVERSION_ID="3.20.0"\nID=alpine'
        uname = "6.6.32-0-lts"
        platform = PlatformDetector.identify_from_evidence(os_release_text=os_release, uname_text=uname)
        self.assertEqual(platform.platform_type, PlatformType.LINUX_ALPINE)
        self.assertEqual(platform.package_manager, "apk")
        self.assertFalse(platform.is_appliance)

    def test_network_appliance_detection_cisco(self):
        cisco_banner = "Cisco IOS XE Software, Version 17.9.4a\nCisco IOS Software [Cupertino]"
        platform = PlatformDetector.identify_from_evidence(device_banner=cisco_banner)
        self.assertEqual(platform.platform_type, PlatformType.CISCO_IOS)
        self.assertTrue(platform.is_appliance)
        self.assertEqual(platform.os_name, "Cisco IOS-XE / NX-OS")

    def test_network_appliance_detection_fortinet(self):
        fortinet_banner = "FortiGate-VM64-KVM v7.2.5,build1517,230612 (GA.M)"
        platform = PlatformDetector.identify_from_evidence(device_banner=fortinet_banner)
        self.assertEqual(platform.platform_type, PlatformType.FORTINET_FORTIOS)
        self.assertTrue(platform.is_appliance)
        self.assertEqual(platform.os_name, "Fortinet FortiOS")

    def test_network_appliance_detection_f5(self):
        f5_banner = "BIG-IP Version 17.1.0.3 Build 0.0.4 Point Release 3"
        platform = PlatformDetector.identify_from_evidence(device_banner=f5_banner)
        self.assertEqual(platform.platform_type, PlatformType.F5_BIGIP)
        self.assertTrue(platform.is_appliance)
        self.assertEqual(platform.os_name, "F5 BIG-IP TMOS")

    def test_package_collector_parsing(self):
        collector = SshEvidenceCollector()
        dpkg_raw = "php8.3-fpm 8.3.6-0ubuntu0.24.04.1\nnginx 1.24.0-2ubuntu7\nopenssh-server 1:9.6p1-3ubuntu13.3"
        pkgs = collector.parse_packages("dpkg", dpkg_raw)
        self.assertEqual(pkgs.get("php8.3-fpm"), "8.3.6-0ubuntu0.24.04.1")
        self.assertEqual(pkgs.get("nginx"), "1.24.0-2ubuntu7")
        self.assertEqual(pkgs.get("openssh-server"), "1:9.6p1-3ubuntu13.3")

    def test_listening_ports_collector_parsing(self):
        collector = SshEvidenceCollector()
        ss_raw = (
            "Netid State Recv-Q Send-Q Local Address:Port Peer Address:Port Process\n"
            'tcp   LISTEN 0      128          0.0.0.0:80         0.0.0.0:*    users:(("nginx",pid=1234,fd=6))\n'
            'tcp   LISTEN 0      511        127.0.0.1:9000       0.0.0.0:*    users:(("php-fpm8.3",pid=5678,fd=7))\n'
            'tcp   LISTEN 0      128          0.0.0.0:22         0.0.0.0:*    users:(("sshd",pid=910,fd=3))\n'
        )
        ports = collector.parse_listening_ports(ss_raw)
        self.assertEqual(len(ports), 3)
        self.assertEqual(ports[0]["port"], 80)
        self.assertEqual(ports[0]["process_name"], "nginx")
        self.assertEqual(ports[1]["port"], 9000)
        self.assertEqual(ports[1]["process_name"], "php-fpm8.3")


if __name__ == "__main__":
    unittest.main()
