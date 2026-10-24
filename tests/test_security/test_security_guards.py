"""Security tests verifying SSRF prevention, command injection defense, credential redaction, and scope enforcement."""

import unittest

from vulnshield.remote.authorization import (
    TargetAuthorizer,
    AuthorizationError,
    redact_sensitive,
    CLOUD_METADATA_IPS,
)
from vulnshield.remote.ssh.collectors import (
    CommandValidator,
    SecurityCommandValidationError,
)
from vulnshield.remote.targets import TargetConfig


class TestSecurityGuards(unittest.TestCase):

    def setUp(self):
        # Strict authorizer: allow_private_ips is FALSE
        self.strict_authorizer = TargetAuthorizer(allow_private_ips=False)

    def test_ssrf_blocks_loopback_and_private_ips(self):
        # Loopback IPv4
        with self.assertRaises(AuthorizationError) as ctx:
            self.strict_authorizer.resolve_and_verify_ip("127.0.0.1")
        self.assertIn("ssrf violation", str(ctx.exception).lower())

        # RFC 1918 Private ranges
        for private_ip in ["10.0.0.1", "172.16.5.10", "192.168.1.1"]:
            with self.assertRaises(AuthorizationError):
                self.strict_authorizer.resolve_and_verify_ip(private_ip)

        # Loopback IPv6
        with self.assertRaises(AuthorizationError):
            self.strict_authorizer.resolve_and_verify_ip("::1")

    def test_ssrf_blocks_cloud_metadata(self):
        for meta_ip in CLOUD_METADATA_IPS:
            with self.assertRaises(AuthorizationError) as ctx:
                self.strict_authorizer.resolve_and_verify_ip(meta_ip)
            self.assertIn("cloud metadata", str(ctx.exception).lower())

    def test_redirect_scope_escape_blocked(self):
        # Attempted redirect to third-party target
        with self.assertRaises(AuthorizationError) as ctx:
            self.strict_authorizer.validate_redirect(
                original_host="authorized.example.com",
                redirect_url="https://attacker.evil.com/callback",
            )
        self.assertIn("redirect scope violation", str(ctx.exception).lower())

    def test_command_injection_prevention_in_ssh_templates(self):
        # 1. Unvetted command template
        with self.assertRaises(SecurityCommandValidationError) as ctx:
            CommandValidator.render_command("malicious_unvetted_template")
        self.assertIn("not in vetted allowlist", str(ctx.exception))

        # 2. Command injection in package argument: semicolon
        with self.assertRaises(SecurityCommandValidationError) as ctx:
            CommandValidator.render_command("apt_changelog", package="php; rm -rf /")
        self.assertIn("unpermitted characters", str(ctx.exception))

        # 3. Command injection: pipe and backticks
        with self.assertRaises(SecurityCommandValidationError):
            CommandValidator.render_command("apt_changelog", package="php | cat /etc/passwd")

        with self.assertRaises(SecurityCommandValidationError):
            CommandValidator.render_command("apt_changelog", package="php`id`")

        # 4. Command injection: subshell expansion
        with self.assertRaises(SecurityCommandValidationError):
            CommandValidator.render_command("apt_changelog", package="$(whoami)")

    def test_credential_redaction(self):
        sample_log = (
            "Connecting with password=SuperSecretPassword123!\n"
            "Header: Authorization: Bearer eyJhbGciOiJIUzI1NiIsIn...\n"
            "User provided token=my_secret_token_abc\n"
            "-----BEGIN OPENSSH PRIVATE KEY-----\nb3BlbnNzaC1rZXktdjEAAAA\n-----END OPENSSH PRIVATE KEY-----"
        )
        redacted = redact_sensitive(sample_log)

        self.assertNotIn("SuperSecretPassword123!", redacted)
        self.assertNotIn("eyJhbGciOiJIUzI1NiIsIn...", redacted)
        self.assertNotIn("my_secret_token_abc", redacted)
        self.assertNotIn("b3BlbnNzaC1rZXktdjEAAAA", redacted)
        self.assertIn("[REDACTED]", redacted)
        self.assertIn("[REDACTED PRIVATE KEY]", redacted)

    def test_scan_authorization_enforcement(self):
        unauthorized_target = TargetConfig(
            id="target-unauthorized",
            authorized=False,
            protocols={"http": {"url": "https://example.com"}},
        )
        with self.assertRaises(AuthorizationError) as ctx:
            self.strict_authorizer.validate_target_authorization(
                unauthorized_target.id, unauthorized_target.authorized
            )
        self.assertIn("not authorized", str(ctx.exception).lower())


if __name__ == "__main__":
    unittest.main()
