"""Unit tests for HTTP, HTTPS, and TLS assessment capabilities."""

import time
import unittest

from vulnshield.findings.model import FindingStatus, Severity, Confidence
from vulnshield.remote.authorization import TargetAuthorizer, AuthorizationError
from vulnshield.remote.http.client import SafeHttpClient, RateLimiter
from vulnshield.remote.http.fingerprint import TechnologyFingerprinter
from vulnshield.remote.http.headers import HeaderSecurityAnalyzer
from vulnshield.remote.http.checks import HttpSecurityChecks
from vulnshield.remote.tls.certificates import CertificateInspector, CertificateInfo
from vulnshield.remote.tls.configuration import TlsConfigurationAuditor, TlsAuditResult


class TestHttpAndTls(unittest.TestCase):

    def setUp(self):
        self.authorizer = TargetAuthorizer(allow_private_ips=True)

    def test_safe_http_client_get_and_head(self):
        def mock_executor(scheme, host, port, path, query, method, headers, verify_tls):
            if method == "HEAD":
                return 200, "OK", {"content-type": "text/html"}, ""
            return 200, "OK", {"content-type": "text/html"}, "<html><body>VulnShield Test Server</body></html>"

        client = SafeHttpClient(authorizer=self.authorizer, transport_executor=mock_executor)
        url = "http://127.0.0.1:8080/"

        resp = client.request("GET", url)
        self.assertEqual(resp.status, 200)
        self.assertIn("VulnShield Test Server", resp.body)

        head_resp = client.request("HEAD", url)
        self.assertEqual(head_resp.status, 200)
        self.assertEqual(head_resp.body, "")

    def test_safe_http_client_disallows_unsafe_methods(self):
        client = SafeHttpClient(authorizer=self.authorizer)
        url = "http://127.0.0.1:8080/"

        with self.assertRaises(ValueError):
            client.request("POST", url)

        with self.assertRaises(ValueError):
            client.request("DELETE", url)

    def test_redirect_loop_detection(self):
        def loop_executor(scheme, host, port, path, query, method, headers, verify_tls):
            return 302, "Found", {"location": "http://127.0.0.1:8080/loop"}, ""

        client = SafeHttpClient(authorizer=self.authorizer, transport_executor=loop_executor)
        url = "http://127.0.0.1:8080/loop"

        with self.assertRaises(AuthorizationError) as ctx:
            client.request("GET", url)
        self.assertIn("loop detected", str(ctx.exception).lower())

    def test_redirect_to_unauthorized_host_blocked(self):
        def redir_executor(scheme, host, port, path, query, method, headers, verify_tls):
            return 302, "Found", {"location": "http://evil.com/unauthorized"}, ""

        client = SafeHttpClient(authorizer=self.authorizer, transport_executor=redir_executor)
        url = "http://127.0.0.1:8080/redir"

        with self.assertRaises(AuthorizationError) as ctx:
            client.request("GET", url)
        self.assertIn("scope violation", str(ctx.exception).lower())

    def test_technology_fingerprinting(self):
        fingerprinter = TechnologyFingerprinter()
        headers = {
            "server": "Apache/2.4.41 (Ubuntu)",
            "x-powered-by": "PHP/8.3.2",
            "set-cookie": "PHPSESSID=abc12345",
        }
        fp = fingerprinter.fingerprint(headers)
        self.assertEqual(fp.server_software, "Apache")
        self.assertEqual(fp.server_version, "2.4.41")
        self.assertEqual(fp.runtimes.get("php"), "8.3.2")

    def test_header_security_analyzer(self):
        analyzer = HeaderSecurityAnalyzer()
        headers = {
            "server": "Apache/2.4.41",
            "x-powered-by": "PHP/8.3.2",
        }
        findings = analyzer.analyze("target-1", "https://example.com/", headers, is_https=True)

        finding_ids = [f.id for f in findings]
        self.assertTrue(any("HSTS-MISSING" in fid for fid in finding_ids))
        self.assertTrue(any("CSP-MISSING" in fid for fid in finding_ids))
        self.assertTrue(any("XCTO-MISSING" in fid for fid in finding_ids))
        self.assertTrue(any("SERVER-VERSION" in fid for fid in finding_ids))
        self.assertTrue(any("X-POWERED-BY" in fid for fid in finding_ids))

    def test_cookie_security_checks(self):
        client = SafeHttpClient(authorizer=self.authorizer)
        checks = HttpSecurityChecks(client)

        headers = {
            "set-cookie": "session_id=12345; Path=/"
        }
        findings = checks.check_cookies("target-1", "https://example.com/", headers, is_https=True)

        finding_ids = [f.id for f in findings]
        self.assertTrue(any("COOKIE-MISSING-SECURE" in fid for fid in finding_ids))
        self.assertTrue(any("COOKIE-MISSING-HTTPONLY" in fid for fid in finding_ids))
        self.assertTrue(any("COOKIE-MISSING-SAMESITE" in fid for fid in finding_ids))

    def test_safe_method_discovery(self):
        def options_executor(scheme, host, port, path, query, method, headers, verify_tls):
            return 200, "OK", {"allow": "GET, HEAD, OPTIONS, TRACE"}, ""

        client = SafeHttpClient(authorizer=self.authorizer, transport_executor=options_executor)
        checks = HttpSecurityChecks(client)
        url = "http://127.0.0.1:8080/"

        findings = checks.check_allowed_methods("target-1", url)
        trace_findings = [f for f in findings if "TRACE" in f.title]
        self.assertEqual(len(trace_findings), 1)
        self.assertEqual(trace_findings[0].severity, Severity.MEDIUM)

    def test_rate_limiter(self):
        limiter = RateLimiter(rate=100.0)
        start = time.time()
        for _ in range(5):
            limiter.acquire()
        elapsed = time.time() - start
        self.assertLess(elapsed, 1.0)

    def test_certificate_inspector_diagnostic_findings(self):
        inspector = CertificateInspector()
        cert_dict = {
            "subject": ((("commonName", "test.example.com"),),),
            "issuer": ((("commonName", "Test CA"),),),
            "notBefore": "Jan 01 00:00:00 2020 GMT",
            "notAfter": "Jan 01 00:00:00 2021 GMT",
            "subjectAltName": (("DNS", "test.example.com"),),
        }
        info = CertificateInfo()
        inspector._populate_cert_info(cert_dict, info)
        self.assertTrue(info.is_expired)
        self.assertLess(info.days_until_expiration, 0)


if __name__ == "__main__":
    unittest.main()
