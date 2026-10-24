"""Local HTTP and HTTPS mock server fixtures for automated testing."""

from __future__ import annotations

import http.server
import ssl
import threading
from typing import Dict, Optional, Tuple


class MockHttpHandler(http.server.BaseHTTPRequestHandler):
    """Configurable HTTP handler for testing redirects, headers, and security checks."""

    # Handlers can override responses via class attributes
    custom_headers: Dict[str, str] = {}
    response_body: str = "<html><body>VulnShield Test Server</body></html>"
    status_code: int = 200
    redirect_target: Optional[str] = None
    redirect_loop: bool = False

    def do_GET(self):
        if self.redirect_loop:
            self.send_response(302)
            self.send_header("Location", self.path)
            self.end_headers()
            return

        if self.redirect_target:
            self.send_response(302)
            self.send_header("Location", self.redirect_target)
            self.end_headers()
            return

        self.send_response(self.status_code)
        for k, v in self.custom_headers.items():
            self.send_header(k, v)
        self.end_headers()
        self.wfile.write(self.response_body.encode("utf-8"))

    def do_HEAD(self):
        self.send_response(self.status_code)
        for k, v in self.custom_headers.items():
            self.send_header(k, v)
        self.end_headers()

    def do_OPTIONS(self):
        self.send_response(200)
        self.send_header("Allow", "GET, HEAD, OPTIONS, TRACE")
        self.end_headers()

    def log_message(self, format, *args):
        # Suppress stdout logging during test runs
        pass


class LocalMockServer:
    """Spins up a lightweight local HTTP server on a random port."""

    def __init__(self, handler_cls=MockHttpHandler):
        self.server = http.server.HTTPServer(("127.0.0.1", 0), handler_cls)
        self.port = self.server.server_port
        self.thread = threading.Thread(target=self.server.serve_forever, daemon=True)

    def start(self):
        self.thread.start()

    def stop(self):
        self.server.shutdown()
        self.server.server_close()
