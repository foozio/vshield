"""Non-invasive HTTP/HTTPS client with SSRF, DNS rebinding, redirect and size protections."""

from __future__ import annotations

import http.client
import ssl
import time
import urllib.parse
from dataclasses import dataclass, field
from typing import Any, Dict, List, Optional, Tuple

from vulnshield.remote.authorization import TargetAuthorizer, AuthorizationError


MAX_RESPONSE_SIZE = 5 * 1024 * 1024  # 5 MB
DEFAULT_TIMEOUT = 10.0
MAX_REDIRECTS = 5


class RateLimiter:
    """Per-target token bucket rate limiter."""

    def __init__(self, rate: float = 5.0):  # requests per second
        self.rate = rate
        self.capacity = max(1.0, rate)
        self.tokens = self.capacity
        self.last_check = time.time()

    def acquire(self) -> None:
        now = time.time()
        elapsed = now - self.last_check
        self.last_check = now
        self.tokens = min(self.capacity, self.tokens + elapsed * self.rate)

        if self.tokens < 1.0:
            sleep_time = (1.0 - self.tokens) / self.rate
            time.sleep(sleep_time)
            self.tokens = 0.0
        else:
            self.tokens -= 1.0


@dataclass
class HttpResponse:
    url: str
    status: int
    reason: str
    headers: Dict[str, str]
    body: str
    redirect_history: List[str] = field(default_factory=list)
    ip_address: Optional[str] = None
    response_time: float = 0.0


class SafeHttpClient:
    """Safe, non-destructive HTTP client designed for agentless security assessments."""

    def __init__(
        self,
        authorizer: Optional[TargetAuthorizer] = None,
        timeout: float = DEFAULT_TIMEOUT,
        max_redirects: int = MAX_REDIRECTS,
        max_size: int = MAX_RESPONSE_SIZE,
        rate_limit: float = 5.0,
        transport_executor: Optional[Callable[..., Tuple[int, str, Dict[str, str], str]]] = None,
    ):
        self.authorizer = authorizer or TargetAuthorizer()
        self.timeout = timeout
        self.max_redirects = max_redirects
        self.max_size = max_size
        self.rate_limiter = RateLimiter(rate_limit)
        self.transport_executor = transport_executor

    def request(
        self,
        method: str,
        url: str,
        headers: Optional[Dict[str, str]] = None,
        verify_tls: bool = True,
    ) -> HttpResponse:
        """
        Executes a safe HTTP request, validating each hop against SSRF and redirect rules.
        Only safe methods (GET, HEAD, OPTIONS) are allowed.
        """
        method = method.upper()
        if method not in ("GET", "HEAD", "OPTIONS"):
            raise ValueError(f"Method '{method}' is not permitted in safe assessment mode. Only GET, HEAD, OPTIONS.")

        req_headers = {
            "User-Agent": "VulnShield-RemoteAssessmentEngine/1.1 (+https://vulnshield.internal/scanner)",
            "Accept": "*/*",
        }
        if headers:
            req_headers.update(headers)

        current_url = url
        redirect_history: List[str] = []
        visited_urls: set = {current_url}

        parsed_initial = self.authorizer.validate_url(current_url)
        initial_host = parsed_initial.hostname

        for hop in range(self.max_redirects + 1):
            self.rate_limiter.acquire()
            parsed = urllib.parse.urlparse(current_url)
            port = parsed.port or (443 if parsed.scheme == "https" else 80)
            host = parsed.hostname or ""

            # Verify IP and resolve with DNS rebinding protection
            ip_addr = self.authorizer.resolve_and_verify_ip(host, port)

            start_t = time.time()
            resp_status, resp_reason, resp_headers, body = self._execute_single_request(
                scheme=parsed.scheme,
                host=host,
                port=port,
                path=parsed.path or "/",
                query=parsed.query,
                method=method,
                headers=req_headers,
                verify_tls=verify_tls,
            )
            elapsed = time.time() - start_t

            # Check redirect status
            if resp_status in (301, 302, 303, 307, 308) and "location" in resp_headers:
                redirect_history.append(current_url)
                raw_loc = resp_headers["location"]
                next_url = urllib.parse.urljoin(current_url, raw_loc)

                # Redirect loop detection
                if next_url in visited_urls:
                    raise AuthorizationError(f"Redirect loop detected at '{next_url}'")
                visited_urls.add(next_url)

                # Validate redirect scope (cannot escape to arbitrary third-party domain)
                parsed_next, _ = self.authorizer.validate_redirect(initial_host, next_url)
                current_url = next_url
                continue

            return HttpResponse(
                url=current_url,
                status=resp_status,
                reason=resp_reason,
                headers=resp_headers,
                body=body,
                redirect_history=redirect_history,
                ip_address=ip_addr,
                response_time=elapsed,
            )

        raise AuthorizationError(f"Maximum redirect limit ({self.max_redirects}) exceeded for '{url}'.")

    def _execute_single_request(
        self,
        scheme: str,
        host: str,
        port: int,
        path: str,
        query: str,
        method: str,
        headers: Dict[str, str],
        verify_tls: bool,
    ) -> Tuple[int, str, Dict[str, str], str]:
        if self.transport_executor:
            return self.transport_executor(
                scheme=scheme,
                host=host,
                port=port,
                path=path,
                query=query,
                method=method,
                headers=headers,
                verify_tls=verify_tls,
            )

        req_path = path if not query else f"{path}?{query}"

        if scheme == "https":
            context = ssl.create_default_context()
            if not verify_tls:
                context.check_hostname = False
                context.verify_mode = ssl.CERT_NONE
            conn = http.client.HTTPSConnection(host, port=port, timeout=self.timeout, context=context)
        else:
            conn = http.client.HTTPConnection(host, port=port, timeout=self.timeout)

        try:
            conn.request(method, req_path, headers=headers)
            res = conn.getresponse()

            res_headers = {k.lower(): v for k, v in res.getheaders()}

            # Limit response body size
            body_bytes = b""
            if method != "HEAD":
                body_bytes = res.read(self.max_size + 1)
                if len(body_bytes) > self.max_size:
                    # Truncate at maximum allowed size
                    body_bytes = body_bytes[:self.max_size]

            body_str = body_bytes.decode("utf-8", errors="replace")
            return res.status, res.reason, res_headers, body_str
        finally:
            conn.close()
