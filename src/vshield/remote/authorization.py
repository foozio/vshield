"""Authorization, SSRF protection, DNS rebinding, and credential redaction."""

from __future__ import annotations

import ipaddress
import re
import socket
import urllib.parse
from typing import List, Optional, Set, Tuple


# Standard private and sensitive IP ranges to block against SSRF
BLOCKED_IP_NETWORKS = [
    ipaddress.ip_network("127.0.0.0/8"),       # Loopback
    ipaddress.ip_network("10.0.0.0/8"),        # RFC 1918 Private
    ipaddress.ip_network("172.16.0.0/12"),     # RFC 1918 Private
    ipaddress.ip_network("192.168.0.0/16"),    # RFC 1918 Private
    ipaddress.ip_network("169.254.0.0/16"),    # Link-local / Cloud Metadata
    ipaddress.ip_network("0.0.0.0/8"),         # Broadcast/Current network
    ipaddress.ip_network("100.64.0.0/10"),     # Shared address space
    ipaddress.ip_network("192.0.0.0/24"),      # IETF Protocol assignments
    ipaddress.ip_network("198.18.0.0/15"),     # Benchmarking
    ipaddress.ip_network("224.0.0.0/4"),       # Multicast
    ipaddress.ip_network("240.0.0.0/4"),       # Reserved
    ipaddress.ip_network("::1/128"),           # IPv6 Loopback
    ipaddress.ip_network("fc00::/7"),          # IPv6 Unique Local
    ipaddress.ip_network("fe80::/10"),         # IPv6 Link-Local
]

CLOUD_METADATA_IPS = {
    "169.254.169.254",                         # AWS / GCP / Azure metadata
    "fd00:ec2::254",                           # AWS IPv6 metadata
}

# Regex patterns for sensitive credential redaction
REDACTION_PATTERNS = [
    (re.compile(r"(password[:=]\s*)([^\s\"'&;]+)", re.IGNORECASE), r"\1[REDACTED]"),
    (re.compile(r"(Authorization:\s*(?:Bearer|Basic)\s+)([^\s]+)", re.IGNORECASE), r"\1[REDACTED]"),
    (re.compile(r"(-----BEGIN [A-Z ]*PRIVATE KEY-----)[\s\S]*?(-----END [A-Z ]*PRIVATE KEY-----)"), r"\1\n[REDACTED PRIVATE KEY]\n\2"),
    (re.compile(r"(token[:=]\s*)([^\s\"'&;]+)", re.IGNORECASE), r"\1[REDACTED]"),
    (re.compile(r"(secret[:=]\s*)([^\s\"'&;]+)", re.IGNORECASE), r"\1[REDACTED]"),
]


class AuthorizationError(Exception):
    """Raised when an operation violates authorization or security boundaries."""
    pass


class TargetAuthorizer:
    """Enforces target authorization, SSRF prevention, and DNS rebinding protections."""

    def __init__(
        self,
        allow_private_ips: bool = False,
        allowed_hosts: Optional[Set[str]] = None,
    ):
        self.allow_private_ips = allow_private_ips
        self.allowed_hosts = set(h.lower() for h in allowed_hosts) if allowed_hosts else set()

    def validate_target_authorization(self, target_id: str, is_authorized: bool) -> None:
        """Verifies that the target inventory explicitly marks the host as authorized."""
        if not is_authorized:
            raise AuthorizationError(
                f"Target '{target_id}' is not authorized. Scans must be explicitly authorized in target inventory or CLI."
            )

    def validate_url(self, url: str) -> urllib.parse.ParseResult:
        """Validates URL structure and scheme."""
        parsed = urllib.parse.urlparse(url)
        if parsed.scheme.lower() not in ("http", "https"):
            raise AuthorizationError(f"Unsupported scheme '{parsed.scheme}'. Only http and https are permitted.")
        if not parsed.hostname:
            raise AuthorizationError(f"URL '{url}' does not specify a valid hostname.")
        return parsed

    def resolve_and_verify_ip(self, hostname: str, port: int = 80) -> str:
        """
        Resolves hostname to IP and verifies it against SSRF and private IP rules.
        Protects against DNS rebinding attacks.
        Returns the verified IP address.
        """
        # If hostname is already an IP address
        try:
            ip_obj = ipaddress.ip_address(hostname)
            ip_str = str(ip_obj)
        except ValueError:
            # Resolve DNS
            try:
                addr_info = socket.getaddrinfo(hostname, port, socket.AF_UNSPEC, socket.SOCK_STREAM)
                if not addr_info:
                    raise AuthorizationError(f"Could not resolve hostname '{hostname}'")
                ip_str = addr_info[0][4][0]
                ip_obj = ipaddress.ip_address(ip_str)
            except socket.gaierror as e:
                raise AuthorizationError(f"DNS resolution failure for '{hostname}': {e}") from e

        # Check metadata IP
        if ip_str in CLOUD_METADATA_IPS:
            raise AuthorizationError(f"SSRF violation: Hostname '{hostname}' resolves to cloud metadata IP {ip_str}.")

        # Check blocked networks
        if not self.allow_private_ips:
            for net in BLOCKED_IP_NETWORKS:
                if ip_obj in net:
                    raise AuthorizationError(
                        f"SSRF violation: IP {ip_str} for host '{hostname}' belongs to restricted network {net}."
                    )

        return ip_str

    def validate_redirect(
        self, original_host: str, redirect_url: str
    ) -> Tuple[urllib.parse.ParseResult, str]:
        """
        Ensures redirects do not escape authorized target scope or redirect to malicious/private destinations.
        """
        parsed_redir = self.validate_url(redirect_url)
        redir_host = (parsed_redir.hostname or "").lower()
        orig_host = original_host.lower()

        # Enforce host matching or explicitly allowed hosts
        if redir_host != orig_host and redir_host not in self.allowed_hosts:
            raise AuthorizationError(
                f"Redirect scope violation: Target redirected from authorized host '{orig_host}' "
                f"to unauthorized third-party host '{redir_host}'."
            )

        # Resolve and verify redirect target IP against SSRF and DNS rebinding
        port = parsed_redir.port or (443 if parsed_redir.scheme == "https" else 80)
        verified_ip = self.resolve_and_verify_ip(redir_host, port)
        return parsed_redir, verified_ip


def redact_sensitive(text: str) -> str:
    """Redacts passwords, tokens, Authorization headers, and private keys."""
    if not text:
        return text
    result = text
    for pattern, replacement in REDACTION_PATTERNS:
        result = pattern.sub(replacement, result)
    return result
