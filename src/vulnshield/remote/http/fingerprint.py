"""Server technology and runtime fingerprinting module."""

from __future__ import annotations

import re
from dataclasses import dataclass, field
from typing import Dict, List, Optional


@dataclass
class FingerprintResult:
    server_software: Optional[str] = None
    server_version: Optional[str] = None
    runtimes: Dict[str, str] = field(default_factory=dict)  # e.g. {"php": "8.3.6", "openssl": "3.0.2"}
    frameworks: List[str] = field(default_factory=list)
    raw_headers_analyzed: Dict[str, str] = field(default_factory=dict)


class TechnologyFingerprinter:
    """Extracts software and version cues from headers, cookies, and responses."""

    def fingerprint(self, headers: Dict[str, str], body: str = "") -> FingerprintResult:
        result = FingerprintResult(raw_headers_analyzed=headers)

        # 1. Inspect Server Header
        server_header = headers.get("server", "")
        if server_header:
            self._parse_server_header(server_header, result)

        # 2. Inspect X-Powered-By Header
        powered_by = headers.get("x-powered-by", "")
        if powered_by:
            self._parse_powered_by(powered_by, result)

        # 3. Inspect X-AspNet-Version or X-AspNetMvc-Version
        if "x-aspnet-version" in headers:
            result.runtimes["aspnet"] = headers["x-aspnet-version"]
        if "x-aspnetmvc-version" in headers:
            result.frameworks.append(f"ASP.NET MVC {headers['x-aspnetmvc-version']}")

        # 4. Inspect cookies for runtime signatures
        set_cookie = headers.get("set-cookie", "")
        if "phpsessid" in set_cookie.lower() and "php" not in result.runtimes:
            result.runtimes["php"] = "detected (via PHPSESSID)"
        elif "jsessionid" in set_cookie.lower() and "java" not in result.runtimes:
            result.runtimes["java"] = "detected (via JSESSIONID)"
        elif "connect.sid" in set_cookie.lower():
            result.frameworks.append("Express / Connect")

        return result

    def _parse_server_header(self, server_str: str, result: FingerprintResult) -> None:
        # e.g., "Apache/2.4.41 (Ubuntu) OpenSSL/1.1.1f"
        # or "nginx/1.18.0"
        tokens = server_str.split()
        for token in tokens:
            if "/" in token:
                name, ver = token.split("/", 1)
                name_clean = name.strip()
                # Clean extra comments e.g. "2.4.41 (Ubuntu)"
                ver_clean = ver.split()[0].rstrip(";,").strip()

                if name_clean.lower() in ("apache", "httpd", "nginx", "lighttpd", "caddy", "envoy", "microsoft-iis"):
                    result.server_software = name_clean
                    result.server_version = ver_clean
                elif name_clean.lower() == "openssl":
                    result.runtimes["openssl"] = ver_clean
                elif name_clean.lower() == "php":
                    result.runtimes["php"] = ver_clean
                else:
                    result.runtimes[name_clean.lower()] = ver_clean
            else:
                if not result.server_software:
                    result.server_software = token.strip()

    def _parse_powered_by(self, powered_by: str, result: FingerprintResult) -> None:
        # e.g., "PHP/8.3.2" or "Express"
        if "/" in powered_by:
            parts = powered_by.split("/", 1)
            tech = parts[0].strip().lower()
            ver = parts[1].strip()
            result.runtimes[tech] = ver
        else:
            result.frameworks.append(powered_by.strip())
