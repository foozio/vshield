"""Vetted command templates and collectors for read-only SSH assessment."""

from __future__ import annotations

import re
from dataclasses import dataclass, field
from typing import Any, Dict, List, Optional, Set, Tuple

from vshield.findings.model import Evidence, Protocol
from vshield.remote.ssh.platforms import PlatformProfile, PlatformType


# Vetted command templates allowlist
VETTED_COMMAND_TEMPLATES: Dict[str, str] = {
    # System identification
    "os_release": "cat /etc/os-release",
    "uname": "uname -r",
    # Package management
    "dpkg_query": "dpkg-query -W -f='${Package} ${Version}\n'",
    "rpm_qa": "rpm -qa --qf '%{NAME} %{VERSION}-%{RELEASE}\n'",
    "apk_info": "apk info -v",
    # Services and sockets
    "running_services": "systemctl list-units --type=service --state=running --no-pager --no-legend",
    "listening_ports": "ss -tulpn",
    # Application runtimes
    "php_version": "php -v",
    "nginx_version": "nginx -v",
    "apache_version": "apache2 -v 2>&1 || httpd -v 2>&1",
    "openssl_version": "openssl version",
    "docker_version": "docker version --format '{{.Server.Version}}'",
    # Package updates
    "apt_upgrades": "apt list --upgradable 2>/dev/null",
    "dnf_updates": "dnf check-update 2>/dev/null",
    # Changelogs with validated package argument
    "apt_changelog": "apt-get changelog {package}",
    "rpm_changelog": "rpm -q --changelog {package}",
    # Appliance diagnostic commands
    "cisco_show_version": "show version",
    "fortinet_status": "get system status",
    "f5_show_version": "show sys version",
    "juniper_show_version": "show version",
}

# Strict whitelist for safe arguments (e.g. package names: php8.3, nginx, openssh-server)
SAFE_ARGUMENT_REGEX = re.compile(r"^[a-zA-Z0-9_\.\-]+$")
DANGEROUS_CHARS_REGEX = re.compile(r"[;&|`$<>\r\n\t]")


class SecurityCommandValidationError(Exception):
    """Raised when an SSH command or argument violates security templates."""
    pass


class CommandValidator:
    """Validates commands and arguments strictly against vetted templates."""

    @classmethod
    def render_command(cls, template_key: str, **kwargs: str) -> str:
        if template_key not in VETTED_COMMAND_TEMPLATES:
            raise SecurityCommandValidationError(
                f"Command template '{template_key}' is not in vetted allowlist."
            )

        template = VETTED_COMMAND_TEMPLATES[template_key]

        # Validate all provided argument values
        for key, val in kwargs.items():
            if not isinstance(val, str) or not SAFE_ARGUMENT_REGEX.match(val):
                raise SecurityCommandValidationError(
                    f"Argument '{key}={val}' contains unpermitted characters. Must match {SAFE_ARGUMENT_REGEX.pattern}."
                )

        rendered = template.format(**kwargs)

        # Defense-in-depth: check for injection attempts
        if DANGEROUS_CHARS_REGEX.search(rendered) and template_key not in ("dpkg_query", "apache_version", "apt_upgrades", "dnf_updates", "docker_version"):
            raise SecurityCommandValidationError(
                f"Rendered command '{rendered}' failed safety audit."
            )

        return rendered


@dataclass
class SshSystemTelemetry:
    platform: PlatformProfile
    packages: Dict[str, str] = field(default_factory=dict)
    listening_ports: List[Dict[str, Any]] = field(default_factory=list)
    running_services: List[str] = field(default_factory=list)
    runtime_versions: Dict[str, str] = field(default_factory=dict)
    upgradable_packages: List[str] = field(default_factory=list)
    raw_evidence_list: List[Evidence] = field(default_factory=list)


class SshEvidenceCollector:
    """Collects and parses read-only system telemetry via vetted commands."""

    def parse_os_release(self, content: str) -> Dict[str, str]:
        data = {}
        for line in content.splitlines():
            line = line.strip()
            if "=" in line and not line.startswith("#"):
                k, v = line.split("=", 1)
                data[k.strip().lower()] = v.strip().strip('"\'')
        return data

    def parse_packages(self, package_manager: Optional[str], content: str) -> Dict[str, str]:
        pkgs: Dict[str, str] = {}
        for line in content.splitlines():
            line = line.strip()
            if not line:
                continue

            if package_manager == "dpkg":
                parts = line.split(None, 1)
                if len(parts) == 2:
                    pkgs[parts[0].strip()] = parts[1].strip()
            elif package_manager == "rpm":
                parts = line.split(None, 1)
                if len(parts) == 2:
                    pkgs[parts[0].strip()] = parts[1].strip()
                elif "-" in line:
                    # e.g., php-8.2.4-2.el9_4.1.x86_64
                    name_ver = line.rsplit("-", 2)
                    if len(name_ver) == 3:
                        pkgs[name_ver[0]] = f"{name_ver[1]}-{name_ver[2]}"
            elif package_manager == "apk":
                # e.g. nginx-1.24.0-r1
                m = re.match(r"^(.+)-(\d+.*)$", line)
                if m:
                    pkgs[m.group(1)] = m.group(2)
        return pkgs

    def parse_listening_ports(self, content: str) -> List[Dict[str, Any]]:
        # ss -tulpn output parsing
        results = []
        for line in content.splitlines():
            line = line.strip()
            if line.startswith("Netid") or line.startswith("State") or not line:
                continue
            parts = line.split()
            if len(parts) >= 5:
                proto = parts[0]
                local_addr = parts[4]
                proc_info = parts[6] if len(parts) > 6 else ""

                port = None
                if ":" in local_addr:
                    port_str = local_addr.rsplit(":", 1)[1]
                    if port_str.isdigit():
                        port = int(port_str)

                proc_name = ""
                m = re.search(r'users:\(\("([^"]+)"', proc_info)
                if m:
                    proc_name = m.group(1)

                results.append({
                    "proto": proto,
                    "local_addr": local_addr,
                    "port": port,
                    "process_name": proc_name,
                    "raw_info": proc_info,
                })
        return results

    def parse_running_services(self, content: str) -> List[str]:
        services = []
        for line in content.splitlines():
            line = line.strip()
            if not line:
                continue
            parts = line.split()
            if parts and parts[0].endswith(".service"):
                services.append(parts[0])
        return services

    def parse_runtime_version(self, app_name: str, content: str) -> Optional[str]:
        content_clean = content.strip()
        if not content_clean:
            return None

        if app_name == "php":
            m = re.search(r"PHP\s+(\d+\.\d+\.\d+[^\s]*)", content_clean)
            return m.group(1) if m else None

        if app_name == "nginx":
            m = re.search(r"nginx/(\d+\.\d+\.\d+)", content_clean)
            return m.group(1) if m else None

        if app_name in ("apache", "httpd"):
            m = re.search(r"Apache/(\d+\.\d+\.\d+)", content_clean)
            return m.group(1) if m else None

        if app_name == "openssl":
            m = re.search(r"OpenSSL\s+(\d+\.\d+\.\d+[a-z]*)", content_clean)
            return m.group(1) if m else None

        if app_name == "docker":
            m = re.search(r"(\d+\.\d+\.\d+)", content_clean)
            return m.group(1) if m else None

        return None
