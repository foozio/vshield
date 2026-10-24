"""Target configuration models, YAML parser, CIDR expansion, and inventory manager."""

from __future__ import annotations

import ipaddress
import json
import os
import re
from dataclasses import dataclass, field
from pathlib import Path
from typing import Any, Dict, List, Optional, Set

try:
    import yaml  # type: ignore
    HAS_PYYAML = True
except ImportError:
    HAS_PYYAML = False

from vulnshield.remote.authorization import TargetAuthorizer, AuthorizationError


MAX_CIDR_HOST_LIMIT = 256


@dataclass
class HttpProtocolConfig:
    url: str
    mode: str = "passive"  # "passive" or "active"
    allowed_paths: List[str] = field(default_factory=lambda: ["/"])
    verify_tls: bool = True
    timeout: float = 10.0
    rate_limit: float = 5.0  # requests per second


@dataclass
class SshProtocolConfig:
    host: str
    port: int = 22
    username: str = "scanner"
    identity: Optional[str] = None
    known_hosts_file: Optional[str] = None
    timeout: float = 10.0
    device_type: Optional[str] = None  # "linux", "cisco", "fortinet", "f5", "juniper"


@dataclass
class TargetConfig:
    id: str
    authorized: bool = False
    protocols: Dict[str, Any] = field(default_factory=dict)
    cidr: Optional[str] = None
    tags: List[str] = field(default_factory=list)
    metadata: Dict[str, Any] = field(default_factory=dict)

    @property
    def http_config(self) -> Optional[HttpProtocolConfig]:
        http_data = self.protocols.get("http") or self.protocols.get("https")
        if not http_data:
            return None
        if isinstance(http_data, HttpProtocolConfig):
            return http_data
        url = http_data.get("url", "")
        return HttpProtocolConfig(
            url=url,
            mode=http_data.get("mode", "passive"),
            allowed_paths=http_data.get("allowed_paths", ["/"]),
            verify_tls=http_data.get("verify_tls", True),
            timeout=float(http_data.get("timeout", 10.0)),
            rate_limit=float(http_data.get("rate_limit", 5.0)),
        )

    @property
    def ssh_config(self) -> Optional[SshProtocolConfig]:
        ssh_data = self.protocols.get("ssh")
        if not ssh_data:
            return None
        if isinstance(ssh_data, SshProtocolConfig):
            return ssh_data
        return SshProtocolConfig(
            host=ssh_data.get("host", ""),
            port=int(ssh_data.get("port", 22)),
            username=ssh_data.get("username", "scanner"),
            identity=ssh_data.get("identity"),
            known_hosts_file=ssh_data.get("known_hosts_file"),
            timeout=float(ssh_data.get("timeout", 10.0)),
            device_type=ssh_data.get("device_type"),
        )

    def to_dict(self) -> Dict[str, Any]:
        return {
            "id": self.id,
            "authorized": self.authorized,
            "protocols": self.protocols,
            "cidr": self.cidr,
            "tags": self.tags,
            "metadata": self.metadata,
        }

    @classmethod
    def from_dict(cls, data: Dict[str, Any]) -> TargetConfig:
        return cls(
            id=data.get("id", "target"),
            authorized=bool(data.get("authorized", False)),
            protocols=data.get("protocols", {}),
            cidr=data.get("cidr"),
            tags=data.get("tags", []),
            metadata=data.get("metadata", {}),
        )


def _simple_yaml_parse(text: str) -> Dict[str, Any]:
    """Lightweight pure-python fallback YAML parser for targets.yaml."""
    lines = text.splitlines()
    result: Dict[str, Any] = {"targets": []}
    curr_target: Optional[Dict[str, Any]] = None
    curr_proto: Optional[str] = None
    curr_list_key: Optional[str] = None

    for line in lines:
        stripped = line.strip()
        if not stripped or stripped.startswith("#"):
            continue

        indent = len(line) - len(line.lstrip(" "))

        if stripped.startswith("- id:") or (stripped.startswith("-") and "id:" in stripped):
            target_id = stripped.split("id:", 1)[1].strip().strip('"\'')
            curr_target = {
                "id": target_id,
                "authorized": False,
                "protocols": {},
                "tags": [],
            }
            result["targets"].append(curr_target)
            curr_proto = None
            curr_list_key = None
            continue

        if curr_target is not None:
            if stripped.startswith("authorized:"):
                val = stripped.split(":", 1)[1].strip().lower()
                curr_target["authorized"] = val in ("true", "yes", "1")
                continue
            if stripped.startswith("cidr:"):
                curr_target["cidr"] = stripped.split(":", 1)[1].strip().strip('"\'')
                continue
            if stripped.startswith("protocols:"):
                curr_proto = None
                continue
            if indent >= 4 and stripped.endswith(":") and not stripped.startswith("-"):
                # Protocol heading like "http:" or "ssh:"
                curr_proto = stripped[:-1].strip()
                curr_target["protocols"][curr_proto] = {}
                curr_list_key = None
                continue
            if curr_proto and curr_target["protocols"].get(curr_proto) is not None:
                if stripped.startswith("- ") and curr_list_key:
                    val = stripped[2:].strip().strip('"\'')
                    curr_target["protocols"][curr_proto].setdefault(curr_list_key, []).append(val)
                    continue
                if ":" in stripped:
                    k, v = stripped.split(":", 1)
                    k = k.strip()
                    v = v.strip().strip('"\'')
                    if v == "":
                        curr_list_key = k
                        curr_target["protocols"][curr_proto][k] = []
                    else:
                        if v.lower() in ("true", "false"):
                            val_b = v.lower() == "true"
                            curr_target["protocols"][curr_proto][k] = val_b
                        elif v.isdigit():
                            curr_target["protocols"][curr_proto][k] = int(v)
                        else:
                            curr_target["protocols"][curr_proto][k] = v
                    continue

    return result


def parse_targets_file(filepath: str) -> List[TargetConfig]:
    """Loads target configurations from a YAML or JSON file."""
    path = Path(filepath)
    if not path.exists():
        raise FileNotFoundError(f"Targets inventory file '{filepath}' does not exist.")

    content = path.read_text(encoding="utf-8")
    if filepath.endswith(".json") or content.strip().startswith("{"):
        raw_data = json.loads(content)
    else:
        if HAS_PYYAML:
            raw_data = yaml.safe_load(content)
        else:
            raw_data = _simple_yaml_parse(content)

    raw_targets = raw_data.get("targets", [])
    targets: List[TargetConfig] = []

    for item in raw_targets:
        target = TargetConfig.from_dict(item)

        # CIDR Inventory Expansion Check
        if target.cidr:
            if not target.authorized:
                raise AuthorizationError(f"CIDR target {target.cidr} must be explicitly authorized.")
            expanded_targets = expand_cidr_target(target)
            targets.extend(expanded_targets)
        else:
            targets.append(target)

    return targets


def expand_cidr_target(target: TargetConfig) -> List[TargetConfig]:
    """Safely expands a CIDR network block enforcing maximum host limits."""
    if not target.cidr:
        return [target]

    try:
        network = ipaddress.ip_network(target.cidr, strict=False)
    except ValueError as e:
        raise AuthorizationError(f"Invalid CIDR notation '{target.cidr}': {e}")

    num_hosts = network.num_addresses
    if num_hosts > MAX_CIDR_HOST_LIMIT:
        raise AuthorizationError(
            f"CIDR block '{target.cidr}' has {num_hosts} hosts, which exceeds strict limit of {MAX_CIDR_HOST_LIMIT} hosts."
        )

    expanded: List[TargetConfig] = []
    # Usable host addresses
    hosts = list(network.hosts()) if num_hosts > 2 else [network.network_address]
    for host in hosts:
        ip_str = str(host)
        sub_protocols = {}
        for proto, conf in target.protocols.items():
            conf_copy = dict(conf)
            if proto in ("http", "https"):
                url = conf_copy.get("url", f"https://{ip_str}")
                parsed = urllib_parse(url)
                conf_copy["url"] = f"{parsed['scheme']}://{ip_str}:{parsed['port']}{parsed['path']}"
            elif proto == "ssh":
                conf_copy["host"] = ip_str
            sub_protocols[proto] = conf_copy

        expanded.append(
            TargetConfig(
                id=f"{target.id}-{ip_str}",
                authorized=target.authorized,
                protocols=sub_protocols,
                tags=target.tags + ["cidr-expanded"],
                metadata={"parent_cidr": target.cidr, "ip": ip_str},
            )
        )

    return expanded


def urllib_parse(url: str) -> Dict[str, Any]:
    import urllib.parse
    p = urllib.parse.urlparse(url)
    return {
        "scheme": p.scheme or "https",
        "host": p.hostname or "localhost",
        "port": p.port or (443 if p.scheme == "https" else 80),
        "path": p.path or "/",
    }


class TargetInventoryManager:
    """Manages local target inventory registry."""

    def __init__(self, inventory_path: Optional[str] = None):
        default_dir = os.environ.get("VULNSHIELD_DATA_DIR")
        if not default_dir:
            try:
                test_p = Path(os.path.expanduser("~/.vulnshield"))
                test_p.mkdir(parents=True, exist_ok=True)
                default_dir = str(test_p)
            except Exception:
                default_dir = os.path.join(os.getcwd(), ".vulnshield")

        self.path = Path(inventory_path or os.path.join(default_dir, "targets.json"))
        self.path.parent.mkdir(parents=True, exist_ok=True)

    def load(self) -> List[TargetConfig]:
        if not self.path.exists():
            return []
        try:
            data = json.loads(self.path.read_text(encoding="utf-8"))
            return [TargetConfig.from_dict(t) for t in data.get("targets", [])]
        except Exception:
            return []

    def save(self, targets: List[TargetConfig]) -> None:
        payload = {"targets": [t.to_dict() for t in targets]}
        self.path.write_text(json.dumps(payload, indent=2), encoding="utf-8")

    def add_target(self, target: TargetConfig) -> None:
        existing = self.load()
        existing = [t for t in existing if t.id != target.id]
        existing.append(target)
        self.save(existing)

    def validate_targets(self, targets: Optional[List[TargetConfig]] = None) -> List[Dict[str, Any]]:
        """Validates target configurations and returns validation diagnostics."""
        targets = targets or self.load()
        results = []
        authorizer = TargetAuthorizer()

        for t in targets:
            issues = []
            if not t.authorized:
                issues.append("Target authorization flag is set to false.")
            if not t.protocols:
                issues.append("No protocols configured.")

            http_c = t.http_config
            if http_c:
                try:
                    parsed = authorizer.validate_url(http_c.url)
                    if not http_c.allowed_paths:
                        issues.append("No allowed paths configured for HTTP.")
                except Exception as e:
                    issues.append(f"HTTP URL invalid: {e}")

            ssh_c = t.ssh_config
            if ssh_c:
                if not ssh_c.host:
                    issues.append("SSH host is missing.")
                if ssh_c.port <= 0 or ssh_c.port > 65535:
                    issues.append(f"Invalid SSH port: {ssh_c.port}")

            results.append({
                "target_id": t.id,
                "valid": len(issues) == 0,
                "issues": issues,
            })

        return results
