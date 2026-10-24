"""Platform detection and command template routing for Linux and network appliances."""

from __future__ import annotations

import re
from dataclasses import dataclass, field
from enum import Enum
from typing import Dict, List, Optional


class PlatformType(str, Enum):
    LINUX_DEBIAN = "LINUX_DEBIAN"
    LINUX_RHEL = "LINUX_RHEL"
    LINUX_ALPINE = "LINUX_ALPINE"
    LINUX_ARCH = "LINUX_ARCH"
    LINUX_GENERIC = "LINUX_GENERIC"
    CISCO_IOS = "CISCO_IOS"
    FORTINET_FORTIOS = "FORTINET_FORTIOS"
    F5_BIGIP = "F5_BIGIP"
    JUNIPER_JUNOS = "JUNIPER_JUNOS"
    UNKNOWN = "UNKNOWN"


@dataclass
class PlatformProfile:
    platform_type: PlatformType
    os_name: str
    os_version: str
    kernel_version: Optional[str] = None
    package_manager: Optional[str] = None
    is_appliance: bool = False
    hardware_model: Optional[str] = None


class PlatformDetector:
    """Detects remote OS distribution or network appliance family from initial probe output."""

    @classmethod
    def identify_from_evidence(
        cls,
        os_release_text: str = "",
        uname_text: str = "",
        device_banner: str = "",
    ) -> PlatformProfile:
        text = f"{os_release_text}\n{uname_text}\n{device_banner}".lower()

        # Check Appliances first
        if "cisco" in text or "ios-xe" in text or "nx-os" in text:
            ver_match = re.search(r"version\s+([0-9\.\(\)a-z]+)", text, re.IGNORECASE)
            version = ver_match.group(1) if ver_match else "unknown"
            return PlatformProfile(
                platform_type=PlatformType.CISCO_IOS,
                os_name="Cisco IOS-XE / NX-OS",
                os_version=version,
                is_appliance=True,
            )

        if "fortios" in text or "fortigate" in text or "fortinet" in text:
            ver_match = re.search(r"v([0-9\.]+)", text)
            version = ver_match.group(1) if ver_match else "unknown"
            return PlatformProfile(
                platform_type=PlatformType.FORTINET_FORTIOS,
                os_name="Fortinet FortiOS",
                os_version=version,
                is_appliance=True,
            )

        if "big-ip" in text or "tmos" in text or "f5 networks" in text:
            ver_match = re.search(r"version\s+([0-9\.]+)", text)
            version = ver_match.group(1) if ver_match else "unknown"
            return PlatformProfile(
                platform_type=PlatformType.F5_BIGIP,
                os_name="F5 BIG-IP TMOS",
                os_version=version,
                is_appliance=True,
            )

        if "junos" in text or "juniper" in text:
            ver_match = re.search(r"junos:\s+([0-9\.]+)", text)
            version = ver_match.group(1) if ver_match else "unknown"
            return PlatformProfile(
                platform_type=PlatformType.JUNIPER_JUNOS,
                os_name="Juniper JunOS",
                os_version=version,
                is_appliance=True,
            )

        # Linux Distributions
        kernel = uname_text.strip() if uname_text else None

        if "ubuntu" in text:
            ver_m = re.search(r'version_id="?([^"\n]+)', os_release_text, re.IGNORECASE)
            version = ver_m.group(1) if ver_m else "unknown"
            return PlatformProfile(
                platform_type=PlatformType.LINUX_DEBIAN,
                os_name="Ubuntu Linux",
                os_version=version,
                kernel_version=kernel,
                package_manager="dpkg",
                is_appliance=False,
            )

        if "debian" in text:
            ver_m = re.search(r'version_id="?([^"\n]+)', os_release_text, re.IGNORECASE)
            version = ver_m.group(1) if ver_m else "unknown"
            return PlatformProfile(
                platform_type=PlatformType.LINUX_DEBIAN,
                os_name="Debian GNU/Linux",
                os_version=version,
                kernel_version=kernel,
                package_manager="dpkg",
                is_appliance=False,
            )

        if any(r in text for r in ["red hat", "rhel", "centos", "rocky", "almalinux", "fedora"]):
            ver_m = re.search(r'version_id="?([^"\n]+)', os_release_text, re.IGNORECASE)
            version = ver_m.group(1) if ver_m else "unknown"
            return PlatformProfile(
                platform_type=PlatformType.LINUX_RHEL,
                os_name="Enterprise Linux (RHEL/CentOS/Rocky)",
                os_version=version,
                kernel_version=kernel,
                package_manager="rpm",
                is_appliance=False,
            )

        if "alpine" in text:
            ver_m = re.search(r'version_id="?([^"\n]+)', os_release_text, re.IGNORECASE)
            version = ver_m.group(1) if ver_m else "unknown"
            return PlatformProfile(
                platform_type=PlatformType.LINUX_ALPINE,
                os_name="Alpine Linux",
                os_version=version,
                kernel_version=kernel,
                package_manager="apk",
                is_appliance=False,
            )

        # Generic Linux fallback
        return PlatformProfile(
            platform_type=PlatformType.LINUX_GENERIC,
            os_name="Generic Linux",
            os_version="unknown",
            kernel_version=kernel,
            package_manager=None,
            is_appliance=False,
        )
