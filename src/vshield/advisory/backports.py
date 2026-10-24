"""Vendor backport detection logic for Debian, Ubuntu, RHEL/CentOS, and SUSE."""

from __future__ import annotations

import re
from typing import Dict, Optional, Tuple


class VendorBackportDetector:
    """Analyzes package strings and vendor release numbers to determine if a fix has been backported."""

    # Examples:
    # Debian: 8.2.7-1~deb12u1, 2.4.56-1~deb12u2
    # Ubuntu: 8.3.6-0ubuntu0.24.04.1, 2.4.41-4ubuntu3.17
    # RHEL / Rocky / Alma: 8.2.4-2.el9_4.1, 2.4.57-11.el9_4
    # Alpine: 8.2.18-r0
    
    DEBIAN_PATTERN = re.compile(r"deb(\d+)u(\d+)")
    UBUNTU_PATTERN = re.compile(r"ubuntu(\d+(?:\.\d+)*)")
    RHEL_PATTERN = re.compile(r"el(\d+)(?:_(\d+))?(?:\.(\d+))?")

    @classmethod
    def parse_vendor_release(cls, package_version: str) -> Dict[str, str]:
        """Extracts vendor release metadata from a package version string."""
        info = {
            "vendor": "upstream",
            "base_version": package_version,
            "security_revision": "",
        }

        deb_match = cls.DEBIAN_PATTERN.search(package_version)
        if deb_match:
            info["vendor"] = "debian"
            info["release"] = deb_match.group(1)
            info["security_revision"] = deb_match.group(2)
            return info

        ubu_match = cls.UBUNTU_PATTERN.search(package_version)
        if ubu_match:
            info["vendor"] = "ubuntu"
            info["security_revision"] = ubu_match.group(1)
            return info

        rhel_match = cls.RHEL_PATTERN.search(package_version)
        if rhel_match:
            info["vendor"] = "rhel"
            info["release"] = rhel_match.group(1)
            info["security_revision"] = rhel_match.group(3) or rhel_match.group(2) or "0"
            return info

        if "-r" in package_version:
            parts = package_version.split("-r")
            info["vendor"] = "alpine"
            info["security_revision"] = parts[1]
            return info

        return info

    @classmethod
    def is_vendor_patched(
        cls,
        component: str,
        installed_package_version: str,
        fixed_vendor_versions: Dict[str, str],
    ) -> Tuple[bool, Optional[str]]:
        """Checks if the installed version satisfies the vendor-specific fixed version."""
        if not installed_package_version:
            return False, None

        vendor_info = cls.parse_vendor_release(installed_package_version)
        vendor = vendor_info["vendor"]

        if vendor in fixed_vendor_versions:
            target_fix = fixed_vendor_versions[vendor]
            # Simple version comparison heuristic or exact match
            # If installed version equals or supersedes the fixed vendor string:
            if cls._version_satisfies(installed_package_version, target_fix):
                return True, f"Vendor backport {installed_package_version} fixes vulnerability (fixed in {target_fix})"

        # Check changelog note if present in raw string
        if "security fix" in installed_package_version.lower() or "backport" in installed_package_version.lower():
            return True, f"Package evidence indicates vendor patch: {installed_package_version}"

        return False, None

    @classmethod
    def _version_satisfies(cls, current: str, required_fix: str) -> bool:
        """Determines if current package version is >= required_fix string."""
        # Simple tokenized comparison
        def tokenize(v: str) -> list:
            return [int(x) if x.isdigit() else x for x in re.split(r"([0-9]+)", v) if x]

        return tokenize(current) >= tokenize(required_fix)
