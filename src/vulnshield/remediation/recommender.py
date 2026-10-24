"""Remediation recommender for Linux packages and network appliances."""

from __future__ import annotations

from dataclasses import dataclass, field
from typing import Any, Dict, List, Optional

from vulnshield.findings.model import Finding, Protocol


@dataclass
class RemediationPlan:
    target_id: str
    target_type: str  # "linux" or "appliance" or "web"
    component: str
    summary: str
    recommended_action: str
    dry_run_command: Optional[str] = None
    production_command: Optional[str] = None
    documentation_url: Optional[str] = None
    vendor_advisory_id: Optional[str] = None
    safety_notes: List[str] = field(default_factory=list)

    def to_dict(self) -> Dict[str, Any]:
        return {
            "target_id": self.target_id,
            "target_type": self.target_type,
            "component": self.component,
            "summary": self.summary,
            "recommended_action": self.recommended_action,
            "dry_run_command": self.dry_run_command,
            "production_command": self.production_command,
            "documentation_url": self.documentation_url,
            "vendor_advisory_id": self.vendor_advisory_id,
            "safety_notes": self.safety_notes,
        }


class RemediationRecommender:
    """Generates vendor-supported remediation plans based on evidence."""

    def recommend_for_finding(self, finding: Finding, distro_or_platform: Optional[str] = None) -> RemediationPlan:
        component = (finding.affected_component or "system").lower()
        platform = (distro_or_platform or "").lower()

        # Check if appliance
        is_appliance = any(
            app in platform or app in component
            for app in ["cisco", "fortinet", "fortios", "f5", "bigip", "big-ip", "juniper", "junos"]
        )

        if is_appliance:
            return self._recommend_appliance(finding, component, platform)
        else:
            return self._recommend_linux(finding, component, platform)

    def _recommend_linux(self, finding: Finding, component: str, platform: str) -> RemediationPlan:
        notes = [
            "Always execute dry-run commands first to inspect package transaction impact.",
            "Verify dependencies will not trigger unexpected package removals.",
            "Remote patch application is disabled by default and requires independent change control approval.",
        ]

        if "ubuntu" in platform or "debian" in platform:
            dry_run = f"apt-get install --dry-run --only-upgrade {component}"
            prod_cmd = f"sudo apt-get install --only-upgrade -y {component}"
        elif "rhel" in platform or "centos" in platform or "rocky" in platform or "alma" in platform or "fedora" in platform:
            dry_run = f"dnf check-update {component}"
            prod_cmd = f"sudo dnf update -y {component}"
        elif "alpine" in platform:
            dry_run = f"apk upgrade --simulate {component}"
            prod_cmd = f"sudo apk upgrade {component}"
        else:
            dry_run = f"# Test upgrade transaction for {component}"
            prod_cmd = f"# Consult official package manager for {component}"

        return RemediationPlan(
            target_id=finding.target_id,
            target_type="linux",
            component=component,
            summary=f"Official vendor security package update for {component}",
            recommended_action=finding.remediation_advice or f"Upgrade {component} package to address {finding.cve or 'finding'}",
            dry_run_command=dry_run,
            production_command=prod_cmd,
            documentation_url=finding.references[0] if finding.references else "https://www.cve.org",
            vendor_advisory_id=finding.cve,
            safety_notes=notes,
        )

    def _recommend_appliance(self, finding: Finding, component: str, platform: str) -> RemediationPlan:
        notes = [
            "CRITICAL: Never attempt generic Linux package manager commands against network appliances.",
            "Firmware updates must be performed through verified vendor maintenance windows with dual-supervisor redundancy if available.",
            "Remote patch application is strictly disabled; manual installation per vendor instructions is required.",
        ]

        if "cisco" in component or "cisco" in platform:
            summary = "Cisco IOS / IOS-XE Software Maintenance Upgrade (SMU) or System Image Upgrade"
            doc = "https://software.cisco.com/download/home"
        elif "fortinet" in component or "fortios" in platform:
            summary = "Fortinet FortiOS Firmware Upgrade via FortiGate Web UI / CLI"
            doc = "https://docs.fortinet.com/product/fortigate/"
        elif "f5" in component or "bigip" in platform:
            summary = "F5 BIG-IP Engineering Hotfix or Base OS ISO Upgrade via TMOS"
            doc = "https://my.f5.com/manage/s/article/K13123"
        elif "juniper" in component or "junos" in platform:
            summary = "Juniper JunOS Junos-signed package upgrade"
            doc = "https://support.juniper.net/support/downloads/"
        else:
            summary = f"Vendor firmware update for {component}"
            doc = "https://www.cve.org"

        return RemediationPlan(
            target_id=finding.target_id,
            target_type="appliance",
            component=component,
            summary=summary,
            recommended_action=f"Obtain official signed firmware image and schedule maintenance window. Advisory: {finding.cve or 'Security Alert'}",
            dry_run_command=None,  # No shell dry run on appliances
            production_command=None,  # Disabled by default
            documentation_url=doc,
            vendor_advisory_id=finding.cve,
            safety_notes=notes,
        )
