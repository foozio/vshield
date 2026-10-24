"""Patch source tracking and remediation verification engine."""

from __future__ import annotations

from typing import Any, Dict, List, Optional
from vshield.findings.model import Finding, FindingStatus, Confidence
from vshield.findings.storage import FindingStore


class PatchEngine:
    """Manages patch repositories and validates post-patch verification scans."""

    def __init__(self, finding_store: Optional[FindingStore] = None):
        self.store = finding_store or FindingStore()

    def get_patch_sources(self, target_id: str) -> List[Dict[str, Any]]:
        """Retrieves official vendor patch sources and channels for a given target."""
        findings = self.store.list_findings(target_id=target_id)
        sources: List[Dict[str, Any]] = []

        seen_components = set()
        for f in findings:
            comp = f.affected_component or "unknown"
            if comp in seen_components:
                continue
            seen_components.add(comp)

            # Determine official upstream and vendor sources
            if "php" in comp.lower():
                sources.append({
                    "component": comp,
                    "target_id": target_id,
                    "official_repo": "https://packages.debian.org / http://archive.ubuntu.com",
                    "security_channel": "Debian Security (security.debian.org) / Ubuntu Security",
                    "cve": f.cve,
                    "patch_status": f.status.value,
                    "recommended_action": f.remediation_advice,
                })
            elif "nginx" in comp.lower():
                sources.append({
                    "component": comp,
                    "target_id": target_id,
                    "official_repo": "http://nginx.org/packages",
                    "security_channel": "Vendor Security Tracker",
                    "cve": f.cve,
                    "patch_status": f.status.value,
                    "recommended_action": f.remediation_advice,
                })
            elif "cisco" in comp.lower():
                sources.append({
                    "component": comp,
                    "target_id": target_id,
                    "official_repo": "https://software.cisco.com",
                    "security_channel": "Cisco Security Advisory Channel",
                    "cve": f.cve,
                    "patch_status": f.status.value,
                    "recommended_action": "Download signed .bin or SMU file",
                })
            elif "f5" in comp.lower():
                sources.append({
                    "component": comp,
                    "target_id": target_id,
                    "official_repo": "https://my.f5.com",
                    "security_channel": "F5 Security Advisories",
                    "cve": f.cve,
                    "patch_status": f.status.value,
                    "recommended_action": "Download signed ISO / Hotfix via F5 Downloads",
                })
            elif "fortinet" in comp.lower():
                sources.append({
                    "component": comp,
                    "target_id": target_id,
                    "official_repo": "https://support.fortinet.com",
                    "security_channel": "FortiGuard PSIRT",
                    "cve": f.cve,
                    "patch_status": f.status.value,
                    "recommended_action": "Download FortiOS image matching hardware model",
                })
            else:
                sources.append({
                    "component": comp,
                    "target_id": target_id,
                    "official_repo": "Standard OS / Vendor Repository",
                    "security_channel": "Official Security Feeds",
                    "cve": f.cve,
                    "patch_status": f.status.value,
                    "recommended_action": f.remediation_advice,
                })

        return sources

    def verify_patch(
        self,
        target_id: str,
        current_findings: List[Finding],
    ) -> Dict[str, Any]:
        """
        Validates remediation results by checking whether previously confirmed
        vulnerabilities have transitioned to PATCHED or are no longer detected.
        """
        historic_findings = self.store.list_findings(target_id=target_id)
        
        # Build map of historic vulnerabilities
        historic_map = {
            f.id: f for f in historic_findings
            if f.status in (FindingStatus.CONFIRMED_VULNERABLE, FindingStatus.POTENTIALLY_VULNERABLE)
        }

        current_active = {
            f.id: f for f in current_findings
            if f.status in (FindingStatus.CONFIRMED_VULNERABLE, FindingStatus.POTENTIALLY_VULNERABLE)
        }

        remediated: List[Dict[str, Any]] = []
        unremediated: List[Dict[str, Any]] = []

        for f_id, hist_f in historic_map.items():
            if f_id not in current_active:
                remediated.append({
                    "finding_id": f_id,
                    "cve": hist_f.cve,
                    "component": hist_f.affected_component,
                    "status": "VERIFIED_REMEDIATED",
                    "previous_severity": hist_f.severity.value,
                })
            else:
                unremediated.append({
                    "finding_id": f_id,
                    "cve": hist_f.cve,
                    "component": hist_f.affected_component,
                    "status": "STILL_VULNERABLE",
                    "severity": hist_f.severity.value,
                })

        return {
            "target_id": target_id,
            "total_historic": len(historic_map),
            "verified_remediated_count": len(remediated),
            "unremediated_count": len(unremediated),
            "remediated": remediated,
            "unremediated": unremediated,
            "verification_status": "PASSED" if not unremediated else "ATTENTION_REQUIRED",
        }
