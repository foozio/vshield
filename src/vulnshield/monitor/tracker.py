"""Remote monitoring, differential state tracking, and alert suppression engine."""

from __future__ import annotations

import time
from dataclasses import dataclass, field
from typing import Any, Dict, List, Optional, Set

from vulnshield.findings.model import Finding, FindingStatus


@dataclass
class Alert:
    alert_id: str
    target_id: str
    title: str
    message: str
    severity: str
    timestamp: float = field(default_factory=time.time)


class DifferentialTracker:
    """Tracks state changes across successive scans and manages alert deduplication."""

    def __init__(self, suppression_window_seconds: int = 3600):
        self.suppression_window = suppression_window_seconds
        # key: target_id:finding_id -> timestamp of last alert
        self._alert_history: Dict[str, float] = {}

    def detect_changes(
        self,
        previous_findings: List[Finding],
        current_findings: List[Finding],
    ) -> Dict[str, Any]:
        """Detects material changes between scan runs."""
        prev_map = {f.id: f for f in previous_findings}
        curr_map = {f.id: f for f in current_findings}

        new_ids = set(curr_map.keys()) - set(prev_map.keys())
        resolved_ids = set(prev_map.keys()) - set(curr_map.keys())

        status_changes = []
        for fid in set(curr_map.keys()) & set(prev_map.keys()):
            prev_f = prev_map[fid]
            curr_f = curr_map[fid]
            if prev_f.status != curr_f.status:
                status_changes.append({
                    "finding_id": fid,
                    "target_id": curr_f.target_id,
                    "previous_status": prev_f.status.value,
                    "new_status": curr_f.status.value,
                    "cve": curr_f.cve,
                })

        return {
            "new_findings_count": len(new_ids),
            "resolved_findings_count": len(resolved_ids),
            "status_changes_count": len(status_changes),
            "new_findings": [curr_map[i].to_dict() for i in new_ids],
            "resolved_findings": [prev_map[i].to_dict() for i in resolved_ids],
            "status_changes": status_changes,
        }

    def generate_alerts(
        self,
        target_id: str,
        current_findings: List[Finding],
        now: Optional[float] = None,
    ) -> List[Alert]:
        """Generates deduplicated alerts subject to suppression window."""
        current_time = now if now is not None else time.time()
        alerts: List[Alert] = []

        for f in current_findings:
            # Only alert on active confirmed or high-severity findings
            if f.status in (FindingStatus.CONFIRMED_VULNERABLE, FindingStatus.POTENTIALLY_VULNERABLE):
                alert_key = f"{target_id}:{f.id}"
                # Check suppression window
                if alert_key not in self._alert_history or (current_time - self._alert_history[alert_key] >= self.suppression_window):
                    alert = Alert(
                        alert_id=f"ALERT-{f.id}-{int(current_time)}",
                        target_id=target_id,
                        title=f"Vulnerability Alert: {f.title}",
                        message=f"Finding {f.id} ({f.cve or 'n/a'}) on target {target_id} is {f.status.value}",
                        severity=f.severity.value,
                        timestamp=current_time,
                    )
                    alerts.append(alert)
                    self._alert_history[alert_key] = current_time

        return alerts
