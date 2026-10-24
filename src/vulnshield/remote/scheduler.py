"""Assessment job scheduler and recurring scan registry."""

from __future__ import annotations

import json
import os
import re
import time
from dataclasses import dataclass, field
from pathlib import Path
from typing import Any, Dict, List, Optional


@dataclass
class ScheduleJob:
    id: str
    targets_file: str
    interval_raw: str
    interval_seconds: int
    created_at: float = field(default_factory=time.time)
    last_run: Optional[float] = None
    next_run: float = field(default_factory=time.time)
    enabled: bool = True

    def to_dict(self) -> Dict[str, Any]:
        return {
            "id": self.id,
            "targets_file": self.targets_file,
            "interval_raw": self.interval_raw,
            "interval_seconds": self.interval_seconds,
            "created_at": self.created_at,
            "last_run": self.last_run,
            "next_run": self.next_run,
            "enabled": self.enabled,
        }

    @classmethod
    def from_dict(cls, data: Dict[str, Any]) -> ScheduleJob:
        return cls(
            id=data["id"],
            targets_file=data["targets_file"],
            interval_raw=data["interval_raw"],
            interval_seconds=data["interval_seconds"],
            created_at=data.get("created_at", time.time()),
            last_run=data.get("last_run"),
            next_run=data.get("next_run", time.time()),
            enabled=data.get("enabled", True),
        )


def parse_interval_to_seconds(interval_str: str) -> int:
    """Parses interval string (e.g. 24h, 30m, 7d, 60s) into integer seconds."""
    m = re.match(r"^(\d+)([smhd])$", interval_str.strip().lower())
    if not m:
        raise ValueError(f"Invalid interval format '{interval_str}'. Examples: 30m, 24h, 7d.")

    val, unit = int(m.group(1)), m.group(2)
    multipliers = {"s": 1, "m": 60, "h": 3600, "d": 86400}
    return val * multipliers[unit]


class ScheduleManager:
    """Persistent registry for scheduled assessment tasks."""

    def __init__(self, storage_path: Optional[str] = None):
        default_dir = os.environ.get("VULNSHIELD_DATA_DIR")
        if not default_dir:
            try:
                test_p = Path(os.path.expanduser("~/.vulnshield"))
                test_p.mkdir(parents=True, exist_ok=True)
                default_dir = str(test_p)
            except Exception:
                default_dir = os.path.join(os.getcwd(), ".vulnshield")

        self.path = Path(storage_path or os.path.join(default_dir, "schedules.json"))
        self.path.parent.mkdir(parents=True, exist_ok=True)

    def load_jobs(self) -> List[ScheduleJob]:
        if not self.path.exists():
            return []
        try:
            data = json.loads(self.path.read_text(encoding="utf-8"))
            return [ScheduleJob.from_dict(j) for j in data.get("jobs", [])]
        except Exception:
            return []

    def save_jobs(self, jobs: List[ScheduleJob]) -> None:
        payload = {"jobs": [j.to_dict() for j in jobs]}
        self.path.write_text(json.dumps(payload, indent=2), encoding="utf-8")

    def add_schedule(self, targets_file: str, interval: str) -> ScheduleJob:
        seconds = parse_interval_to_seconds(interval)
        job_id = f"job-{int(time.time())}-{os.path.basename(targets_file)}"

        job = ScheduleJob(
            id=job_id,
            targets_file=os.path.abspath(targets_file),
            interval_raw=interval,
            interval_seconds=seconds,
            next_run=time.time() + seconds,
        )

        jobs = self.load_jobs()
        jobs.append(job)
        self.save_jobs(jobs)
        return job

    def list_schedules(self) -> List[ScheduleJob]:
        return self.load_jobs()
