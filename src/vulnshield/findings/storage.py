"""Persistent storage and differential comparison for VulnShield findings."""

from __future__ import annotations

import json
import os
import sqlite3
from pathlib import Path
from typing import Any, Dict, List, Optional, Tuple

from vulnshield.findings.model import Finding, ScanResult, Severity, FindingStatus, Confidence


def _get_default_data_dir() -> str:
    env_dir = os.environ.get("VULNSHIELD_DATA_DIR")
    if env_dir:
        return env_dir
    try:
        user_p = Path(os.path.expanduser("~/.vulnshield"))
        user_p.mkdir(parents=True, exist_ok=True)
        return str(user_p)
    except Exception:
        return os.path.join(os.getcwd(), ".vulnshield")


DEFAULT_DATA_DIR = _get_default_data_dir()


class FindingStore:
    """SQLite-backed finding and scan storage."""

    def __init__(self, data_dir: Optional[str] = None):
        self.data_dir = Path(data_dir or DEFAULT_DATA_DIR)
        self.data_dir.mkdir(parents=True, exist_ok=True)
        self.db_path = self.data_dir / "vulnshield.db"
        self._init_db()

    def _get_connection(self) -> sqlite3.Connection:
        conn = sqlite3.connect(str(self.db_path))
        conn.row_factory = sqlite3.Row
        return conn

    def _init_db(self) -> None:
        with self._get_connection() as conn:
            conn.executescript(
                """
                CREATE TABLE IF NOT EXISTS scans (
                    scan_id TEXT PRIMARY KEY,
                    start_time TEXT,
                    end_time TEXT,
                    target_ids TEXT,
                    raw_json TEXT
                );

                CREATE TABLE IF NOT EXISTS findings (
                    id TEXT PRIMARY KEY,
                    scan_id TEXT,
                    target_id TEXT,
                    title TEXT,
                    severity TEXT,
                    confidence TEXT,
                    status TEXT,
                    cve TEXT,
                    cvss_score REAL,
                    affected_component TEXT,
                    detected_version TEXT,
                    created_at TEXT,
                    raw_json TEXT,
                    FOREIGN KEY (scan_id) REFERENCES scans (scan_id)
                );

                CREATE INDEX IF NOT EXISTS idx_findings_target ON findings(target_id);
                CREATE INDEX IF NOT EXISTS idx_findings_cve ON findings(cve);
                CREATE INDEX IF NOT EXISTS idx_findings_severity ON findings(severity);
                """
            )
            conn.commit()

    def save_scan_result(self, result: ScanResult) -> None:
        with self._get_connection() as conn:
            conn.execute(
                """
                INSERT OR REPLACE INTO scans (scan_id, start_time, end_time, target_ids, raw_json)
                VALUES (?, ?, ?, ?, ?)
                """,
                (
                    result.scan_id,
                    result.start_time,
                    result.end_time,
                    json.dumps(result.target_ids),
                    json.dumps(result.to_dict()),
                ),
            )

            for finding in result.findings:
                conn.execute(
                    """
                    INSERT OR REPLACE INTO findings (
                        id, scan_id, target_id, title, severity, confidence,
                        status, cve, cvss_score, affected_component,
                        detected_version, created_at, raw_json
                    ) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
                    """,
                    (
                        finding.id,
                        result.scan_id,
                        finding.target_id,
                        finding.title,
                        finding.severity.value,
                        finding.confidence.value,
                        finding.status.value,
                        finding.cve,
                        finding.cvss_score,
                        finding.affected_component,
                        finding.detected_version,
                        finding.created_at,
                        json.dumps(finding.to_dict()),
                    ),
                )
            conn.commit()

    def get_finding(self, finding_id: str) -> Optional[Finding]:
        with self._get_connection() as conn:
            cur = conn.execute(
                "SELECT raw_json FROM findings WHERE id = ?",
                (finding_id,),
            )
            row = cur.fetchone()
            if row:
                return Finding.from_dict(json.loads(row["raw_json"]))
        return None

    def list_findings(
        self,
        target_id: Optional[str] = None,
        severity: Optional[str] = None,
        status: Optional[str] = None,
        limit: int = 100,
    ) -> List[Finding]:
        query = "SELECT raw_json FROM findings WHERE 1=1"
        params: List[Any] = []

        if target_id:
            query += " AND target_id = ?"
            params.append(target_id)
        if severity:
            query += " AND severity = ?"
            params.append(severity.upper())
        if status:
            query += " AND status = ?"
            params.append(status.upper())

        query += " ORDER BY created_at DESC LIMIT ?"
        params.append(limit)

        with self._get_connection() as conn:
            cur = conn.execute(query, params)
            return [Finding.from_dict(json.loads(r["raw_json"])) for r in cur.fetchall()]

    def get_scan(self, scan_id: str) -> Optional[ScanResult]:
        with self._get_connection() as conn:
            cur = conn.execute(
                "SELECT raw_json FROM scans WHERE scan_id = ?",
                (scan_id,),
            )
            row = cur.fetchone()
            if row:
                return ScanResult.from_dict(json.loads(row["raw_json"]))
        return None

    def list_scans(self, limit: int = 20) -> List[ScanResult]:
        with self._get_connection() as conn:
            cur = conn.execute(
                "SELECT raw_json FROM scans ORDER BY start_time DESC LIMIT ?",
                (limit,),
            )
            return [ScanResult.from_dict(json.loads(r["raw_json"])) for r in cur.fetchall()]

    def compare_scans(
        self, scan_id_1: str, scan_id_2: str
    ) -> Dict[str, Any]:
        """Compares two scans and returns new, resolved, and persistent findings."""
        s1 = self.get_scan(scan_id_1)
        s2 = self.get_scan(scan_id_2)

        if not s1 or not s2:
            raise ValueError(f"Scan {scan_id_1 if not s1 else scan_id_2} not found")

        # Map by unique fingerprint (target_id + cve or title + affected_component)
        def fingerprint(f: Finding) -> str:
            key = f"{f.target_id}:{f.cve or f.title}:{f.affected_component}"
            return key

        f1_map = {fingerprint(f): f for f in s1.findings}
        f2_map = {fingerprint(f): f for f in s2.findings}

        new_keys = set(f2_map.keys()) - set(f1_map.keys())
        resolved_keys = set(f1_map.keys()) - set(f2_map.keys())
        persisting_keys = set(f1_map.keys()) & set(f2_map.keys())

        return {
            "scan_1": scan_id_1,
            "scan_2": scan_id_2,
            "new_findings": [f2_map[k].to_dict() for k in new_keys],
            "resolved_findings": [f1_map[k].to_dict() for k in resolved_keys],
            "persistent_findings": [
                {
                    "key": k,
                    "previous": f1_map[k].to_dict(),
                    "current": f2_map[k].to_dict(),
                    "status_changed": f1_map[k].status != f2_map[k].status,
                }
                for k in persisting_keys
            ],
            "summary": {
                "total_previous": len(s1.findings),
                "total_current": len(s2.findings),
                "new": len(new_keys),
                "resolved": len(resolved_keys),
                "persistent": len(persisting_keys),
            },
        }
