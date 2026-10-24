"""Data models for VulnShield findings, evidence, and scan results."""

from __future__ import annotations

import dataclasses
from dataclasses import dataclass, field
from datetime import datetime, timezone
from enum import Enum
from typing import Any, Dict, List, Optional
import json


class Severity(str, Enum):
    CRITICAL = "CRITICAL"
    HIGH = "HIGH"
    MEDIUM = "MEDIUM"
    LOW = "LOW"
    INFO = "INFO"


class Confidence(str, Enum):
    LOW = "LOW"
    MEDIUM = "MEDIUM"
    HIGH = "HIGH"
    FIXED = "FIXED"


class FindingStatus(str, Enum):
    CONFIRMED_VULNERABLE = "CONFIRMED_VULNERABLE"
    POTENTIALLY_VULNERABLE = "POTENTIALLY_VULNERABLE"
    PATCHED = "PATCHED"
    NOT_AFFECTED = "NOT_AFFECTED"
    UNKNOWN = "UNKNOWN"
    UNABLE_TO_ASSESS = "UNABLE_TO_ASSESS"


class Protocol(str, Enum):
    HTTP = "HTTP"
    HTTPS = "HTTPS"
    SSH = "SSH"
    LOCAL = "LOCAL"


@dataclass
class Evidence:
    """Read-only evidence collected during scanning."""
    protocol: Protocol
    collector: str
    raw_data: str
    extracted_value: Optional[str] = None
    source_command_or_uri: Optional[str] = None
    timestamp: str = field(
        default_factory=lambda: datetime.now(timezone.utc).isoformat()
    )

    def to_dict(self) -> Dict[str, Any]:
        return {
            "protocol": self.protocol.value if isinstance(self.protocol, Protocol) else str(self.protocol),
            "collector": self.collector,
            "raw_data": self.raw_data,
            "extracted_value": self.extracted_value,
            "source_command_or_uri": self.source_command_or_uri,
            "timestamp": self.timestamp,
        }

    @classmethod
    def from_dict(cls, data: Dict[str, Any]) -> Evidence:
        proto = data.get("protocol", "LOCAL")
        if isinstance(proto, str):
            try:
                proto = Protocol(proto.upper())
            except ValueError:
                proto = Protocol.LOCAL
        return cls(
            protocol=proto,
            collector=data.get("collector", "unknown"),
            raw_data=data.get("raw_data", ""),
            extracted_value=data.get("extracted_value"),
            source_command_or_uri=data.get("source_command_or_uri"),
            timestamp=data.get("timestamp", datetime.now(timezone.utc).isoformat()),
        )


@dataclass
class Finding:
    """Security finding identified by VulnShield."""
    id: str
    target_id: str
    title: str
    description: str
    severity: Severity
    confidence: Confidence
    status: FindingStatus
    cve: Optional[str] = None
    cvss_score: Optional[float] = None
    affected_component: Optional[str] = None
    detected_version: Optional[str] = None
    fixed_version: Optional[str] = None
    protocols: List[Protocol] = field(default_factory=list)
    evidence: List[Evidence] = field(default_factory=list)
    remediation_advice: Optional[str] = None
    references: List[str] = field(default_factory=list)
    created_at: str = field(
        default_factory=lambda: datetime.now(timezone.utc).isoformat()
    )

    def to_dict(self) -> Dict[str, Any]:
        return {
            "id": self.id,
            "target_id": self.target_id,
            "title": self.title,
            "description": self.description,
            "severity": self.severity.value if isinstance(self.severity, Severity) else str(self.severity),
            "confidence": self.confidence.value if isinstance(self.confidence, Confidence) else str(self.confidence),
            "status": self.status.value if isinstance(self.status, FindingStatus) else str(self.status),
            "cve": self.cve,
            "cvss_score": self.cvss_score,
            "affected_component": self.affected_component,
            "detected_version": self.detected_version,
            "fixed_version": self.fixed_version,
            "protocols": [p.value if isinstance(p, Protocol) else str(p) for p in self.protocols],
            "evidence": [e.to_dict() for e in self.evidence],
            "remediation_advice": self.remediation_advice,
            "references": self.references,
            "created_at": self.created_at,
        }

    @classmethod
    def from_dict(cls, data: Dict[str, Any]) -> Finding:
        sev_str = data.get("severity", "INFO")
        conf_str = data.get("confidence", "LOW")
        stat_str = data.get("status", "POTENTIALLY_VULNERABLE")

        sev = Severity[sev_str.upper()] if sev_str.upper() in Severity.__members__ else Severity.INFO
        conf = Confidence[conf_str.upper()] if conf_str.upper() in Confidence.__members__ else Confidence.LOW
        stat = FindingStatus[stat_str.upper()] if stat_str.upper() in FindingStatus.__members__ else FindingStatus.POTENTIALLY_VULNERABLE

        raw_protocols = data.get("protocols", [])
        protocols = []
        for p in raw_protocols:
            try:
                protocols.append(Protocol(p.upper()))
            except ValueError:
                protocols.append(Protocol.LOCAL)

        evidence_list = [
            Evidence.from_dict(e) for e in data.get("evidence", [])
        ]

        return cls(
            id=data["id"],
            target_id=data.get("target_id", "default"),
            title=data.get("title", "Finding"),
            description=data.get("description", ""),
            severity=sev,
            confidence=conf,
            status=stat,
            cve=data.get("cve"),
            cvss_score=data.get("cvss_score"),
            affected_component=data.get("affected_component"),
            detected_version=data.get("detected_version"),
            fixed_version=data.get("fixed_version"),
            protocols=protocols,
            evidence=evidence_list,
            remediation_advice=data.get("remediation_advice"),
            references=data.get("references", []),
            created_at=data.get("created_at", datetime.now(timezone.utc).isoformat()),
        )


@dataclass
class ScanResult:
    """Aggregated scan output for one or more targets."""
    scan_id: str
    target_ids: List[str]
    start_time: str
    end_time: str
    findings: List[Finding] = field(default_factory=list)
    errors: List[Dict[str, str]] = field(default_factory=list)
    metadata: Dict[str, Any] = field(default_factory=dict)

    def to_dict(self) -> Dict[str, Any]:
        return {
            "scan_id": self.scan_id,
            "target_ids": self.target_ids,
            "start_time": self.start_time,
            "end_time": self.end_time,
            "findings": [f.to_dict() for f in self.findings],
            "errors": self.errors,
            "metadata": self.metadata,
        }

    @classmethod
    def from_dict(cls, data: Dict[str, Any]) -> ScanResult:
        findings = [Finding.from_dict(f) for f in data.get("findings", [])]
        return cls(
            scan_id=data.get("scan_id", "unknown"),
            target_ids=data.get("target_ids", []),
            start_time=data.get("start_time", ""),
            end_time=data.get("end_time", ""),
            findings=findings,
            errors=data.get("errors", []),
            metadata=data.get("metadata", {}),
        )
