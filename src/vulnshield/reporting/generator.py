"""Report generation and formatting for VulnShield."""

from __future__ import annotations

import json
from typing import Any, Dict, List, Optional
from vulnshield.findings.model import Finding, ScanResult, Severity


class ReportGenerator:
    """Formats findings and scan outputs for terminal and files."""

    @staticmethod
    def format_findings_table(findings: List[Finding]) -> str:
        if not findings:
            return "No findings recorded."

        header = f"{'SEVERITY':<10} {'CONFIDENCE':<10} {'STATUS':<22} {'CVE / ID':<18} {'COMPONENT':<16} {'TITLE'}"
        separator = "-" * 110
        lines = [header, separator]

        for f in findings:
            cve_str = f.cve or f.id[:16]
            comp_str = f.affected_component or "n/a"
            lines.append(
                f"{f.severity.value:<10} {f.confidence.value:<10} {f.status.value:<22} {cve_str:<18} {comp_str:<16} {f.title[:35]}"
            )

        return "\n".join(lines)

    @staticmethod
    def format_finding_detail(f: Finding) -> str:
        lines = [
            "=" * 80,
            f"FINDING: {f.title}",
            "=" * 80,
            f"ID:                 {f.id}",
            f"Target ID:          {f.target_id}",
            f"Severity:           {f.severity.value}",
            f"Confidence:         {f.confidence.value}",
            f"Status:             {f.status.value}",
            f"CVE:                {f.cve or 'None'}",
            f"CVSS Score:         {f.cvss_score or 'N/A'}",
            f"Affected Component: {f.affected_component or 'N/A'}",
            f"Detected Version:   {f.detected_version or 'N/A'}",
            f"Fixed Version:      {f.fixed_version or 'N/A'}",
            f"Protocols:          {', '.join(p.value for p in f.protocols)}",
            f"Created At:         {f.created_at}",
            "-" * 80,
            "Description:",
            f"  {f.description}",
            "-" * 80,
            "Remediation Advice:",
            f"  {f.remediation_advice or 'No specific advice provided.'}",
            "-" * 80,
            f"Evidence Items ({len(f.evidence)}):",
        ]

        for i, ev in enumerate(f.evidence, start=1):
            lines.append(f"  [{i}] Protocol: {ev.protocol.value} | Collector: {ev.collector}")
            if ev.source_command_or_uri:
                lines.append(f"      Source: {ev.source_command_or_uri}")
            if ev.extracted_value:
                lines.append(f"      Extracted: {ev.extracted_value}")
            raw_preview = ev.raw_data.strip()
            if len(raw_preview) > 120:
                raw_preview = raw_preview[:120] + "... [truncated]"
            lines.append(f"      Raw Evidence: {raw_preview}")

        if f.references:
            lines.append("-" * 80)
            lines.append("References:")
            for r in f.references:
                lines.append(f"  - {r}")

        lines.append("=" * 80)
        return "\n".join(lines)

    @staticmethod
    def format_compare_report(comparison: Dict[str, Any]) -> str:
        summary = comparison.get("summary", {})
        lines = [
            "=" * 80,
            f"DIFFERENTIAL SCAN COMPARISON: {comparison.get('scan_1')} <---> {comparison.get('scan_2')}",
            "=" * 80,
            f"Total Previous: {summary.get('total_previous', 0)}",
            f"Total Current:  {summary.get('total_current', 0)}",
            f"New Findings:       {summary.get('new', 0)}",
            f"Resolved Findings:  {summary.get('resolved', 0)}",
            f"Persistent:         {summary.get('persistent', 0)}",
            "-" * 80,
        ]

        if comparison.get("new_findings"):
            lines.append("NEW FINDINGS:")
            for nf in comparison["new_findings"]:
                lines.append(f"  + [{nf['severity']}] {nf['title']} ({nf.get('cve') or nf['id']})")

        if comparison.get("resolved_findings"):
            lines.append("RESOLVED FINDINGS:")
            for rf in comparison["resolved_findings"]:
                lines.append(f"  - [{rf['severity']}] {rf['title']} ({rf.get('cve') or rf['id']})")

        lines.append("=" * 80)
        return "\n".join(lines)
