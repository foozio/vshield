"""Local vulnerability scanner for inspecting directories and manifests."""

from __future__ import annotations

import os
from pathlib import Path
from typing import List

from vulnshield.findings.model import Finding, Evidence, Protocol, Severity, Confidence, FindingStatus


class LocalScanner:
    """Performs local filesystem dependency and manifest vulnerability scanning."""

    def scan_path(self, target_path: str) -> List[Finding]:
        findings: List[Finding] = []
        path = Path(target_path)

        if not path.exists():
            return findings

        # Check for exposed environment files
        env_files = list(path.glob("**/.env*"))
        for ef in env_files:
            if ef.is_file():
                findings.append(
                    Finding(
                        id=f"LOCAL-ENV-EXPOSED-{ef.name}",
                        target_id=target_path,
                        title=f"Sensitive Environment Configuration Detected: {ef.name}",
                        description=f"Local path contains an environment configuration file ({ef.name}) which may store unencrypted credentials.",
                        severity=Severity.HIGH,
                        confidence=Confidence.HIGH,
                        status=FindingStatus.CONFIRMED_VULNERABLE,
                        protocols=[Protocol.LOCAL],
                        evidence=[
                            Evidence(
                                protocol=Protocol.LOCAL,
                                collector="local_filesystem",
                                raw_data=f"Found file at {ef.resolve()}",
                                source_command_or_uri=str(ef),
                            )
                        ],
                        remediation_advice="Ensure .env files are in .gitignore and protected with strict 0600 file permissions.",
                    )
                )

        return findings
