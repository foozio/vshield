# vShield CLI - Agent Guidelines & Architecture

## System Overview

vShield CLI is a production-grade vulnerability assessment and remediation engine supporting both local scanning (source code, dependencies, containers) and agentless remote assessment (HTTP, HTTPS, SSH).

**Official Product Name:** vShield  
**CLI:** `vshield`  
**Target Release:** v1.1  
**Positioning:** Universal Vulnerability Detection, Monitoring & Remediation Framework

### Design Principles

1. **Non-Destructive & Safe by Default**:
   - HTTP/HTTPS assessments use safe `GET`, `HEAD`, and `OPTIONS` requests. No exploit payloads, brute force, or intrusive fuzzing.
   - SSH assessments are strictly read-only, non-interactive, and run vetted command templates. Never execute unvetted commands or elevate privileges.
   - Patch application is disabled by default and requires independent approval.

2. **Strict Authorization & Scope Control**:
   - All targets must have explicit authorization.
   - Built-in SSRF protection rejects private/loopback/cloud metadata IP ranges unless running in authorized test mode.
   - DNS rebinding protection resolves and verifies target IPs before every connection and redirect hop.
   - Redirect scope protection ensures scans never escape to third-party domains.

3. **Cross-Protocol Evidence Correlation**:
   - Differentiates between superficial banners (`LOW` confidence) and verified installed package/build versions (`HIGH` or `FIXED`).
   - Classifies findings with high precision: `CONFIRMED_VULNERABLE`, `POTENTIALLY_VULNERABLE`, `PATCHED`, `NOT_AFFECTED`, `UNKNOWN`, `UNABLE_TO_ASSESS`.
   - Recognizes vendor backports (Debian, Ubuntu, Red Hat, SUSE) to prevent false positives.

4. **Extensible & Pluggable**:
   - Protocol-agnostic assessment interface allows adding protocols (e.g. SNMP, RDP, Database) in future versions.
   - Lifecycle hooks for external plugins (`on_scan_start`, `on_target_discovered`, `on_evidence_collected`, `on_finding`, `on_scan_complete`).

## Repository Layout

```text
src/vshield/
├── __init__.py
├── cli.py                     # Unified CLI entry point
├── config.py                  # Environment variable resolution & legacy migration
├── findings/                  # Finding models & persistent storage
│   ├── model.py
│   └── storage.py
├── advisory/                  # Vulnerability database & vendor advisory engine
│   ├── intelligence.py
│   └── backports.py
├── local/                     # Local file and dependency scanning
│   └── scanner.py
├── plugins/                   # Plugin hooks and extension manager
│   └── manager.py
├── remediation/               # Remediation advisor, patch sources, verification
│   ├── recommender.py
│   └── patches.py
├── monitor/                   # Differential scanning & alert deduplication
│   └── tracker.py
├── reporting/                 # Report output (text, json, markdown, html)
│   └── generator.py
└── remote/                    # Remote Assessment Engine (v1.1)
    ├── __init__.py
    ├── targets.py             # YAML target configuration & CIDR validator
    ├── authorization.py       # SSRF, DNS rebinding, redirect scope protection
    ├── scheduler.py           # Scheduled assessments & cron runner
    ├── scanner.py             # Remote orchestrator, concurrency & rate limiter
    ├── correlation.py         # Cross-protocol evidence correlation
    ├── http/
    │   ├── client.py          # Safe HTTP client, size & redirect limits
    │   ├── fingerprint.py     # Server technology & runtime fingerprinting
    │   ├── headers.py         # Security headers & disclosure analysis
    │   └── checks.py          # Method discovery, cookie security, safe checks
    ├── tls/
    │   ├── certificates.py    # X.509 cert validation, expiration, SAN inventory
    │   └── configuration.py   # TLS versions (1.0-1.3), cipher suite audit
    └── ssh/
        ├── client.py          # Safe SSH execution, strict host-key checking
        ├── authentication.py  # Public key, agent, cert, protected credentials
        ├── collectors.py      # Vetted Linux & package command templates
        └── platforms.py       # Platform detection (Linux vs Appliances)
```

## Testing Protocol

Unit, integration, and security tests reside under `tests/`:
- `tests/test_remote/`: HTTP, TLS, SSH collectors, correlation, and scheduling tests.
- `tests/test_security/`: SSRF prevention, DNS rebinding, command injection prevention, credential redaction, redirect scope escapes.
