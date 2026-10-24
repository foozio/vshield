# VulnShield Remote Assessment Engine Architecture

## 1. Overview

VulnShield v1.1 introduces an agentless Remote Assessment Engine covering HTTP, HTTPS, and SSH. The engine assesses systems remotely without intrusive exploits, correlating low-fidelity signals (such as web banners) with high-fidelity system telemetry (such as package manager databases and vendor backport fixes).

## 2. Threat Model & Security Controls

```text
[ Target Input ] 
       │
       ▼
[ Authorization Guard ]  <-- Validates target authorization & organizational allowlist
       │
       ▼
[ SSRF & Scope Guard ]   <-- Blocks private/cloud metadata IPs, enforces host allowlists
       │
       ▼
[ DNS Rebinding Guard ]  <-- Resolves IP and locks connection to validated IP
       │
       ▼
[ Rate Limiter & Concurrency Pool ] <-- Prevents denial-of-service on remote targets
       │
       ├─────────────────────────┬─────────────────────────┐
       ▼                         ▼                         ▼
 [ HTTP/HTTPS Client ]     [ TLS Inspector ]       [ SSH Safe Client ]
 (Safe GET/HEAD/OPTIONS)  (Version & Ciphers)   (Vetted Read-Only Shell)
       │                         │                         │
       └─────────────────────────┼─────────────────────────┘
                                 │
                                 ▼
                     [ Correlation Engine ]
                     (Maps banner to runtime,
                      applies vendor backport intelligence,
                      computes confidence & status)
                                 │
                                 ▼
                        [ Finding Store ]
```

### Security Controls

- **SSRF Prevention**: IP address inspection prior to socket connection. Cloud metadata (`169.254.169.254`), loopback (`127.0.0.0/8`, `::1`), link-local, and RFC1918 private subnets are blocked unless explicitly allowed in test environments.
- **DNS Rebinding Guard**: Hostnames are resolved to IP addresses and verified before connection and at every redirect hop.
- **Safe HTTP Operations**: Restricts HTTP requests to `GET`, `HEAD`, and safe `OPTIONS`. Enforces maximum redirect depth (default: 5) and response size limits (default: 5MB).
- **SSH Command Allowlists**: Commands are checked against a strict template allowlist. Arbitrary shell arguments, pipes, subshells, and write operations are strictly disallowed.
- **Credential Protection**: Redacts passwords, private keys, and tokens from all stdout, stderr, logs, and stored findings.

## 3. Evidence Correlation & Confidence Scoring

Remote scanning evidence ranges from superficial banners to authoritative package changelogs. VulnShield calculates finding confidence and status as follows:

| Evidence Level | Description | Confidence | Typical Status |
|---|---|---|---|
| Level 1 | HTTP Server or X-Powered-By Banner | LOW | POTENTIALLY_VULNERABLE |
| Level 2 | HTTP Fingerprint + Matching Service Name | MEDIUM | POTENTIALLY_VULNERABLE |
| Level 3 | Verified Package Version via SSH with known CVE | HIGH | CONFIRMED_VULNERABLE |
| Level 4 | Verified Package with Vendor Backport Fix | HIGH | PATCHED or NOT_AFFECTED |

## 4. Remediation Workflow

VulnShield recommends vendor-supported remediation:
- **Linux Systems**: Distribution-native package manager update commands (`apt-get install --only-upgrade <pkg>`, `dnf update <pkg>`, `apk upgrade <pkg>`) with non-destructive `--dry-run` simulation options.
- **Network Appliances**: Documented firmware download URLs, hotfixes, and vendor security advisory references (Cisco, Fortinet, F5, Juniper). Generic Linux shell commands are never attempted against appliances.
