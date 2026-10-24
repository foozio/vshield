# vShield CLI v1.1

> **Universal Vulnerability Detection, Monitoring & Remediation Framework**  
> Agentless Remote & Local Assessment Engine (HTTP / HTTPS / SSH)

vShield (formerly VulnShield) is a production-grade vulnerability assessment and remediation engine. It evaluates remote web services (HTTP/HTTPS) and Linux hosts/appliances (SSH) non-destructively, correlates low-fidelity signals with high-fidelity system telemetry, and generates authoritative vendor-supported remediation plans.

---

## 1. Key Capabilities

### HTTP / HTTPS Assessment
- **HTTP/1.1 and HTTP/2**: Safe `GET`, `HEAD`, and safe `OPTIONS` probes.
- **Technology Fingerprinting**: Identifies web servers (Apache, Nginx, IIS, Caddy, Envoy) and runtimes (PHP, Python, ASP.NET, OpenSSL).
- **Security Headers**: Audits `Strict-Transport-Security`, `Content-Security-Policy`, `X-Content-Type-Options`, `X-Frame-Options`, `Referrer-Policy`, and version disclosures.
- **Cookie Security**: Flags missing `Secure`, `HttpOnly`, and `SameSite` flags.
- **TLS Inspection**:
  - Validates certificates against CA store with diagnostics for expired, self-signed, or mismatched certs without blindly trusting invalid certs.
  - Computes days remaining until certificate expiration.
  - Audits TLS versions (flagging deprecated TLS 1.0 / 1.1) and detects weak cipher suites (NULL, EXPORT, RC4, 3DES, DES, CBC).
  - Enforces HTTPS redirection from HTTP port 80 to HTTPS port 443.

### SSH Authenticated Assessment
- **Strict Host-Key Checking**: Checks against `known_hosts` and blocks unknown or changed host keys.
- **Non-Destructive & Read-Only**: Enforces strict allowlist of vetted command templates (`/etc/os-release`, `uname -r`, `dpkg-query`, `rpm -qa`, `apk info`, `systemctl`, `ss -tulpn`, `php -v`, etc.).
- **No Implicit Escalation**: Operates with least-privilege credentials; never executes `sudo`, `su`, or writes to disks.
- **Platform Separation**: Automatically differentiates Linux distributions (Debian/Ubuntu, RHEL/CentOS, Alpine) from Network Appliances (Cisco IOS-XE, Fortinet FortiOS, F5 BIG-IP, Juniper JunOS). Generic Linux package managers are never run on appliances.

### Cross-Protocol Evidence Correlation
- Correlates superficial HTTP banners with authenticated SSH package information and active listening sockets.
- Differentiates findings:
  - **LOW Confidence**: HTTP banner only (classified as `POTENTIALLY_VULNERABLE`).
  - **MEDIUM Confidence**: HTTP banner + matching software signature.
  - **HIGH Confidence**: Verified vulnerable package version with authoritative vendor advisory (`CONFIRMED_VULNERABLE`).
  - **FIXED Confidence**: Verified vendor security backport (`PATCHED`).

### Security Controls
- **SSRF Prevention**: Strict pre-connection checks blocking loopback (`127.0.0.0/8`, `::1`), RFC1918 private subnets (`10.0.0.0/8`, `172.16.0.0/12`, `192.168.0.0/16`), and cloud metadata (`169.254.169.254`).
- **DNS Rebinding Guard**: Hostnames are resolved and verified before connection and re-validated at each redirect hop.
- **Redirect Scope Protection**: Redirects to third-party domains outside authorized target scope are blocked.
- **Credential Redaction**: Passwords, private keys, and authorization tokens are redacted across all logs, stdout, and persisted finding evidence.

---

## 2. CLI Usage Guide

### System Health & Diagnostics
```bash
vshield doctor
```

### HTTP / HTTPS Scanning
```bash
# Basic passive URL scan
vshield scan --url https://example.com

# Custom port
vshield scan --url http://example.com:8080

# Active discovery mode (safe OPTIONS method probe)
vshield scan --url https://example.com --mode active
```

### Authenticated SSH Assessment
```bash
# Standard SSH assessment
vshield scan --ssh admin@server.example.com

# With specific private key identity
vshield scan --ssh admin@server.example.com --identity ~/.ssh/id_ed25519

# Custom SSH port
vshield scan --ssh admin@server.example.com --port 2222
```

### Combined Cross-Protocol Assessment
```bash
vshield scan --url https://example.com --ssh admin@server.example.com
```

### Batch Target Inventories
```bash
vshield scan --targets targets.yaml
vshield scan --targets targets.yaml --concurrency 5
```

### Target Management
```bash
vshield targets add --url https://example.com
vshield targets add --ssh admin@server.example.com
vshield targets list
vshield targets validate
```

### Scheduled Scanning
```bash
vshield schedule add --targets targets.yaml --interval 24h
vshield schedule list
```

### Findings & Differential Analysis
```bash
vshield findings list
vshield findings show FINDING_ID
vshield findings compare SCAN_ID_1 SCAN_ID_2
```

### Remediation & Patch Verification
```bash
vshield remediate recommend --target TARGET_ID
vshield patch sources --target TARGET_ID
vshield patch verify --target TARGET_ID
```

---

## 3. Environment Variables & Backward Compatibility

| Environment Variable | Description | Legacy Fallback |
|---|---|---|
| `VSHIELD_DATA_DIR` | Path to persistent storage and findings database | `VULNSHIELD_DATA_DIR` |
| `VSHIELD_SSH_PASSWORD` | In-memory protected password provider for SSH | `VULNSHIELD_SSH_PASSWORD` |

Backward-compatible command alias: `vulnshield` is aliased to `vshield` with a deprecation notice.

---

## 4. Supported Environments & Limitations

### Supported Environments
- **Linux Hosts**: Ubuntu, Debian, Red Hat Enterprise Linux (RHEL), CentOS, Rocky Linux, AlmaLinux, Fedora, Alpine Linux.
- **Network Appliances**: Cisco IOS / IOS-XE, Fortinet FortiOS, F5 BIG-IP TMOS, Juniper JunOS.
- **Web Services**: Any HTTP/1.1 or HTTP/2 compliant web server or reverse proxy.

### Limitations & Deliberate Exclusions
- **No Exploitation**: vShield never sends exploit payloads or memory-corrupting fuzz vectors.
- **No In-Band Credential Guessing**: No brute-forcing of passwords or private keys.
- **No Unapproved Subnet Sweeps**: CIDR inventories require explicit authorization flags and have an enforced maximum limit of 256 hosts.
- **Remote Patch Execution Disabled**: Remote patch execution is disabled by default to prevent unintentional operational disruption.
