# ReconNexus — Attack Surface Management (ASM) & OSINT Reconnaissance Framework

[![Recon: ASM](https://img.shields.io/badge/Security-Attack%20Surface-orange.svg)](#)
[![Python: 3.11+](https://img.shields.io/badge/Python-3.11%2B-blue.svg)](#)
[![License: MIT](https://img.shields.io/badge/License-MIT-green.svg)](#)

ReconNexus is an automated attack surface discovery and external exposure profiling engine designed for penetration testers, security engineers, and red teams.

---

## Key Features

- **Asynchronous Port Discovery**: High-concurrency TCP port prober with banner grabbing capabilities.
- **SSL/TLS Cryptographic Audit**: Extracts Common Name (CN), Subject Alternative Names (SANs), certificate issuer, and expiry status.
- **HTTP Security Header Profiling**: Detects the presence or absence of critical defensive headers:
  - `Strict-Transport-Security` (HSTS)
  - `Content-Security-Policy` (CSP)
  - `X-Frame-Options` (Clickjacking mitigation)
  - `X-Content-Type-Options` (MIME-sniffing prevention)
- **Technology Fingerprinting**: Identifies backend server banners (`Server`, `X-Powered-By`).
- **Subdomain Enumeration**: DNS-based discovery across critical infrastructure prefixes.
- **Dual Output Modes**: Clean human-readable terminal reports and machine-parsable JSON output.

---

## Installation & Setup

```bash
# Clone the repository
git clone https://github.com/thenudasahas2008/recon-nexus.git
cd recon-nexus

# Install dependencies and local CLI
pip install -e .
```

---

## CLI Usage

### 1. Perform Reconnaissance Scan
```bash
# Scan a domain or IP target
recon-nexus example.com
```

### 2. Export JSON Telemetry
```bash
# Output full asset graph as JSON
recon-nexus example.com --json > attack_surface.json
```

---

## Automated Verification & Testing

```bash
# Run pytest test cases
pytest -v tests
```

---

## Repository Structure

```
recon-nexus/
├── reconnexus/
│   ├── dns_scanner.py       # DNS resolution and subdomain enumeration
│   ├── port_scanner.py      # Async TCP socket prober and banner grabber
│   ├── ssl_scanner.py       # TLS/SSL certificate inspector
│   ├── http_fingerprint.py  # Security header auditor and server banners
│   ├── engine.py            # Orchestrator aggregating exposure metrics
│   ├── models.py            # Pydantic schemas for assets and findings
│   └── cli.py               # Command-line interface
└── tests/                   # Pytest test cases
```
