# ReconNexus

Automated Attack Surface Management (ASM) & OSINT reconnaissance engine.

## Features
- Multi-threaded asynchronous port and banner discovery.
- SSL/TLS cryptographic certificate inspection and expiry verification.
- HTTP security header profiling (HSTS, CSP, X-Frame-Options).
- Subdomain enumeration and infrastructure mapping.
- Structured JSON and terminal reporting.

## Usage
```bash
pip install -e .
recon-nexus example.com
recon-nexus example.com --json
```
