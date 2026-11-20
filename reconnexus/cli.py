import argparse
import asyncio
import json
import sys
from reconnexus.engine import ReconEngine

def main():
    parser = argparse.ArgumentParser(
        description="ReconNexus — Attack Surface Management & OSINT Reconnaissance Framework"
    )
    parser.add_argument("target", help="Target domain or IP address (e.g. example.com)")
    parser.add_argument("--json", action="store_true", help="Output results as JSON")
    args = parser.parse_args()

    engine = ReconEngine()
    asset = asyncio.run(engine.scan_target(args.target))

    if args.json:
        print(asset.model_dump_json(indent=2))
        return

    print("=" * 65)
    print("RECONNEXUS // ATTACK SURFACE MANAGEMENT REPORT")
    print("=" * 65)
    print(f"Target:       {asset.target}")
    print(f"IP Addresses: {', '.join(asset.ip_addresses) if asset.ip_addresses else 'None resolved'}")
    print(f"Scanned At:   {asset.scanned_at}")
    print("\n[+] Open Ports & Discovered Services:")
    if asset.open_ports:
        for p in asset.open_ports:
            banner_info = f" ({p.banner})" if p.banner else ""
            print(f"  - Port {p.port} [{p.service}]{banner_info}")
    else:
        print("  - No open ports found in standard probe set.")

    if asset.tls_certificate:
        print("\n[+] TLS / SSL Certificate Details:")
        print(f"  - Common Name: {asset.tls_certificate.subject.get('commonName', 'N/A')}")
        print(f"  - Issuer:      {asset.tls_certificate.issuer.get('organizationName', 'N/A')}")
        print(f"  - Valid Until: {asset.tls_certificate.valid_until}")
        print(f"  - Expired:     {asset.tls_certificate.is_expired}")

    if asset.security_headers:
        print("\n[+] HTTP Security Header Posture:")
        print(f"  - HSTS:                  {'ENFORCED' if asset.security_headers.has_hsts else 'MISSING'}")
        print(f"  - CSP:                   {'ENFORCED' if asset.security_headers.has_csp else 'MISSING'}")
        print(f"  - X-Frame-Options:       {'ENFORCED' if asset.security_headers.has_x_frame_options else 'MISSING'}")
        print(f"  - X-Content-Type-Options: {'ENFORCED' if asset.security_headers.has_x_content_type_options else 'MISSING'}")
        if asset.security_headers.missing_headers:
            print(f"  - Missing Headers: {', '.join(asset.security_headers.missing_headers)}")

    if asset.server_technologies:
        print("\n[+] Technology Fingerprints:")
        for t in asset.server_technologies:
            print(f"  - {t}")
    print("=" * 65)

if __name__ == "__main__":
    main()
