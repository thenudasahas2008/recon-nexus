import asyncio
from typing import List, Optional
from reconnexus.models import ReconAsset
from reconnexus.dns_scanner import DNSResolver
from reconnexus.port_scanner import PortScanner
from reconnexus.ssl_scanner import SSLScanner
from reconnexus.http_fingerprint import HTTPFingerprinter

class ReconEngine:
    def __init__(self, ports: Optional[List[int]] = None):
        self.ports = ports or [80, 443, 22, 21, 8080, 8443, 3306, 5432]
        self.port_scanner = PortScanner()
        self.ssl_scanner = SSLScanner()
        self.http_scanner = HTTPFingerprinter()

    async def scan_target(self, target: str) -> ReconAsset:
        ips = DNSResolver.resolve_target(target)
        open_ports = await self.port_scanner.scan_ports(target, self.ports)
        tls_cert = self.ssl_scanner.inspect_certificate(target, 443) if 443 in [p.port for p in open_ports] else None
        sec_headers, techs = self.http_scanner.analyze_headers(target)

        return ReconAsset(
            target=target,
            ip_addresses=ips,
            open_ports=open_ports,
            tls_certificate=tls_cert,
            security_headers=sec_headers,
            server_technologies=techs
        )
