import asyncio
import socket
from typing import List, Optional
from reconnexus.models import OpenPort

COMMON_PORTS = {
    21: "FTP",
    22: "SSH",
    25: "SMTP",
    53: "DNS",
    80: "HTTP",
    110: "POP3",
    143: "IMAP",
    443: "HTTPS",
    445: "SMB",
    3306: "MySQL",
    3389: "RDP",
    5432: "PostgreSQL",
    6379: "Redis",
    8080: "HTTP-Proxy",
    8443: "HTTPS-Alt",
    27017: "MongoDB"
}

class PortScanner:
    def __init__(self, timeout: float = 0.5):
        self.timeout = timeout

    async def probe_port(self, host: str, port: int) -> Optional[OpenPort]:
        service_name = COMMON_PORTS.get(port, "unknown")
        try:
            reader, writer = await asyncio.wait_for(
                asyncio.open_connection(host, port),
                timeout=self.timeout
            )
            banner = None
            try:
                # Banner grab
                writer.write(b"HEAD / HTTP/1.0\r\n\r\n")
                await writer.drain()
                data = await asyncio.wait_for(reader.read(256), timeout=0.3)
                if data:
                    banner = data.decode(errors="ignore").strip().splitlines()[0][:100]
            except Exception:
                pass
            finally:
                writer.close()
                await writer.wait_closed()
            return OpenPort(port=port, service=service_name, banner=banner)
        except Exception:
            return None

    async def scan_ports(self, host: str, ports: List[int]) -> List[OpenPort]:
        tasks = [self.probe_port(host, p) for p in ports]
        results = await asyncio.gather(*tasks, return_exceptions=True)
        open_ports: List[OpenPort] = []
        for r in results:
            if isinstance(r, OpenPort):
                open_ports.append(r)
        return sorted(open_ports, key=lambda x: x.port)
