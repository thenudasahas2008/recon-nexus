import socket
from typing import List

DEFAULT_SUBDOMAINS = [
    "www", "mail", "api", "dev", "staging", "vpn", "admin", "portal", "cloud", "auth"
]

class DNSResolver:
    @staticmethod
    def resolve_target(target: str) -> List[str]:
        try:
            _, _, ips = socket.gethostbyname_ex(target)
            return ips
        except Exception:
            return []

    @staticmethod
    def enumerate_subdomains(domain: str, wordlist: List[str] = None) -> List[str]:
        if wordlist is None:
            wordlist = DEFAULT_SUBDOMAINS
        discovered = []
        for sub in wordlist:
            fqdn = f"{sub}.{domain}"
            try:
                socket.gethostbyname(fqdn)
                discovered.append(fqdn)
            except Exception:
                continue
        return discovered
