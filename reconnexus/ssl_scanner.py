import ssl
import socket
from datetime import datetime
from typing import Optional, Dict
from reconnexus.models import CertificateInfo

class SSLScanner:
    def __init__(self, timeout: float = 2.0):
        self.timeout = timeout

    def inspect_certificate(self, hostname: str, port: int = 443) -> Optional[CertificateInfo]:
        context = ssl.create_default_context()
        context.check_hostname = False
        context.verify_mode = ssl.CERT_NONE

        try:
            with socket.create_connection((hostname, port), timeout=self.timeout) as sock:
                with context.wrap_socket(sock, server_hostname=hostname) as ssock:
                    cert = ssock.getpeercert(binary_form=False)
                    if not cert:
                        return None

                    subject_dict = {}
                    for item in cert.get("subject", []):
                        for k, v in item:
                            subject_dict[k] = v

                    issuer_dict = {}
                    for item in cert.get("issuer", []):
                        for k, v in item:
                            issuer_dict[k] = v

                    sans = [entry[1] for entry in cert.get("subjectAltName", []) if entry[0] == "DNS"]

                    valid_from = cert.get("notBefore")
                    valid_until = cert.get("notAfter")
                    is_expired = False
                    if valid_until:
                        try:
                            expiry_dt = datetime.strptime(valid_until, "%b %d %H:%M:%S %Y %Z")
                            is_expired = datetime.utcnow() > expiry_dt
                        except Exception:
                            pass

                    return CertificateInfo(
                        subject=subject_dict,
                        issuer=issuer_dict,
                        san=sans,
                        valid_from=valid_from,
                        valid_until=valid_until,
                        is_expired=is_expired
                    )
        except Exception:
            return None
