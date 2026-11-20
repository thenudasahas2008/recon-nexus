import urllib.request
import urllib.error
from typing import Tuple, List, Optional
from reconnexus.models import SecurityHeaders

class HTTPFingerprinter:
    def __init__(self, timeout: float = 2.5):
        self.timeout = timeout

    def analyze_headers(self, target_url: str) -> Tuple[SecurityHeaders, List[str]]:
        if not target_url.startswith("http://") and not target_url.startswith("https://"):
            target_url = f"https://{target_url}"

        technologies: List[str] = []
        sec_headers = SecurityHeaders()
        missing = []

        req = urllib.request.Request(
            target_url,
            headers={"User-Agent": "Mozilla/5.0 (ReconNexus-Security-Scanner/1.0)"}
        )

        try:
            with urllib.request.urlopen(req, timeout=self.timeout) as resp:
                headers = dict(resp.headers)
        except urllib.error.HTTPError as e:
            headers = dict(e.headers)
        except Exception:
            return sec_headers, technologies

        # Server banner
        server = headers.get("Server") or headers.get("server")
        if server:
            technologies.append(f"Server: {server}")

        powered_by = headers.get("X-Powered-By") or headers.get("x-powered-by")
        if powered_by:
            technologies.append(f"X-Powered-By: {powered_by}")

        # Security Headers check
        hsts = headers.get("Strict-Transport-Security") or headers.get("strict-transport-security")
        if hsts:
            sec_headers.has_hsts = True
        else:
            missing.append("Strict-Transport-Security")

        csp = headers.get("Content-Security-Policy") or headers.get("content-security-policy")
        if csp:
            sec_headers.has_csp = True
        else:
            missing.append("Content-Security-Policy")

        x_frame = headers.get("X-Frame-Options") or headers.get("x-frame-options")
        if x_frame:
            sec_headers.has_x_frame_options = True
        else:
            missing.append("X-Frame-Options")

        x_content = headers.get("X-Content-Type-Options") or headers.get("x-content-type-options")
        if x_content:
            sec_headers.has_x_content_type_options = True
        else:
            missing.append("X-Content-Type-Options")

        sec_headers.missing_headers = missing
        return sec_headers, technologies
