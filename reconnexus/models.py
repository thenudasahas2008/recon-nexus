from typing import List, Dict, Optional, Any
from pydantic import BaseModel, Field
from datetime import datetime, timezone

class OpenPort(BaseModel):
    port: int
    state: str = "open"
    service: str = "unknown"
    banner: Optional[str] = None

class CertificateInfo(BaseModel):
    subject: Dict[str, str] = Field(default_factory=dict)
    issuer: Dict[str, str] = Field(default_factory=dict)
    san: List[str] = Field(default_factory=list)
    valid_from: Optional[str] = None
    valid_until: Optional[str] = None
    is_expired: bool = False

class SecurityHeaders(BaseModel):
    has_hsts: bool = False
    has_csp: bool = False
    has_x_frame_options: bool = False
    has_x_content_type_options: bool = False
    missing_headers: List[str] = Field(default_factory=list)

class ReconAsset(BaseModel):
    target: str
    ip_addresses: List[str] = Field(default_factory=list)
    open_ports: List[OpenPort] = Field(default_factory=list)
    tls_certificate: Optional[CertificateInfo] = None
    security_headers: Optional[SecurityHeaders] = None
    server_technologies: List[str] = Field(default_factory=list)
    scanned_at: str = Field(default_factory=lambda: datetime.now(timezone.utc).isoformat())
