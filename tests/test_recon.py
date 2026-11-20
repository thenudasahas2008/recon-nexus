import pytest
from reconnexus.models import ReconAsset, OpenPort, SecurityHeaders
from reconnexus.dns_scanner import DNSResolver

def test_asset_model_serialization():
    asset = ReconAsset(
        target="internal-sec.test",
        ip_addresses=["10.0.0.1"],
        open_ports=[OpenPort(port=443, service="HTTPS", banner="nginx/1.24")],
        security_headers=SecurityHeaders(has_hsts=True, has_csp=False, missing_headers=["Content-Security-Policy"])
    )
    assert asset.target == "internal-sec.test"
    assert len(asset.open_ports) == 1
    assert asset.open_ports[0].port == 443
    assert asset.security_headers.has_hsts is True
    assert asset.security_headers.has_csp is False

def test_dns_resolver_empty_on_invalid():
    ips = DNSResolver.resolve_target("invalid-non-existent-domain-99999999.xyz")
    assert isinstance(ips, list)
    assert len(ips) == 0
