import pytest
from backend.app.core.security import is_ip_allowed, validate_target_url
from backend.app.core.exceptions import SSRFSecurityViolation


def test_private_ips_blocked():
    """Ensure RFC 1918 and loopback IPs are strictly forbidden."""
    private_test_ips = [
        "127.0.0.1",
        "127.0.1.1",
        "10.0.0.1",
        "10.254.254.254",
        "172.16.0.1",
        "172.31.255.255",
        "192.168.1.1",
        "192.168.100.254",
        "169.254.169.254",  # Cloud metadata IP
        "0.0.0.0",
        "255.255.255.255",
        "::1",              # IPv6 loopback
        "fe80::1",          # IPv6 link-local
    ]

    for ip in private_test_ips:
        assert not is_ip_allowed(ip), f"Expected {ip} to be blocked by SSRF filter"


def test_public_ips_allowed():
    """Ensure standard public unicast IPs are allowed."""
    public_test_ips = [
        "8.8.8.8",
        "1.1.1.1",
        "93.184.216.34",
    ]

    for ip in public_test_ips:
        assert is_ip_allowed(ip), f"Expected {ip} to be permitted"


def test_validate_target_url_blocks_metadata_probe():
    """Ensure AWS/GCP metadata endpoint is immediately blocked."""
    metadata_url = "http://169.254.169.254/latest/meta-data/"
    with pytest.raises(SSRFSecurityViolation) as exc_info:
        validate_target_url(metadata_url)
    assert "restricted" in str(exc_info.value).lower() or "ssrf" in str(exc_info.value).lower()


def test_validate_target_url_blocks_localhost():
    """Ensure localhost loopback URL is blocked."""
    localhost_url = "http://localhost:8000/api"
    with pytest.raises(SSRFSecurityViolation):
        validate_target_url(localhost_url)


def test_validate_target_url_blocks_invalid_scheme():
    """Ensure non-HTTP schemes are rejected."""
    bad_scheme_url = "file:///etc/passwd"
    with pytest.raises(SSRFSecurityViolation):
        validate_target_url(bad_scheme_url)
