import datetime
import unittest.mock as mock
import pytest
from cryptography import x509
from cryptography.x509.oid import NameOID, ExtensionOID
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.asymmetric import rsa, ec
from cryptography.hazmat.primitives.serialization import Encoding

from backend.app.services.scanner.ssl_inspector import ssl_inspector, SSLInspector
from backend.app.services.scanner.risk_engine import risk_engine
from backend.app.schemas.scan import CheckStatusEnum, ConcernLevel


def create_test_cert_der(
    common_name: str = "example.com",
    issuer_name: str = "Let's Encrypt Authority X3",
    issuer_org: str = "Let's Encrypt",
    sans: list = None,
    days_valid: int = 90,
    is_expired: bool = False,
    is_not_yet_valid: bool = False,
    key_size: int = 2048,
    sig_hash = hashes.SHA256(),
    is_self_signed: bool = False,
) -> bytes:
    """Helper to generate in-memory X.509 DER certificates with exact cryptographic parameters."""
    key = rsa.generate_private_key(65537, key_size)
    subject = x509.Name([
        x509.NameAttribute(NameOID.COMMON_NAME, common_name),
        x509.NameAttribute(NameOID.ORGANIZATION_NAME, "Test Org"),
        x509.NameAttribute(NameOID.COUNTRY_NAME, "US"),
    ])
    
    if is_self_signed:
        issuer = subject
    else:
        issuer = x509.Name([
            x509.NameAttribute(NameOID.COMMON_NAME, issuer_name),
            x509.NameAttribute(NameOID.ORGANIZATION_NAME, issuer_org),
            x509.NameAttribute(NameOID.COUNTRY_NAME, "US"),
        ])

    now = datetime.datetime.now(datetime.timezone.utc)
    if is_expired:
        not_before = now - datetime.timedelta(days=120)
        not_after = now - datetime.timedelta(days=30)
    elif is_not_yet_valid:
        not_before = now + datetime.timedelta(days=10)
        not_after = now + datetime.timedelta(days=100)
    else:
        not_before = now - datetime.timedelta(days=10)
        not_after = now + datetime.timedelta(days=days_valid)

    builder = (
        x509.CertificateBuilder()
        .subject_name(subject)
        .issuer_name(issuer)
        .public_key(key.public_key())
        .serial_number(x509.random_serial_number())
        .not_valid_before(not_before)
        .not_valid_after(not_after)
    )

    san_list = sans if sans is not None else [common_name]
    if san_list:
        dns_names = [x509.DNSName(s) for s in san_list]
        builder = builder.add_extension(
            x509.SubjectAlternativeName(dns_names),
            critical=False,
        )

    cert = builder.sign(key, sig_hash)
    return cert.public_bytes(Encoding.DER)


def test_tls_valid_certificate():
    """Verify inspection of a standard valid certificate."""
    der = create_test_cert_der(
        common_name="secure.example.com",
        issuer_name="DigiCert Global Root G2",
        issuer_org="DigiCert Inc",
        sans=["secure.example.com", "example.com"],
        days_valid=90,
    )

    with mock.patch("socket.create_connection") as mock_conn:
        mock_sock = mock.MagicMock()
        mock_conn.return_value.__enter__.return_value = mock_sock
        with mock.patch("ssl.SSLContext.wrap_socket") as mock_wrap:
            mock_ssock = mock.MagicMock()
            mock_wrap.return_value.__enter__.return_value = mock_ssock
            mock_ssock.getpeercert.side_effect = lambda binary_form=True: der if binary_form else {
                "subject": ((("commonName", "secure.example.com"),),),
                "issuer": ((("organizationName", "DigiCert Inc"),),),
                "subjectAltName": (("DNS", "secure.example.com"), ("DNS", "example.com")),
            }
            mock_ssock.cipher.return_value = ("TLS_AES_256_GCM_SHA384", "TLSv1.3", 256)
            mock_ssock.version.return_value = "TLSv1.3"

            res = ssl_inspector.inspect("secure.example.com")

            assert res["has_ssl"] is True
            assert res["validity_status"] == "VALID"
            assert res["is_expired"] is False
            assert res["hostname_matches"] is True
            assert res["hostname_mismatch"] is False
            assert res["public_key_algorithm"] == "RSA"
            assert res["public_key_size"] == 2048
            assert res["signature_hash_algorithm"] == "SHA256"
            assert res["is_weak_signature"] is False
            assert res["is_weak_key"] is False
            assert res["crypto_security_level"] == "STRONG"
            assert "encrypted" in res["consumer_explanation"]
            assert res["revocation_message"] == "Revocation status could not be verified."


def test_tls_expired_certificate():
    """Verify inspection detects expired certificate."""
    der = create_test_cert_der(
        common_name="expired.badssl.com",
        is_expired=True,
    )

    with mock.patch("socket.create_connection") as mock_conn:
        mock_sock = mock.MagicMock()
        mock_conn.return_value.__enter__.return_value = mock_sock
        with mock.patch("ssl.SSLContext.wrap_socket") as mock_wrap:
            mock_ssock = mock.MagicMock()
            mock_wrap.return_value.__enter__.return_value = mock_ssock
            mock_ssock.getpeercert.return_value = der
            mock_ssock.cipher.return_value = ("ECDHE-RSA-AES128-GCM-SHA256", "TLSv1.2", 128)
            mock_ssock.version.return_value = "TLSv1.2"

            res = ssl_inspector.inspect("expired.badssl.com")

            assert res["has_ssl"] is True
            assert res["is_expired"] is True
            assert res["validity_status"] == "EXPIRED"
            assert "expired on" in res["consumer_explanation"]


def test_tls_hostname_mismatch():
    """Verify inspection identifies certificate issued for a different hostname."""
    der = create_test_cert_der(
        common_name="wrong.host.badssl.com",
        sans=["wrong.host.badssl.com"],
    )

    with mock.patch("socket.create_connection") as mock_conn:
        mock_sock = mock.MagicMock()
        mock_conn.return_value.__enter__.return_value = mock_sock
        with mock.patch("ssl.SSLContext.wrap_socket") as mock_wrap:
            mock_ssock = mock.MagicMock()
            mock_wrap.return_value.__enter__.return_value = mock_ssock
            mock_ssock.getpeercert.return_value = der
            mock_ssock.cipher.return_value = ("TLS_AES_256_GCM_SHA384", "TLSv1.3", 256)
            mock_ssock.version.return_value = "TLSv1.3"

            # Requested host is paypal.com, but certificate is for wrong.host.badssl.com
            res = ssl_inspector.inspect("paypal.com")

            assert res["has_ssl"] is True
            assert res["hostname_matches"] is False
            assert res["hostname_mismatch"] is True
            assert res["validity_status"] == "HOSTNAME_MISMATCH"
            assert "issued for wrong.host.badssl.com, not the address you entered" in res["consumer_explanation"]


def test_tls_invalid_chain_and_self_signed():
    """Verify inspection detects self-signed and untrusted certificates."""
    der = create_test_cert_der(
        common_name="self-signed.local",
        is_self_signed=True,
    )

    with mock.patch("socket.create_connection") as mock_conn:
        mock_sock = mock.MagicMock()
        mock_conn.return_value.__enter__.return_value = mock_sock
        with mock.patch("ssl.SSLContext.wrap_socket") as mock_wrap:
            mock_ssock = mock.MagicMock()
            mock_wrap.return_value.__enter__.return_value = mock_ssock
            mock_ssock.getpeercert.return_value = der
            mock_ssock.cipher.return_value = ("TLS_AES_256_GCM_SHA384", "TLSv1.3", 256)
            mock_ssock.version.return_value = "TLSv1.3"

            res = ssl_inspector.inspect("self-signed.local")

            assert res["has_ssl"] is True
            assert res["is_self_signed"] is True
            assert res["validity_status"] == "SELF_SIGNED"
            assert "untrusted, self-signed" in res["consumer_explanation"]


def test_tls_distrusted_ca():
    """Verify detection of known-distrusted Certificate Authorities (e.g. WoSign)."""
    der = create_test_cert_der(
        common_name="phish-bank.com",
        issuer_name="WoSign Class 3 Server CA",
        issuer_org="WoSign CA Limited",
    )

    with mock.patch("socket.create_connection") as mock_conn:
        mock_sock = mock.MagicMock()
        mock_conn.return_value.__enter__.return_value = mock_sock
        with mock.patch("ssl.SSLContext.wrap_socket") as mock_wrap:
            mock_ssock = mock.MagicMock()
            mock_wrap.return_value.__enter__.return_value = mock_ssock
            mock_ssock.getpeercert.return_value = der
            mock_ssock.cipher.return_value = ("TLS_AES_256_GCM_SHA384", "TLSv1.3", 256)
            mock_ssock.version.return_value = "TLSv1.3"

            res = ssl_inspector.inspect("phish-bank.com")

            assert res["has_ssl"] is True
            assert res["is_distrusted_ca"] is True
            assert "WoSign" in res["distrust_reason"]
            assert res["validity_status"] == "DISTRUSTED_CA"
            assert "globally distrusted" in res["consumer_explanation"]


def test_tls_weak_cryptography():
    """Verify detection of weak cryptographic parameters (e.g. 1024-bit RSA key below recommended 2048 bits)."""
    der = create_test_cert_der(
        common_name="weak-crypto.test",
        key_size=1024,
        sig_hash=hashes.SHA256(),
    )

    with mock.patch("socket.create_connection") as mock_conn:
        mock_sock = mock.MagicMock()
        mock_conn.return_value.__enter__.return_value = mock_sock
        with mock.patch("ssl.SSLContext.wrap_socket") as mock_wrap:
            mock_ssock = mock.MagicMock()
            mock_wrap.return_value.__enter__.return_value = mock_ssock
            mock_ssock.getpeercert.return_value = der
            mock_ssock.cipher.return_value = ("TLS_RSA_WITH_AES_128_CBC_SHA", "TLSv1.2", 128)
            mock_ssock.version.return_value = "TLSv1.2"

            res = ssl_inspector.inspect("weak-crypto.test")

            assert res["has_ssl"] is True
            assert res["is_weak_key"] is True
            assert res["public_key_size"] == 1024
            assert res["crypto_security_level"] == "WEAK"
            assert any("below recommended 2048 bits" in w for w in res["crypto_warnings"])


def test_tls_http_only_url():
    """Verify handling of unencrypted plain HTTP URLs."""
    with mock.patch("socket.create_connection", side_effect=ConnectionRefusedError("Port 443 refused")):
        res = ssl_inspector.inspect("plain-http-site.com", port=80, scheme="http")

        assert res["has_ssl"] is False
        assert res["is_http_only"] is True
        assert res["validity_status"] == "NO_CERTIFICATE"
        assert "does not use encryption (HTTP)" in res["consumer_explanation"]


def test_tls_unreachable_host():
    """Verify handling when host is completely unreachable."""
    with mock.patch("socket.create_connection", side_effect=TimeoutError("Timed out")):
        res = ssl_inspector.inspect("unreachable-host.example")

        assert res["has_ssl"] is False
        assert res["error"] is not None
        assert "timed out" in res["consumer_explanation"].lower()


def test_tls_unavailable_revocation_data():
    """Verify explicit notice when revocation status could not be verified."""
    der = create_test_cert_der(common_name="example.com")

    with mock.patch("socket.create_connection") as mock_conn:
        mock_sock = mock.MagicMock()
        mock_conn.return_value.__enter__.return_value = mock_sock
        with mock.patch("ssl.SSLContext.wrap_socket") as mock_wrap:
            mock_ssock = mock.MagicMock()
            mock_wrap.return_value.__enter__.return_value = mock_ssock
            mock_ssock.getpeercert.return_value = der
            mock_ssock.cipher.return_value = ("TLS_AES_256_GCM_SHA384", "TLSv1.3", 256)
            mock_ssock.version.return_value = "TLSv1.3"

            res = ssl_inspector.inspect("example.com")

            # Mandated requirement: Never claim unrevoked simply because check was skipped/unreachable
            assert res["revocation_status"] == "UNVERIFIED"
            assert res["revocation_message"] == "Revocation status could not be verified."


def test_risk_engine_integration_with_tls():
    """Verify risk engine responds appropriately to suspicious TLS findings."""
    dns_clean = {"a_records": ["93.184.216.34"]}
    typo_clean = {"registered_domain": "example.com", "subdomain": "", "is_brand_impersonation": False}
    http_clean = {"has_password_form": False, "redirect_chain": []}
    feed_clean = {"found": False}

    # Case A: Expired Certificate
    ssl_expired = {
        "has_ssl": True,
        "is_expired": True,
        "valid_to": "2026-01-01T00:00:00Z",
        "validity_status": "EXPIRED",
        "chain_verified": True,
    }
    res_a = risk_engine.evaluate("https://example.com", "example.com", dns_clean, ssl_expired, typo_clean, http_clean, feed_clean, feed_clean)
    assert any(c.id == "expired-cert" for c in res_a["concerns"])
    assert res_a["checks"]["tls_certificate"].status == CheckStatusEnum.SUSPICIOUS_FINDING

    # Case B: Hostname Mismatch
    ssl_mismatch = {
        "has_ssl": True,
        "hostname_mismatch": True,
        "subject_common_name": "chase-phish.net",
        "validity_status": "HOSTNAME_MISMATCH",
        "chain_verified": True,
    }
    res_b = risk_engine.evaluate("https://example.com", "example.com", dns_clean, ssl_mismatch, typo_clean, http_clean, feed_clean, feed_clean)
    assert any(c.id == "hostname-mismatch" for c in res_b["concerns"])
    assert res_b["risk_score"] >= 30

    # Case C: Distrusted CA
    ssl_distrusted = {
        "has_ssl": True,
        "is_distrusted_ca": True,
        "distrust_reason": "WoSign roots were distrusted globally in 2016-2017.",
        "issuer_organization": "WoSign CA Limited",
        "validity_status": "DISTRUSTED_CA",
    }
    res_c = risk_engine.evaluate("https://example.com", "example.com", dns_clean, ssl_distrusted, typo_clean, http_clean, feed_clean, feed_clean)
    assert any(c.id == "distrusted-ca" for c in res_c["concerns"])
    assert res_c["risk_score"] >= 40
