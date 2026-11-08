import ssl
import socket
import datetime
from typing import Dict, Any, List, Optional
from cryptography import x509
from cryptography.hazmat.backends import default_backend
from cryptography.x509.oid import NameOID, ExtensionOID


class SSLInspector:
    """
    Forensics engine for TLS/SSL certificates.
    Inspects issuer credibility, validity periods, SANs, and certificate fingerprints.
    """

    def __init__(self, timeout: float = 4.0):
        self.timeout = timeout

    def inspect(self, hostname: str, port: int = 443) -> Dict[str, Any]:
        clean_host = hostname.strip().lower()
        if ":" in clean_host:
            clean_host = clean_host.split(":")[0]

        results: Dict[str, Any] = {
            "has_ssl": False,
            "issuer_common_name": None,
            "issuer_organization": None,
            "subject_common_name": None,
            "subject_organization": None,
            "subject_alt_names": [],
            "valid_from": None,
            "valid_to": None,
            "days_remaining": None,
            "is_expired": False,
            "is_self_signed": False,
            "is_short_lived": False,  # e.g., <= 90 days like automated free certs
            "serial_number": None,
            "fingerprint_sha256": None,
            "cipher_suite": None,
            "tls_version": None,
            "error": None,
        }

        ctx = ssl.create_default_context()
        ctx.check_hostname = False
        ctx.verify_mode = ssl.CERT_NONE  # We want to inspect even invalid/self-signed certs

        try:
            with socket.create_connection((clean_host, port), timeout=self.timeout) as sock:
                with ctx.wrap_socket(sock, server_hostname=clean_host) as ssock:
                    der_cert = ssock.getpeercert(binary_form=True)
                    cipher = ssock.cipher()
                    results["cipher_suite"] = cipher[0] if cipher else None
                    results["tls_version"] = ssock.version()

                    if not der_cert:
                        results["error"] = "No peer certificate presented by server"
                        return results

                    cert = x509.load_der_x509_certificate(der_cert, default_backend())

                    # Subject
                    subject = cert.subject
                    cn_attrs = subject.get_attributes_for_oid(NameOID.COMMON_NAME)
                    org_attrs = subject.get_attributes_for_oid(NameOID.ORGANIZATION_NAME)
                    results["subject_common_name"] = cn_attrs[0].value if cn_attrs else None
                    results["subject_organization"] = org_attrs[0].value if org_attrs else None

                    # Issuer
                    issuer = cert.issuer
                    i_cn = issuer.get_attributes_for_oid(NameOID.COMMON_NAME)
                    i_org = issuer.get_attributes_for_oid(NameOID.ORGANIZATION_NAME)
                    results["issuer_common_name"] = i_cn[0].value if i_cn else None
                    results["issuer_organization"] = i_org[0].value if i_org else None

                    # Self-signed check
                    results["is_self_signed"] = subject == issuer

                    # SANs
                    try:
                        san_ext = cert.extensions.get_extension_for_oid(ExtensionOID.SUBJECT_ALTERNATIVE_NAME)
                        results["subject_alt_names"] = san_ext.value.get_values_for_type(x509.DNSName)
                    except Exception:
                        results["subject_alt_names"] = []

                    # Validity
                    # In cryptography >= 42.0, not_valid_before_utc and not_valid_after_utc are preferred
                    try:
                        not_before = cert.not_valid_before_utc
                        not_after = cert.not_valid_after_utc
                    except AttributeError:
                        not_before = cert.not_valid_before.replace(tzinfo=datetime.timezone.utc)
                        not_after = cert.not_valid_after.replace(tzinfo=datetime.timezone.utc)

                    now = datetime.datetime.now(datetime.timezone.utc)

                    results["valid_from"] = not_before.isoformat()
                    results["valid_to"] = not_after.isoformat()
                    results["is_expired"] = now > not_after

                    remaining_days = (not_after - now).days
                    results["days_remaining"] = remaining_days

                    cert_lifespan_days = (not_after - not_before).days
                    results["is_short_lived"] = cert_lifespan_days <= 90

                    # Serial and Fingerprint
                    results["serial_number"] = hex(cert.serial_number)
                    results["fingerprint_sha256"] = cert.fingerprint(cert.signature_hash_algorithm).hex()
                    results["has_ssl"] = True

        except socket.timeout:
            results["error"] = "TLS connection timed out"
        except ConnectionRefusedError:
            results["error"] = "Connection refused on port 443"
        except Exception as e:
            results["error"] = f"TLS inspection failed: {str(e)}"

        return results


ssl_inspector = SSLInspector()
