import ssl
import socket
import datetime
import logging
from typing import Dict, Any, List, Optional, Tuple
from urllib.parse import urlparse

import certifi
from cryptography import x509
from cryptography.hazmat.backends import default_backend
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.asymmetric import rsa, ec, ed25519, dsa
from cryptography.x509.oid import NameOID, ExtensionOID, AuthorityInformationAccessOID
from cryptography.x509 import ocsp

from backend.app.core.security import is_ip_allowed

logger = logging.getLogger(__name__)

# Registry of documented known-distrusted or compromised Certificate Authorities
# Citations: Mozilla Root Store Policy, Google Chrome Root CA Policy, Apple Root Certificate Policy
DISTRUSTED_CA_PATTERNS: Dict[str, str] = {
    "wosign": "WoSign roots were distrusted globally by Apple, Mozilla, and Google in 2016-2017 after backdating SHA-1 certificates and unnotified control changes.",
    "guangdong wosign": "WoSign intermediate and root authorities were distrusted globally in 2016-2017.",
    "startcom": "StartCom/StartSSL roots were distrusted globally by Apple, Mozilla, and Google in 2016-2017 due to operational irregularities and shared ownership with WoSign.",
    "startssl": "StartSSL roots were distrusted globally by major browser vendors in 2016-2017.",
    "diginotar": "DigiNotar was distrusted globally in 2011 after a major intrusion resulting in fraudulent wildcard certificates for high-profile domains.",
    "cnnic": "CNNIC was distrusted by Google and Mozilla in 2015 following unauthorized intermediate CA issuance used for man-in-the-middle attacks.",
    "darkmatter": "DarkMatter was denied inclusion and distrusted by Mozilla, Apple, and Google in 2019-2022 following security and human rights risk assessments.",
    "trustcor": "TrustCor Systems roots were removed from Mozilla, Chrome, and Apple root stores in 2022 due to lack of operational transparency and surveillance affiliations.",
    "equifax secure certificate authority": "Legacy Equifax / Symantec root distrusted by Chrome 70 and Mozilla 63 in 2018.",
    "geotrust global ca": "Legacy GeoTrust / Symantec root distrusted by modern browsers in 2018 following CA deprecation.",
    "thawte premium server ca": "Legacy Thawte / Symantec root distrusted by modern browsers in 2018 following CA deprecation.",
}


class SSLInspector:
    """
    Comprehensive Forensics & Digital Trust Engine for TLS/SSL Certificates.
    Evaluates:
    - Certificate validity periods and expiration
    - Hostname matching and Subject Alternative Names (SANs)
    - Certificate Authority credibility and known distrust indicators
    - Cryptographic key strength, curves, and signature hashing algorithms
    - Certificate Transparency (Embedded SCTs)
    - Revocation indicators (OCSP / CRL) with strict unavailable notices
    - SSRF isolation and plain-HTTP containment
    """

    def __init__(self, timeout: float = 4.0):
        self.timeout = timeout

    def inspect(
        self,
        hostname: str,
        port: int = 443,
        scheme: str = "https",
        pre_resolved_ips: Optional[List[str]] = None,
    ) -> Dict[str, Any]:
        """
        Inspects the TLS certificate of the target host.
        Never fabricates certificate data. Preserves partial results when individual checks fail.
        """
        clean_host = hostname.strip().lower()
        if ":" in clean_host:
            clean_host = clean_host.split(":")[0]

        # Standard baseline response structure
        results: Dict[str, Any] = {
            "has_ssl": False,
            "is_http_only": scheme.lower() == "http",
            "validity_status": "NO_CERTIFICATE",
            # 1. Validity details
            "valid_from": None,
            "valid_to": None,
            "days_remaining": None,
            "is_expired": False,
            "not_yet_valid": False,
            "is_short_lived": False,
            "hostname_matches": False,
            "hostname_mismatch": False,
            "matched_name": None,
            "requested_hostname": clean_host,
            "subject_alt_names": [],
            # 2. Authority & Chain details
            "issuer_common_name": None,
            "issuer_organization": None,
            "issuer_country": None,
            "subject_common_name": None,
            "subject_organization": None,
            "subject_country": None,
            "is_self_signed": False,
            "chain_verified": False,
            "verification_error": None,
            "ca_issuers": [],
            "is_distrusted_ca": False,
            "distrust_reason": None,
            # 3. Cryptographic Security
            "public_key_algorithm": None,
            "public_key_size": None,
            "ec_curve": None,
            "signature_algorithm": None,
            "signature_hash_algorithm": None,
            "is_weak_signature": False,
            "is_weak_key": False,
            "crypto_security_level": "UNKNOWN",
            "crypto_warnings": [],
            # 4. Certificate Transparency
            "has_embedded_scts": False,
            "embedded_scts_count": 0,
            "ct_status": "UNVERIFIED",
            "ct_details": {},
            # 5. Revocation & Distrust
            "ocsp_urls": [],
            "crl_urls": [],
            "revocation_status": "UNVERIFIED",
            "revocation_message": "Revocation status could not be verified.",
            # 6. Consumer Explanation & Identifiers
            "consumer_explanation": "This website does not provide an encrypted connection (HTTP).",
            "serial_number": None,
            "fingerprint_sha256": None,
            "fingerprint_sha1": None,
            "cipher_suite": None,
            "tls_version": None,
            "error": None,
        }

        # -------------------------------------------------------------
        # 1. SSRF Quarantine Check
        # -------------------------------------------------------------
        # If pre-resolved IPs were supplied, verify all are public/safe
        if pre_resolved_ips:
            for ip in pre_resolved_ips:
                if not is_ip_allowed(ip):
                    results["error"] = f"SSRF blocked: Host resolves to private/reserved IP ({ip})"
                    results["consumer_explanation"] = "Security check blocked: This destination points to a private internal network."
                    return results

        # -------------------------------------------------------------
        # 2. Plain HTTP Check
        # -------------------------------------------------------------
        # If the target URL is strictly HTTP and port 443 fails to connect,
        # return unencrypted HTTP status cleanly without error crash.
        if scheme.lower() == "http" and port == 80:
            # Check if port 443 has TLS available
            port = 443

        # -------------------------------------------------------------
        # 3. Step 1: Strict Verification TLS Handshake
        # -------------------------------------------------------------
        # Attempt connection with standard root CA verification enabled
        der_cert: Optional[bytes] = None
        dict_cert: Optional[Dict[str, Any]] = None
        cipher: Optional[Tuple[str, str, int]] = None
        tls_ver: Optional[str] = None
        verification_error: Optional[str] = None

        strict_ctx = ssl.create_default_context(cafile=certifi.where())
        strict_ctx.check_hostname = True
        strict_ctx.verify_mode = ssl.CERT_REQUIRED

        try:
            with socket.create_connection((clean_host, port), timeout=self.timeout) as sock:
                with strict_ctx.wrap_socket(sock, server_hostname=clean_host) as ssock:
                    der_cert = ssock.getpeercert(binary_form=True)
                    dict_cert = ssock.getpeercert(binary_form=False)
                    cipher = ssock.cipher()
                    tls_ver = ssock.version()
                    results["chain_verified"] = True
                    results["hostname_matches"] = True
        except ssl.SSLCertVerificationError as e:
            verification_error = f"Certificate verification failed: {e.verify_message} (Code {e.verify_code})"
            results["chain_verified"] = False
            results["verification_error"] = verification_error
        except ssl.CertificateError as e:
            verification_error = f"Hostname mismatch: {str(e)}"
            results["chain_verified"] = False
            results["hostname_mismatch"] = True
            results["verification_error"] = verification_error
        except (socket.timeout, TimeoutError):
            results["error"] = "TLS connection timed out"
            results["consumer_explanation"] = "Connection timed out while checking the website's security certificate."
            return results
        except (ConnectionRefusedError, OSError) as e:
            if scheme.lower() == "http":
                results["is_http_only"] = True
                results["has_ssl"] = False
                results["consumer_explanation"] = "This website does not use encryption (HTTP). Any information you enter could be intercepted."
                return results
            results["error"] = f"Unable to establish TLS connection: {str(e)}"
            results["consumer_explanation"] = "Could not establish an encrypted connection to this host."
            return results
        except Exception as e:
            verification_error = f"TLS handshake issue: {str(e)}"
            results["chain_verified"] = False
            results["verification_error"] = verification_error

        # -------------------------------------------------------------
        # 4. Step 2: Unverified Fallback (Extract Leaf Data if Handshake Failed)
        # -------------------------------------------------------------
        # If strict verification failed, connect with unverified context
        # ONLY to inspect the peer certificate DER for forensic analysis.
        if der_cert is None:
            unverified_ctx = ssl.create_default_context()
            unverified_ctx.check_hostname = False
            unverified_ctx.verify_mode = ssl.CERT_NONE
            try:
                with socket.create_connection((clean_host, port), timeout=self.timeout) as sock:
                    with unverified_ctx.wrap_socket(sock, server_hostname=clean_host) as ssock:
                        der_cert = ssock.getpeercert(binary_form=True)
                        cipher = ssock.cipher()
                        tls_ver = ssock.version()
            except Exception as e:
                if scheme.lower() == "http":
                    results["is_http_only"] = True
                    results["has_ssl"] = False
                    results["consumer_explanation"] = "This website does not use encryption (HTTP). Any information you enter could be intercepted."
                    return results
                results["error"] = f"TLS connection failed: {str(e)}"
                results["consumer_explanation"] = "Could not establish an encrypted connection to this host."
                return results

        if not der_cert:
            results["error"] = "No peer certificate presented by server"
            results["consumer_explanation"] = "The server did not present a digital security certificate."
            return results

        # -------------------------------------------------------------
        # 5. Parse Certificate with Cryptography Engine
        # -------------------------------------------------------------
        try:
            cert = x509.load_der_x509_certificate(der_cert, default_backend())
        except Exception as e:
            results["error"] = f"Failed to parse X.509 certificate: {str(e)}"
            return results

        results["has_ssl"] = True
        results["cipher_suite"] = cipher[0] if cipher else None
        results["tls_version"] = tls_ver

        # Subject Details
        subject = cert.subject
        cn_attrs = subject.get_attributes_for_oid(NameOID.COMMON_NAME)
        org_attrs = subject.get_attributes_for_oid(NameOID.ORGANIZATION_NAME)
        country_attrs = subject.get_attributes_for_oid(NameOID.COUNTRY_NAME)
        results["subject_common_name"] = cn_attrs[0].value if cn_attrs else None
        results["subject_organization"] = org_attrs[0].value if org_attrs else None
        results["subject_country"] = country_attrs[0].value if country_attrs else None

        # Issuer Details
        issuer = cert.issuer
        i_cn = issuer.get_attributes_for_oid(NameOID.COMMON_NAME)
        i_org = issuer.get_attributes_for_oid(NameOID.ORGANIZATION_NAME)
        i_country = issuer.get_attributes_for_oid(NameOID.COUNTRY_NAME)
        results["issuer_common_name"] = i_cn[0].value if i_cn else None
        results["issuer_organization"] = i_org[0].value if i_org else None
        results["issuer_country"] = i_country[0].value if i_country else None

        # Self-signed check
        results["is_self_signed"] = subject == issuer

        # Serial number and fingerprints
        results["serial_number"] = hex(cert.serial_number)
        results["fingerprint_sha256"] = cert.fingerprint(hashes.SHA256()).hex()
        results["fingerprint_sha1"] = cert.fingerprint(hashes.SHA1()).hex()

        # Subject Alternative Names (SANs)
        sans: List[str] = []
        try:
            san_ext = cert.extensions.get_extension_for_oid(ExtensionOID.SUBJECT_ALTERNATIVE_NAME)
            for name in san_ext.value:
                if isinstance(name, x509.DNSName):
                    sans.append(name.value.lower())
                elif isinstance(name, x509.IPAddress):
                    sans.append(str(name.value))
        except Exception:
            sans = []
        results["subject_alt_names"] = sans

        # Hostname Matching
        matched, matched_name = self._verify_hostname_match(clean_host, results["subject_common_name"], sans)
        results["hostname_matches"] = matched
        results["hostname_mismatch"] = not matched
        results["matched_name"] = matched_name

        # Validity Dates
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
        results["not_yet_valid"] = now < not_before
        remaining_days = (not_after - now).days
        results["days_remaining"] = remaining_days
        results["is_short_lived"] = (not_after - not_before).days <= 90

        # Cryptographic Key Inspection
        self._inspect_cryptography(cert, results)

        # Distrusted CA Inspection
        self._check_distrusted_ca(results)

        # Certificate Transparency (Embedded SCTs)
        self._check_certificate_transparency(cert, results)

        # Revocation (OCSP & CRL)
        self._check_revocation(cert, results)

        # Determine Overall Validity Status
        if results["is_expired"]:
            results["validity_status"] = "EXPIRED"
        elif results["not_yet_valid"]:
            results["validity_status"] = "NOT_YET_VALID"
        elif results["is_distrusted_ca"]:
            results["validity_status"] = "DISTRUSTED_CA"
        elif results["is_self_signed"]:
            results["validity_status"] = "SELF_SIGNED"
        elif results["hostname_mismatch"]:
            results["validity_status"] = "HOSTNAME_MISMATCH"
        elif not results["chain_verified"]:
            results["validity_status"] = "UNTRUSTED_CHAIN"
        else:
            results["validity_status"] = "VALID"

        # Generate Consumer-Friendly Explanation
        results["consumer_explanation"] = self._generate_consumer_explanation(results)

        return results

    def _verify_hostname_match(
        self,
        target_hostname: str,
        common_name: Optional[str],
        sans: List[str]
    ) -> Tuple[bool, Optional[str]]:
        """
        Validates target hostname against SANs and CN per RFC 6125 with wildcard support.
        """
        target = target_hostname.lower().strip()
        candidates = [s.lower().strip() for s in sans]
        if common_name and common_name.lower().strip() not in candidates:
            candidates.append(common_name.lower().strip())

        for cand in candidates:
            if cand == target:
                return True, cand
            # Wildcard matching (e.g. *.example.com matches sub.example.com)
            if cand.startswith("*."):
                suffix = cand[2:]
                target_parts = target.split(".")
                suffix_parts = suffix.split(".")
                if len(target_parts) == len(suffix_parts) + 1:
                    if target.endswith("." + suffix):
                        return True, cand

        return False, None

    def _inspect_cryptography(self, cert: x509.Certificate, results: Dict[str, Any]) -> None:
        """
        Inspects public key algorithm, size, signature hashing, and weak/deprecated parameters.
        """
        warnings: List[str] = []
        pubkey = cert.public_key()

        if isinstance(pubkey, rsa.RSAPublicKey):
            results["public_key_algorithm"] = "RSA"
            results["public_key_size"] = pubkey.key_size
            if pubkey.key_size < 2048:
                results["is_weak_key"] = True
                warnings.append(f"RSA key size ({pubkey.key_size} bits) is below recommended 2048 bits")
        elif isinstance(pubkey, ec.EllipticCurvePublicKey):
            results["public_key_algorithm"] = "EC"
            results["public_key_size"] = pubkey.key_size
            results["ec_curve"] = pubkey.curve.name
            if pubkey.key_size < 256:
                results["is_weak_key"] = True
                warnings.append(f"EC key size ({pubkey.key_size} bits) is below recommended 256 bits")
        elif isinstance(pubkey, ed25519.Ed25519PublicKey):
            results["public_key_algorithm"] = "Ed25519"
            results["public_key_size"] = 256
        elif isinstance(pubkey, dsa.DSAPublicKey):
            results["public_key_algorithm"] = "DSA"
            results["public_key_size"] = pubkey.key_size
            results["is_weak_key"] = True
            warnings.append("DSA public key algorithm is deprecated")
        else:
            results["public_key_algorithm"] = type(pubkey).__name__
            results["public_key_size"] = getattr(pubkey, "key_size", None)

        # Signature algorithm & hash
        try:
            results["signature_algorithm"] = cert.signature_algorithm_oid._name
        except Exception:
            results["signature_algorithm"] = cert.signature_algorithm_oid.dotted_string

        sig_hash = getattr(cert, "signature_hash_algorithm", None)
        if sig_hash:
            hash_name = sig_hash.name.upper()
            results["signature_hash_algorithm"] = hash_name
            if hash_name in ("MD5", "SHA1"):
                results["is_weak_signature"] = True
                warnings.append(f"Deprecated signature hash algorithm ({hash_name}) vulnerable to collision attacks")
        else:
            results["signature_hash_algorithm"] = "PURE_ED25519"

        # Crypto security rating
        if results["is_weak_signature"] or results["is_weak_key"]:
            results["crypto_security_level"] = "WEAK"
        elif results["public_key_algorithm"] in ("EC", "Ed25519") or (results["public_key_size"] and results["public_key_size"] >= 2048):
            results["crypto_security_level"] = "STRONG"
        else:
            results["crypto_security_level"] = "ACCEPTABLE"

        results["crypto_warnings"] = warnings

    def _check_distrusted_ca(self, results: Dict[str, Any]) -> None:
        """
        Cross-references certificate issuer details against documented known-distrusted CAs.
        """
        issuer_text = f"{results.get('issuer_organization') or ''} {results.get('issuer_common_name') or ''}".lower()

        for pattern, reason in DISTRUSTED_CA_PATTERNS.items():
            if pattern in issuer_text:
                results["is_distrusted_ca"] = True
                results["distrust_reason"] = reason
                return

    def _check_certificate_transparency(self, cert: x509.Certificate, results: Dict[str, Any]) -> None:
        """
        Inspects embedded Signed Certificate Timestamps (SCTs) per RFC 6962.
        """
        scts_count = 0
        # Check Precertificate SCTs (OID 1.3.6.1.4.1.11129.2.4.2)
        try:
            precert_sct_ext = cert.extensions.get_extension_for_oid(ExtensionOID.PRECERT_SIGNED_CERTIFICATE_TIMESTAMPS)
            scts_count += len(precert_sct_ext.value)
        except Exception:
            pass

        # Check Certificate SCTs (OID 1.3.6.1.4.1.11129.2.4.5)
        try:
            cert_sct_ext = cert.extensions.get_extension_for_oid(ExtensionOID.SIGNED_CERTIFICATE_TIMESTAMPS)
            scts_count += len(cert_sct_ext.value)
        except Exception:
            pass

        results["embedded_scts_count"] = scts_count
        results["has_embedded_scts"] = scts_count > 0

        if scts_count > 0:
            results["ct_status"] = "EMBEDDED_SCTS_PRESENT"
            results["ct_details"] = {
                "embedded_scts": scts_count,
                "transparency_policy": "Compliant with public audit log requirements (RFC 6962)",
            }
        else:
            results["ct_status"] = "NO_EMBEDDED_SCTS"
            results["ct_details"] = {
                "embedded_scts": 0,
                "transparency_policy": "No embedded SCTs detected in leaf certificate",
            }

    def _check_revocation(self, cert: x509.Certificate, results: Dict[str, Any]) -> None:
        """
        Extracts Authority Information Access (AIA OCSP) and CRL Distribution Points.
        If revocation checking cannot be definitively completed, explicitly records
        'Revocation status could not be verified'. Never claims safe simply because check failed.
        """
        ocsp_urls: List[str] = []
        ca_issuers: List[str] = []
        crl_urls: List[str] = []

        # Extract AIA (OCSP and caIssuers)
        try:
            aia_ext = cert.extensions.get_extension_for_oid(ExtensionOID.AUTHORITY_INFORMATION_ACCESS)
            for desc in aia_ext.value:
                if desc.access_method == AuthorityInformationAccessOID.OCSP:
                    uri = getattr(desc.access_location, "value", None)
                    if uri and uri.startswith("http"):
                        ocsp_urls.append(uri)
                elif desc.access_method == AuthorityInformationAccessOID.CA_ISSUERS:
                    uri = getattr(desc.access_location, "value", None)
                    if uri and uri.startswith("http"):
                        ca_issuers.append(uri)
        except Exception:
            pass

        # Extract CRL Distribution Points
        try:
            crl_ext = cert.extensions.get_extension_for_oid(ExtensionOID.CRL_DISTRIBUTION_POINTS)
            for dp in crl_ext.value:
                if dp.full_name:
                    for name in dp.full_name:
                        uri = getattr(name, "value", None)
                        if uri and uri.startswith("http"):
                            crl_urls.append(uri)
        except Exception:
            pass

        results["ocsp_urls"] = ocsp_urls
        results["ca_issuers"] = ca_issuers
        results["crl_urls"] = crl_urls

        # As mandated by Task 1 rule 5:
        # If revocation cannot be verified via active online OCSP or CRL cache,
        # explicitly display 'Revocation status could not be verified.'
        # Never claim a certificate is not revoked simply because the check was skipped or failed.
        results["revocation_status"] = "UNVERIFIED"
        results["revocation_message"] = "Revocation status could not be verified."

    def _generate_consumer_explanation(self, results: Dict[str, Any]) -> str:
        """
        Generates ordinary consumer-friendly explanation according to Task 1 specifications.
        """
        if results.get("is_http_only") or not results.get("has_ssl"):
            return "This website does not use encryption (HTTP). Any information you enter could be intercepted."

        status = results.get("validity_status")

        if status == "EXPIRED":
            return f"This website's security certificate expired on {results.get('valid_to', 'unknown date')}."
        if status == "NOT_YET_VALID":
            return f"This website's security certificate is not yet valid (starts on {results.get('valid_from', 'unknown date')})."
        if status == "HOSTNAME_MISMATCH":
            matched = results.get("subject_common_name") or "another domain"
            return f"This website's security certificate was issued for {matched}, not the address you entered. This may indicate an impersonation attempt."
        if status == "SELF_SIGNED":
            return "This website uses an untrusted, self-signed security certificate. Standard web browsers will block this connection."
        if status == "DISTRUSTED_CA":
            return "This website's security certificate was issued by a Certificate Authority that has been globally distrusted by web browsers."
        if status == "UNTRUSTED_CHAIN":
            return "The certificate authority that issued this security certificate is not recognized or trusted by standard security systems."
        if status == "VALID":
            return "Your connection to this website is encrypted, but this does not guarantee the website is legitimate."

        return "Your connection to this website is encrypted, but this does not guarantee the website is legitimate."


ssl_inspector = SSLInspector()
