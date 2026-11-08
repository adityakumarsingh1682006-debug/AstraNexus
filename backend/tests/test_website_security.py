"""Comprehensive Automated Tests for AstraNexus Website Security Assessor.

Tests safe, passive security posture analysis:
1. HTTP Security Headers (CSP, HSTS, X-Content-Type-Options, Referrer-Policy, Frame Protection)
2. HTTPS & Transport Security
3. Redirect Chain Analysis & Protocol Downgrade Detection
4. Mixed Content (Active vs. Passive)
5. Software Version Disclosure & Known CVE Mapping (without guessing)
6. SSRF Protection & Private IP Blocking on Redirects
7. Risk Engine Score Calibration (hygiene issues must not produce false-positive scam verdicts)
8. Graceful Handling of Unreachable / Malformed Inputs
"""

import pytest
from backend.app.services.scanner.security_assessor import WebsiteSecurityAssessor
from backend.app.services.scanner.risk_engine import RiskEngine
from backend.app.core.security import validate_target_url, is_ip_allowed
from backend.app.core.exceptions import SSRFSecurityViolation


@pytest.fixture
def assessor():
    return WebsiteSecurityAssessor()


@pytest.fixture
def risk_engine():
    return RiskEngine()


# ---------------------------------------------------------------------------
# 1. HTTP Security Headers Tests
# ---------------------------------------------------------------------------

def test_missing_security_headers(assessor):
    """When a website provides zero security headers, all missing header findings are generated."""
    http_data = {
        "final_url": "https://example-bare.com",
        "status_code": 200,
        "headers": {},
        "redirect_hops": [],
        "meta_generator": None,
        "mixed_content": {"active_items": [], "passive_items": []},
    }
    ssl_data = {"is_valid": True, "chain_verified": True}

    assessment = assessor.assess("https://example-bare.com", http_data, ssl_data)

    # Score should be significantly penalized
    assert assessment["score"] < 70
    assert assessment["grade"] in ["C", "D", "F"]

    # Verify headers audit
    sec_headers = assessment["security_headers"]
    assert sec_headers["configured_count"] == 0
    assert sec_headers["missing_count"] == 5

    # Verify specific findings generated
    finding_ids = [f["id"] for f in assessment["findings"]]
    assert "sec-csp-missing" in finding_ids
    assert "sec-hsts-missing" in finding_ids
    assert "sec-xcto-missing" in finding_ids
    assert "sec-frame-protection-missing" in finding_ids
    assert "sec-referrer-policy-missing" in finding_ids

    # Verify structured fields on every finding
    for finding in assessment["findings"]:
        assert finding["title"]
        assert finding["severity"] in ["CRITICAL", "HIGH", "MEDIUM", "LOW", "INFO"]
        assert finding["technical_evidence"] is not None
        assert finding["potential_impact"]
        assert finding["recommended_remediation"]
        assert finding["limitations"]


def test_valid_security_headers_grade_a_plus(assessor):
    """When all recommended security headers are present and valid, website achieves Grade A+."""
    http_data = {
        "final_url": "https://secure-bank.example.com",
        "status_code": 200,
        "headers": {
            "content-security-policy": "default-src 'self'; script-src 'self'; object-src 'none';",
            "strict-transport-security": "max-age=63072000; includeSubDomains; preload",
            "x-content-type-options": "nosniff",
            "referrer-policy": "strict-origin-when-cross-origin",
            "x-frame-options": "DENY",
        },
        "redirect_hops": [],
        "meta_generator": None,
        "mixed_content": {"active_items": [], "passive_items": []},
    }
    ssl_data = {"is_valid": True, "chain_verified": True}

    assessment = assessor.assess("https://secure-bank.example.com", http_data, ssl_data)

    assert assessment["score"] >= 95
    assert assessment["grade"] == "A+"
    assert assessment["security_headers"]["configured_count"] >= 4
    assert assessment["security_headers"]["missing_count"] <= 1

    # Ensure no missing header findings for present headers
    finding_ids = [f["id"] for f in assessment["findings"]]
    assert "sec-csp-missing" not in finding_ids
    assert "sec-hsts-missing" not in finding_ids


# ---------------------------------------------------------------------------
# 2. HTTPS & Transport Security Tests
# ---------------------------------------------------------------------------

def test_insecure_http_transport(assessor):
    """Plain HTTP website triggers HIGH severity unencrypted transport finding."""
    http_data = {
        "final_url": "http://plaintext-blog.example.com",
        "status_code": 200,
        "headers": {},
        "redirect_hops": [],
        "meta_generator": None,
        "mixed_content": {"active_items": [], "passive_items": []},
    }
    ssl_data = None

    assessment = assessor.assess("http://plaintext-blog.example.com", http_data, ssl_data)

    assert assessment["transport_security"]["is_https"] is False
    assert assessment["transport_security"]["status"] == "INSECURE"

    finding_ids = [f["id"] for f in assessment["findings"]]
    assert "sec-transport-unencrypted" in finding_ids

    no_https_finding = next(f for f in assessment["findings"] if f["id"] == "sec-transport-unencrypted")
    assert no_https_finding["severity"] == "HIGH"
    assert "TLS" in no_https_finding["recommended_remediation"]


def test_invalid_tls_certificate(assessor):
    """Valid HTTPS URL but invalid/expired TLS certificate produces transport warning."""
    http_data = {
        "final_url": "https://expired-ssl.example.com",
        "status_code": 200,
        "headers": {},
        "redirect_hops": [],
        "meta_generator": None,
        "mixed_content": {"active_items": [], "passive_items": []},
    }
    ssl_data = {
        "is_valid": False,
        "chain_verified": False,
        "error_message": "Certificate expired",
    }

    assessment = assessor.assess("https://expired-ssl.example.com", http_data, ssl_data)

    finding_ids = [f["id"] for f in assessment["findings"]]
    assert "sec-ssl-invalid" in finding_ids

    tls_finding = next(f for f in assessment["findings"] if f["id"] == "sec-ssl-invalid")
    assert tls_finding["severity"] == "HIGH"
    assert "Certificate expired" in tls_finding["technical_evidence"]["reason"]


# ---------------------------------------------------------------------------
# 3. Redirect Analysis & Downgrade Detection Tests
# ---------------------------------------------------------------------------

def test_redirect_protocol_downgrade(assessor):
    """Redirecting from HTTPS to insecure HTTP triggers a HIGH severity protocol downgrade finding."""
    http_data = {
        "final_url": "http://insecure-destination.example.com/login",
        "status_code": 200,
        "headers": {},
        "redirect_hops": [
            {
                "hop_index": 1,
                "status_code": 302,
                "from_url": "https://secure-portal.example.com/auth",
                "to_url": "http://insecure-destination.example.com/login",
                "is_cross_domain": True,
                "is_downgrade": True,
            }
        ],
        "meta_generator": None,
        "mixed_content": {"active_items": [], "passive_items": []},
    }
    ssl_data = {"is_valid": True, "chain_verified": True}

    assessment = assessor.assess("https://secure-portal.example.com/auth", http_data, ssl_data)

    assert assessment["redirect_analysis"]["is_protocol_downgrade"] is True
    assert assessment["redirect_analysis"]["is_cross_domain"] is True
    assert assessment["redirect_analysis"]["redirect_count"] == 1

    finding_ids = [f["id"] for f in assessment["findings"]]
    assert "sec-redirect-downgrade" in finding_ids
    assert "sec-redirect-cross-domain" in finding_ids

    downgrade_finding = next(f for f in assessment["findings"] if f["id"] == "sec-redirect-downgrade")
    assert downgrade_finding["severity"] == "HIGH"


def test_cross_domain_redirect_chain(assessor):
    """Multiple redirects across domains are safely mapped with hop indices."""
    http_data = {
        "final_url": "https://landing-page.com/offer",
        "status_code": 200,
        "headers": {},
        "redirect_hops": [
            {
                "hop_index": 1,
                "status_code": 301,
                "from_url": "https://short.ly/xyz",
                "to_url": "https://track.adnetwork.com/click",
                "is_cross_domain": True,
                "is_downgrade": False,
            },
            {
                "hop_index": 2,
                "status_code": 302,
                "from_url": "https://track.adnetwork.com/click",
                "to_url": "https://landing-page.com/offer",
                "is_cross_domain": True,
                "is_downgrade": False,
            },
        ],
        "meta_generator": None,
        "mixed_content": {"active_items": [], "passive_items": []},
    }
    ssl_data = {"is_valid": True, "chain_verified": True}

    assessment = assessor.assess("https://short.ly/xyz", http_data, ssl_data)

    assert assessment["redirect_analysis"]["redirect_count"] == 2
    assert assessment["redirect_analysis"]["is_cross_domain"] is True
    assert len(assessment["redirect_analysis"]["hops"]) == 3


# ---------------------------------------------------------------------------
# 4. Mixed Content Detection Tests
# ---------------------------------------------------------------------------

def test_active_and_passive_mixed_content(assessor):
    """Active mixed content generates HIGH severity; passive generates LOW severity."""
    http_data = {
        "final_url": "https://shop.example.com",
        "status_code": 200,
        "headers": {},
        "redirect_hops": [],
        "meta_generator": None,
        "mixed_content": {
            "active_items": ["http://insecure-cdn.com/app.js", "http://insecure-cdn.com/style.css"],
            "passive_items": ["http://insecure-cdn.com/banner.png"],
        },
    }
    ssl_data = {"is_valid": True, "chain_verified": True}

    assessment = assessor.assess("https://shop.example.com", http_data, ssl_data)

    assert assessment["mixed_content"]["detected"] is True
    assert assessment["mixed_content"]["active_mixed_count"] == 2
    assert assessment["mixed_content"]["passive_mixed_count"] == 1

    finding_ids = [f["id"] for f in assessment["findings"]]
    assert "sec-mixed-content-active" in finding_ids
    assert "sec-mixed-content-passive" in finding_ids

    active_f = next(f for f in assessment["findings"] if f["id"] == "sec-mixed-content-active")
    assert active_f["severity"] == "HIGH"

    passive_f = next(f for f in assessment["findings"] if f["id"] == "sec-mixed-content-passive")
    assert passive_f["severity"] == "LOW"


# ---------------------------------------------------------------------------
# 5. Software Exposure & CVE Mapping Tests
# ---------------------------------------------------------------------------

def test_software_version_disclosure_with_cve(assessor):
    """Known vulnerable software version triggers CVE mapping without guessing."""
    http_data = {
        "final_url": "https://vulnerable-server.example.com",
        "status_code": 200,
        "headers": {
            "server": "Apache/2.4.49 (Unix)",
            "x-powered-by": "PHP/7.4.3",
        },
        "redirect_hops": [],
        "meta_generator": "WordPress 5.8",
        "mixed_content": {"active_items": [], "passive_items": []},
    }
    ssl_data = {"is_valid": True, "chain_verified": True}

    assessment = assessor.assess("https://vulnerable-server.example.com", http_data, ssl_data)

    software = assessment["software_exposure"]
    assert software["server_banner"] == "Apache/2.4.49 (Unix)"
    assert software["x_powered_by"] == "PHP/7.4.3"
    assert software["meta_generator"] == "WordPress 5.8"

    # Apache 2.4.49 has known path traversal CVE-2021-41773 in our catalog
    cve_ids = [vuln["cve_id"] for vuln in software["vulnerabilities"]]
    assert "CVE-2021-41773" in cve_ids

    finding_ids = [f["id"] for f in assessment["findings"]]
    assert "sec-cve-cve-2021-41773" in finding_ids


def test_clean_banner_no_guessing(assessor):
    """Generic banners without known vulnerabilities do not map speculative CVEs."""
    http_data = {
        "final_url": "https://modern-app.example.com",
        "status_code": 200,
        "headers": {
            "server": "cloudflare",
        },
        "redirect_hops": [],
        "meta_generator": None,
        "mixed_content": {"active_items": [], "passive_items": []},
    }
    ssl_data = {"is_valid": True, "chain_verified": True}

    assessment = assessor.assess("https://modern-app.example.com", http_data, ssl_data)

    software = assessment["software_exposure"]
    assert len(software["vulnerabilities"]) == 0
    # No speculative vulnerability findings
    for finding in assessment["findings"]:
        assert not finding["id"].startswith("sec-cve-")


# ---------------------------------------------------------------------------
# 6. SSRF Protection on Redirect Hops
# ---------------------------------------------------------------------------

def test_ssrf_validator_blocks_internal_redirects():
    """Ensure internal/loopback IPs are blocked during URL inspection."""
    for blocked_url in [
        "http://127.0.0.1/admin",
        "http://169.254.169.254/latest/meta-data",
        "http://10.0.0.1/internal",
        "http://192.168.1.1/router",
        "http://localhost:8080",
    ]:
        with pytest.raises(SSRFSecurityViolation):
            validate_target_url(blocked_url)

    # Public unicast IP check
    assert is_ip_allowed("8.8.8.8") is True
    assert is_ip_allowed("127.0.0.1") is False


# ---------------------------------------------------------------------------
# 7. Risk Engine Integration Calibration
# ---------------------------------------------------------------------------

def test_missing_headers_do_not_produce_scam_verdict(risk_engine, assessor):
    """Crucial safety test: A benign website lacking security headers must NOT

    be classified as FRAUDULENT or SCAM simply for missing headers.
    """
    http_data = {
        "final_url": "https://small-business.example.com",
        "status_code": 200,
        "headers": {},  # Missing all headers
        "redirect_hops": [],
        "meta_generator": None,
        "mixed_content": {"active_items": [], "passive_items": []},
    }
    ssl_data = {"is_valid": True, "chain_verified": True, "days_until_expiration": 90}

    security_data = assessor.assess("https://small-business.example.com", http_data, ssl_data)

    # Evaluate through RiskEngine with benign telemetry
    result = risk_engine.evaluate(
        target_url="https://small-business.example.com",
        domain="small-business.example.com",
        dns_data={"a_records": ["93.184.216.34"], "has_mx_record": True},
        ssl_data=ssl_data,
        typosquat_data={"is_typosquat": False, "registered_domain": "small-business.example.com"},
        http_data=http_data,
        urlhaus_data={"found": False, "status": "NO_MATCH_FOUND"},
        openphish_data={"found": False, "status": "NO_MATCH_FOUND"},
        website_security_data=security_data,
    )

    # Even with missing headers, the verdict must remain SAFE / LOW RISK / CAUTION
    verdict = result["verdict"]
    verdict_str = verdict.value if hasattr(verdict, "value") else str(verdict)
    assert verdict_str in ["SAFE", "LOW_RISK", "CAUTION"]
    assert verdict_str not in ["FRAUDULENT", "SCAM", "HIGH_RISK", "DANGEROUS"]

    # website_security check must be populated in the result
    assert "website_security" in result["checks"]
    assert result["checks"]["website_security"].name == "Website Security Details"
