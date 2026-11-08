import asyncio
import pytest
from backend.app.services.scanner.typosquat import typosquat_detector
from backend.app.services.scanner.risk_engine import risk_engine
from backend.app.schemas.scan import RiskVerdict, URLScanRequest, CheckStatusEnum, ConcernLevel
from backend.app.api.v1.endpoints.scan import scan_url


def test_case_a_paypal_subdomain_on_example_domain():
    """
    TEST A:
    Input: http://paypal.com.security-check.example.com/login
    Expected: Suspicious due to misleading brand subdomain.
    The scanner MUST identify suspicious URL structures even when DNS fails or domain is synthetic.
    """
    target = "http://paypal.com.security-check.example.com/login"

    # Step 1: Verify PSL domain parsing and brand detection
    typo_res = typosquat_detector.analyze(target)
    assert typo_res["registered_domain"] == "example.com"
    assert "paypal.com" in typo_res["subdomain"]
    assert typo_res["is_impersonation"] is True
    assert typo_res["impersonated_brand"] == "PayPal"
    assert typo_res["brand_in_subdomain"] is True
    assert "MISLEADING_BRAND_SUBDOMAIN" in typo_res["techniques"]

    # Step 2: Verify Risk Engine handles this case (even if DNS fails)
    dns_unavailable = {"error": "DNS resolution failed: NXDOMAIN", "a_records": []}
    ssl_unavailable = {"has_ssl": False, "error": "DNS resolution failed"}
    http_unavailable = {"error": "DNS resolution failed"}
    urlhaus_clean = {"found": False}
    openphish_clean = {"found": False}

    evaluation = risk_engine.evaluate(
        target_url=target,
        domain="paypal.com.security-check.example.com",
        dns_data=dns_unavailable,
        ssl_data=ssl_unavailable,
        typosquat_data=typo_res,
        http_data=http_unavailable,
        urlhaus_data=urlhaus_clean,
        openphish_data=openphish_clean,
    )

    assert evaluation["verdict"] in (RiskVerdict.SUSPICIOUS, RiskVerdict.HIGH_RISK)
    assert evaluation["verdict"] == RiskVerdict.SUSPICIOUS
    assert any("PayPal" in t for t in evaluation["threat_types"])

    # Verify structured concerns
    concerns = evaluation["concerns"]
    assert any(c.category == "BRAND_IMPERSONATION" for c in concerns)
    assert any(c.concern_level == ConcernLevel.HIGH_CONCERN for c in concerns)

    # Verify checks transparency
    checks = evaluation["checks"]
    assert checks["brand_impersonation"].status == CheckStatusEnum.SUSPICIOUS_FINDING
    assert checks["dns_resolution"].status == CheckStatusEnum.UNAVAILABLE


def test_case_b_example_com_clean():
    """
    TEST B:
    Input: https://example.com
    Expected: Low Risk, assuming available checks pass.
    """
    target = "https://example.com"
    typo_res = typosquat_detector.analyze(target)
    assert typo_res["registered_domain"] == "example.com"
    assert typo_res["is_impersonation"] is False

    dns_clean = {"a_records": ["93.184.216.34"], "resolution_time_ms": 25.0}
    ssl_clean = {"has_ssl": True, "issuer_organization": "DigiCert Inc", "days_remaining": 120}
    http_clean = {"status_code": 200, "redirect_count": 0, "has_password_form": False}
    urlhaus_clean = {"found": False}
    openphish_clean = {"found": False}

    evaluation = risk_engine.evaluate(
        target_url=target,
        domain="example.com",
        dns_data=dns_clean,
        ssl_data=ssl_clean,
        typosquat_data=typo_res,
        http_data=http_clean,
        urlhaus_data=urlhaus_clean,
        openphish_data=openphish_clean,
    )

    assert evaluation["verdict"] == RiskVerdict.LOW_RISK
    assert evaluation["risk_score"] < 20
    assert evaluation["checks"]["dns_resolution"].status == CheckStatusEnum.COMPLETED
    assert evaluation["checks"]["tls_certificate"].status == CheckStatusEnum.COMPLETED


def test_case_c_unresolvable_hostname_with_suspicious_structure():
    """
    TEST C:
    Input: http://chase.com.account-verify.unresolvable-fake-site-999.com/auth
    Expected: Continue analysis and preserve structural findings even though DNS fails.
    Never treat DNS failure as proof that a URL is safe.
    """
    target = "http://chase.com.account-verify.unresolvable-fake-site-999.com/auth"
    typo_res = typosquat_detector.analyze(target)

    assert typo_res["is_impersonation"] is True
    assert typo_res["impersonated_brand"] == "Chase Bank"
    assert typo_res["brand_in_subdomain"] is True

    # DNS fails completely
    dns_failed = {"error": "socket.gaierror: [Errno 11001] getaddrinfo failed", "a_records": []}
    ssl_unavail = {"has_ssl": False, "error": "Host unreachable"}
    http_unavail = {"error": "Host unreachable"}

    evaluation = risk_engine.evaluate(
        target_url=target,
        domain="chase.com.account-verify.unresolvable-fake-site-999.com",
        dns_data=dns_failed,
        ssl_data=ssl_unavail,
        typosquat_data=typo_res,
        http_data=http_unavail,
        urlhaus_data={"found": False},
        openphish_data={"found": False},
    )

    # Must preserve structural findings and MUST NOT be classified as safe
    assert evaluation["verdict"] in (RiskVerdict.SUSPICIOUS, RiskVerdict.HIGH_RISK)
    assert evaluation["checks"]["dns_resolution"].status == CheckStatusEnum.UNAVAILABLE
    assert evaluation["checks"]["brand_impersonation"].status == CheckStatusEnum.SUSPICIOUS_FINDING
    assert len(evaluation["concerns"]) > 0


def test_case_d_ordinary_unresolvable_hostname_inconclusive():
    """
    TEST D:
    Input: http://nonexistent-random-domain-xyz987654321.com
    Expected: Inconclusive, NOT automatically safe.
    Confidence should reflect that live inspection could not be completed.
    """
    target = "http://nonexistent-random-domain-xyz987654321.com"
    typo_res = typosquat_detector.analyze(target)
    assert typo_res["is_impersonation"] is False

    # DNS fails and has no A records
    dns_failed = {"error": "DNS lookup failed: NXDOMAIN", "a_records": []}
    ssl_unavail = {"has_ssl": False, "error": "DNS resolution failed"}
    http_unavail = {"error": "DNS resolution failed"}

    evaluation = risk_engine.evaluate(
        target_url=target,
        domain="nonexistent-random-domain-xyz987654321.com",
        dns_data=dns_failed,
        ssl_data=ssl_unavail,
        typosquat_data=typo_res,
        http_data=http_unavail,
        urlhaus_data={"found": False},
        openphish_data={"found": False},
    )

    assert evaluation["verdict"] == RiskVerdict.INCONCLUSIVE
    assert "could not be reached" in evaluation["consumer_headline"].lower()
    assert evaluation["confidence_score"] < 50.0
    assert evaluation["checks"]["dns_resolution"].status == CheckStatusEnum.UNAVAILABLE


def test_case_e_known_threat_feed_match():
    """
    TEST E:
    Input with positive URLhaus or OpenPhish threat intelligence match.
    Expected: Confirmed Malicious or High Risk.
    """
    target = "http://malicious-botnet-c2-drop.xyz/payload.exe"
    typo_res = typosquat_detector.analyze(target)

    dns_data = {"a_records": ["198.51.100.42"]}
    ssl_data = {"has_ssl": False}
    http_data = {"status_code": 200, "redirect_count": 0}
    urlhaus_match = {
        "found": True,
        "threat": "Mozi.Botnet",
        "tags": ["mozi", "elf", "botnet"],
        "status": "online",
    }
    openphish_data = {"found": False}

    evaluation = risk_engine.evaluate(
        target_url=target,
        domain="malicious-botnet-c2-drop.xyz",
        dns_data=dns_data,
        ssl_data=ssl_data,
        typosquat_data=typo_res,
        http_data=http_data,
        urlhaus_data=urlhaus_match,
        openphish_data=openphish_data,
    )

    assert evaluation["verdict"] == RiskVerdict.CONFIRMED_MALICIOUS
    assert evaluation["risk_score"] >= 85
    assert evaluation["confidence_score"] >= 95.0
    assert evaluation["checks"]["threat_feed_urlhaus"].status == CheckStatusEnum.SUSPICIOUS_FINDING
    assert any("URLhaus" in t for t in evaluation["threat_types"])


def test_case_f_phishing_simulation_test_page():
    """
    TEST F:
    Input: http://testsafebrowsing.appspot.com/s/phishing.html
    Expected:
    - Recognize the known phishing simulation (Google Safe Browsing test page).
    - Clearly identify it as a test page (Verdict: PHISHING_SIMULATION).
    - NEVER classify this unmatched URL as verified safe.
    - Show which threat intelligence sources were checked.
    - Distinguish no match from unavailable checks.
    - Do NOT treat the test result as proof of an actual active phishing attack.
    """
    from backend.app.services.scanner.simulation_detector import simulation_detector

    target = "http://testsafebrowsing.appspot.com/s/phishing.html"

    # Step 1: Verify Simulation Detector identifies it as Google Safe Browsing Phishing Simulation
    sim_res = simulation_detector.analyze(target)
    assert sim_res["is_simulation"] is True
    assert sim_res["simulation_type"] == "PHISHING_SIMULATION"
    assert sim_res["suite_id"] == "google-safe-browsing-test"
    assert "Google Safe Browsing" in sim_res["provider"]

    # Step 2: Verify Risk Engine produces PHISHING_SIMULATION verdict
    dns_data = {"a_records": ["172.217.16.144"]}
    ssl_data = {"has_ssl": False}
    http_data = {"status_code": 200, "redirect_count": 0}
    typo_res = typosquat_detector.analyze(target)
    urlhaus_clean = {"found": False}
    openphish_clean = {"found": False, "feed_size": 1500}
    gsb_unavail = {"found": False, "configured": False, "status": "UNAVAILABLE"}

    evaluation = risk_engine.evaluate(
        target_url=target,
        domain="testsafebrowsing.appspot.com",
        dns_data=dns_data,
        ssl_data=ssl_data,
        typosquat_data=typo_res,
        http_data=http_data,
        urlhaus_data=urlhaus_clean,
        openphish_data=openphish_clean,
        google_safebrowsing_data=gsb_unavail,
        simulation_data=sim_res,
    )

    # Must be recognized as simulation and NEVER as LOW_RISK or verified safe
    assert evaluation["verdict"] == RiskVerdict.PHISHING_SIMULATION
    assert evaluation["verdict"] != RiskVerdict.LOW_RISK
    assert "Phishing Simulation" in evaluation["consumer_headline"]

    # Must clearly explain that it is an industry test page, not a real attack
    concerns = evaluation["concerns"]
    assert any(c.category == "SECURITY_SIMULATION" for c in concerns)
    assert any("benchmark" in c.title.lower() or "simulation" in c.title.lower() for c in concerns)

    # Must show transparency across all threat intelligence sources
    checks = evaluation["checks"]
    assert "security_simulation" in checks
    assert checks["security_simulation"].status == CheckStatusEnum.COMPLETED

    assert "threat_feed_urlhaus" in checks
    assert checks["threat_feed_urlhaus"].status == CheckStatusEnum.NO_MATCH_FOUND

    assert "threat_feed_openphish" in checks
    assert checks["threat_feed_openphish"].status == CheckStatusEnum.NO_MATCH_FOUND

    assert "threat_feed_google_safe_browsing" in checks
    assert checks["threat_feed_google_safe_browsing"].status == CheckStatusEnum.UNAVAILABLE


@pytest.mark.asyncio
async def test_scan_url_endpoint_phishing_simulation():
    """
    End-to-End Endpoint Test for Google Safe Browsing test URL:
    http://testsafebrowsing.appspot.com/s/phishing.html must return PHISHING_SIMULATION.
    """
    with patch("backend.app.api.v1.endpoints.scan.urlhaus_client.lookup_url", new_callable=AsyncMock) as mock_uh, \
         patch("backend.app.api.v1.endpoints.scan.openphish_client.lookup", new_callable=AsyncMock) as mock_op, \
         patch("backend.app.api.v1.endpoints.scan.google_safe_browsing_client.lookup_url", new_callable=AsyncMock) as mock_gsb, \
         patch("backend.app.api.v1.endpoints.scan.gemini_explainer.explain_url_verdict", new_callable=AsyncMock) as mock_ai:
        mock_uh.return_value = {"found": False, "source": "URLhaus"}
        mock_op.return_value = {"found": False, "source": "OpenPhish", "feed_size": 1200}
        mock_gsb.return_value = {"found": False, "configured": False, "status": "UNAVAILABLE"}
        mock_ai.return_value = {"headline": "Phishing Simulation", "summary": "Test page", "what_to_do": []}

        req = URLScanRequest(target_url="http://testsafebrowsing.appspot.com/s/phishing.html")
        response = await scan_url(req)

        assert response.verdict == RiskVerdict.PHISHING_SIMULATION
        assert "Phishing Simulation" in response.consumer_headline
        assert response.checks["security_simulation"].status == CheckStatusEnum.COMPLETED
        assert response.checks["threat_feed_google_safe_browsing"].status == CheckStatusEnum.UNAVAILABLE


from unittest.mock import patch, AsyncMock


@pytest.mark.asyncio
async def test_scan_url_endpoint_test_1_unresolvable_subdomain():
    """
    End-to-End Endpoint Test for Test 1:
    paypal.com.security-check.example.com must not raise HTTP 400 SSRF error,
    must not fail, and must return SUSPICIOUS verdict.
    """
    with patch("backend.app.api.v1.endpoints.scan.urlhaus_client.lookup_url", new_callable=AsyncMock) as mock_uh, \
         patch("backend.app.api.v1.endpoints.scan.openphish_client.lookup", new_callable=AsyncMock) as mock_op, \
         patch("backend.app.api.v1.endpoints.scan.gemini_explainer.explain_url_verdict", new_callable=AsyncMock) as mock_ai:
        mock_uh.return_value = {"found": False, "source": "URLhaus"}
        mock_op.return_value = {"found": False, "source": "OpenPhish"}
        mock_ai.return_value = {"headline": "Suspicious Website", "summary": "Impersonates PayPal", "what_to_do": []}

        req = URLScanRequest(target_url="http://paypal.com.security-check.example.com/login")
        response = await scan_url(req)

        assert response.verdict in (RiskVerdict.SUSPICIOUS, RiskVerdict.HIGH_RISK)
        assert response.verdict == RiskVerdict.SUSPICIOUS
        assert response.impersonated_brand == "PayPal"
        assert len(response.concerns) > 0
        assert response.checks["dns_resolution"].status == CheckStatusEnum.UNAVAILABLE
        assert response.checks["brand_impersonation"].status == CheckStatusEnum.SUSPICIOUS_FINDING

