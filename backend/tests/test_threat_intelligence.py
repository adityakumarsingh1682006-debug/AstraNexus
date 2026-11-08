import asyncio
import pytest
from unittest.mock import AsyncMock, patch, MagicMock

from backend.app.services.feeds.normalizer import normalize_threat_url
from backend.app.services.feeds.urlhaus import URLhausClient
from backend.app.services.feeds.openphish import OpenPhishClient
from backend.app.services.feeds.google_safe_browsing import GoogleSafeBrowsingClient
from backend.app.services.feeds.phishtank import PhishTankClient
from backend.app.services.feeds.virustotal import VirusTotalClient
from backend.app.services.scanner.risk_engine import risk_engine
from backend.app.schemas.scan import RiskVerdict, CheckStatusEnum, ConcernLevel


# =====================================================================
# 1. Normalization & Indicator Formatting Tests
# =====================================================================

def test_url_normalizer_schemes_and_candidates():
    norm = normalize_threat_url("HTTPS://Sub.Example.Com:443/Path/Login.php?user=admin&token=123#ref")
    assert norm["hostname"] == "sub.example.com"
    assert norm["registered_domain"] == "example.com"
    assert "https://sub.example.com/path/login.php" in norm["lookup_candidates"]
    assert "sub.example.com" in norm["lookup_candidates"]
    assert "example.com" in norm["lookup_candidates"]


def test_url_normalizer_scheme_less_and_ports():
    norm = normalize_threat_url("malicious-domain.xyz:80/payload.sh")
    assert norm["hostname"] == "malicious-domain.xyz"
    assert norm["registered_domain"] == "malicious-domain.xyz"
    assert "http://malicious-domain.xyz/payload.sh" in norm["lookup_candidates"]


# =====================================================================
# 2. URLhaus Integration Tests
# =====================================================================

def test_urlhaus_known_malicious_api():
    client = URLhausClient(api_url="https://urlhaus-api.abuse.ch/v1", timeout=2.0)
    client.auth_key = "dummy-auth-key"

    mock_resp = MagicMock()
    mock_resp.status_code = 200
    mock_resp.json.return_value = {
        "query_status": "ok",
        "url_status": "online",
        "threat": "malware_download",
        "tags": ["Mozi", "elf"],
        "urlhaus_reference": "https://urlhaus.abuse.ch/url/999999/",
        "reporter": "abuse_hunter",
    }
    mock_client = AsyncMock()
    mock_client.__aenter__.return_value = mock_client
    mock_client.post.return_value = mock_resp

    with patch("backend.app.services.feeds.urlhaus.httpx.AsyncClient", return_value=mock_client):
        res = asyncio.run(client.lookup_url("http://malware.example.com/payload.exe"))
        assert res["found"] is True
        assert res["match_status"] == "THREAT_FOUND"
        assert res["threat"] == "malware_download"
        assert res["confidence"] == "HIGH"
        assert "urlhaus.abuse.ch" in res["evidence_reference"]


def test_urlhaus_feed_threat_match():
    client = URLhausClient(timeout=2.0)
    target = "http://infected-host.net/bot.bin"

    with patch.object(client, "ensure_feed_synced", new_callable=AsyncMock, return_value=True):
        with patch("backend.app.services.feeds.urlhaus._urlhaus_online_urls", {target}):
            with patch("backend.app.services.feeds.urlhaus._urlhaus_online_domains", {"infected-host.net"}):
                res = asyncio.run(client.lookup_url(target))
                assert res["found"] is True
                assert res["match_status"] == "THREAT_FOUND"
                assert "Malware" in res["threat"]


def test_urlhaus_benign_no_match():
    client = URLhausClient(timeout=2.0)
    with patch.object(client, "ensure_feed_synced", new_callable=AsyncMock, return_value=True):
        with patch("backend.app.services.feeds.urlhaus._urlhaus_online_urls", {"http://bad-actor.com/malware"}):
            with patch("backend.app.services.feeds.urlhaus._urlhaus_online_domains", {"bad-actor.com"}):
                res = asyncio.run(client.lookup_url("https://benign-site.com/about"))
                assert res["found"] is False
                assert res["match_status"] == "NO_MATCH_FOUND"


def test_urlhaus_unavailable_never_treats_as_clean():
    client = URLhausClient(timeout=2.0)
    with patch.object(client, "ensure_feed_synced", new_callable=AsyncMock, return_value=False):
        with patch("backend.app.services.feeds.urlhaus._urlhaus_online_urls", set()):
            res = asyncio.run(client.lookup_url("https://unverified-domain.xyz"))
            assert res["found"] is False
            assert res["match_status"] == "API_UNAVAILABLE"
            assert res["error"] is not None


# =====================================================================
# 3. OpenPhish Integration Tests
# =====================================================================

def test_openphish_known_malicious_match():
    client = OpenPhishClient(timeout=2.0)
    target = "https://phishing-portal.com/login"

    with patch.object(client, "ensure_feed_synced", new_callable=AsyncMock, return_value=True):
        with patch("backend.app.services.feeds.openphish._openphish_urls", {target}):
            with patch("backend.app.services.feeds.openphish._openphish_domains", {"phishing-portal.com"}):
                res = asyncio.run(client.lookup(target))
                assert res["found"] is True
                assert res["match_status"] == "THREAT_FOUND"
                assert res["match_type"] == "EXACT_URL"
                assert res["confidence"] == "HIGH"


def test_openphish_benign_no_match():
    client = OpenPhishClient(timeout=2.0)
    with patch.object(client, "ensure_feed_synced", new_callable=AsyncMock, return_value=True):
        with patch("backend.app.services.feeds.openphish._openphish_urls", {"https://some-other-bad-url.com"}):
            with patch("backend.app.services.feeds.openphish._openphish_domains", {"some-other-bad-url.com"}):
                res = asyncio.run(client.lookup("https://clean-example-site.org/index.html"))
                assert res["found"] is False
                assert res["match_status"] == "NO_MATCH_FOUND"


def test_openphish_unavailable_reports_honestly():
    client = OpenPhishClient(timeout=2.0)
    with patch.object(client, "ensure_feed_synced", new_callable=AsyncMock, return_value=False):
        with patch("backend.app.services.feeds.openphish._openphish_urls", set()):
            res = asyncio.run(client.lookup("https://any-test-url.com"))
            assert res["found"] is False
            assert res["match_status"] == "API_UNAVAILABLE"


# =====================================================================
# 4. Google Safe Browsing Integration Tests
# =====================================================================

def test_safe_browsing_known_malicious():
    client = GoogleSafeBrowsingClient(api_key="valid-test-key", timeout=2.0)
    mock_resp = MagicMock()
    mock_resp.status_code = 200
    mock_resp.json.return_value = {
        "matches": [
            {
                "threatType": "SOCIAL_ENGINEERING",
                "platformType": "ANY_PLATFORM",
            }
        ]
    }
    mock_client = AsyncMock()
    mock_client.__aenter__.return_value = mock_client
    mock_client.post.return_value = mock_resp

    with patch("backend.app.services.feeds.google_safe_browsing.httpx.AsyncClient", return_value=mock_client):
        res = asyncio.run(client.lookup_url("https://suspicious-login-site.com"))
        assert res["found"] is True
        assert res["match_status"] == "THREAT_FOUND"
        assert res["threat"] == "Phishing / Social Engineering"


def test_safe_browsing_unconfigured_never_clean():
    client = GoogleSafeBrowsingClient(api_key=None)
    res = asyncio.run(client.lookup_url("https://example.com"))
    assert res["found"] is False
    assert res["match_status"] == "API_UNAVAILABLE"
    assert "not configured" in res["error"]


def test_safe_browsing_rate_limited():
    client = GoogleSafeBrowsingClient(api_key="valid-key")
    mock_resp = MagicMock()
    mock_resp.status_code = 429
    mock_client = AsyncMock()
    mock_client.__aenter__.return_value = mock_client
    mock_client.post.return_value = mock_resp

    with patch("backend.app.services.feeds.google_safe_browsing.httpx.AsyncClient", return_value=mock_client):
        res = asyncio.run(client.lookup_url("https://example.com/item"))
        assert res["match_status"] == "RATE_LIMITED"
        assert res["found"] is False


# =====================================================================
# 5. PhishTank & VirusTotal Integration Tests
# =====================================================================

def test_phishtank_rate_limited_handling():
    client = PhishTankClient(api_key="valid-app-key")
    mock_resp = MagicMock()
    mock_resp.status_code = 429
    mock_client = AsyncMock()
    mock_client.__aenter__.return_value = mock_client
    mock_client.post.return_value = mock_resp

    with patch("backend.app.services.feeds.phishtank.httpx.AsyncClient", return_value=mock_client):
        res = asyncio.run(client.lookup_url("https://test.com/phish"))
        assert res["match_status"] == "RATE_LIMITED"
        assert res["found"] is False


def test_phishtank_unconfigured_key():
    client = PhishTankClient(api_key=None)
    res = asyncio.run(client.lookup_url("https://test.com/phish"))
    assert res["match_status"] == "API_UNAVAILABLE"
    assert res["found"] is False


def test_virustotal_threat_detection():
    client = VirusTotalClient(api_key="vt-key")
    mock_resp = MagicMock()
    mock_resp.status_code = 200
    mock_resp.json.return_value = {
        "data": {
            "attributes": {
                "last_analysis_stats": {
                    "malicious": 8,
                    "suspicious": 2,
                    "undetected": 60,
                    "harmless": 10,
                }
            }
        }
    }
    mock_client = AsyncMock()
    mock_client.__aenter__.return_value = mock_client
    mock_client.get.return_value = mock_resp

    with patch("backend.app.services.feeds.virustotal.httpx.AsyncClient", return_value=mock_client):
        res = asyncio.run(client.lookup_url("http://malware-drop.com/file.exe"))
        assert res["found"] is True
        assert res["match_status"] == "THREAT_FOUND"
        assert res["malicious_count"] == 8
        assert res["confidence"] == "HIGH"


def test_virustotal_malformed_response():
    client = VirusTotalClient(api_key="vt-key")
    mock_resp = MagicMock()
    mock_resp.status_code = 500
    mock_client = AsyncMock()
    mock_client.__aenter__.return_value = mock_client
    mock_client.get.return_value = mock_resp

    with patch("backend.app.services.feeds.virustotal.httpx.AsyncClient", return_value=mock_client):
        res = asyncio.run(client.lookup_url("http://malware-drop.com/file.exe"))
        assert res["found"] is False
        assert res["match_status"] == "INVALID_RESPONSE"


# =====================================================================
# 6. Risk Engine Threat Classification Mapping Tests
# =====================================================================

def test_risk_engine_confirmed_malicious_from_threat_intel():
    evaluation = risk_engine.evaluate(
        target_url="http://malware-server.com/trojan.exe",
        domain="malware-server.com",
        dns_data={"a_records": ["198.51.100.1"], "error": None},
        ssl_data={"has_ssl": False},
        typosquat_data={"is_impersonation": False},
        http_data={},
        urlhaus_data={"found": True, "threat": "Trojan.Downloader", "match_status": "THREAT_FOUND"},
        openphish_data={"found": False, "match_status": "NO_MATCH_FOUND"},
        google_safebrowsing_data={"found": False, "match_status": "NO_MATCH_FOUND"},
    )
    assert evaluation["verdict"] == RiskVerdict.CONFIRMED_MALICIOUS
    assert evaluation["risk_score"] >= 85
    assert evaluation["checks"]["threat_feed_urlhaus"].status == CheckStatusEnum.SUSPICIOUS_FINDING


def test_risk_engine_unavailable_threat_intel_never_marked_clean():
    evaluation = risk_engine.evaluate(
        target_url="http://unknown-server.com",
        domain="unknown-server.com",
        dns_data={"a_records": ["198.51.100.2"], "error": None},
        ssl_data={"has_ssl": True, "is_self_signed": False, "days_remaining": 60},
        typosquat_data={"is_impersonation": False},
        http_data={},
        urlhaus_data={"found": False, "match_status": "API_UNAVAILABLE", "error": "Feed unavailable"},
        openphish_data={"found": False, "match_status": "API_UNAVAILABLE", "error": "Feed cache empty"},
        google_safebrowsing_data={"found": False, "match_status": "API_UNAVAILABLE", "error": "Key missing"},
        phishtank_data={"found": False, "match_status": "API_UNAVAILABLE", "error": "Key missing"},
        virustotal_data={"found": False, "match_status": "API_UNAVAILABLE", "error": "Key missing"},
    )
    assert evaluation["checks"]["threat_feed_urlhaus"].status == CheckStatusEnum.UNAVAILABLE
    assert evaluation["checks"]["threat_feed_openphish"].status == CheckStatusEnum.UNAVAILABLE
    assert evaluation["checks"]["threat_feed_google_safe_browsing"].status == CheckStatusEnum.UNAVAILABLE
    assert evaluation["checks"]["threat_feed_phishtank"].status == CheckStatusEnum.UNAVAILABLE
    assert evaluation["checks"]["threat_feed_virustotal"].status == CheckStatusEnum.UNAVAILABLE


def test_risk_engine_inconclusive_when_unresolvable_and_unmatched():
    evaluation = risk_engine.evaluate(
        target_url="http://nonexistent-random-domain-12345.org",
        domain="nonexistent-random-domain-12345.org",
        dns_data={"a_records": [], "error": "NXDOMAIN"},
        ssl_data={"has_ssl": False, "error": "DNS resolution failed"},
        typosquat_data={"is_impersonation": False},
        http_data={"error": "DNS resolution failed"},
        urlhaus_data={"found": False, "match_status": "NO_MATCH_FOUND"},
        openphish_data={"found": False, "match_status": "NO_MATCH_FOUND"},
        google_safebrowsing_data={"found": False, "match_status": "NO_MATCH_FOUND"},
    )
    assert evaluation["verdict"] == RiskVerdict.INCONCLUSIVE
    assert evaluation["confidence_score"] <= 50.0
