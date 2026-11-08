import time
from datetime import datetime, timezone
import httpx
from typing import Dict, Any, Optional, List
from cachetools import TTLCache
from backend.app.core.config import settings

# In-memory cache for Google Safe Browsing lookups (1 hour TTL)
_gsb_cache = TTLCache(maxsize=5000, ttl=getattr(settings, "FEED_CACHE_TTL_SECONDS", 3600))


class GoogleSafeBrowsingClient:
    """
    Google Safe Browsing v4 Threat Intelligence Integration.
    Checks target URLs against Google's global index of malware, phishing (social engineering),
    and unwanted software.
    """

    def __init__(self, api_key: Optional[str] = None, timeout: float = 4.0):
        self.api_key = api_key or getattr(settings, "SAFE_BROWSING_API_KEY", None) or getattr(settings, "GEMINI_API_KEY", None)
        self.endpoint = "https://safebrowsing.googleapis.com/v4/threatMatches:find"
        self.timeout = timeout

    async def lookup_url(self, target_url: str) -> Dict[str, Any]:
        """
        Queries Google Safe Browsing for a specific target URL.
        Never treats an unconfigured or failing API as a clean verdict.
        """
        clean_url = target_url.strip()
        normalized_key = f"gsb:{clean_url}"

        if normalized_key in _gsb_cache:
            cached = dict(_gsb_cache[normalized_key])
            cached["cached"] = True
            return cached

        now_iso = datetime.now(timezone.utc).isoformat()
        results: Dict[str, Any] = {
            "source": "Google Safe Browsing v4",
            "indicator_checked": clean_url,
            "lookup_timestamp": now_iso,
            "match_status": "API_UNAVAILABLE" if not self.api_key else "CHECKED",
            "found": False,
            "configured": bool(self.api_key),
            "threat": None,
            "threat_type": None,
            "platform": None,
            "confidence": "HIGH" if bool(self.api_key) else None,
            "evidence_reference": None,
            "limitations": "Requires Google Cloud project API key with Safe Browsing API v4 enabled.",
            "cached": False,
            "error": None,
            "status": "CHECKED" if bool(self.api_key) else "UNAVAILABLE",
        }

        # If API key is not set, report status honestly without fabricating
        if not self.api_key:
            results["error"] = "Google Safe Browsing API key not configured (Set SAFE_BROWSING_API_KEY in environment)"
            results["match_status"] = "API_UNAVAILABLE"
            results["status"] = "UNAVAILABLE"
            return results

        payload = {
            "client": {
                "clientId": "astranexus-security-scanner",
                "clientVersion": "1.0.0",
            },
            "threatInfo": {
                "threatTypes": [
                    "MALWARE",
                    "SOCIAL_ENGINEERING",
                    "UNWANTED_SOFTWARE",
                    "POTENTIALLY_HARMFUL_APPLICATION",
                ],
                "platformTypes": ["ANY_PLATFORM"],
                "threatEntryTypes": ["URL"],
                "threatEntries": [{"url": clean_url}],
            },
        }

        try:
            timeout_cfg = httpx.Timeout(self.timeout, connect=min(2.0, self.timeout))
            async with httpx.AsyncClient(timeout=timeout_cfg) as client:
                response = await client.post(
                    f"{self.endpoint}?key={self.api_key}",
                    json=payload,
                    headers={"Content-Type": "application/json", "User-Agent": "AstraNexus-SecurityScanner/1.0"},
                )

                if response.status_code == 200:
                    data = response.json()
                    matches: List[Dict[str, Any]] = data.get("matches", [])

                    if matches:
                        match = matches[0]
                        threat_type = match.get("threatType", "MALICIOUS")
                        results["found"] = True
                        results["threat_type"] = threat_type
                        results["platform"] = match.get("platformType")
                        results["match_status"] = "THREAT_FOUND"
                        results["status"] = "MATCH_FOUND"
                        results["evidence_reference"] = f"Documented in Google Safe Browsing threat lists ({threat_type})"

                        if threat_type == "SOCIAL_ENGINEERING":
                            results["threat"] = "Phishing / Social Engineering"
                        elif threat_type == "MALWARE":
                            results["threat"] = "Malware Distribution"
                        elif threat_type == "UNWANTED_SOFTWARE":
                            results["threat"] = "Unwanted Deceptive Software"
                        else:
                            results["threat"] = threat_type.replace("_", " ").title()
                    else:
                        results["found"] = False
                        results["match_status"] = "NO_MATCH_FOUND"
                        results["status"] = "NO_MATCH"
                elif response.status_code in (400, 403):
                    results["match_status"] = "AUTH_FAILURE"
                    results["status"] = "AUTH_FAILURE"
                    results["error"] = f"Google Safe Browsing authentication failure (HTTP {response.status_code})"
                elif response.status_code == 429:
                    results["match_status"] = "RATE_LIMITED"
                    results["status"] = "RATE_LIMITED"
                    results["error"] = "Google Safe Browsing API quota/rate limit exceeded"
                else:
                    results["match_status"] = "INVALID_RESPONSE"
                    results["status"] = "FAILED"
                    results["error"] = f"HTTP {response.status_code} from Google Safe Browsing API"

        except httpx.TimeoutException:
            results["error"] = "Google Safe Browsing lookup timed out"
            results["match_status"] = "API_UNAVAILABLE"
            results["status"] = "UNAVAILABLE"
        except Exception as e:
            results["error"] = f"Google Safe Browsing connection error: {str(e)}"
            results["match_status"] = "API_UNAVAILABLE"
            results["status"] = "FAILED"

        _gsb_cache[normalized_key] = results
        return results


google_safe_browsing_client = GoogleSafeBrowsingClient()
