import time
import httpx
from typing import Dict, Any, Optional, List
from cachetools import TTLCache
from backend.app.core.config import settings

# In-memory cache for Google Safe Browsing lookups (1 hour TTL)
_gsb_cache = TTLCache(maxsize=5000, ttl=settings.FEED_CACHE_TTL_SECONDS)


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
        """
        clean_url = target_url.strip()
        normalized_key = f"gsb:{clean_url}"

        if normalized_key in _gsb_cache:
            cached = _gsb_cache[normalized_key]
            cached["cached"] = True
            return cached

        results: Dict[str, Any] = {
            "source": "Google Safe Browsing",
            "found": False,
            "configured": bool(self.api_key),
            "threat": None,
            "threat_type": None,
            "platform": None,
            "cached": False,
            "error": None,
            "status": "CHECKED" if bool(self.api_key) else "UNAVAILABLE",
        }

        # If API key is not set, report status honestly without fabricating
        if not self.api_key:
            results["error"] = "Google Safe Browsing API key not configured (Set SAFE_BROWSING_API_KEY in environment)"
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
                        results["status"] = "MATCH_FOUND"

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
                        results["status"] = "NO_MATCH"
                else:
                    results["error"] = f"HTTP {response.status_code} from Google Safe Browsing API"
                    results["status"] = "FAILED"

        except httpx.TimeoutException:
            results["error"] = "Google Safe Browsing lookup timed out"
            results["status"] = "UNAVAILABLE"
        except Exception as e:
            results["error"] = f"Google Safe Browsing connection error: {str(e)}"
            results["status"] = "FAILED"

        _gsb_cache[normalized_key] = results
        return results


google_safe_browsing_client = GoogleSafeBrowsingClient()
