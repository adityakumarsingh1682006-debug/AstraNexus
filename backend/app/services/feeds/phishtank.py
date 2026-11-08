from datetime import datetime, timezone
import httpx
from typing import Dict, Any, Optional
from backend.app.core.config import settings
from backend.app.services.feeds.normalizer import normalize_threat_url


class PhishTankClient:
    """
    PhishTank Community Anti-Phishing Integration.
    Checks URLs against PhishTank verified phishing telemetry.
    Respects upstream developer API key requirements and rate limiting.
    """

    def __init__(self, api_key: Optional[str] = None, timeout: float = 4.0):
        self.api_key = api_key or getattr(settings, "PHISHTANK_API_KEY", None)
        self.endpoint = "https://checkurl.phishtank.com/checkurl/"
        self.timeout = timeout

    async def lookup_url(self, target_url: str) -> Dict[str, Any]:
        """
        Check URL against PhishTank database.
        Never treats an unavailable or rate-limited API as clean.
        """
        normalized = normalize_threat_url(target_url)
        canonical = normalized["canonical_url"]
        now_iso = datetime.now(timezone.utc).isoformat()

        results: Dict[str, Any] = {
            "source": "PhishTank",
            "indicator_checked": canonical,
            "lookup_timestamp": now_iso,
            "match_status": "API_UNAVAILABLE",
            "found": False,
            "threat": None,
            "confidence": None,
            "evidence_reference": None,
            "limitations": "PhishTank requires registered developer AppKey for unthrottled queries.",
            "error": None,
        }

        if not self.api_key:
            results["match_status"] = "API_UNAVAILABLE"
            results["error"] = "PhishTank API key not configured (Set PHISHTANK_API_KEY in environment)"
            return results

        payload = {
            "url": canonical,
            "format": "json",
            "app_key": self.api_key,
        }

        try:
            timeout_cfg = httpx.Timeout(self.timeout, connect=min(2.0, self.timeout))
            async with httpx.AsyncClient(timeout=timeout_cfg) as client:
                resp = await client.post(
                    self.endpoint,
                    data=payload,
                    headers={"User-Agent": "phishtank/AstraNexus-1.0"},
                )

                if resp.status_code == 200:
                    data = resp.json()
                    res_data = data.get("results", {})
                    in_database = res_data.get("in_database", False)
                    verified = res_data.get("verified", False)
                    valid = res_data.get("valid", False)

                    if in_database and verified and valid:
                        results["found"] = True
                        results["match_status"] = "THREAT_FOUND"
                        results["threat"] = "Verified Phishing Page"
                        results["confidence"] = "HIGH"
                        results["evidence_reference"] = res_data.get("phish_detail_page")
                    else:
                        results["found"] = False
                        results["match_status"] = "NO_MATCH_FOUND"
                        results["confidence"] = "HIGH"
                elif resp.status_code == 429:
                    results["match_status"] = "RATE_LIMITED"
                    results["error"] = "PhishTank API rate limit exceeded (HTTP 429)"
                elif resp.status_code in (401, 403):
                    results["match_status"] = "AUTH_FAILURE"
                    results["error"] = "PhishTank API key authentication failure"
                else:
                    results["match_status"] = "INVALID_RESPONSE"
                    results["error"] = f"HTTP {resp.status_code} from PhishTank API"
        except httpx.TimeoutException:
            results["match_status"] = "API_UNAVAILABLE"
            results["error"] = "PhishTank lookup timed out"
        except Exception as e:
            results["match_status"] = "API_UNAVAILABLE"
            results["error"] = f"PhishTank connection error: {str(e)}"

        return results


phishtank_client = PhishTankClient()
