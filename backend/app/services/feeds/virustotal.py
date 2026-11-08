import base64
from datetime import datetime, timezone
import httpx
from typing import Dict, Any, Optional
from backend.app.core.config import settings
from backend.app.services.feeds.normalizer import normalize_threat_url


class VirusTotalClient:
    """
    VirusTotal v3 Real-Time Threat Intelligence Integration.
    Checks target URLs against multi-engine antivirus and URL scanner consortium.
    Respects strict API key and rate limits (4 req/min for public tiers).
    """

    def __init__(self, api_key: Optional[str] = None, timeout: float = 4.0):
        self.api_key = api_key or getattr(settings, "VIRUSTOTAL_API_KEY", None)
        self.endpoint = "https://www.virustotal.com/api/v3/urls"
        self.timeout = timeout

    async def lookup_url(self, target_url: str) -> Dict[str, Any]:
        """
        Check URL against VirusTotal v3 URL intelligence.
        Never treats an unconfigured or rate-limited API as clean.
        """
        normalized = normalize_threat_url(target_url)
        canonical = normalized["canonical_url"]
        now_iso = datetime.now(timezone.utc).isoformat()

        results: Dict[str, Any] = {
            "source": "VirusTotal v3",
            "indicator_checked": canonical,
            "lookup_timestamp": now_iso,
            "match_status": "API_UNAVAILABLE",
            "found": False,
            "threat": None,
            "malicious_count": 0,
            "suspicious_count": 0,
            "total_engines": 0,
            "confidence": None,
            "evidence_reference": None,
            "limitations": "Requires VirusTotal v3 API key with public/private tier quota.",
            "error": None,
        }

        if not self.api_key:
            results["match_status"] = "API_UNAVAILABLE"
            results["error"] = "VirusTotal API key not configured (Set VIRUSTOTAL_API_KEY in environment)"
            return results

        # VirusTotal v3 URL identifier is base64 of the URL without padding
        url_id = base64.urlsafe_b64encode(canonical.encode("utf-8")).decode("utf-8").strip("=")

        try:
            timeout_cfg = httpx.Timeout(self.timeout, connect=min(2.0, self.timeout))
            headers = {
                "x-apikey": self.api_key,
                "User-Agent": "AstraNexus-ThreatIntelligence/1.0",
            }
            async with httpx.AsyncClient(timeout=timeout_cfg) as client:
                resp = await client.get(f"{self.endpoint}/{url_id}", headers=headers)

                if resp.status_code == 200:
                    data = resp.json()
                    attributes = data.get("data", {}).get("attributes", {})
                    stats = attributes.get("last_analysis_stats", {})
                    malicious = stats.get("malicious", 0)
                    suspicious = stats.get("suspicious", 0)
                    total = sum(stats.values()) if stats else 0

                    results["malicious_count"] = malicious
                    results["suspicious_count"] = suspicious
                    results["total_engines"] = total

                    if malicious >= 3:
                        results["found"] = True
                        results["match_status"] = "THREAT_FOUND"
                        results["threat"] = f"Flagged by {malicious} security vendors on VirusTotal"
                        results["confidence"] = "HIGH"
                        results["evidence_reference"] = f"VirusTotal multi-engine consensus ({malicious}/{total} engines detected threat)"
                    elif malicious > 0 or suspicious >= 2:
                        results["found"] = True
                        results["match_status"] = "THREAT_FOUND"
                        results["threat"] = f"Suspicious activity flagged by {malicious + suspicious} engines on VirusTotal"
                        results["confidence"] = "MEDIUM"
                        results["evidence_reference"] = f"VirusTotal telemetry ({malicious} malicious, {suspicious} suspicious)"
                    else:
                        results["found"] = False
                        results["match_status"] = "NO_MATCH_FOUND"
                        results["confidence"] = "HIGH"
                elif resp.status_code == 404:
                    # URL never analyzed on VirusTotal
                    results["found"] = False
                    results["match_status"] = "NO_MATCH_FOUND"
                    results["confidence"] = "LOW"
                    results["evidence_reference"] = "URL not currently indexed in VirusTotal database"
                elif resp.status_code == 429:
                    results["match_status"] = "RATE_LIMITED"
                    results["error"] = "VirusTotal API rate limit exceeded (HTTP 429)"
                elif resp.status_code in (401, 403):
                    results["match_status"] = "AUTH_FAILURE"
                    results["error"] = "VirusTotal API key authentication failure"
                else:
                    results["match_status"] = "INVALID_RESPONSE"
                    results["error"] = f"HTTP {resp.status_code} from VirusTotal API"
        except httpx.TimeoutException:
            results["match_status"] = "API_UNAVAILABLE"
            results["error"] = "VirusTotal lookup timed out"
        except Exception as e:
            results["match_status"] = "API_UNAVAILABLE"
            results["error"] = f"VirusTotal connection error: {str(e)}"

        return results


virustotal_client = VirusTotalClient()
