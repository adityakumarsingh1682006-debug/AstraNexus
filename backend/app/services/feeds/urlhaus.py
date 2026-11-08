import time
import httpx
from typing import Dict, Any, Optional
from cachetools import TTLCache
from backend.app.core.config import settings

# In-memory cache: max 5000 items, TTL from settings (default 1 hour)
_urlhaus_cache = TTLCache(maxsize=5000, ttl=settings.FEED_CACHE_TTL_SECONDS)


class URLhausClient:
    """
    Abuse.ch URLhaus Real-Time Threat Intelligence Integration.
    Checks target URLs and hostnames against authoritative malware and botnet database.
    Includes in-memory LRU caching with TTL.
    """

    def __init__(self, api_url: Optional[str] = None, timeout: float = 4.0):
        self.api_url = (api_url or settings.URLHAUS_API_URL).rstrip("/")
        self.timeout = timeout

    async def lookup_url(self, target_url: str) -> Dict[str, Any]:
        """
        Query URLhaus for a specific URL indicator.
        """
        normalized_key = f"url:{target_url.strip()}"
        if normalized_key in _urlhaus_cache:
            cached = _urlhaus_cache[normalized_key]
            cached["cached"] = True
            return cached

        results: Dict[str, Any] = {
            "source": "URLhaus (Abuse.ch)",
            "found": False,
            "threat": None,
            "status": None,
            "tags": [],
            "urlhaus_reference": None,
            "reporter": None,
            "cached": False,
            "error": None,
        }

        headers = {"User-Agent": "AstraNexus-ThreatIntelligence/1.0"}
        if settings.URLHAUS_AUTH_KEY:
            headers["Auth-Key"] = settings.URLHAUS_AUTH_KEY

        try:
            timeout_cfg = httpx.Timeout(self.timeout, connect=min(2.0, self.timeout))
            async with httpx.AsyncClient(timeout=timeout_cfg) as client:
                response = await client.post(
                    f"{self.api_url}/url/",
                    data={"url": target_url.strip()},
                    headers=headers,
                )

                if response.status_code == 200:
                    data = response.json()
                    status = data.get("query_status")

                    if status == "ok":
                        results["found"] = True
                        results["threat"] = data.get("threat") or "Malware URL"
                        results["status"] = data.get("url_status")
                        results["tags"] = data.get("tags") or []
                        results["urlhaus_reference"] = data.get("urlhaus_reference")
                        results["reporter"] = data.get("reporter")
                    elif status == "no_results":
                        results["found"] = False
                    else:
                        results["error"] = f"URLhaus query status: {status}"
                else:
                    results["error"] = f"HTTP {response.status_code} from URLhaus API"

        except httpx.TimeoutException:
            results["error"] = "URLhaus lookup timed out"
        except Exception as e:
            results["error"] = f"URLhaus connection error: {str(e)}"

        _urlhaus_cache[normalized_key] = results
        return results

    async def lookup_host(self, host: str) -> Dict[str, Any]:
        """
        Query URLhaus for a domain/hostname.
        """
        clean_host = host.strip().lower()
        if ":" in clean_host:
            clean_host = clean_host.split(":")[0]

        normalized_key = f"host:{clean_host}"
        if normalized_key in _urlhaus_cache:
            cached = _urlhaus_cache[normalized_key]
            cached["cached"] = True
            return cached

        results: Dict[str, Any] = {
            "source": "URLhaus (Abuse.ch)",
            "found": False,
            "threat": None,
            "status": None,
            "tags": [],
            "url_count": 0,
            "urlhaus_reference": None,
            "cached": False,
            "error": None,
        }

        try:
            async with httpx.AsyncClient(timeout=self.timeout) as client:
                response = await client.post(
                    f"{self.api_url}/host/",
                    data={"host": clean_host},
                    headers={"User-Agent": "AstraNexus-ThreatIntelligence/1.0"},
                )

                if response.status_code == 200:
                    data = response.json()
                    status = data.get("query_status")

                    if status == "ok":
                        urls = data.get("urls") or []
                        results["found"] = len(urls) > 0
                        results["url_count"] = len(urls)
                        if urls:
                            results["threat"] = urls[0].get("threat") or "Malware Hosting Domain"
                            results["status"] = urls[0].get("url_status")
                            results["tags"] = urls[0].get("tags") or []
                            results["urlhaus_reference"] = urls[0].get("urlhaus_reference")
                    elif status == "no_results":
                        results["found"] = False
                    else:
                        results["error"] = f"URLhaus query status: {status}"
                else:
                    results["error"] = f"HTTP {response.status_code} from URLhaus API"

        except httpx.TimeoutException:
            results["error"] = "URLhaus lookup timed out"
        except Exception as e:
            results["error"] = f"URLhaus connection error: {str(e)}"

        _urlhaus_cache[normalized_key] = results
        return results


urlhaus_client = URLhausClient()
