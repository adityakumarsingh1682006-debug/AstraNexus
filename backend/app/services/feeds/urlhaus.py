import time
from datetime import datetime, timezone
import httpx
from typing import Dict, Any, Optional, Set, List
from urllib.parse import urlparse
from cachetools import TTLCache
from backend.app.core.config import settings
from backend.app.services.feeds.normalizer import normalize_threat_url

# In-memory LRU cache: max 5000 items, TTL from settings (default 1 hour)
_urlhaus_cache = TTLCache(maxsize=5000, ttl=getattr(settings, "FEED_CACHE_TTL_SECONDS", 3600))

# In-memory online malware feed cache from Abuse.ch
_urlhaus_online_urls: Set[str] = set()
_urlhaus_online_domains: Set[str] = set()
_urlhaus_last_feed_sync: float = 0.0
_urlhaus_last_error: Optional[str] = None


class URLhausClient:
    """
    Abuse.ch URLhaus Real-Time Threat Intelligence Integration.
    Checks target URLs and hostnames against authoritative malware and botnet database.
    Supports both direct authenticated Abuse.ch API and real-time public online threat feed.
    """

    def __init__(
        self,
        api_url: Optional[str] = None,
        feed_url: str = "https://raw.githubusercontent.com/curbengh/urlhaus-filter/master/urlhaus-filter-online.txt",
        timeout: float = 4.0,
    ):
        self.api_url = (api_url or getattr(settings, "URLHAUS_API_URL", "https://urlhaus-api.abuse.ch/v1")).rstrip("/")
        self.feed_url = feed_url
        self.timeout = timeout
        self.auth_key = getattr(settings, "URLHAUS_AUTH_KEY", None)

    async def ensure_feed_synced(self) -> bool:
        """
        Synchronizes live URLhaus online malware feed if cache is expired or empty.
        """
        global _urlhaus_online_urls, _urlhaus_online_domains, _urlhaus_last_feed_sync, _urlhaus_last_error
        now = time.time()

        if _urlhaus_online_urls and (now - _urlhaus_last_feed_sync < 3600.0):
            return True

        timeout_cfg = httpx.Timeout(self.timeout, connect=min(3.0, self.timeout))
        try:
            async with httpx.AsyncClient(timeout=timeout_cfg, follow_redirects=True) as client:
                response = await client.get(
                    self.feed_url,
                    headers={"User-Agent": "AstraNexus-ThreatIntelligence/1.0"},
                )

                if response.status_code == 200 and response.text.strip():
                    lines = response.text.strip().splitlines()
                    new_urls = set()
                    new_domains = set()

                    for line in lines:
                        clean = line.strip().lower()
                        if clean and not clean.startswith("#"):
                            new_urls.add(clean)
                            if clean.endswith("/"):
                                new_urls.add(clean[:-1])
                            try:
                                parsed = urlparse(clean)
                                if parsed.netloc:
                                    host = parsed.netloc.split(":")[0].strip().lower()
                                    new_domains.add(host)
                            except Exception:
                                pass

                    if new_urls:
                        _urlhaus_online_urls = new_urls
                        _urlhaus_online_domains = new_domains
                        _urlhaus_last_feed_sync = now
                        _urlhaus_last_error = None
                        return True
        except Exception as e:
            _urlhaus_last_error = f"URLhaus feed sync error: {str(e)}"

        return len(_urlhaus_online_urls) > 0

    async def lookup_url(self, target_url: str) -> Dict[str, Any]:
        """
        Query URLhaus for a specific URL indicator.
        Never treats an unavailable API or feed as clean.
        """
        normalized = normalize_threat_url(target_url)
        canonical = normalized["canonical_url"]
        cache_key = f"url:{canonical}"

        if cache_key in _urlhaus_cache:
            cached = dict(_urlhaus_cache[cache_key])
            cached["cached"] = True
            return cached

        now_iso = datetime.now(timezone.utc).isoformat()
        results: Dict[str, Any] = {
            "source": "URLhaus (Abuse.ch)",
            "indicator_checked": canonical,
            "lookup_timestamp": now_iso,
            "match_status": "NO_MATCH_FOUND",
            "found": False,
            "threat": None,
            "status": None,
            "tags": [],
            "urlhaus_reference": None,
            "reporter": None,
            "match_type": None,
            "matched_indicator": None,
            "confidence": None,
            "evidence_reference": None,
            "limitations": "Focuses on malware distribution URLs and payload hosting domains.",
            "cached": False,
            "error": None,
        }

        # Step 1: If an API key is configured, query the official Abuse.ch JSON API
        api_tried = False
        api_success = False

        if self.auth_key:
            api_tried = True
            headers = {
                "User-Agent": "AstraNexus-ThreatIntelligence/1.0",
                "Auth-Key": self.auth_key,
            }
            try:
                timeout_cfg = httpx.Timeout(self.timeout, connect=min(2.0, self.timeout))
                async with httpx.AsyncClient(timeout=timeout_cfg) as client:
                    resp = await client.post(
                        f"{self.api_url}/url/",
                        data={"url": canonical},
                        headers=headers,
                    )
                    if resp.status_code == 200:
                        api_success = True
                        data = resp.json()
                        q_status = data.get("query_status")
                        if q_status == "ok":
                            results["found"] = True
                            results["match_status"] = "THREAT_FOUND"
                            results["threat"] = data.get("threat") or "Malware URL"
                            results["status"] = data.get("url_status")
                            results["tags"] = data.get("tags") or []
                            results["urlhaus_reference"] = data.get("urlhaus_reference")
                            results["reporter"] = data.get("reporter")
                            results["match_type"] = "EXACT_URL"
                            results["confidence"] = "HIGH"
                            results["evidence_reference"] = f"Documented in Abuse.ch URLhaus (Reference: {data.get('urlhaus_reference')})"
                            _urlhaus_cache[cache_key] = results
                            return results
                        elif q_status == "no_results":
                            pass
                    elif resp.status_code == 401:
                        results["error"] = "URLhaus API authentication failure (Auth-Key invalid or expired)"
                    elif resp.status_code == 429:
                        results["error"] = "URLhaus API rate limit exceeded"
                    else:
                        results["error"] = f"HTTP {resp.status_code} from URLhaus API"
            except Exception as e:
                results["error"] = f"URLhaus API connection error: {str(e)}"

        # Step 2: Query the real-time Abuse.ch online threat dataset
        feed_synced = await self.ensure_feed_synced()

        if feed_synced and len(_urlhaus_online_urls) > 0:
            for cand in normalized["lookup_candidates"]:
                if cand in _urlhaus_online_urls:
                    results["found"] = True
                    results["match_status"] = "THREAT_FOUND"
                    results["threat"] = "Active Malware / Payload Distribution URL"
                    results["status"] = "online"
                    results["match_type"] = "EXACT_URL"
                    results["matched_indicator"] = cand
                    results["confidence"] = "HIGH"
                    results["evidence_reference"] = "Active malware distribution link confirmed in Abuse.ch URLhaus real-time telemetry"
                    _urlhaus_cache[cache_key] = results
                    return results

            # Check domain
            host = normalized["hostname"]
            reg_domain = normalized["registered_domain"]
            if host in _urlhaus_online_domains or reg_domain in _urlhaus_online_domains:
                matched_dom = host if host in _urlhaus_online_domains else reg_domain
                results["found"] = True
                results["match_status"] = "THREAT_FOUND"
                results["threat"] = f"Malware Hosting Infrastructure ({matched_dom})"
                results["status"] = "online"
                results["match_type"] = "DOMAIN_MATCH"
                results["matched_indicator"] = matched_dom
                results["confidence"] = "MEDIUM"
                results["evidence_reference"] = f"Domain {matched_dom} is documented as hosting active malware payloads in Abuse.ch URLhaus"
                _urlhaus_cache[cache_key] = results
                return results

            # Clean match against active feed
            results["found"] = False
            results["match_status"] = "NO_MATCH_FOUND"
            results["confidence"] = "HIGH"
            _urlhaus_cache[cache_key] = results
            return results

        # Step 3: If neither API nor feed succeeded, report UNAVAILABLE honestly
        if not api_success and len(_urlhaus_online_urls) == 0:
            results["match_status"] = "API_UNAVAILABLE"
            results["error"] = results.get("error") or _urlhaus_last_error or "URLhaus feed and API unavailable"

        _urlhaus_cache[cache_key] = results
        return results

    async def lookup_host(self, host: str) -> Dict[str, Any]:
        """
        Query URLhaus for a domain/hostname.
        """
        return await self.lookup_url(f"http://{host.strip()}")


urlhaus_client = URLhausClient()
