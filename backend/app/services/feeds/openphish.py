import time
from datetime import datetime, timezone
import httpx
from typing import Dict, Any, Set, Optional, List
from urllib.parse import urlparse
from backend.app.core.config import settings
from backend.app.services.feeds.normalizer import normalize_threat_url

# In-memory storage for OpenPhish feed
_openphish_urls: Set[str] = set()
_openphish_domains: Set[str] = set()
_openphish_last_fetched: float = 0.0
_openphish_last_error: Optional[str] = None


class OpenPhishClient:
    """
    OpenPhish Real-Time Threat Intelligence Integration.
    Ingests and parses community phishing feeds with automatic periodic sync.
    Supports exact full-URL and domain-based matching with explainable confidence.
    """

    def __init__(
        self,
        feed_url: Optional[str] = None,
        sync_interval: float = 3600.0,
        timeout: float = 5.0,
    ):
        self.feed_url = feed_url or getattr(settings, "OPENPHISH_FEED_URL", "https://openphish.com/feed.txt")
        self.backup_feed_url = "https://raw.githubusercontent.com/openphish/public_feed/refs/heads/main/feed.txt"
        self.sync_interval = sync_interval
        self.timeout = timeout

    async def ensure_feed_synced(self) -> bool:
        """
        Synchronizes OpenPhish feed if cache has expired or is empty.
        Follows HTTP redirects (302) to the active upstream repository.
        """
        global _openphish_urls, _openphish_domains, _openphish_last_fetched, _openphish_last_error
        now = time.time()

        if _openphish_urls and (now - _openphish_last_fetched < self.sync_interval):
            return True  # Feed cache is fresh

        urls_to_try = [self.feed_url, self.backup_feed_url]
        # Avoid duplicate if feed_url is already the backup
        urls_to_try = list(dict.fromkeys(urls_to_try))

        timeout_cfg = httpx.Timeout(self.timeout, connect=min(3.0, self.timeout))

        for url in urls_to_try:
            try:
                async with httpx.AsyncClient(timeout=timeout_cfg, follow_redirects=True) as client:
                    response = await client.get(
                        url,
                        headers={"User-Agent": "AstraNexus-ThreatIntelligence/1.0"},
                    )

                    if response.status_code == 200 and response.text.strip():
                        lines = response.text.strip().splitlines()
                        new_urls = set()
                        new_domains = set()

                        for line in lines:
                            clean_line = line.strip().lower()
                            if clean_line and not clean_line.startswith("#"):
                                new_urls.add(clean_line)
                                # Also strip trailing slash
                                if clean_line.endswith("/"):
                                    new_urls.add(clean_line[:-1])
                                try:
                                    parsed = urlparse(clean_line)
                                    if parsed.netloc:
                                        host = parsed.netloc.split(":")[0].strip().lower()
                                        new_domains.add(host)
                                except Exception:
                                    pass

                        if new_urls:
                            _openphish_urls = new_urls
                            _openphish_domains = new_domains
                            _openphish_last_fetched = now
                            _openphish_last_error = None
                            return True
                    elif response.status_code == 429:
                        _openphish_last_error = "Rate limit reached on OpenPhish feed"
                    else:
                        _openphish_last_error = f"HTTP {response.status_code} from OpenPhish feed"
            except httpx.TimeoutException:
                _openphish_last_error = "OpenPhish feed request timed out"
            except Exception as e:
                _openphish_last_error = f"OpenPhish connection error: {str(e)}"

        return len(_openphish_urls) > 0

    async def lookup(self, target_url: str, domain: Optional[str] = None) -> Dict[str, Any]:
        """
        Check if target URL or domain appears in OpenPhish active phishing feed.
        Never treats an unavailable feed as a clean result.
        """
        feed_synced = await self.ensure_feed_synced()
        now_iso = datetime.now(timezone.utc).isoformat()
        normalized = normalize_threat_url(target_url)

        results: Dict[str, Any] = {
            "source": "OpenPhish Community Feed",
            "indicator_checked": normalized["canonical_url"],
            "lookup_timestamp": now_iso,
            "match_status": "NO_MATCH_FOUND",
            "found": False,
            "threat": None,
            "threat_category": None,
            "match_type": None,
            "matched_indicator": None,
            "feed_size": len(_openphish_urls),
            "last_synced": _openphish_last_fetched if _openphish_last_fetched > 0 else None,
            "confidence": None,
            "evidence_reference": None,
            "limitations": "Community feed contains active online phishing URLs from the past 12-24 hours.",
            "error": None,
        }

        if not feed_synced and len(_openphish_urls) == 0:
            results["match_status"] = "API_UNAVAILABLE"
            results["error"] = _openphish_last_error or "OpenPhish feed unavailable or offline."
            return results

        # 1. Check exact candidate URLs first
        for cand in normalized["lookup_candidates"]:
            if cand in _openphish_urls:
                results["found"] = True
                results["match_status"] = "THREAT_FOUND"
                results["threat"] = "Active Phishing / Credential Harvesting URL"
                results["threat_category"] = "Phishing / Social Engineering"
                results["match_type"] = "EXACT_URL"
                results["matched_indicator"] = cand
                results["confidence"] = "HIGH"
                results["evidence_reference"] = "Documented in OpenPhish real-time verified phishing stream"
                return results

        # 2. Check hostname / domain
        host = normalized["hostname"]
        reg_domain = normalized["registered_domain"]

        if host in _openphish_domains or reg_domain in _openphish_domains:
            matched_dom = host if host in _openphish_domains else reg_domain
            results["found"] = True
            results["match_status"] = "THREAT_FOUND"
            results["threat"] = f"Phishing Infrastructure Hosting ({matched_dom})"
            results["threat_category"] = "Phishing Infrastructure"
            results["match_type"] = "DOMAIN_MATCH"
            results["matched_indicator"] = matched_dom
            results["confidence"] = "MEDIUM"
            results["evidence_reference"] = f"Domain {matched_dom} is documented as hosting active phishing targets in OpenPhish"
            return results

        # 3. No match found
        results["match_status"] = "NO_MATCH_FOUND"
        results["found"] = False
        results["confidence"] = "HIGH"
        return results


openphish_client = OpenPhishClient()
