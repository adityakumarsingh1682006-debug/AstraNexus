import time
import httpx
from typing import Dict, Any, Set, Optional
from urllib.parse import urlparse
from backend.app.core.config import settings

# In-memory storage for OpenPhish feed
_openphish_urls: Set[str] = set()
_openphish_domains: Set[str] = set()
_openphish_last_fetched: float = 0.0


class OpenPhishClient:
    """
    OpenPhish Real-Time Threat Intelligence Integration.
    Ingests and parses community phishing feeds with periodic automatic sync.
    """

    def __init__(self, feed_url: Optional[str] = None, sync_interval: float = 3600.0, timeout: float = 5.0):
        self.feed_url = feed_url or settings.OPENPHISH_FEED_URL
        self.sync_interval = sync_interval
        self.timeout = timeout

    async def ensure_feed_synced(self) -> bool:
        """
        Synchronizes OpenPhish feed if cache has expired or is empty.
        """
        global _openphish_urls, _openphish_domains, _openphish_last_fetched
        now = time.time()

        if _openphish_urls and (now - _openphish_last_fetched < self.sync_interval):
            return True  # Feed is fresh

        try:
            timeout_cfg = httpx.Timeout(self.timeout, connect=min(2.0, self.timeout))
            async with httpx.AsyncClient(timeout=timeout_cfg) as client:
                response = await client.get(
                    self.feed_url,
                    headers={"User-Agent": "AstraNexus-ThreatIntelligence/1.0"},
                )

                if response.status_code == 200:
                    lines = response.text.strip().splitlines()
                    new_urls = set()
                    new_domains = set()

                    for line in lines:
                        clean_line = line.strip()
                        if clean_line and not clean_line.startswith("#"):
                            new_urls.add(clean_line.lower())
                            try:
                                parsed = urlparse(clean_line)
                                if parsed.netloc:
                                    new_domains.add(parsed.netloc.lower())
                            except Exception:
                                pass

                    _openphish_urls = new_urls
                    _openphish_domains = new_domains
                    _openphish_last_fetched = now
                    return True

        except Exception:
            # If fetch fails (e.g. rate limit, offline sandbox), keep existing entries if any
            pass

        return len(_openphish_urls) > 0

    async def lookup(self, target_url: str, domain: Optional[str] = None) -> Dict[str, Any]:
        """
        Check if target URL or domain appears in OpenPhish active phishing feed.
        """
        await self.ensure_feed_synced()

        clean_url = target_url.strip().lower()
        clean_domain = (domain or urlparse(clean_url).netloc).strip().lower()
        if ":" in clean_domain:
            clean_domain = clean_domain.split(":")[0]

        is_url_match = clean_url in _openphish_urls
        is_domain_match = clean_domain in _openphish_domains

        found = is_url_match or is_domain_match

        return {
            "source": "OpenPhish",
            "found": found,
            "threat_category": "Phishing / Social Engineering" if found else None,
            "match_type": "EXACT_URL" if is_url_match else ("DOMAIN_MATCH" if is_domain_match else None),
            "feed_size": len(_openphish_urls),
            "last_synced": _openphish_last_fetched if _openphish_last_fetched > 0 else None,
        }


openphish_client = OpenPhishClient()
