import urllib.parse
from typing import Dict, Any, List
import tldextract

# Use local bundled PSL snapshot to avoid network blocking or latency
_tld_extractor = tldextract.TLDExtract(suffix_list_urls=None)


def normalize_threat_url(raw_url: str) -> Dict[str, Any]:
    """
    Normalizes a URL or hostname for threat intelligence lookups.
    Generates deterministic candidate indicators (exact URL, stripped query, alternate scheme,
    root host, and registered domain) according to provider capabilities.
    """
    clean = raw_url.strip()
    if not clean.lower().startswith(("http://", "https://")):
        clean = "http://" + clean

    parsed = urllib.parse.urlsplit(clean)
    scheme = parsed.scheme.lower()
    netloc = parsed.netloc.lower()

    # Normalize default ports
    if ":" in netloc:
        host, port = netloc.split(":", 1)
        if (scheme == "http" and port == "80") or (scheme == "https" and port == "443"):
            netloc = host
    else:
        host = netloc

    ext = _tld_extractor(host)
    reg_dom = getattr(ext, "top_domain_under_public_suffix", None) or getattr(ext, "registered_domain", None) or host
    registered_domain = reg_dom.lower()

    path = parsed.path or "/"
    # Collapse duplicate slashes in path
    while "//" in path:
        path = path.replace("//", "/")

    query = f"?{parsed.query}" if parsed.query else ""
    canonical = f"{scheme}://{netloc}{path}{query}"
    no_query = f"{scheme}://{netloc}{path}"
    alt_scheme = "https" if scheme == "http" else "http"

    candidates: List[str] = [
        canonical.lower(),
        no_query.lower(),
        f"{alt_scheme}://{netloc}{path}{query}".lower(),
        f"{alt_scheme}://{netloc}{path}".lower(),
        f"{scheme}://{netloc}/".lower(),
        f"{alt_scheme}://{netloc}/".lower(),
        host.lower(),
        registered_domain.lower(),
    ]

    # Remove duplicates preserving order
    seen = set()
    unique_candidates: List[str] = [c for c in candidates if not (c in seen or seen.add(c))]

    return {
        "canonical_url": canonical,
        "url_no_query": no_query,
        "hostname": host,
        "registered_domain": registered_domain,
        "path": path,
        "lookup_candidates": unique_candidates,
    }
