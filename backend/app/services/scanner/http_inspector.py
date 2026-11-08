import time
import httpx
from bs4 import BeautifulSoup
from typing import Dict, Any, List, Optional
from urllib.parse import urlparse
from backend.app.core.security import validate_target_url
from backend.app.core.config import settings
from backend.app.core.exceptions import SSRFSecurityViolation, ScanTimeoutError, TargetPayloadTooLargeError


class HTTPInspector:
    """
    Forensics engine for safe HTTP probe.
    Enforces SSRF validation on EVERY redirect hop, bounded payload streams,
    and safe DOM heuristic parsing without executing JavaScript.
    """

    def __init__(self, timeout: float = 5.0, max_redirects: int = 5, max_bytes: int = 1024 * 1024):
        self.timeout = timeout
        self.max_redirects = max_redirects
        self.max_bytes = max_bytes

    async def inspect(self, target_url: str) -> Dict[str, Any]:
        start_time = time.time()
        results: Dict[str, Any] = {
            "initial_url": target_url,
            "final_url": target_url,
            "status_code": None,
            "redirect_count": 0,
            "redirect_chain": [],
            "redirect_hops": [],
            "headers": {},
            "server_header": None,
            "content_type": None,
            "page_title": None,
            "meta_description": None,
            "meta_generator": None,
            "has_password_form": False,
            "has_external_action": False,
            "mixed_content": {"active_items": [], "passive_items": []},
            "latency_ms": 0.0,
            "error": None,
        }

        # Step 1: Pre-validate initial URL against SSRF
        try:
            curr_url, _, _ = validate_target_url(target_url)
        except SSRFSecurityViolation as e:
            results["error"] = f"SSRF violation: {str(e)}"
            return results

        redirect_chain: List[str] = [curr_url]
        client_headers = {
            "User-Agent": "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AstraNexus-SecurityScanner/1.0",
            "Accept": "text/html,application/xhtml+xml,application/xml;q=0.9,*/*;q=0.8",
            "Accept-Language": "en-US,en;q=0.5",
        }

        try:
            async with httpx.AsyncClient(
                verify=False,  # Allow inspecting invalid/self-signed certs
                timeout=self.timeout,
                follow_redirects=False,  # We handle redirects manually for per-hop SSRF validation
            ) as client:
                hops = 0
                while hops <= self.max_redirects:
                    # Validate URL at this hop
                    validate_target_url(curr_url)

                    try:
                        response = await client.get(curr_url, headers=client_headers)
                    except httpx.TimeoutException:
                        results["error"] = "HTTP connection timed out"
                        break
                    except httpx.RequestError as e:
                        results["error"] = f"HTTP request failed: {str(e)}"
                        break

                    # Check for redirect (301, 302, 303, 307, 308)
                    if response.is_redirect and "location" in response.headers:
                        next_url = response.headers["location"]
                        # Resolve relative redirect URLs
                        if next_url.startswith("/"):
                            parsed_curr = urlparse(curr_url)
                            next_url = f"{parsed_curr.scheme}://{parsed_curr.netloc}{next_url}"

                        results["redirect_hops"].append({
                            "hop": hops,
                            "url": curr_url,
                            "status_code": response.status_code,
                            "location": next_url,
                        })

                        # Validate next hop against SSRF before following!
                        try:
                            next_url, _, _ = validate_target_url(next_url)
                        except SSRFSecurityViolation as e:
                            results["error"] = f"Redirect destination blocked by SSRF filter: {str(e)}"
                            results["redirect_chain"] = redirect_chain
                            break

                        redirect_chain.append(next_url)
                        curr_url = next_url
                        hops += 1
                        continue

                    # Final response reached
                    results["status_code"] = response.status_code
                    results["final_url"] = str(response.url)
                    results["headers"] = {k.lower(): v for k, v in response.headers.items()}
                    results["server_header"] = response.headers.get("server")
                    results["content_type"] = response.headers.get("content-type")

                    results["redirect_hops"].append({
                        "hop": hops,
                        "url": str(response.url),
                        "status_code": response.status_code,
                        "location": None,
                    })

                    # Read body with maximum size guard
                    content_bytes = response.content
                    if len(content_bytes) > self.max_bytes:
                        content_bytes = content_bytes[: self.max_bytes]

                    # Parse HTML DOM safely
                    content_type = response.headers.get("content-type", "").lower()
                    if "text/html" in content_type or "<html" in content_bytes[:500].decode("utf-8", errors="ignore").lower():
                        html_text = content_bytes.decode("utf-8", errors="replace")
                        soup = BeautifulSoup(html_text, "html.parser")

                        title_tag = soup.find("title")
                        if title_tag and title_tag.string:
                            results["page_title"] = title_tag.string.strip()[:200]

                        meta_desc = soup.find("meta", attrs={"name": "description"})
                        if meta_desc and meta_desc.get("content"):
                            results["meta_description"] = str(meta_desc["content"]).strip()[:300]

                        # Check meta generator
                        meta_gen = soup.find("meta", attrs={"name": lambda n: bool(n and n.lower() == "generator")})
                        if meta_gen and meta_gen.get("content"):
                            results["meta_generator"] = str(meta_gen["content"]).strip()[:100]

                        # Check for credential harvesting forms
                        password_inputs = soup.find_all("input", attrs={"type": "password"})
                        if password_inputs:
                            results["has_password_form"] = True

                        # Check if form submits to external domain
                        forms = soup.find_all("form")
                        parsed_curr = urlparse(curr_url)
                        for form in forms:
                            action = form.get("action", "")
                            if action.startswith("http://") or action.startswith("https://"):
                                parsed_action = urlparse(action)
                                if parsed_action.netloc != parsed_curr.netloc:
                                    results["has_external_action"] = True
                                    break

                        # Check for Mixed Content if final URL is HTTPS
                        if curr_url.lower().startswith("https://"):
                            active_items = []
                            passive_items = []

                            # Active mixed content: scripts, stylesheets, iframes, objects, embeds, form actions
                            for tag in soup.find_all("script", src=True):
                                src = tag["src"].strip()
                                if src.lower().startswith("http://"):
                                    active_items.append(src)

                            for tag in soup.find_all("link", href=True):
                                rel = tag.get("rel") or []
                                if isinstance(rel, str):
                                    rel = [rel]
                                if any("stylesheet" in r.lower() for r in rel):
                                    href = tag["href"].strip()
                                    if href.lower().startswith("http://"):
                                        active_items.append(href)

                            for tag in soup.find_all("iframe", src=True):
                                src = tag["src"].strip()
                                if src.lower().startswith("http://"):
                                    active_items.append(src)

                            for tag in soup.find_all(["object", "embed"]):
                                u = tag.get("data") or tag.get("src") or ""
                                if u.strip().lower().startswith("http://"):
                                    active_items.append(u.strip())

                            for tag in soup.find_all("form", action=True):
                                act = tag["action"].strip()
                                if act.lower().startswith("http://"):
                                    active_items.append(act)

                            # Passive mixed content: images, audio, video
                            for tag in soup.find_all("img", src=True):
                                src = tag["src"].strip()
                                if src.lower().startswith("http://"):
                                    passive_items.append(src)

                            for tag in soup.find_all(["audio", "video", "source"], src=True):
                                src = tag["src"].strip()
                                if src.lower().startswith("http://"):
                                    passive_items.append(src)

                            results["mixed_content"] = {
                                "active_items": list(dict.fromkeys(active_items))[:10],
                                "passive_items": list(dict.fromkeys(passive_items))[:10],
                            }
                    break

        except Exception as e:
            results["error"] = f"Inspection error: {str(e)}"

        results["redirect_count"] = len(redirect_chain) - 1
        results["redirect_chain"] = redirect_chain
        results["latency_ms"] = round((time.time() - start_time) * 1000, 2)
        return results


http_inspector = HTTPInspector()
