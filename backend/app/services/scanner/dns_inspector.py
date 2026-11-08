import time
from typing import Dict, List, Any, Optional
import dns.resolver
import dns.exception


class DNSInspector:
    """
    Asynchronous and robust DNS forensics engine.
    Collects A, AAAA, MX, NS, and TXT records with latency measurement.
    """

    def __init__(self, timeout: float = 1.5):
        self.resolver = dns.resolver.Resolver()
        self.resolver.lifetime = timeout
        self.resolver.timeout = timeout
        # Use standard reliable public DNS as fallback
        self.resolver.nameservers = ["1.1.1.1", "8.8.8.8", "9.9.9.9"]

    def inspect(self, domain: str) -> Dict[str, Any]:
        clean_domain = domain.strip().lower()
        if ":" in clean_domain:
            clean_domain = clean_domain.split(":")[0]

        start_time = time.time()
        results: Dict[str, Any] = {
            "domain": clean_domain,
            "a_records": [],
            "aaaa_records": [],
            "mx_records": [],
            "ns_records": [],
            "txt_records": [],
            "has_mx": False,
            "has_spf": False,
            "has_dmarc": False,
            "resolution_time_ms": 0.0,
            "error": None,
        }

        # Resolve A records (IPv4)
        try:
            answers = self.resolver.resolve(clean_domain, "A")
            results["a_records"] = [r.to_text() for r in answers]
        except (dns.resolver.NoAnswer, dns.resolver.NXDOMAIN):
            pass
        except Exception as e:
            results["error"] = f"A record lookup failed: {str(e)}"

        # Resolve AAAA records (IPv6)
        try:
            answers = self.resolver.resolve(clean_domain, "AAAA")
            results["aaaa_records"] = [r.to_text() for r in answers]
        except Exception:
            pass

        # Resolve MX records (Mail eXchange)
        try:
            answers = self.resolver.resolve(clean_domain, "MX")
            results["mx_records"] = [r.exchange.to_text().rstrip(".") for r in answers]
            results["has_mx"] = len(results["mx_records"]) > 0
        except Exception:
            pass

        # Resolve NS records (Authoritative Nameservers)
        try:
            answers = self.resolver.resolve(clean_domain, "NS")
            results["ns_records"] = [r.target.to_text().rstrip(".") for r in answers]
        except Exception:
            pass

        # Resolve TXT records (SPF / DMARC verification)
        try:
            answers = self.resolver.resolve(clean_domain, "TXT")
            for r in answers:
                txt_str = b"".join(r.strings).decode("utf-8", errors="replace")
                results["txt_records"].append(txt_str)
                if "v=spf1" in txt_str.lower():
                    results["has_spf"] = True
        except Exception:
            pass

        # Check DMARC
        try:
            dmarc_host = f"_dmarc.{clean_domain}"
            answers = self.resolver.resolve(dmarc_host, "TXT")
            for r in answers:
                txt_str = b"".join(r.strings).decode("utf-8", errors="replace")
                if "v=dmarc1" in txt_str.lower():
                    results["has_dmarc"] = True
        except Exception:
            pass

        results["resolution_time_ms"] = round((time.time() - start_time) * 1000, 2)
        return results


dns_inspector = DNSInspector()
