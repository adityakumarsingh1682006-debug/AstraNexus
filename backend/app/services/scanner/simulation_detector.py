from typing import Dict, Any, Optional, List
from urllib.parse import urlparse
import tldextract


# Recognized industry cybersecurity test suites, phishing awareness platforms, and diagnostic benchmarks
KNOWN_SECURITY_SIMULATIONS = [
    {
        "suite_id": "google-safe-browsing-test",
        "name": "Google Safe Browsing Diagnostic Test Suite",
        "provider": "Google Safe Browsing",
        "host_patterns": ["testsafebrowsing.appspot.com"],
        "path_rules": [
            {"path_prefix": "/s/phishing.html", "type": "PHISHING_SIMULATION", "label": "Google Safe Browsing Phishing Test Page"},
            {"path_prefix": "/s/malware.html", "type": "MALWARE_SIMULATION", "label": "Google Safe Browsing Malware Test Page"},
            {"path_prefix": "/s/unwanted.html", "type": "UNWANTED_SOFTWARE_SIMULATION", "label": "Google Safe Browsing Unwanted Software Test Page"},
        ],
        "default_type": "SECURITY_DIAGNOSTIC_TEST",
        "description": "An official diagnostic test page provided by Google to verify whether browser and endpoint anti-phishing protections are functioning correctly.",
        "reference_url": "https://developers.google.com/safe-browsing",
    },
    {
        "suite_id": "badssl-test",
        "name": "BadSSL Certificate Diagnostic Suite",
        "provider": "Chromium / WICG",
        "host_patterns": ["badssl.com"],
        "path_rules": [],
        "default_type": "TLS_SECURITY_SIMULATION",
        "description": "A diagnostic test harness used to test browser, TLS client, and scanner handling of broken or misconfigured SSL/TLS certificates.",
        "reference_url": "https://badssl.com",
    },
    {
        "suite_id": "eicar-antivirus-test",
        "name": "EICAR Standard Anti-Malware Test Suite",
        "provider": "European Institute for Computer Antivirus Research",
        "host_patterns": ["eicar.org"],
        "path_rules": [
            {"path_prefix": "/download/", "type": "MALWARE_SIMULATION", "label": "EICAR Standard Anti-Virus Test File"},
        ],
        "default_type": "SECURITY_DIAGNOSTIC_TEST",
        "description": "The international standard benign test pattern used to verify that anti-malware and file inspection scanners are operational without deploying real malware.",
        "reference_url": "https://www.eicar.org",
    },
    {
        "suite_id": "amtso-feature-check",
        "name": "AMTSO Security Feature Check",
        "provider": "Anti-Malware Testing Standards Organization",
        "host_patterns": ["amtso.org"],
        "path_rules": [
            {"path_prefix": "/check-desktop-phishing-page", "type": "PHISHING_SIMULATION", "label": "AMTSO Phishing Feature Check"},
            {"path_prefix": "/check-desktop-drive-by-download", "type": "MALWARE_SIMULATION", "label": "AMTSO Drive-by Download Feature Check"},
        ],
        "default_type": "SECURITY_DIAGNOSTIC_TEST",
        "description": "Industry benchmark test pages used to validate that security solutions detect standard security feature triggers.",
        "reference_url": "https://www.amtso.org",
    },
    {
        "suite_id": "w3c-web-platform-tests",
        "name": "W3C Web Platform Test Suite",
        "provider": "W3C / WHATWG",
        "host_patterns": ["wpt.live", "web-platform.test"],
        "path_rules": [],
        "default_type": "SECURITY_DIAGNOSTIC_TEST",
        "description": "Official W3C web platform security and specification conformance test suite.",
        "reference_url": "https://wpt.fyi",
    },
]


class SimulationDetector:
    """
    Forensics engine to identify known cybersecurity test suites, phishing simulations,
    and diagnostic benchmark pages.
    
    Prevents false negatives (e.g., classifying a phishing test page as ordinary safe web)
    and false positives (e.g., claiming a test page is an active criminal attack).
    """

    def __init__(self):
        self.extractor = tldextract.TLDExtract(suffix_list_urls=None)

    def analyze(self, target_url: str) -> Dict[str, Any]:
        """
        Evaluates whether a target URL or domain belongs to a recognized security test suite.
        """
        parsed = urlparse(target_url if "://" in target_url else f"http://{target_url}")
        host = (parsed.hostname or "").lower().strip()
        path = parsed.path.lower()

        results: Dict[str, Any] = {
            "is_simulation": False,
            "suite_id": None,
            "suite_name": None,
            "provider": None,
            "simulation_type": None,
            "label": None,
            "description": None,
            "reference_url": None,
        }

        if not host:
            return results

        ext = self.extractor(host)
        registered_domain = f"{ext.domain}.{ext.suffix}" if ext.suffix else ext.domain

        for suite in KNOWN_SECURITY_SIMULATIONS:
            matched_host = False
            for pattern in suite["host_patterns"]:
                if host == pattern or host.endswith(f".{pattern}"):
                    matched_host = True
                    break

            if matched_host:
                results["is_simulation"] = True
                results["suite_id"] = suite["suite_id"]
                results["suite_name"] = suite["name"]
                results["provider"] = suite["provider"]
                results["description"] = suite["description"]
                results["reference_url"] = suite["reference_url"]
                results["simulation_type"] = suite["default_type"]
                results["label"] = f"{suite['name']} Benchmark"

                # Check path rules for specific simulated attack type (e.g., /s/phishing.html)
                for rule in suite.get("path_rules", []):
                    prefix = rule["path_prefix"].lower()
                    if path.startswith(prefix) or prefix in path:
                        results["simulation_type"] = rule["type"]
                        results["label"] = rule["label"]
                        break

                return results

        return results


simulation_detector = SimulationDetector()
