import re
import idna
import tldextract
import Levenshtein
from typing import Dict, Any, List, Optional
from urllib.parse import urlparse

PROTECTED_BRANDS = {
    "paypal": {
        "name": "PayPal",
        "primary_brand": "paypal",
        "legit_domains": ["paypal.com", "paypal.me", "paypal-community.com"],
        "known_patterns": ["paypal.com", "paypal"]
    },
    "chase": {
        "name": "Chase Bank",
        "primary_brand": "chase",
        "legit_domains": ["chase.com"],
        "known_patterns": ["chase.com", "chase"]
    },
    "apple": {
        "name": "Apple",
        "primary_brand": "apple",
        "legit_domains": ["apple.com", "icloud.com"],
        "known_patterns": ["apple.com", "icloud.com", "apple", "icloud"]
    },
    "google": {
        "name": "Google",
        "primary_brand": "google",
        "legit_domains": ["google.com", "google.co.uk", "google.ca", "google.co.in", "youtube.com"],
        "known_patterns": ["google.com", "google", "youtube.com"]
    },
    "microsoft": {
        "name": "Microsoft",
        "primary_brand": "microsoft",
        "legit_domains": ["microsoft.com", "live.com", "office.com", "outlook.com", "microsoftonline.com"],
        "known_patterns": ["microsoft.com", "live.com", "office.com", "microsoft"]
    },
    "netflix": {
        "name": "Netflix",
        "primary_brand": "netflix",
        "legit_domains": ["netflix.com"],
        "known_patterns": ["netflix.com", "netflix"]
    },
    "amazon": {
        "name": "Amazon",
        "primary_brand": "amazon",
        "legit_domains": ["amazon.com", "amazon.co.uk", "amazon.de", "amazon.in"],
        "known_patterns": ["amazon.com", "amazon"]
    },
    "wellsfargo": {
        "name": "Wells Fargo",
        "primary_brand": "wellsfargo",
        "legit_domains": ["wellsfargo.com"],
        "known_patterns": ["wellsfargo.com", "wellsfargo"]
    },
    "bankofamerica": {
        "name": "Bank of America",
        "primary_brand": "bankofamerica",
        "legit_domains": ["bankofamerica.com", "bofa.com"],
        "known_patterns": ["bankofamerica.com", "bofa.com", "bankofamerica"]
    },
    "dhl": {
        "name": "DHL",
        "primary_brand": "dhl",
        "legit_domains": ["dhl.com", "dhl.de"],
        "known_patterns": ["dhl.com", "dhl"]
    },
    "usps": {
        "name": "USPS",
        "primary_brand": "usps",
        "legit_domains": ["usps.com"],
        "known_patterns": ["usps.com", "usps"]
    },
    "fedex": {
        "name": "FedEx",
        "primary_brand": "fedex",
        "legit_domains": ["fedex.com"],
        "known_patterns": ["fedex.com", "fedex"]
    },
    "coinbase": {
        "name": "Coinbase",
        "primary_brand": "coinbase",
        "legit_domains": ["coinbase.com"],
        "known_patterns": ["coinbase.com", "coinbase"]
    },
    "binance": {
        "name": "Binance",
        "primary_brand": "binance",
        "legit_domains": ["binance.com"],
        "known_patterns": ["binance.com", "binance"]
    },
    "steam": {
        "name": "Steam",
        "primary_brand": "steam",
        "legit_domains": ["steampowered.com", "steamcommunity.com"],
        "known_patterns": ["steamcommunity.com", "steampowered.com", "steam"]
    },
}

SUSPICIOUS_KEYWORD_AFFIXES = [
    "login", "verify", "secure", "auth", "account", "update", "signin",
    "security", "support", "portal", "confirm", "service", "helpdesk",
    "security-check", "billing", "recovery", "password", "wallet"
]


class TyposquatDetector:
    """
    Public Suffix List-aware domain and brand impersonation forensics engine.
    Detects brand impersonation in subdomains, combosquatting, homoglyphs, and typos.
    """

    def __init__(self):
        # Use bundled offline snapshot to prevent network hangs on publicsuffix.org
        self.extractor = tldextract.TLDExtract(suffix_list_urls=None)

    def analyze(self, domain_or_url: str) -> Dict[str, Any]:
        ext = self.extractor(domain_or_url)
        registered_domain = f"{ext.domain}.{ext.suffix}" if ext.suffix else ext.domain
        subdomain = ext.subdomain.lower()
        full_host = ext.fqdn.lower()
        parsed = urlparse(domain_or_url if "://" in domain_or_url else f"https://{domain_or_url}")
        path = parsed.path.lower()

        results: Dict[str, Any] = {
            "registered_domain": registered_domain,
            "subdomain": subdomain,
            "full_host": full_host,
            "is_impersonation": False,
            "impersonated_brand": None,
            "legit_domain": None,
            "brand_in_subdomain": False,
            "brand_like_token": None,
            "similarity_ratio": 0.0,
            "techniques": [],
            "findings": [],
            "is_legit_brand_domain": False,
        }

        # 1. Homoglyph / Punycode check
        if full_host.startswith("xn--") or ".xn--" in full_host:
            results["techniques"].append("PUNYCODE_HOMOGRAPH")
            results["findings"].append({
                "id": "punycode-homograph",
                "category": "PUNYCODE_HOMOGRAPH",
                "title": "Internationalized lookalike characters",
                "concern_level": "HIGH_CONCERN",
                "plain_explanation": "This address uses internationalized punycode characters (xn--) that appear identical to ordinary letters but lead to a completely different server.",
                "technical_evidence": {"full_hostname": full_host},
            })

        # 2. Check each protected brand against legitimate domains first
        for brand_key, brand_info in PROTECTED_BRANDS.items():
            legit_domains = brand_info["legit_domains"]

            # If registered domain matches the official brand domain, it's NOT an impersonation
            if registered_domain in legit_domains or any(full_host.endswith(f".{d}") for d in legit_domains):
                results["is_legit_brand_domain"] = True
                results["impersonated_brand"] = brand_info["name"]
                results["legit_domain"] = legit_domains[0]
                return results

        # 3. Check for Misleading Brand in SUBDOMAINS (Critical Test 1 case)
        # e.g. "paypal.com.security-check.example.com"
        if subdomain:
            subdomain_parts = subdomain.split(".")
            for brand_key, brand_info in PROTECTED_BRANDS.items():
                legit_domains = brand_info["legit_domains"]
                patterns = brand_info.get("known_patterns", [brand_key])

                # Check if full brand domain or brand name is in the subdomain
                # e.g. "paypal.com" in "paypal.com.security-check"
                # or "paypal" in subdomain_parts
                has_brand_in_sub = False
                matched_pattern = None

                for pat in patterns:
                    if pat in subdomain:
                        has_brand_in_sub = True
                        matched_pattern = pat
                        break

                if not has_brand_in_sub:
                    for part in subdomain_parts:
                        # Check sub-part words (e.g. "paypal-security")
                        words = re.split(r"[-_]", part)
                        if brand_key in words or any(brand_key == w for w in words):
                            has_brand_in_sub = True
                            matched_pattern = brand_key
                            break

                if has_brand_in_sub:
                    # Verified: Subdomain references brand, but registered_domain is NOT legit!
                    results["is_impersonation"] = True
                    results["brand_in_subdomain"] = True
                    results["brand_like_token"] = matched_pattern
                    results["impersonated_brand"] = brand_info["name"]
                    results["legit_domain"] = legit_domains[0]
                    results["techniques"].append("MISLEADING_BRAND_SUBDOMAIN")

                    results["findings"].append({
                        "id": "misleading-brand-identity",
                        "category": "BRAND_IMPERSONATION",
                        "title": "Misleading website identity",
                        "concern_level": "HIGH_CONCERN",
                        "plain_explanation": (
                            f'The address contains "{matched_pattern}", but the actual registered website domain is "{registered_domain}". '
                            f'Scammers frequently place trusted brand names in subdomains to deceive visitors into thinking they are on the real website.'
                        ),
                        "technical_evidence": {
                            "brand_like_hostname": matched_pattern,
                            "actual_registered_domain": registered_domain,
                            "full_hostname": full_host,
                            "official_brand_domain": legit_domains[0],
                        },
                    })

                    results["findings"].append({
                        "id": "unusual-subdomain-structure",
                        "category": "SUBDOMAIN_ANALYSIS",
                        "title": "Unusual subdomain structure",
                        "concern_level": "MEDIUM_CONCERN",
                        "plain_explanation": (
                            f'The website uses a recognizable brand name in its subdomain hierarchy ({subdomain}), '
                            f'which is commonly used in deceptive phishing campaigns to bypass visual inspection.'
                        ),
                        "technical_evidence": {
                            "subdomain": subdomain,
                            "depth": len(subdomain_parts),
                        },
                    })
                    return results

        # 4. Check for Combosquatting in Registered Domain (e.g. chase-security.com)
        for brand_key, brand_info in PROTECTED_BRANDS.items():
            legit_domains = brand_info["legit_domains"]
            domain_name = ext.domain.lower()

            # Word boundary / hyphen split: "chase-auth", "chasesecurity"
            if brand_key in domain_name and registered_domain not in legit_domains:
                results["is_impersonation"] = True
                results["impersonated_brand"] = brand_info["name"]
                results["legit_domain"] = legit_domains[0]
                results["similarity_ratio"] = 0.90
                results["techniques"].append("COMBOSQUATTING")

                results["findings"].append({
                    "id": "combosquatting-domain",
                    "category": "BRAND_IMPERSONATION",
                    "title": f"Domain stitches brand name '{brand_info['name']}'",
                    "concern_level": "HIGH_CONCERN",
                    "plain_explanation": (
                        f'The domain name "{registered_domain}" includes the trademarked brand "{brand_info["name"]}", '
                        f'but is not owned or operated by {brand_info["name"]} (official: {legit_domains[0]}).'
                    ),
                    "technical_evidence": {
                        "registered_domain": registered_domain,
                        "brand_name": brand_info["name"],
                        "legit_domain": legit_domains[0],
                    },
                })

                # Check if it also uses deceptive security keywords
                for affix in SUSPICIOUS_KEYWORD_AFFIXES:
                    if affix in domain_name:
                        results["techniques"].append("CREDENTIAL_HARVESTING_AFFIX")
                        results["findings"].append({
                            "id": "credential-harvesting-affix",
                            "category": "DECEPTIVE_KEYWORD",
                            "title": f"Uses deceptive security lure '{affix}'",
                            "concern_level": "MEDIUM_CONCERN",
                            "plain_explanation": f'The address combines a brand name with the word "{affix}" to create a false impression of security.',
                            "technical_evidence": {"lure_word": affix},
                        })
                        break
                return results

            # 5. Check Levenshtein typo lookalike (e.g. paypa1.com, g00gle.com)
            for legit in legit_domains:
                legit_ext = self.extractor(legit)
                ratio = Levenshtein.ratio(domain_name, legit_ext.domain)
                distance = Levenshtein.distance(domain_name, legit_ext.domain)

                if 0 < distance <= 2 and ratio >= 0.80:
                    results["is_impersonation"] = True
                    results["impersonated_brand"] = brand_info["name"]
                    results["legit_domain"] = legit
                    results["similarity_ratio"] = round(ratio, 3)
                    results["techniques"].append("TYPOSQUATTING_LEVENSHTEIN")

                    results["findings"].append({
                        "id": "typosquatting-lookalike",
                        "category": "BRAND_IMPERSONATION",
                        "title": f"Misspelled lookalike of {brand_info['name']}",
                        "concern_level": "HIGH_CONCERN",
                        "plain_explanation": (
                            f'The domain "{domain_name}" is a deceptive misspelling of "{legit_ext.domain}". '
                            f'Fraudsters register visual lookalikes hoping users will mistype or fail to notice the slight difference.'
                        ),
                        "technical_evidence": {
                            "domain": domain_name,
                            "legit_target": legit_ext.domain,
                            "edit_distance": distance,
                            "similarity_ratio": ratio,
                        },
                    })
                    return results

        # 6. Deceptive Domain Structure & Authentication Lure Analysis
        # Generic heuristic analysis independent of specific brand trademarks
        if subdomain:
            subdomain_parts = [p for p in subdomain.split(".") if p]
            subdomain_tokens = [w for p in subdomain_parts for w in re.split(r"[-_]", p) if w]

            matched_subdomain_kws = [
                kw for kw in SUSPICIOUS_KEYWORD_AFFIXES
                if kw in subdomain_tokens or any(kw == t for t in subdomain_tokens) or any(kw in p for p in subdomain_parts)
            ]

            sensitive_action_paths = [
                "/update", "/login", "/verify", "/account", "/auth", "/signin",
                "/confirm", "/recovery", "/password", "/security", "/portal", "/wallet",
                "/billing", "/authenticate", "/validate"
            ]
            matched_path = next(
                (p for p in sensitive_action_paths if path == p or path.startswith(p + "/") or path.startswith(p + "?")),
                None
            )

            # Detect deceptive keyword chaining in subdomain (e.g. secure-login-verify-account)
            has_keyword_chain = len(matched_subdomain_kws) >= 2 or (
                len(matched_subdomain_kws) >= 1 and (matched_path is not None or len(subdomain_parts) >= 2)
            )

            if has_keyword_chain:
                results["deceptive_structure"] = True
                results["matched_subdomain_keywords"] = matched_subdomain_kws
                results["techniques"].append("DECEPTIVE_SUBDOMAIN_KEYWORDS")

                results["findings"].append({
                    "id": "deceptive-subdomain-keywords",
                    "category": "URL_STRUCTURE",
                    "title": "Deceptive authentication keywords in subdomain",
                    "concern_level": "MEDIUM_CONCERN",
                    "plain_explanation": (
                        f'The subdomain "{subdomain}" chains deceptive authentication and security keywords '
                        f'({", ".join(matched_subdomain_kws)}) commonly used in credential harvesting lures to mimic authentic verification portals.'
                    ),
                    "technical_evidence": {
                        "subdomain": subdomain,
                        "matched_keywords": matched_subdomain_kws,
                        "registered_domain": registered_domain,
                    },
                })

            # Detect sensitive action paths (e.g. /update, /login, /verify)
            if matched_path:
                results["sensitive_action_path"] = matched_path
                results["techniques"].append("SENSITIVE_ACTION_PATH")
                results["findings"].append({
                    "id": "sensitive-action-path",
                    "category": "URL_STRUCTURE",
                    "title": "Sensitive account action path",
                    "concern_level": "LOW_CONCERN",
                    "plain_explanation": (
                        f'The URL path "{path}" targets a sensitive account action ({matched_path}), '
                        f'a pattern frequently seen in credential harvesting and phishing lures.'
                    ),
                    "technical_evidence": {
                        "path": path,
                        "matched_action": matched_path,
                    },
                })

            # Detect high subdomain depth or complexity
            if len(subdomain_parts) >= 3 or len(subdomain_tokens) >= 4:
                results["findings"].append({
                    "id": "high-subdomain-depth",
                    "category": "SUBDOMAIN_ANALYSIS",
                    "title": "Unusual subdomain depth and complexity",
                    "concern_level": "LOW_CONCERN",
                    "plain_explanation": (
                        f'The website uses an unusually complex subdomain structure ({subdomain}), '
                        f'which can be used to obfuscate the real registered destination domain ({registered_domain}).'
                    ),
                    "technical_evidence": {
                        "subdomain": subdomain,
                        "depth": len(subdomain_parts),
                        "token_count": len(subdomain_tokens),
                        "registered_domain": registered_domain,
                    },
                })

        return results


typosquat_detector = TyposquatDetector()
