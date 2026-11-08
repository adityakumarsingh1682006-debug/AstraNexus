from typing import Dict, Any, List, Optional
from urllib.parse import urlparse
import re


class WebsiteSecurityAssessor:
    """
    Safe, passive website security assessment engine.
    Inspects response headers, transport encryption, redirect hygiene,
    DOM mixed-content indicators, and disclosed software banners.

    Security Boundaries Enforced:
    - Zero active exploit probing
    - Zero port scanning or path brute-forcing
    - Strictly non-intrusive passive observation
    - Does NOT confuse missing security headers with proof of fraud
    """

    KNOWN_SOFTWARE_CVES = {
        "apache/2.4.49": {
            "cve": "CVE-2021-41773",
            "title": "Apache 2.4.49 Path Traversal and Remote Code Execution",
            "severity": "CRITICAL",
            "description": "A flaw was found in a change made to path normalization in Apache HTTP Server 2.4.49. An attacker could use a path traversal attack to map URLs to files outside the expected document root.",
            "remediation": "Upgrade Apache HTTP Server to version 2.4.51 or later immediately.",
        },
        "apache/2.4.50": {
            "cve": "CVE-2021-42013",
            "title": "Apache 2.4.50 Path Traversal and RCE Incomplete Fix",
            "severity": "CRITICAL",
            "description": "It was found that the fix for CVE-2021-41773 in Apache HTTP Server 2.4.50 was insufficient, permitting path traversal and potential remote script execution if CGI is enabled.",
            "remediation": "Upgrade Apache HTTP Server to version 2.4.51 or later.",
        },
        "openssl/1.0.1": {
            "cve": "CVE-2014-0160",
            "title": "OpenSSL Heartbleed TLS Information Disclosure",
            "severity": "CRITICAL",
            "description": "The TLS heartbeat implementation in OpenSSL 1.0.1 allows remote attackers to obtain private memory contents including private keys and user credentials.",
            "remediation": "Upgrade OpenSSL to a supported, patched release immediately.",
        },
    }

    def assess(
        self,
        target_url: str,
        http_data: Dict[str, Any],
        ssl_data: Optional[Dict[str, Any]] = None,
    ) -> Dict[str, Any]:
        """
        Runs comprehensive, passive website security assessment.
        """
        ssl_res = ssl_data or {}
        findings: List[Dict[str, Any]] = []

        headers = {k.lower(): v for k, v in (http_data.get("headers") or {}).items()}
        status_code = http_data.get("status_code")
        final_url = http_data.get("final_url") or target_url
        parsed_final = urlparse(final_url)
        is_https = parsed_final.scheme.lower() == "https"

        # -------------------------------------------------------------
        # 1. HTTP Security Headers Analysis
        # -------------------------------------------------------------
        headers_eval: Dict[str, Any] = {}

        # A. Content-Security-Policy (CSP)
        csp_val = headers.get("content-security-policy")
        if csp_val:
            csp_val_clean = csp_val.strip()
            is_permissive = "unsafe-inline" in csp_val_clean or "unsafe-eval" in csp_val_clean or "default-src *" in csp_val_clean
            if is_permissive:
                headers_eval["content_security_policy"] = {
                    "header_name": "Content-Security-Policy",
                    "present": True,
                    "value": csp_val_clean,
                    "status": "WARNING",
                    "summary": "Present with permissive directives ('unsafe-inline' or 'unsafe-eval').",
                }
                findings.append({
                    "id": "sec-csp-permissive",
                    "title": "Permissive Content-Security-Policy Directives",
                    "severity": "LOW",
                    "technical_evidence": {"header": "Content-Security-Policy", "observed": csp_val_clean[:200]},
                    "potential_impact": "Permits execution of inline JavaScript or eval functions, reducing the policy's effectiveness against Cross-Site Scripting (XSS).",
                    "recommended_remediation": "Refactor inline scripts to static assets and replace 'unsafe-inline' with cryptographic nonces or hashes.",
                    "limitations": "Evaluated via static token inspection without dynamic execution of client scripts.",
                })
            else:
                headers_eval["content_security_policy"] = {
                    "header_name": "Content-Security-Policy",
                    "present": True,
                    "value": csp_val_clean,
                    "status": "SECURE",
                    "summary": "Valid Content-Security-Policy enforced.",
                }
        else:
            headers_eval["content_security_policy"] = {
                "header_name": "Content-Security-Policy",
                "present": False,
                "value": None,
                "status": "MISSING",
                "summary": "Missing Content-Security-Policy header.",
            }
            findings.append({
                "id": "sec-csp-missing",
                "title": "Missing Content-Security-Policy (CSP) Header",
                "severity": "MEDIUM",
                "technical_evidence": {"header": "Content-Security-Policy", "observed": "Not Present"},
                "potential_impact": "The browser has no restricted policy for loading scripts, styles, or iframes, increasing exposure to Cross-Site Scripting (XSS) and data injection.",
                "recommended_remediation": "Deploy a Content-Security-Policy header defining trusted sources (e.g., default-src 'self'; script-src 'self').",
                "limitations": "Passive header inspection. The application may employ meta-tag policies or frontend framework sanitization.",
            })

        # B. Strict-Transport-Security (HSTS)
        hsts_val = headers.get("strict-transport-security")
        if hsts_val:
            hsts_val_clean = hsts_val.strip().lower()
            max_age_match = re.search(r"max-age=(\d+)", hsts_val_clean)
            max_age = int(max_age_match.group(1)) if max_age_match else 0
            has_subdomains = "includesubdomains" in hsts_val_clean
            has_preload = "preload" in hsts_val_clean

            if max_age < 10368000:  # < 120 days
                headers_eval["strict_transport_security"] = {
                    "header_name": "Strict-Transport-Security",
                    "present": True,
                    "value": hsts_val,
                    "status": "WARNING",
                    "summary": f"Present with short duration ({max_age}s; recommended >= 31536000s).",
                }
                findings.append({
                    "id": "sec-hsts-short-duration",
                    "title": "Short HSTS max-age Duration",
                    "severity": "LOW",
                    "technical_evidence": {"header": "Strict-Transport-Security", "observed": hsts_val, "max_age_seconds": max_age},
                    "potential_impact": "The HSTS duration window is shorter than the recommended 1 year (31,536,000s), limiting long-term SSL-stripping protection.",
                    "recommended_remediation": "Increase max-age to at least 31536000 seconds (1 year) and consider adding includeSubDomains and preload.",
                    "limitations": "Domain may still enforce HTTPS via reverse-proxy 301 redirects.",
                })
            else:
                headers_eval["strict_transport_security"] = {
                    "header_name": "Strict-Transport-Security",
                    "present": True,
                    "value": hsts_val,
                    "status": "SECURE",
                    "summary": f"HSTS enforced ({max_age}s duration" + (", with subdomains" if has_subdomains else "") + (", preload ready" if has_preload else "") + ").",
                }
        elif is_https:
            headers_eval["strict_transport_security"] = {
                "header_name": "Strict-Transport-Security",
                "present": False,
                "value": None,
                "status": "MISSING",
                "summary": "Missing Strict-Transport-Security (HSTS) header on HTTPS website.",
            }
            findings.append({
                "id": "sec-hsts-missing",
                "title": "Missing Strict-Transport-Security (HSTS) Header",
                "severity": "MEDIUM",
                "technical_evidence": {"header": "Strict-Transport-Security", "observed": "Not Present", "transport": "HTTPS"},
                "potential_impact": "Browsers are not mandated to enforce encrypted connections, leaving first-time visitors vulnerable to SSL-stripping attacks on insecure Wi-Fi.",
                "recommended_remediation": "Configure your web server or CDN to send 'Strict-Transport-Security: max-age=31536000; includeSubDomains; preload'.",
                "limitations": "Check does not verify whether the domain is hardcoded in the Chromium HSTS preload list.",
            })
        else:
            headers_eval["strict_transport_security"] = {
                "header_name": "Strict-Transport-Security",
                "present": False,
                "value": None,
                "status": "INSECURE",
                "summary": "HSTS not applicable (website served over unencrypted HTTP).",
            }

        # C. X-Content-Type-Options
        xcto_val = headers.get("x-content-type-options")
        if xcto_val and "nosniff" in xcto_val.lower():
            headers_eval["x_content_type_options"] = {
                "header_name": "X-Content-Type-Options",
                "present": True,
                "value": xcto_val,
                "status": "SECURE",
                "summary": "Configured correctly ('nosniff').",
            }
        else:
            headers_eval["x_content_type_options"] = {
                "header_name": "X-Content-Type-Options",
                "present": bool(xcto_val),
                "value": xcto_val,
                "status": "MISSING" if not xcto_val else "WARNING",
                "summary": "Missing 'nosniff' MIME protection." if not xcto_val else f"Unexpected value: {xcto_val}",
            }
            findings.append({
                "id": "sec-xcto-missing",
                "title": "Missing X-Content-Type-Options: nosniff Header",
                "severity": "LOW",
                "technical_evidence": {"header": "X-Content-Type-Options", "observed": xcto_val or "Not Present"},
                "potential_impact": "Older or non-standard browsers may perform MIME sniffing on untyped downloads, potentially treating user-uploaded images or text as executable JavaScript.",
                "recommended_remediation": "Add the response header: 'X-Content-Type-Options: nosniff'.",
                "limitations": "Modern evergreen browsers use strict MIME handling for scripts and stylesheets by default.",
            })

        # D. Frame Protection (X-Frame-Options & CSP frame-ancestors)
        xfo_val = headers.get("x-frame-options")
        csp_frame_ancestors = "frame-ancestors" in (csp_val or "").lower()

        if (xfo_val and xfo_val.strip().upper() in ("DENY", "SAMEORIGIN")) or csp_frame_ancestors:
            evidence_label = f"X-Frame-Options: {xfo_val}" if xfo_val else "CSP frame-ancestors"
            headers_eval["frame_protection"] = {
                "header_name": "Frame Protection (Clickjacking)",
                "present": True,
                "value": evidence_label,
                "status": "SECURE",
                "summary": f"Clickjacking protection active ({evidence_label}).",
            }
        else:
            headers_eval["frame_protection"] = {
                "header_name": "Frame Protection (Clickjacking)",
                "present": bool(xfo_val),
                "value": xfo_val,
                "status": "MISSING",
                "summary": "Missing X-Frame-Options or CSP frame-ancestors directive.",
            }
            findings.append({
                "id": "sec-frame-protection-missing",
                "title": "Missing Anti-Clickjacking Frame Protection",
                "severity": "MEDIUM",
                "technical_evidence": {"X-Frame-Options": xfo_val or "Not Present", "CSP frame-ancestors": "Not Present"},
                "potential_impact": "The website can be embedded in an invisible iframe on a third-party site, exposing users to UI redressing (Clickjacking) attacks.",
                "recommended_remediation": "Add 'X-Frame-Options: SAMEORIGIN' (or 'DENY'), or include 'frame-ancestors 'self'' in your Content-Security-Policy.",
                "limitations": "Cross-Origin-Opener-Policy (COOP) and SameSite cookies on modern browsers provide defense against certain state-changing iframe attacks.",
            })

        # E. Referrer-Policy
        ref_val = headers.get("referrer-policy")
        if ref_val:
            ref_clean = ref_val.strip().lower()
            if ref_clean in ("unsafe-url", "no-referrer-when-downgrade"):
                headers_eval["referrer_policy"] = {
                    "header_name": "Referrer-Policy",
                    "present": True,
                    "value": ref_val,
                    "status": "WARNING",
                    "summary": f"Permissive policy ('{ref_clean}').",
                }
                findings.append({
                    "id": "sec-referrer-policy-permissive",
                    "title": "Permissive Referrer-Policy Configuration",
                    "severity": "LOW",
                    "technical_evidence": {"header": "Referrer-Policy", "observed": ref_val},
                    "potential_impact": "Full page URLs including query parameters may be transmitted to external third-party origins in the Referer header.",
                    "recommended_remediation": "Configure 'Referrer-Policy: strict-origin-when-cross-origin' or 'no-referrer'.",
                    "limitations": "Browsers may automatically truncate cross-origin referrers to the origin only.",
                })
            else:
                headers_eval["referrer_policy"] = {
                    "header_name": "Referrer-Policy",
                    "present": True,
                    "value": ref_val,
                    "status": "SECURE",
                    "summary": f"Referrer-Policy enforced ('{ref_clean}').",
                }
        else:
            headers_eval["referrer_policy"] = {
                "header_name": "Referrer-Policy",
                "present": False,
                "value": None,
                "status": "INFO",
                "summary": "Missing Referrer-Policy header (browsers default to strict-origin-when-cross-origin).",
            }
            findings.append({
                "id": "sec-referrer-policy-missing",
                "title": "Missing Explicit Referrer-Policy Header",
                "severity": "INFO",
                "technical_evidence": {"header": "Referrer-Policy", "observed": "Not Present"},
                "potential_impact": "Relies on default browser behavior rather than an explicit server-mandated privacy policy for referrer data.",
                "recommended_remediation": "Explicitly declare 'Referrer-Policy: strict-origin-when-cross-origin'.",
                "limitations": "Evergreen browsers default to strict-origin-when-cross-origin when omitted.",
            })

        # -------------------------------------------------------------
        # 2. HTTPS Configuration & Transport Security
        # -------------------------------------------------------------
        has_ssl = ssl_res.get("has_ssl", is_https or bool(ssl_res.get("cert")) or bool(ssl_res.get("issuer_organization")))
        is_http_only = ssl_res.get("is_http_only", not is_https)
        chain_verified = ssl_res.get("chain_verified", True)
        is_expired = ssl_res.get("is_expired", False)
        hostname_mismatch = ssl_res.get("hostname_mismatch", False)
        is_self_signed = ssl_res.get("is_self_signed", False)
        is_valid_ssl = (ssl_res.get("is_valid", True) is not False) and not is_expired and not hostname_mismatch

        http_to_https_redirect = False
        redirect_chain = http_data.get("redirect_chain")
        if not redirect_chain:
            raw_hops = http_data.get("redirect_hops") or []
            if raw_hops:
                urls = []
                for h in raw_hops:
                    u = h.get("url") or h.get("from_url")
                    if u and u not in urls:
                        urls.append(u)
                    dest = h.get("location") or h.get("to_url")
                    if dest and dest not in urls:
                        urls.append(dest)
                redirect_chain = urls if urls else [target_url, final_url] if target_url != final_url else [target_url]
            elif target_url != final_url:
                redirect_chain = [target_url, final_url]
            else:
                redirect_chain = [target_url]

        if target_url.lower().startswith("http://") and final_url.lower().startswith("https://"):
            http_to_https_redirect = True

        if is_http_only or not is_https:
            findings.append({
                "id": "sec-transport-unencrypted",
                "title": "Unencrypted HTTP Transport",
                "severity": "HIGH",
                "technical_evidence": {"initial_url": target_url, "final_url": final_url, "scheme": "http"},
                "potential_impact": "Traffic, cookies, and sensitive form inputs are transmitted in plaintext across the network, vulnerable to interception or modification.",
                "recommended_remediation": "Install a trusted TLS certificate and configure a permanent 301 redirect from HTTP to HTTPS.",
                "limitations": "Tested on standard web ports 80 and 443.",
            })

        if has_ssl and not is_valid_ssl:
            findings.append({
                "id": "sec-ssl-invalid",
                "title": "Invalid or Expired TLS Certificate",
                "severity": "HIGH",
                "technical_evidence": {"reason": ssl_res.get("error_message") or "Certificate validation failed"},
                "potential_impact": "Connections to this website are not authenticated, allowing attackers to perform Man-in-the-Middle (MITM) attacks.",
                "recommended_remediation": "Renew or replace your TLS certificate with a valid certificate from a trusted Certificate Authority.",
                "limitations": "Tested against public Web PKI standards.",
            })

        if has_ssl and not chain_verified:
            findings.append({
                "id": "sec-tls-untrusted-chain",
                "title": "Untrusted Certificate Chain",
                "severity": "HIGH",
                "technical_evidence": {"issuer": ssl_res.get("issuer_organization"), "error": ssl_res.get("verification_error")},
                "potential_impact": "Web browsers will display a full-page security warning; connection cannot be verified against official trust stores.",
                "recommended_remediation": "Install the complete intermediate certificate bundle provided by your Certificate Authority.",
                "limitations": "Verified against Mozilla Root Store trust roots.",
            })

        # -------------------------------------------------------------
        # 3. Redirect Chain Analysis
        # -------------------------------------------------------------
        redirect_hops: List[Dict[str, Any]] = []
        raw_hops = http_data.get("redirect_hops") or []
        has_cross_domain = False
        has_downgrade = False

        prev_parsed = urlparse(target_url)
        for idx, u in enumerate(redirect_chain):
            curr_p = urlparse(u)
            is_cd = curr_p.netloc.lower() != prev_parsed.netloc.lower() if idx > 0 else False
            is_dg = (prev_parsed.scheme.lower() == "https" and curr_p.scheme.lower() == "http") if idx > 0 else False
            if is_cd:
                has_cross_domain = True
            if is_dg:
                has_downgrade = True

            hop_info = {
                "hop_number": idx,
                "url": u,
                "domain": curr_p.netloc,
                "scheme": curr_p.scheme,
                "is_cross_domain": is_cd,
                "is_downgrade": is_dg,
            }
            redirect_hops.append(hop_info)
            prev_parsed = curr_p

        if has_downgrade:
            findings.append({
                "id": "sec-redirect-downgrade",
                "title": "Protocol Downgrade During Redirection (HTTPS to HTTP)",
                "severity": "HIGH",
                "technical_evidence": {"redirect_chain": redirect_chain},
                "potential_impact": "An encrypted HTTPS session was redirected onto an unencrypted HTTP connection, stripping transport security.",
                "recommended_remediation": "Update redirection rules to ensure all redirection destinations preserve or upgrade to HTTPS.",
                "limitations": "Evaluated passively based on server Location response headers.",
            })

        if has_cross_domain and len(redirect_chain) > 1:
            findings.append({
                "id": "sec-redirect-cross-domain",
                "title": "Cross-Domain Redirection Observed",
                "severity": "MEDIUM",
                "technical_evidence": {
                    "initial_domain": urlparse(target_url).netloc,
                    "final_domain": parsed_final.netloc,
                    "hops": len(redirect_chain) - 1,
                },
                "potential_impact": "User is forwarded across separate domain identities. While common in marketing links, it is also frequently used in phishing redirects.",
                "recommended_remediation": "Verify that cross-domain destinations are intentional, documented, and preserve user trust.",
                "limitations": "Passive inspection cannot determine business relationship between distinct domain owners.",
            })

        redirect_analysis = {
            "initial_url": target_url,
            "final_url": final_url,
            "redirect_count": len(redirect_chain) - 1,
            "has_redirects": len(redirect_chain) > 1,
            "has_cross_domain": has_cross_domain,
            "has_protocol_downgrade": has_downgrade,
            "chain": redirect_hops,
            "summary": (
                f"Direct connection ({parsed_final.netloc})"
                if len(redirect_chain) <= 1
                else f"{len(redirect_chain)-1} redirect hop(s) ending at {parsed_final.netloc}"
                + (" (Cross-domain)" if has_cross_domain else "")
                + (" (Downgrade warning!)" if has_downgrade else "")
            ),
        }

        # -------------------------------------------------------------
        # 4. Mixed Content Forensics (HTTPS Only)
        # -------------------------------------------------------------
        mixed_content_data = http_data.get("mixed_content") or {}
        active_items = mixed_content_data.get("active_items") or []
        passive_items = mixed_content_data.get("passive_items") or []
        has_mixed = bool(active_items or passive_items)

        if is_https and active_items:
            findings.append({
                "id": "sec-mixed-content-active",
                "title": "Active Mixed Content Detected",
                "severity": "HIGH",
                "technical_evidence": {"active_elements_count": len(active_items), "sample": active_items[:5]},
                "potential_impact": "Unencrypted scripts, stylesheets, or iframes loaded on an HTTPS origin can be intercepted and tampered with, risking arbitrary script execution.",
                "recommended_remediation": "Update all resource references (scripts, stylesheets, frames) to use HTTPS or protocol-relative URLs.",
                "limitations": "Detected from static HTML DOM analysis. Dynamically injected DOM nodes are not observed.",
            })

        if is_https and passive_items:
            findings.append({
                "id": "sec-mixed-content-passive",
                "title": "Passive Mixed Content (Images / Media)",
                "severity": "LOW",
                "technical_evidence": {"passive_elements_count": len(passive_items), "sample": passive_items[:5]},
                "potential_impact": "Images or media loaded over HTTP can be monitored or replaced by network eavesdroppers.",
                "recommended_remediation": "Host media assets over HTTPS.",
                "limitations": "Static DOM check only.",
            })

        mixed_content_report = {
            "has_mixed_content": has_mixed,
            "active_count": len(active_items),
            "passive_count": len(passive_items),
            "sample_active": active_items[:5],
            "sample_passive": passive_items[:5],
            "summary": (
                "Clean: No mixed content detected."
                if not has_mixed
                else f"Detected {len(active_items)} active and {len(passive_items)} passive insecure elements."
            ),
        }

        # -------------------------------------------------------------
        # 5. Software Security & Version Disclosure
        # -------------------------------------------------------------
        server_banner = headers.get("server")
        powered_by = headers.get("x-powered-by")
        meta_generator = http_data.get("meta_generator")

        software_security = self._evaluate_software_security(server_banner, powered_by, meta_generator, findings)

        # -------------------------------------------------------------
        # 6. Overall Security Posture Grade & Numeric Score
        # -------------------------------------------------------------
        grade = self._compute_security_grade(
            is_https=is_https,
            has_ssl=has_ssl,
            chain_verified=chain_verified,
            is_expired=is_expired,
            headers_eval=headers_eval,
            has_downgrade=has_downgrade,
            has_active_mixed=bool(active_items),
            is_valid_ssl=is_valid_ssl,
        )

        grade_scores = {"A+": 98, "A": 90, "B": 80, "C": 65, "D": 50, "F": 25}
        score = grade_scores.get(grade, 50)

        # Transport security telemetry block
        transport_security = {
            "is_https": is_https,
            "tls_status": "SECURE" if (has_ssl and chain_verified and not is_expired) else "INSECURE",
            "hsts_configured": headers_eval.get("strict_transport_security", {}).get("status") == "SECURE",
            "status": "SECURE" if is_https and (has_ssl and chain_verified and not is_expired) else "INSECURE",
            "details": "Encrypted HTTPS transport" if is_https else "Unencrypted plain HTTP transport",
        }

        # Redirect analysis enrichment
        redirect_analysis["hops"] = redirect_hops
        redirect_analysis["is_cross_domain"] = has_cross_domain
        redirect_analysis["is_protocol_downgrade"] = has_downgrade
        redirect_analysis["final_destination"] = final_url

        # Mixed content enrichment
        mixed_content_report["detected"] = has_mixed
        mixed_content_report["active_mixed_count"] = len(active_items)
        mixed_content_report["passive_mixed_count"] = len(passive_items)
        mixed_content_report["active_items"] = active_items
        mixed_content_report["passive_items"] = passive_items

        # Software exposure enrichment
        software_exposure = {
            "server_banner": server_banner,
            "x_powered_by": powered_by,
            "meta_generator": meta_generator,
            "is_version_disclosed": software_security.get("is_version_disclosed", False),
            "disclosed_banners": software_security.get("disclosed_banners", []),
            "vulnerabilities": [
                {**v, "cve_id": v.get("cve", v.get("cve_id", ""))}
                for v in software_security.get("known_vulnerabilities", [])
            ],
            "summary": software_security.get("summary", ""),
        }

        # Security headers enrichment
        configured_headers_count = sum(
            1 for item in headers_eval.values() if isinstance(item, dict) and item.get("status") == "SECURE"
        )
        total_headers_count = len(headers_eval)
        security_headers = {
            "total_evaluated": total_headers_count,
            "configured_count": configured_headers_count,
            "missing_count": total_headers_count - configured_headers_count,
            "status": "SECURE" if configured_headers_count >= 4 else "NEEDS_IMPROVEMENT",
            "headers": {
                k: {
                    "standard_header": v.get("header_name", k),
                    "is_present": v.get("present", False),
                    "raw_value": v.get("value"),
                    "status": v.get("status"),
                    "description": v.get("summary"),
                    "recommended_directive": v.get("recommended_directive"),
                }
                for k, v in headers_eval.items()
            },
        }

        return {
            "score": score,
            "grade": grade,
            "https_enforced": is_https,
            "http_to_https_redirect": http_to_https_redirect,
            "transport_security": transport_security,
            "headers_evaluated": headers_eval,
            "security_headers": security_headers,
            "redirect_analysis": redirect_analysis,
            "mixed_content": mixed_content_report,
            "software_security": software_security,
            "software_exposure": software_exposure,
            "findings": findings,
            "findings_count": len(findings),
            "consumer_explanation": (
                "Security headers and configuration hygiene reflect server defense practices. "
                "Missing security headers do not mean a website is fraudulent, but indicate areas where security hardening is recommended."
            ),
        }

    def _evaluate_software_security(
        self,
        server_banner: Optional[str],
        powered_by: Optional[str],
        meta_generator: Optional[str],
        findings: List[Dict[str, Any]],
    ) -> Dict[str, Any]:
        """
        Extracts disclosed software versions and reports known CVEs.
        Strictly does NOT guess software versions when not disclosed.
        """
        disclosed_items: List[Dict[str, Any]] = []
        is_disclosed = False

        candidates = [
            ("Server header", server_banner),
            ("X-Powered-By header", powered_by),
            ("HTML meta generator", meta_generator),
        ]

        cve_findings: List[Dict[str, Any]] = []

        for source_name, banner in candidates:
            if not banner:
                continue
            banner_clean = banner.strip()
            # Check if banner discloses a version number (contains digit)
            has_version = bool(re.search(r"\d+\.\d+", banner_clean))
            if has_version:
                is_disclosed = True
                disclosed_items.append({
                    "source": source_name,
                    "banner": banner_clean,
                })

                # Check known CVE database
                lower_banner = banner_clean.lower()
                for known_key, cve_info in self.KNOWN_SOFTWARE_CVES.items():
                    if known_key in lower_banner:
                        cve_findings.append(cve_info)
                        findings.append({
                            "id": f"sec-cve-{cve_info['cve'].lower()}",
                            "title": cve_info["title"],
                            "severity": cve_info["severity"],
                            "technical_evidence": {"source": source_name, "banner": banner_clean, "cve": cve_info["cve"]},
                            "potential_impact": cve_info["description"],
                            "recommended_remediation": cve_info["remediation"],
                            "limitations": "Vulnerability identified through passive banner disclosure. Active exploit validation was not performed.",
                        })

        if is_disclosed:
            findings.append({
                "id": "sec-info-software-version-disclosed",
                "title": "Software Version Disclosed in HTTP Response",
                "severity": "LOW",
                "technical_evidence": {"disclosed_banners": disclosed_items},
                "potential_impact": "Revealing precise software and framework versions assists attackers in selecting target-specific exploits.",
                "recommended_remediation": "Suppress version tokens in web server and runtime configuration (e.g. ServerTokens Prod).",
                "limitations": "Banners may reflect proxy configurations rather than internal application stacks.",
            })

        return {
            "is_version_disclosed": is_disclosed,
            "disclosed_banners": disclosed_items,
            "known_vulnerabilities": cve_findings,
            "summary": (
                f"Disclosed: {', '.join([d['banner'] for d in disclosed_items])}"
                if is_disclosed
                else "No software versions disclosed in public headers or DOM metadata (Banner protected)."
            ),
        }

    def _compute_security_grade(
        self,
        is_https: bool,
        has_ssl: bool,
        chain_verified: bool,
        is_expired: bool,
        headers_eval: Dict[str, Any],
        has_downgrade: bool,
        has_active_mixed: bool,
        is_valid_ssl: bool = True,
    ) -> str:
        """
        Computes standardized website security hygiene grade (A+, A, B, C, D, F).
        """
        if not is_https or not has_ssl or not chain_verified or is_expired or has_downgrade or not is_valid_ssl:
            return "F"

        if has_active_mixed:
            return "D"

        secure_headers_count = sum(
            1 for item in headers_eval.values() if isinstance(item, dict) and item.get("status") == "SECURE"
        )

        hsts_secure = headers_eval.get("strict_transport_security", {}).get("status") == "SECURE"
        csp_present = headers_eval.get("content_security_policy", {}).get("present", False)
        xcto_secure = headers_eval.get("x_content_type_options", {}).get("status") == "SECURE"
        frame_secure = headers_eval.get("frame_protection", {}).get("status") == "SECURE"

        if secure_headers_count >= 4 and hsts_secure and csp_present and xcto_secure and frame_secure:
            return "A+"
        elif secure_headers_count >= 3 and hsts_secure:
            return "A"
        elif secure_headers_count >= 2:
            return "B"
        elif secure_headers_count >= 1:
            return "C"
        else:
            return "D"


website_security_assessor = WebsiteSecurityAssessor()
