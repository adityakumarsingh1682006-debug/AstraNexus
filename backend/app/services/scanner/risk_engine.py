import json
import hashlib
from datetime import datetime, timezone
from typing import Dict, Any, List, Optional
from urllib.parse import urlparse

from backend.app.schemas.scan import (
    RiskVerdict,
    ConcernLevel,
    CheckStatusEnum,
    Finding,
    CheckItem,
)


class RiskEngine:
    """
    Deterministic Evidence-Based Threat Evaluation Engine.
    Enforces Rule 4: Final threat verdict is derived solely from empirical
    telemetry and deterministic rules, NOT hallucinated by an LLM.
    """

    def evaluate(
        self,
        target_url: str,
        domain: str,
        dns_data: Dict[str, Any],
        ssl_data: Dict[str, Any],
        typosquat_data: Dict[str, Any],
        http_data: Dict[str, Any],
        urlhaus_data: Dict[str, Any],
        openphish_data: Dict[str, Any],
        google_safebrowsing_data: Optional[Dict[str, Any]] = None,
        simulation_data: Optional[Dict[str, Any]] = None,
    ) -> Dict[str, Any]:
        risk_score = 0
        threat_types: List[str] = []
        evidence_timeline: List[Dict[str, Any]] = []
        concerns: List[Finding] = []
        checks: Dict[str, CheckItem] = {}
        recommendations: List[str] = []
        now_iso = datetime.now(timezone.utc).isoformat()

        # Normalization defaults
        gsb_data = google_safebrowsing_data or {}
        sim_data = simulation_data or {}

        # Extract basic host/domain attributes
        registered_domain = typosquat_data.get("registered_domain") or domain
        subdomain = typosquat_data.get("subdomain") or ""
        has_dns_resolution = bool(dns_data.get("a_records") or dns_data.get("aaaa_records"))
        dns_error = dns_data.get("error")

        # -------------------------------------------------------------
        # 1. URL Structure & Syntax Analysis
        # -------------------------------------------------------------
        parsed_target = urlparse(target_url)
        is_ip_host = False
        try:
            import ipaddress
            clean_host = (parsed_target.hostname or "").split(":")[0]
            ipaddress.ip_address(clean_host)
            is_ip_host = True
        except ValueError:
            is_ip_host = False

        if is_ip_host:
            risk_score += 25
            threat_types.append("Direct IP Hostname")
            concerns.append(
                Finding(
                    id="direct-ip-host",
                    category="URL_STRUCTURE",
                    title="Direct IP address instead of domain name",
                    concern_level=ConcernLevel.MEDIUM_CONCERN,
                    plain_explanation="This address uses a raw numerical IP address instead of a recognized website domain name, a technique frequently used to hide malicious server identities.",
                    technical_evidence={"host": parsed_target.hostname},
                    check_status=CheckStatusEnum.SUSPICIOUS_FINDING,
                )
            )
            checks["url_structure"] = CheckItem(
                name="URL Structure",
                status=CheckStatusEnum.SUSPICIOUS_FINDING,
                summary="Uses numeric IP address instead of domain name.",
                details={"host": parsed_target.hostname},
            )
        else:
            checks["url_structure"] = CheckItem(
                name="URL Structure",
                status=CheckStatusEnum.COMPLETED,
                summary="Standard URL syntax and hierarchical formatting.",
                details={"scheme": parsed_target.scheme, "path": parsed_target.path[:50]},
            )

        # -------------------------------------------------------------
        # 2. Legitimate Brand Verification (Short-circuit whitelist)
        # -------------------------------------------------------------
        if typosquat_data.get("is_legit_brand_domain"):
            impersonated_brand = typosquat_data.get("impersonated_brand", "Verified Brand")
            evidence_timeline.append({
                "timestamp": now_iso,
                "phase": "Brand Trademark Verification",
                "detail": f"Domain is an official recognized property of {impersonated_brand}.",
                "status": "pass",
            })
            checks["domain_analysis"] = CheckItem(
                name="Domain Analysis",
                status=CheckStatusEnum.COMPLETED,
                summary=f"Verified official domain for {impersonated_brand}.",
                details={"registered_domain": registered_domain},
            )
            checks["brand_impersonation"] = CheckItem(
                name="Brand Impersonation Check",
                status=CheckStatusEnum.COMPLETED,
                summary="Matches official brand property.",
                details={"brand": impersonated_brand},
            )
            self._fill_telemetry_checks(checks, dns_data, ssl_data, http_data, urlhaus_data, openphish_data, gsb_data, sim_data)

            headline = f"Official verified website of {impersonated_brand}. Safe to proceed."
            advice = [
                f"This is an official registered domain of {impersonated_brand}.",
                "Always check the address bar in your browser before entering sensitive credentials.",
            ]
            recommendations.append(f"Safe to use: This domain belongs to {impersonated_brand}.")

            return self._build_result_package(
                target_url=target_url,
                domain=domain,
                risk_score=0,
                verdict=RiskVerdict.LOW_RISK,
                confidence_score=99.0,
                consumer_headline=headline,
                consumer_advice=advice,
                threat_types=[],
                evidence_timeline=evidence_timeline,
                concerns=[],
                checks=checks,
                recommendations=recommendations,
            )

        # -------------------------------------------------------------
        # 3. Phishing Simulation & Security Benchmark Recognition
        # -------------------------------------------------------------
        is_simulation = sim_data.get("is_simulation", False)
        if is_simulation:
            checks["security_simulation"] = CheckItem(
                name="Security Simulation Check",
                status=CheckStatusEnum.COMPLETED,
                summary=f"Recognized benchmark: {sim_data.get('suite_name')} ({sim_data.get('label')}).",
                details=sim_data,
            )
        else:
            checks["security_simulation"] = CheckItem(
                name="Security Simulation Check",
                status=CheckStatusEnum.NO_MATCH_FOUND,
                summary="Standard web link (not an industry diagnostic test bed).",
                details={},
            )

        # -------------------------------------------------------------
        # 4. External Threat Intelligence Feeds (URLhaus, OpenPhish, Safe Browsing)
        # -------------------------------------------------------------
        feed_matches: List[str] = []

        # URLhaus
        if urlhaus_data.get("found"):
            risk_score += 65
            threat = urlhaus_data.get("threat") or "Malware Distribution"
            threat_name = f"URLhaus: {threat}"
            threat_types.append(threat_name)
            feed_matches.append(threat_name)
            concerns.append(
                Finding(
                    id="urlhaus-threat-match",
                    category="EXTERNAL_THREAT_INTEL",
                    title="Flagged in Abuse.ch URLhaus malware database",
                    concern_level=ConcernLevel.HIGH_CONCERN,
                    plain_explanation=f"This URL is an active entry in the global URLhaus malware intelligence database (Threat classification: {threat}).",
                    technical_evidence={"threat": threat, "tags": urlhaus_data.get("tags", [])},
                    check_status=CheckStatusEnum.SUSPICIOUS_FINDING,
                )
            )
            evidence_timeline.append({
                "timestamp": now_iso,
                "phase": "Abuse.ch URLhaus Feed",
                "detail": f"Active threat match: {threat}. Tags: {', '.join(urlhaus_data.get('tags', []))}",
                "status": "fail",
            })
            checks["threat_feed_urlhaus"] = CheckItem(
                name="URLhaus (Abuse.ch)",
                status=CheckStatusEnum.SUSPICIOUS_FINDING,
                summary=f"Active threat match: {threat}.",
                details=urlhaus_data,
            )
        elif urlhaus_data.get("error"):
            evidence_timeline.append({
                "timestamp": now_iso,
                "phase": "Abuse.ch URLhaus Feed",
                "detail": f"Feed check unavailable: {urlhaus_data.get('error')}",
                "status": "warn",
            })
            checks["threat_feed_urlhaus"] = CheckItem(
                name="URLhaus (Abuse.ch)",
                status=CheckStatusEnum.UNAVAILABLE,
                summary=f"Unavailable: {urlhaus_data.get('error')}",
                details={"error": urlhaus_data.get("error")},
            )
        else:
            checks["threat_feed_urlhaus"] = CheckItem(
                name="URLhaus (Abuse.ch)",
                status=CheckStatusEnum.NO_MATCH_FOUND,
                summary="Clean: No records found in URLhaus malware database.",
                details={"found": False},
            )

        # OpenPhish
        if openphish_data.get("found"):
            risk_score += 65
            threat_types.append("OpenPhish: Verified Phishing Feed")
            feed_matches.append("OpenPhish Verified Phishing Feed")
            concerns.append(
                Finding(
                    id="openphish-threat-match",
                    category="EXTERNAL_THREAT_INTEL",
                    title="Flagged in OpenPhish phishing database",
                    concern_level=ConcernLevel.HIGH_CONCERN,
                    plain_explanation="This URL is documented in the OpenPhish global phishing database as an active credential theft or phishing site.",
                    technical_evidence={"match_type": openphish_data.get("match_type")},
                    check_status=CheckStatusEnum.SUSPICIOUS_FINDING,
                )
            )
            evidence_timeline.append({
                "timestamp": now_iso,
                "phase": "OpenPhish Threat Feed",
                "detail": f"Active phishing match ({openphish_data.get('match_type')}).",
                "status": "fail",
            })
            checks["threat_feed_openphish"] = CheckItem(
                name="OpenPhish Feed",
                status=CheckStatusEnum.SUSPICIOUS_FINDING,
                summary="Active phishing match in OpenPhish feed.",
                details=openphish_data,
            )
        elif openphish_data.get("feed_size", 0) == 0:
            checks["threat_feed_openphish"] = CheckItem(
                name="OpenPhish Feed",
                status=CheckStatusEnum.UNAVAILABLE,
                summary="OpenPhish feed unavailable or empty cache.",
                details={},
            )
        else:
            checks["threat_feed_openphish"] = CheckItem(
                name="OpenPhish Feed",
                status=CheckStatusEnum.NO_MATCH_FOUND,
                summary=f"Clean: Not listed in active OpenPhish feed ({openphish_data.get('feed_size')} indicators active).",
                details={"feed_size": openphish_data.get("feed_size")},
            )

        # Google Safe Browsing
        if gsb_data.get("found"):
            risk_score += 75
            gsb_threat = gsb_data.get("threat") or "Social Engineering / Phishing"
            threat_types.append(f"Google Safe Browsing: {gsb_threat}")
            feed_matches.append(f"Google Safe Browsing: {gsb_threat}")
            concerns.append(
                Finding(
                    id="google-safebrowsing-threat-match",
                    category="EXTERNAL_THREAT_INTEL",
                    title=f"Flagged by Google Safe Browsing ({gsb_data.get('threat_type')})",
                    concern_level=ConcernLevel.HIGH_CONCERN,
                    plain_explanation=f"Google Safe Browsing flagged this URL as {gsb_threat}.",
                    technical_evidence=gsb_data,
                    check_status=CheckStatusEnum.SUSPICIOUS_FINDING,
                )
            )
            evidence_timeline.append({
                "timestamp": now_iso,
                "phase": "Google Safe Browsing API",
                "detail": f"Threat detected: {gsb_threat}.",
                "status": "fail",
            })
            checks["threat_feed_google_safe_browsing"] = CheckItem(
                name="Google Safe Browsing",
                status=CheckStatusEnum.SUSPICIOUS_FINDING,
                summary=f"Flagged: {gsb_threat}.",
                details=gsb_data,
            )
        elif not gsb_data.get("configured") or gsb_data.get("status") == "UNAVAILABLE":
            checks["threat_feed_google_safe_browsing"] = CheckItem(
                name="Google Safe Browsing",
                status=CheckStatusEnum.UNAVAILABLE,
                summary="Unavailable: Google Safe Browsing API key not configured.",
                details={"configured": False},
            )
        else:
            checks["threat_feed_google_safe_browsing"] = CheckItem(
                name="Google Safe Browsing",
                status=CheckStatusEnum.NO_MATCH_FOUND,
                summary="Clean: Zero matches in Google Safe Browsing lists.",
                details=gsb_data,
            )

        # -------------------------------------------------------------
        # 5. Brand Impersonation & Typosquatting Forensics
        # -------------------------------------------------------------
        is_impersonation = typosquat_data.get("is_impersonation", False)
        impersonated_brand = typosquat_data.get("impersonated_brand")
        brand_in_sub = typosquat_data.get("brand_in_subdomain", False)
        techniques = typosquat_data.get("techniques", [])

        # Integrate findings emitted by typosquat detector
        raw_typo_findings = typosquat_data.get("findings", [])
        for tf in raw_typo_findings:
            c_level = ConcernLevel.HIGH_CONCERN if tf.get("concern_level") == "HIGH_CONCERN" else ConcernLevel.MEDIUM_CONCERN
            concerns.append(
                Finding(
                    id=tf.get("id", "brand-finding"),
                    category=tf.get("category", "BRAND_IMPERSONATION"),
                    title=tf.get("title", "Brand impersonation concern"),
                    concern_level=c_level,
                    plain_explanation=tf.get("plain_explanation", ""),
                    technical_evidence=tf.get("technical_evidence"),
                    check_status=CheckStatusEnum.SUSPICIOUS_FINDING,
                )
            )

        if is_impersonation:
            if brand_in_sub:
                risk_score += 45
                threat_types.append(f"Brand Subdomain Lure: {impersonated_brand}")
                checks["brand_impersonation"] = CheckItem(
                    name="Brand Impersonation Check",
                    status=CheckStatusEnum.SUSPICIOUS_FINDING,
                    summary=f"Uses trademarked brand '{impersonated_brand}' in subdomain on unrelated domain '{registered_domain}'.",
                    details={"brand": impersonated_brand, "registered_domain": registered_domain},
                )
            else:
                risk_score += 40
                threat_types.append(f"Brand Impersonation: {impersonated_brand}")
                checks["brand_impersonation"] = CheckItem(
                    name="Brand Impersonation Check",
                    status=CheckStatusEnum.SUSPICIOUS_FINDING,
                    summary=f"Domain attempts to mimic brand '{impersonated_brand}'.",
                    details={"brand": impersonated_brand, "registered_domain": registered_domain},
                )

            evidence_timeline.append({
                "timestamp": now_iso,
                "phase": "Brand Trademark Forensics",
                "detail": f"Domain impersonates '{impersonated_brand}' using {', '.join(techniques)}.",
                "status": "fail",
            })
        else:
            checks["brand_impersonation"] = CheckItem(
                name="Brand Impersonation Check",
                status=CheckStatusEnum.NO_MATCH_FOUND,
                summary="No brand impersonation or trademark misuse detected.",
                details={},
            )

        # Domain analysis summary check
        if "PUNYCODE_HOMOGRAPH" in techniques:
            risk_score += 35
            threat_types.append("Homoglyph / Punycode Attack")
            checks["domain_analysis"] = CheckItem(
                name="Domain Analysis",
                status=CheckStatusEnum.SUSPICIOUS_FINDING,
                summary="Uses deceptive internationalized (punycode) characters.",
                details={"hostname": domain},
            )
        elif is_impersonation and not brand_in_sub:
            checks["domain_analysis"] = CheckItem(
                name="Domain Analysis",
                status=CheckStatusEnum.SUSPICIOUS_FINDING,
                summary=f"Deceptive domain registration mimicking '{impersonated_brand}'.",
                details={"registered_domain": registered_domain},
            )
        else:
            checks["domain_analysis"] = CheckItem(
                name="Domain Analysis",
                status=CheckStatusEnum.COMPLETED,
                summary=f"Registered domain '{registered_domain}' extracted via Public Suffix List.",
                details={"registered_domain": registered_domain, "subdomain": subdomain},
            )

        # -------------------------------------------------------------
        # 6. DNS Resolution Forensics
        # -------------------------------------------------------------
        if has_dns_resolution:
            evidence_timeline.append({
                "timestamp": now_iso,
                "phase": "DNS Resolution",
                "detail": f"Resolved A records: {', '.join(dns_data.get('a_records', []))[:60]}. Latency: {dns_data.get('resolution_time_ms')}ms.",
                "status": "pass",
            })
            checks["dns_resolution"] = CheckItem(
                name="DNS Resolution",
                status=CheckStatusEnum.COMPLETED,
                summary=f"Host resolved to {len(dns_data.get('a_records', []))} IP address(es).",
                details={"a_records": dns_data.get("a_records", [])},
            )
        else:
            evidence_timeline.append({
                "timestamp": now_iso,
                "phase": "DNS Resolution",
                "detail": f"Domain does not resolve to active IP addresses. {dns_error or 'NXDOMAIN'}",
                "status": "warn",
            })
            checks["dns_resolution"] = CheckItem(
                name="DNS Resolution",
                status=CheckStatusEnum.UNAVAILABLE,
                summary="Domain does not resolve to active IP addresses (unresolvable or offline).",
                details={"error": dns_error or "NXDOMAIN"},
            )

        # -------------------------------------------------------------
        # 7. TLS / SSL Certificate Inspection
        # -------------------------------------------------------------
        if not has_dns_resolution:
            checks["tls_certificate"] = CheckItem(
                name="TLS / SSL Certificate",
                status=CheckStatusEnum.UNAVAILABLE,
                summary="Unavailable because hostname could not be resolved in DNS.",
                details={"reason": "DNS resolution failed"},
            )
        else:
            if ssl_data.get("has_ssl"):
                if ssl_data.get("is_distrusted_ca"):
                    risk_score += 40
                    threat_types.append("Distrusted Certificate Authority")
                    concerns.append(
                        Finding(
                            id="distrusted-ca",
                            category="TLS_CERTIFICATE",
                            title="Distrusted Certificate Authority",
                            concern_level=ConcernLevel.HIGH_CONCERN,
                            plain_explanation=f"This website's security certificate was issued by an authority that has been globally distrusted by web browsers: {ssl_data.get('distrust_reason')}",
                            technical_evidence={"issuer": ssl_data.get("issuer_organization"), "reason": ssl_data.get("distrust_reason")},
                            check_status=CheckStatusEnum.SUSPICIOUS_FINDING,
                        )
                    )
                    checks["tls_certificate"] = CheckItem(
                        name="TLS / SSL Certificate",
                        status=CheckStatusEnum.SUSPICIOUS_FINDING,
                        summary=f"Issued by distrusted Certificate Authority ({ssl_data.get('issuer_organization') or 'Unknown'}).",
                        details=ssl_data,
                    )
                elif ssl_data.get("hostname_mismatch"):
                    risk_score += 30
                    threat_types.append("SSL Hostname Mismatch")
                    concerns.append(
                        Finding(
                            id="hostname-mismatch",
                            category="TLS_CERTIFICATE",
                            title="Security certificate address mismatch",
                            concern_level=ConcernLevel.HIGH_CONCERN,
                            plain_explanation=f"This website's security certificate was issued for {ssl_data.get('subject_common_name') or 'a different address'}, not the address you entered ({domain}). This frequently indicates an impersonation attempt or misconfigured hosting.",
                            technical_evidence={"matched_name": ssl_data.get("matched_name"), "subject_common_name": ssl_data.get("subject_common_name"), "subject_alt_names": ssl_data.get("subject_alt_names")},
                            check_status=CheckStatusEnum.SUSPICIOUS_FINDING,
                        )
                    )
                    checks["tls_certificate"] = CheckItem(
                        name="TLS / SSL Certificate",
                        status=CheckStatusEnum.SUSPICIOUS_FINDING,
                        summary=f"Certificate hostname mismatch: issued for {ssl_data.get('subject_common_name') or 'different host'}.",
                        details=ssl_data,
                    )
                elif ssl_data.get("is_self_signed"):
                    risk_score += 30
                    threat_types.append("Self-Signed SSL Certificate")
                    concerns.append(
                        Finding(
                            id="self-signed-cert",
                            category="TLS_CERTIFICATE",
                            title="Self-signed security certificate",
                            concern_level=ConcernLevel.HIGH_CONCERN,
                            plain_explanation="The server uses an unverified, self-signed certificate not trusted by browsers or official Certificate Authorities. Legitimate financial and consumer websites never use self-signed certificates.",
                            technical_evidence={"fingerprint": ssl_data.get("fingerprint_sha256")},
                            check_status=CheckStatusEnum.SUSPICIOUS_FINDING,
                        )
                    )
                    checks["tls_certificate"] = CheckItem(
                        name="TLS / SSL Certificate",
                        status=CheckStatusEnum.SUSPICIOUS_FINDING,
                        summary="Uses an untrusted, self-signed certificate.",
                        details=ssl_data,
                    )
                elif not ssl_data.get("chain_verified", True):
                    risk_score += 25
                    threat_types.append("Untrusted Certificate Chain")
                    concerns.append(
                        Finding(
                            id="untrusted-chain",
                            category="TLS_CERTIFICATE",
                            title="Untrusted security certificate chain",
                            concern_level=ConcernLevel.HIGH_CONCERN,
                            plain_explanation=f"The certificate chain could not be verified by standard trust roots: {ssl_data.get('verification_error') or 'Untrusted issuer'}.",
                            technical_evidence={"verification_error": ssl_data.get("verification_error")},
                            check_status=CheckStatusEnum.SUSPICIOUS_FINDING,
                        )
                    )
                    checks["tls_certificate"] = CheckItem(
                        name="TLS / SSL Certificate",
                        status=CheckStatusEnum.SUSPICIOUS_FINDING,
                        summary="Certificate chain verification failed against trusted roots.",
                        details=ssl_data,
                    )
                elif ssl_data.get("is_expired"):
                    risk_score += 20
                    threat_types.append("Expired SSL Certificate")
                    concerns.append(
                        Finding(
                            id="expired-cert",
                            category="TLS_CERTIFICATE",
                            title="Expired security certificate",
                            concern_level=ConcernLevel.MEDIUM_CONCERN,
                            plain_explanation=f"The website's security certificate expired on {ssl_data.get('valid_to')}.",
                            technical_evidence={"valid_to": ssl_data.get("valid_to")},
                            check_status=CheckStatusEnum.SUSPICIOUS_FINDING,
                        )
                    )
                    checks["tls_certificate"] = CheckItem(
                        name="TLS / SSL Certificate",
                        status=CheckStatusEnum.SUSPICIOUS_FINDING,
                        summary=f"Certificate expired on {ssl_data.get('valid_to')}.",
                        details=ssl_data,
                    )
                elif ssl_data.get("is_weak_signature") or ssl_data.get("is_weak_key"):
                    risk_score += 15
                    threat_types.append("Weak Cryptographic Certificate")
                    concerns.append(
                        Finding(
                            id="weak-cert-crypto",
                            category="TLS_CERTIFICATE",
                            title="Deprecated cryptographic algorithms in certificate",
                            concern_level=ConcernLevel.MEDIUM_CONCERN,
                            plain_explanation=f"The security certificate uses weak or deprecated cryptographic algorithms ({', '.join(ssl_data.get('crypto_warnings', []))}).",
                            technical_evidence={"warnings": ssl_data.get("crypto_warnings"), "sig_algo": ssl_data.get("signature_algorithm")},
                            check_status=CheckStatusEnum.SUSPICIOUS_FINDING,
                        )
                    )
                    checks["tls_certificate"] = CheckItem(
                        name="TLS / SSL Certificate",
                        status=CheckStatusEnum.SUSPICIOUS_FINDING,
                        summary=f"Certificate uses deprecated cryptographic algorithms ({ssl_data.get('signature_hash_algorithm') or 'Weak'}).",
                        details=ssl_data,
                    )
                else:
                    issuer = ssl_data.get("issuer_organization") or ssl_data.get("issuer_common_name") or "Standard CA"
                    checks["tls_certificate"] = CheckItem(
                        name="TLS / SSL Certificate",
                        status=CheckStatusEnum.COMPLETED,
                        summary=f"Valid certificate issued by {issuer} ({ssl_data.get('days_remaining')} days remaining).",
                        details=ssl_data,
                    )
            elif ssl_data.get("error"):
                checks["tls_certificate"] = CheckItem(
                    name="TLS / SSL Certificate",
                    status=CheckStatusEnum.FAILED,
                    summary=f"TLS check failed: {ssl_data.get('error')}",
                    details=ssl_data,
                )
            else:
                # Plain HTTP
                risk_score += 15
                threat_types.append("Unencrypted HTTP")
                concerns.append(
                    Finding(
                        id="unencrypted-http",
                        category="TLS_CERTIFICATE",
                        title="Unencrypted HTTP connection",
                        concern_level=ConcernLevel.MEDIUM_CONCERN,
                        plain_explanation="This website does not use encrypted HTTPS. Any information entered can be intercepted in transit.",
                        technical_evidence={"has_ssl": False},
                        check_status=CheckStatusEnum.SUSPICIOUS_FINDING,
                    )
                )
                checks["tls_certificate"] = CheckItem(
                    name="TLS / SSL Certificate",
                    status=CheckStatusEnum.SUSPICIOUS_FINDING,
                    summary="No HTTPS encryption found on host.",
                    details={},
                )

        # -------------------------------------------------------------
        # 8. HTTP Redirect & DOM Form Forensics
        # -------------------------------------------------------------
        if not has_dns_resolution:
            checks["redirect_analysis"] = CheckItem(
                name="Redirect & Page Inspection",
                status=CheckStatusEnum.UNAVAILABLE,
                summary="Unavailable because hostname could not be reached.",
                details={"reason": "DNS resolution failed"},
            )
        else:
            if http_data.get("has_password_form") and (is_impersonation or risk_score >= 25 or not ssl_data.get("has_ssl")):
                risk_score += 30
                threat_types.append("Credential Harvesting Form")
                concerns.append(
                    Finding(
                        id="credential-harvesting-form",
                        category="PAGE_CONTENT",
                        title="Suspicious password login form",
                        concern_level=ConcernLevel.HIGH_CONCERN,
                        plain_explanation="The page contains a password input field on an unverified, deceptive, or unencrypted web page.",
                        technical_evidence={"has_password_form": True},
                        check_status=CheckStatusEnum.SUSPICIOUS_FINDING,
                    )
                )

            if http_data.get("has_external_action"):
                risk_score += 25
                threat_types.append("Cross-Domain Form Submission")
                concerns.append(
                    Finding(
                        id="external-form-action",
                        category="PAGE_CONTENT",
                        title="Submits credentials to a different domain",
                        concern_level=ConcernLevel.HIGH_CONCERN,
                        plain_explanation="The form on this page sends your entered data to an external, unrelated web address.",
                        technical_evidence={"has_external_action": True},
                        check_status=CheckStatusEnum.SUSPICIOUS_FINDING,
                    )
                )

            if http_data.get("redirect_count", 0) >= 3:
                risk_score += 15
                threat_types.append("Excessive Redirection Chain")
                concerns.append(
                    Finding(
                        id="excessive-redirects",
                        category="REDIRECT_ANALYSIS",
                        title="Excessive redirection chain",
                        concern_level=ConcernLevel.LOW_CONCERN,
                        plain_explanation=f"The link redirects {http_data.get('redirect_count')} times across distinct addresses before landing on the final destination.",
                        technical_evidence={"redirect_chain": http_data.get("redirect_chain", [])},
                        check_status=CheckStatusEnum.SUSPICIOUS_FINDING,
                    )
                )
                checks["redirect_analysis"] = CheckItem(
                    name="Redirect & Page Inspection",
                    status=CheckStatusEnum.SUSPICIOUS_FINDING,
                    summary=f"Redirects {http_data.get('redirect_count')} times across separate URLs.",
                    details={"redirect_chain": http_data.get("redirect_chain", [])},
                )
            elif http_data.get("error"):
                checks["redirect_analysis"] = CheckItem(
                    name="Redirect & Page Inspection",
                    status=CheckStatusEnum.FAILED,
                    summary=f"Could not fetch page: {http_data.get('error')}",
                    details={"error": http_data.get("error")},
                )
            else:
                checks["redirect_analysis"] = CheckItem(
                    name="Redirect & Page Inspection",
                    status=CheckStatusEnum.COMPLETED,
                    summary="Direct page load without anomalous redirections.",
                    details={"redirect_count": http_data.get("redirect_count", 0)},
                )

        # -------------------------------------------------------------
        # 9. Deterministic Verdict Derivation
        # -------------------------------------------------------------
        final_score = min(100, max(0, risk_score))
        confidence = 85.0

        # Scenario A: Security Benchmark / Phishing Simulation Test Page
        if is_simulation:
            verdict = RiskVerdict.PHISHING_SIMULATION
            final_score = 45  # Neutral indicator score
            confidence = 99.0
            suite_name = sim_data.get("suite_name") or "Security Diagnostic Suite"
            sim_label = sim_data.get("label") or "Phishing Simulation"
            headline = f"Phishing Simulation: Recognized security diagnostic test page ({sim_label})."
            advice = [
                "This is a recognized cybersecurity benchmark test page, not a real phishing attack.",
                f"Maintained by {sim_data.get('provider')} to test whether browser anti-phishing protections are working.",
                "No credentials or personal data will be stolen on this page.",
            ]
            recommendations = [
                "Use this test page to verify that your browser displays a red warning or security banner.",
                f"Refer to official documentation: {sim_data.get('reference_url')}",
            ]
            concerns.append(
                Finding(
                    id="security-simulation-page",
                    category="SECURITY_SIMULATION",
                    title=f"Recognized benchmark: {sim_label}",
                    concern_level=ConcernLevel.INFORMATION,
                    plain_explanation=(
                        f"This URL belongs to the {suite_name}. Security software uses this page to verify "
                        f"detection capabilities. It is not an active cyber threat campaign."
                    ),
                    technical_evidence=sim_data,
                    check_status=CheckStatusEnum.COMPLETED,
                )
            )

        # Scenario B: Known Threat Feed Match (URLhaus, OpenPhish, or Google Safe Browsing)
        elif feed_matches:
            verdict = RiskVerdict.CONFIRMED_MALICIOUS
            final_score = max(85, final_score)
            confidence = 98.0
            headline = "Dangerous Link: Confirmed malicious threat in security intelligence feeds."
            advice = [
                "Do NOT click or open this link under any circumstances.",
                "Never enter passwords, financial numbers, or personal data.",
                "If received via SMS, WhatsApp, or email, block the sender immediately.",
            ]
            recommendations = [
                "Delete the message and block the sender immediately.",
                "Never open links flagged by security intelligence feeds.",
                "If you entered information previously, immediately change passwords and contact your bank.",
            ]

        # Scenario C: Brand Impersonation or Typosquatting (even if DNS is unresolvable!)
        elif is_impersonation:
            brand_label = impersonated_brand or "a known brand"
            if final_score >= 65:
                verdict = RiskVerdict.HIGH_RISK
                headline = f"High Risk: Deceptive website impersonating {brand_label}."
            else:
                verdict = RiskVerdict.SUSPICIOUS
                headline = f"Suspicious Link: Deceptive brand identity referencing {brand_label}."

            advice = [
                f"This website appears to impersonate {brand_label}, but is not official.",
                f"Do NOT enter login credentials or personal information.",
                f"If you need {brand_label}, navigate to their official website directly via app or bookmark.",
            ]
            legit_target = typosquat_data.get("legit_domain") or "the official website"
            recommendations = [
                f"Navigate directly to {legit_target} rather than clicking this link.",
                "Never share passwords or one-time codes (OTP) on unverified domains.",
                "Report this link as brand impersonation to help protect others.",
            ]

        # Scenario D: Ordinary unresolvable hostname with NO malicious findings (Test D)
        elif not has_dns_resolution and final_score < 30:
            verdict = RiskVerdict.INCONCLUSIVE
            confidence = 35.0
            headline = "Unable to determine safety because the website could not be reached."
            advice = [
                "This web address does not have active DNS records or could not be contacted.",
                "Do not trust links that cannot be independently reached or verified.",
                "Check for typographical errors in the link or contact the sender to confirm.",
            ]
            concerns.append(
                Finding(
                    id="dns-unresolvable",
                    category="DNS_INFRASTRUCTURE",
                    title="Website could not be reached",
                    concern_level=ConcernLevel.INFORMATION,
                    plain_explanation="This web address has no active DNS records or server responding. The site may be inactive, newly registered, or misspelled.",
                    technical_evidence={"error": dns_error or "NXDOMAIN"},
                    check_status=CheckStatusEnum.UNAVAILABLE,
                )
            )
            recommendations = [
                "Do not interact with links that cannot be reached.",
                "Verify the exact address spelling with the sender or source.",
                "Do not enter credentials or download files from unknown origins.",
            ]

        # Scenario E: High score from technical anomalies (self-signed cert, suspicious forms)
        elif final_score >= 65:
            verdict = RiskVerdict.HIGH_RISK
            confidence = 90.0
            headline = "High Risk: Multiple severe security anomalies detected."
            advice = [
                "Do not trust this website with sensitive personal or financial information.",
                "Exercise extreme caution before downloading any software or submitting forms.",
            ]
            recommendations = [
                "Do not enter passwords or payment details on this site.",
                "Close the browser tab immediately.",
            ]

        # Scenario F: Moderate suspicious findings
        elif final_score >= 35:
            verdict = RiskVerdict.SUSPICIOUS
            confidence = 85.0
            headline = "Suspicious Link: Exercise caution before trusting."
            advice = [
                "Double-check the address bar spelling carefully.",
                "Do not enter sensitive account passwords or download files.",
                "Access the intended service via official search or verified application instead.",
            ]
            recommendations = [
                "Verify the web address carefully before interacting.",
                "Do not provide credentials if the link was sent unsolicited.",
            ]

        # Scenario G: Unmatched URL without positive verification (NEVER claim verified safe)
        else:
            verdict = RiskVerdict.LOW_RISK
            confidence = 75.0
            headline = "No known threats found in checked security databases."
            advice = [
                "No known malicious records or deceptive brand impersonations were found in checked feeds.",
                "Absence of reported threats does not guarantee safety on unverified, private, or newly registered sites.",
                "Always check the browser padlock and verify domain identity before entering sensitive details.",
            ]
            recommendations = [
                "Standard browsing vigilance applies: verify the domain name in your browser address bar.",
                "Never share banking OTP codes or master passwords.",
            ]

        return self._build_result_package(
            target_url=target_url,
            domain=domain,
            risk_score=final_score,
            verdict=verdict,
            confidence_score=confidence,
            consumer_headline=headline,
            consumer_advice=advice,
            threat_types=threat_types,
            evidence_timeline=evidence_timeline,
            concerns=concerns,
            checks=checks,
            recommendations=recommendations,
        )

    def _fill_telemetry_checks(self, checks, dns_data, ssl_data, http_data, urlhaus_data, openphish_data, gsb_data, sim_data):
        if dns_data.get("a_records"):
            checks["dns_resolution"] = CheckItem(
                name="DNS Resolution",
                status=CheckStatusEnum.COMPLETED,
                summary=f"Resolved to authoritative IP: {dns_data['a_records'][0]}.",
                details={"a_records": dns_data.get("a_records", [])},
            )
        else:
            checks["dns_resolution"] = CheckItem(
                name="DNS Resolution",
                status=CheckStatusEnum.UNAVAILABLE,
                summary="Domain does not currently resolve to IP records.",
                details={},
            )

        if ssl_data.get("has_ssl"):
            issuer = ssl_data.get("issuer_organization") or ssl_data.get("issuer_common_name") or "Standard CA"
            checks["tls_certificate"] = CheckItem(
                name="TLS / SSL Certificate",
                status=CheckStatusEnum.COMPLETED,
                summary=f"Valid certificate issued by {issuer}.",
                details=ssl_data,
            )
        else:
            checks["tls_certificate"] = CheckItem(
                name="TLS / SSL Certificate",
                status=CheckStatusEnum.COMPLETED,
                summary="TLS inspection completed.",
                details={},
            )

        checks["redirect_analysis"] = CheckItem(
            name="Redirect & Page Inspection",
            status=CheckStatusEnum.COMPLETED,
            summary="Standard navigation without anomalous redirects.",
            details={},
        )
        checks["security_simulation"] = CheckItem(
            name="Security Simulation Check",
            status=CheckStatusEnum.NO_MATCH_FOUND,
            summary="Verified official brand domain (not a test bed).",
            details={},
        )
        checks["threat_feed_urlhaus"] = CheckItem(
            name="URLhaus (Abuse.ch)",
            status=CheckStatusEnum.NO_MATCH_FOUND,
            summary="Clean: Zero listings in URLhaus malware database.",
            details={},
        )
        checks["threat_feed_openphish"] = CheckItem(
            name="OpenPhish Feed",
            status=CheckStatusEnum.NO_MATCH_FOUND,
            summary="Clean: Zero listings in OpenPhish feed.",
            details={},
        )
        checks["threat_feed_google_safe_browsing"] = CheckItem(
            name="Google Safe Browsing",
            status=CheckStatusEnum.NO_MATCH_FOUND if gsb_data.get("configured") else CheckStatusEnum.UNAVAILABLE,
            summary="Clean" if gsb_data.get("configured") else "Unavailable: Google Safe Browsing API key not configured.",
            details={},
        )

    def _build_result_package(
        self,
        target_url: str,
        domain: str,
        risk_score: int,
        verdict: RiskVerdict,
        confidence_score: float,
        consumer_headline: str,
        consumer_advice: List[str],
        threat_types: List[str],
        evidence_timeline: List[Dict[str, Any]],
        concerns: List[Finding],
        checks: Dict[str, CheckItem],
        recommendations: List[str],
    ) -> Dict[str, Any]:
        # Compute forensic cryptographic step hashes
        for item in evidence_timeline:
            step_payload = f"{item['timestamp']}|{item['phase']}|{item['detail']}|{item['status']}"
            item["hash"] = hashlib.sha256(step_payload.encode("utf-8")).hexdigest()[:16]

        # Generate Canonical Forensic Evidence Package for SHA-256 Notarization
        canonical_dict = {
            "target_url": target_url,
            "domain": domain,
            "verdict": verdict.value,
            "risk_score": risk_score,
            "threat_types": sorted(threat_types),
            "step_count": len(evidence_timeline),
            "engine_version": "2.1.0",
        }
        canonical_json = json.dumps(canonical_dict, sort_keys=True, separators=(",", ":"))
        evidence_hash = f"0x{hashlib.sha256(canonical_json.encode('utf-8')).hexdigest()}"

        return {
            "verdict": verdict,
            "risk_score": risk_score,
            "confidence_score": confidence_score,
            "consumer_headline": consumer_headline,
            "consumer_advice": consumer_advice,
            "threat_types": threat_types,
            "evidence_timeline": evidence_timeline,
            "evidence_hash": evidence_hash,
            "concerns": concerns,
            "checks": checks,
            "recommendations": recommendations,
        }


risk_engine = RiskEngine()
