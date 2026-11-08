import asyncio
from fastapi import APIRouter, HTTPException, status
from urllib.parse import urlparse

from backend.app.schemas.scan import (
    URLScanRequest,
    URLScanResponse,
    TechnicalEvidence,
    RiskVerdict,
)
from backend.app.core.security import validate_target_url_syntax, resolve_and_verify_safe_ips
from backend.app.core.exceptions import SSRFSecurityViolation
from backend.app.services.scanner.dns_inspector import dns_inspector
from backend.app.services.scanner.ssl_inspector import ssl_inspector
from backend.app.services.scanner.typosquat import typosquat_detector
from backend.app.services.scanner.http_inspector import http_inspector
from backend.app.services.scanner.simulation_detector import simulation_detector
from backend.app.services.feeds.urlhaus import urlhaus_client
from backend.app.services.feeds.openphish import openphish_client
from backend.app.services.feeds.google_safe_browsing import google_safe_browsing_client
from backend.app.services.feeds.phishtank import phishtank_client
from backend.app.services.feeds.virustotal import virustotal_client
from backend.app.services.scanner.security_assessor import website_security_assessor
from backend.app.services.scanner.risk_engine import risk_engine
from backend.app.services.ai.gemini_explainer import gemini_explainer
from backend.app.services.blockchain.canonicalizer import compute_report_commitment
from backend.app.services.blockchain.registry_client import threat_registry_client
from backend.app.core.config import settings

router = APIRouter()


@router.post("/url", response_model=URLScanResponse, tags=["URL Investigation"])
async def scan_url(request: URLScanRequest):
    """
    Performs comprehensive, multi-layer digital safety investigation of a URL.
    - SSRF pre-quarantine (blocks private IPs and invalid schemas)
    - Resilient DNS inspection: DNS failure does NOT stop investigation
    - PSL-aware domain extraction and brand impersonation detection
    - Cybersecurity test suite & phishing simulation recognition
    - Real-time Abuse.ch URLhaus, OpenPhish & Google Safe Browsing lookups
    - Deterministic, evidence-based risk assessment (Rule 4 compliant)
    - Structured findings with concern levels and dynamic guidance
    - Optional cognitive explanation via Google Gemini
    """
    target = request.target_url.strip()
    if not target:
        raise HTTPException(
            status_code=status.HTTP_400_BAD_REQUEST,
            detail="Target URL or domain cannot be empty."
        )

    # Step 1: Pre-validate syntax and direct IPs (SSRF quarantine)
    try:
        canonical_url, hostname, direct_ip = validate_target_url_syntax(target)
    except SSRFSecurityViolation as e:
        raise HTTPException(
            status_code=status.HTTP_400_BAD_REQUEST,
            detail=f"Security check blocked: {str(e)}"
        )
    except Exception as e:
        raise HTTPException(
            status_code=status.HTTP_422_UNPROCESSABLE_ENTITY,
            detail=f"Invalid domain or URL format: {str(e)}"
        )

    parsed = urlparse(canonical_url)
    domain = parsed.hostname or hostname

    is_resolvable = False
    resolved_ips = []
    dns_err_msg = None

    if direct_ip:
        is_resolvable = True
        resolved_ips = [direct_ip]
    else:
        try:
            is_resolvable, resolved_ips, dns_err_msg = resolve_and_verify_safe_ips(domain)
        except SSRFSecurityViolation as e:
            raise HTTPException(
                status_code=status.HTTP_400_BAD_REQUEST,
                detail=f"Security check blocked: {str(e)}"
            )

    # Step 2: Run static heuristics (typosquatting and security simulation detection)
    typo_res = typosquat_detector.analyze(canonical_url)
    sim_res = simulation_detector.analyze(canonical_url)

    # Step 3: Run network and threat feed lookups
    try:
        if is_resolvable:
            dns_res = dns_inspector.inspect(domain)
            ssl_res = ssl_inspector.inspect(
                hostname=domain,
                port=parsed.port or (443 if parsed.scheme == "https" else 80),
                scheme=parsed.scheme or "https",
                pre_resolved_ips=resolved_ips,
            )
            results = await asyncio.gather(
                http_inspector.inspect(canonical_url),
                urlhaus_client.lookup_url(canonical_url),
                openphish_client.lookup(canonical_url, domain=domain),
                google_safe_browsing_client.lookup_url(canonical_url),
                phishtank_client.lookup_url(canonical_url),
                virustotal_client.lookup_url(canonical_url),
                return_exceptions=True
            )
            http_res = results[0] if not isinstance(results[0], Exception) else {"error": str(results[0])}
            urlhaus_res = results[1] if not isinstance(results[1], Exception) else {"found": False, "error": str(results[1]), "match_status": "API_UNAVAILABLE"}
            openphish_res = results[2] if not isinstance(results[2], Exception) else {"found": False, "error": str(results[2]), "match_status": "API_UNAVAILABLE"}
            gsb_res = results[3] if not isinstance(results[3], Exception) else {"found": False, "error": str(results[3]), "match_status": "API_UNAVAILABLE"}
            phishtank_res = results[4] if not isinstance(results[4], Exception) else {"found": False, "error": str(results[4]), "match_status": "API_UNAVAILABLE"}
            vt_res = results[5] if not isinstance(results[5], Exception) else {"found": False, "error": str(results[5]), "match_status": "API_UNAVAILABLE"}
        else:
            results = await asyncio.gather(
                urlhaus_client.lookup_url(canonical_url),
                openphish_client.lookup(canonical_url, domain=domain),
                google_safe_browsing_client.lookup_url(canonical_url),
                phishtank_client.lookup_url(canonical_url),
                virustotal_client.lookup_url(canonical_url),
                return_exceptions=True
            )
            urlhaus_res = results[0] if not isinstance(results[0], Exception) else {"found": False, "error": str(results[0]), "match_status": "API_UNAVAILABLE"}
            openphish_res = results[1] if not isinstance(results[1], Exception) else {"found": False, "error": str(results[1]), "match_status": "API_UNAVAILABLE"}
            gsb_res = results[2] if not isinstance(results[2], Exception) else {"found": False, "error": str(results[2]), "match_status": "API_UNAVAILABLE"}
            phishtank_res = results[3] if not isinstance(results[3], Exception) else {"found": False, "error": str(results[3]), "match_status": "API_UNAVAILABLE"}
            vt_res = results[4] if not isinstance(results[4], Exception) else {"found": False, "error": str(results[4]), "match_status": "API_UNAVAILABLE"}

            dns_res = {
                "domain": domain,
                "a_records": [],
                "aaaa_records": [],
                "mx_records": [],
                "ns_records": [],
                "txt_records": [],
                "has_mx": False,
                "has_spf": False,
                "has_dmarc": False,
                "resolution_time_ms": 0.0,
                "error": dns_err_msg or "DNS resolution failed (host does not resolve)",
            }

            # Network checks marked as unavailable
            ssl_res = {
                "has_ssl": False,
                "is_http_only": parsed.scheme == "http",
                "validity_status": "NO_CERTIFICATE",
                "consumer_explanation": "Could not check security certificate because the host could not be resolved in DNS.",
                "error": "Host unreachable (DNS resolution failed)",
                "revocation_status": "UNVERIFIED",
                "revocation_message": "Revocation status could not be verified.",
            }
            http_res = {
                "error": "Host unreachable (DNS resolution failed)",
                "redirect_count": 0,
                "redirect_chain": [],
                "has_password_form": False,
                "has_external_action": False,
            }

    except Exception as e:
        raise HTTPException(
            status_code=status.HTTP_500_INTERNAL_SERVER_ERROR,
            detail=f"Investigation engine failure: {str(e)}"
        )

    # Step 3b: Safe, passive website security assessment (headers, redirects, mixed content, software security)
    website_sec_res = website_security_assessor.assess(
        target_url=canonical_url,
        http_data=http_res,
        ssl_data=ssl_res,
    )

    # Step 4: Deterministic Evidence-Based Risk Evaluation
    evaluation = risk_engine.evaluate(
        target_url=canonical_url,
        domain=domain,
        dns_data=dns_res,
        ssl_data=ssl_res,
        typosquat_data=typo_res,
        http_data=http_res,
        urlhaus_data=urlhaus_res,
        openphish_data=openphish_res,
        google_safebrowsing_data=gsb_res,
        simulation_data=sim_res,
        phishtank_data=phishtank_res,
        virustotal_data=vt_res,
        website_security_data=website_sec_res,
    )

    verdict = evaluation["verdict"]
    score = evaluation["risk_score"]
    threat_types = evaluation["threat_types"]
    headline = evaluation["consumer_headline"]
    advice = evaluation["consumer_advice"]
    concerns = evaluation["concerns"]
    checks = evaluation["checks"]
    recommendations = evaluation["recommendations"]

    # Step 5: Threat feed matches & reasons
    threat_matches = []
    if urlhaus_res.get("found"):
        threat_matches.append(f"URLhaus Malware Feed: {urlhaus_res.get('threat', 'Malicious')}")
    if openphish_res.get("found"):
        threat_matches.append("OpenPhish Verified Phishing Feed")
    if gsb_res.get("found"):
        threat_matches.append(f"Google Safe Browsing: {gsb_res.get('threat', 'Phishing')}")
    if phishtank_res.get("found"):
        threat_matches.append(f"PhishTank: {phishtank_res.get('threat', 'Verified Phishing')}")
    if vt_res.get("found"):
        threat_matches.append(f"VirusTotal: {vt_res.get('threat', 'Multi-Engine Detection')}")

    reasons = [c.plain_explanation for c in concerns if c.plain_explanation]
    if not reasons:
        if verdict == RiskVerdict.LOW_RISK:
            reasons = [
                f"Domain analyzed: {domain}",
                "No deceptive brand impersonation patterns found",
                "No listings in checked threat intelligence databases",
            ]
        elif verdict == RiskVerdict.INCONCLUSIVE:
            reasons = [
                "Domain does not currently resolve to active IP addresses",
                "No live website response could be inspected",
            ]

    # Step 6: AI Cognitive Explanation (Gemini or heuristic fallback)
    ai_explanation = None
    try:
        ai_explanation = await gemini_explainer.explain_url_verdict(
            target_url=canonical_url,
            domain=domain,
            verdict=verdict.value,
            risk_score=score,
            threat_types=threat_types,
            impersonated_brand=typo_res.get("impersonated_brand"),
            technical_reasons=reasons[:3],
        )
    except Exception:
        ai_explanation = None

    # Generate canonical commitment and register on-chain if notary is available
    report_id = f"scan-{evaluation['evidence_hash'][:16]}"
    _, commitment_hex, canonical_payload, _ = compute_report_commitment(
        report_id=report_id,
        target_type="URL",
        threat_category=threat_types[0] if threat_types else "BENIGN",
        risk_score=score,
        verdict=verdict.value,
        indicators_count=len(threat_matches) + len(concerns),
        evidence_digest=evaluation["evidence_hash"],
    )

    blockchain_res = None
    if threat_registry_client.is_connected() and settings.NOTARY_SIGNER_PRIVATE_KEY:
        try:
            blockchain_res = threat_registry_client.register_report(
                report_id=report_id,
                commitment_hash=commitment_hex,
            )
        except Exception as e:
            blockchain_res = {
                "status": "FAILED",
                "is_registered": False,
                "message": str(e),
                "report_id": report_id,
                "commitment_hash": commitment_hex,
            }
    else:
        blockchain_res = {
            "status": "RPC_UNAVAILABLE" if settings.EVM_RPC_URL else "NOT_CONFIGURED",
            "is_registered": False,
            "message": "Blockchain notary node standby or offline.",
            "report_id": report_id,
            "commitment_hash": commitment_hex,
        }

    verifiable_certificate = {
        "report_id": report_id,
        "canonical_payload": canonical_payload,
        "commitment_hash": commitment_hex,
        "network": blockchain_res.get("network") if blockchain_res else "EVM Localnet (Chain 31337)",
        "contract_address": blockchain_res.get("contract_address") if blockchain_res else settings.ASTRA_REGISTRY_CONTRACT_ADDRESS,
        "tx_hash": blockchain_res.get("tx_hash") if blockchain_res else None,
        "exported_at": str(evaluation["evidence_timeline"][-1]["timestamp"]) if evaluation.get("evidence_timeline") else None,
    }

    technical_evidence = TechnicalEvidence(
        dns_records=dns_res,
        ssl_certificate=ssl_res,
        http_inspection=http_res,
        typosquatting=typo_res,
        urlhaus_match=urlhaus_res,
        openphish_match=openphish_res,
        google_safebrowsing_match=gsb_res,
        phishtank_match=phishtank_res,
        virustotal_match=vt_res,
        simulation_check=sim_res,
        website_security=website_sec_res,
        evidence_timeline=evaluation["evidence_timeline"],
        evidence_hash=evaluation["evidence_hash"],
        blockchain_ready=True,
        blockchain_registration=blockchain_res,
        commitment_hash=commitment_hex,
        verifiable_export=verifiable_certificate,
    )

    return URLScanResponse(
        target_url=target,
        normalized_url=canonical_url,
        domain=domain,
        verdict=verdict,
        consumer_headline=headline,
        consumer_advice=advice,
        risk_score=score,
        confidence_score=evaluation["confidence_score"],
        reasons=reasons,
        concerns=concerns,
        checks=checks,
        recommendations=recommendations,
        impersonated_brand=typo_res.get("impersonated_brand"),
        threat_matches=threat_matches,
        ai_explanation=ai_explanation,
        technical_evidence=technical_evidence,
    )
