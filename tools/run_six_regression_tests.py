"""Live Six-Scenario Regression Suite for AstraNexus Production Readiness Audit.

Executes and verifies:
URL Tests:
A. https://chase-security-verify.xyz/auth
B. https://www.wikipedia.org
C. https://secure-login-verify-account.example.com/update

Message Tests:
D. SBI KYC message containing a suspicious verification link.
E. Amazon work-from-home message requesting a refundable ₹499 registration fee.
F. Benign college class-rescheduling announcement.
"""

import sys
import os
sys.path.insert(0, os.path.abspath("."))

import json
from backend.app.services.scanner.typosquat import TyposquatDetector
from backend.app.services.scanner.risk_engine import RiskEngine
from backend.app.services.scanner.message_analyzer import MessageAnalyzer
from backend.app.schemas.scan import RiskVerdict, CheckStatusEnum


def run_tests():
    typosquat = TyposquatDetector()
    risk_engine = RiskEngine()
    analyzer = MessageAnalyzer()

    results = {}

    print("======================================================================")
    print("RUNNING 6 FINAL REGRESSION TESTS FOR ASTRANEXUS")
    print("======================================================================")

    # -------------------------------------------------------------------------
    # TEST A: https://chase-security-verify.xyz/auth
    # -------------------------------------------------------------------------
    url_a = "https://chase-security-verify.xyz/auth"
    typo_a = typosquat.analyze(url_a)
    eval_a = risk_engine.evaluate(
        target_url=url_a,
        domain="chase-security-verify.xyz",
        dns_data={"domain": "chase-security-verify.xyz", "a_records": ["198.51.100.10"]},
        ssl_data={"has_ssl": True, "is_valid": True, "chain_verified": True},
        typosquat_data=typo_a,
        http_data={"status_code": 200, "headers": {}},
        urlhaus_data={"found": False, "match_status": "NO_MATCH_FOUND"},
        openphish_data={"found": False, "match_status": "NO_MATCH_FOUND"},
    )
    print(f"\n[TEST A] URL: {url_a}")
    print(f"  Verdict: {eval_a['verdict'].value}")
    print(f"  Classification: {eval_a['risk_classification']}")
    print(f"  Risk Score: {eval_a['risk_score']}")
    print(f"  Headline: {eval_a['consumer_headline']}")
    print(f"  Techniques: {typo_a['techniques']}")
    assert eval_a['verdict'] in (RiskVerdict.HIGH_RISK, RiskVerdict.SUSPICIOUS)
    assert typo_a['is_impersonation'] is True
    assert "chase" in str(typo_a['impersonated_brand']).lower()
    results["Test A"] = {
        "target": url_a,
        "verdict": eval_a['verdict'].value,
        "classification": eval_a['risk_classification'],
        "score": eval_a['risk_score'],
        "headline": eval_a['consumer_headline'],
        "status": "PASS",
    }

    # -------------------------------------------------------------------------
    # TEST B: https://www.wikipedia.org
    # -------------------------------------------------------------------------
    url_b = "https://www.wikipedia.org"
    typo_b = typosquat.analyze(url_b)
    eval_b = risk_engine.evaluate(
        target_url=url_b,
        domain="www.wikipedia.org",
        dns_data={"domain": "www.wikipedia.org", "a_records": ["208.80.154.224"]},
        ssl_data={"has_ssl": True, "is_valid": True, "chain_verified": True, "issuer_organization": "Let's Encrypt"},
        typosquat_data=typo_b,
        http_data={"status_code": 200, "headers": {}},
        urlhaus_data={"found": False, "match_status": "NO_MATCH_FOUND"},
        openphish_data={"found": False, "match_status": "NO_MATCH_FOUND"},
    )
    print(f"\n[TEST B] URL: {url_b}")
    print(f"  Verdict: {eval_b['verdict'].value}")
    print(f"  Classification: {eval_b['risk_classification']}")
    print(f"  Risk Score: {eval_b['risk_score']}")
    print(f"  Headline: {eval_b['consumer_headline']}")
    assert eval_b['verdict'] == RiskVerdict.LOW_RISK
    assert eval_b['risk_classification'] == "LOW RISK"
    assert eval_b['risk_score'] < 30
    results["Test B"] = {
        "target": url_b,
        "verdict": eval_b['verdict'].value,
        "classification": eval_b['risk_classification'],
        "score": eval_b['risk_score'],
        "headline": eval_b['consumer_headline'],
        "status": "PASS",
    }

    # -------------------------------------------------------------------------
    # TEST C: https://secure-login-verify-account.example.com/update
    # -------------------------------------------------------------------------
    url_c = "https://secure-login-verify-account.example.com/update"
    typo_c = typosquat.analyze(url_c)
    eval_c = risk_engine.evaluate(
        target_url=url_c,
        domain="secure-login-verify-account.example.com",
        dns_data={"domain": "secure-login-verify-account.example.com", "a_records": [], "error": "NXDOMAIN"},
        ssl_data={"has_ssl": False, "error": "Host unreachable (DNS resolution failed)"},
        typosquat_data=typo_c,
        http_data={"error": "Host unreachable (DNS resolution failed)"},
        urlhaus_data={"found": False, "match_status": "NO_MATCH_FOUND"},
        openphish_data={"found": False, "match_status": "NO_MATCH_FOUND"},
    )
    print(f"\n[TEST C] URL: {url_c}")
    print(f"  Verdict: {eval_c['verdict'].value}")
    print(f"  Classification: {eval_c['risk_classification']}")
    print(f"  Risk Score: {eval_c['risk_score']}")
    print(f"  DNS Status: {eval_c['checks']['dns_resolution'].status.value}")
    print(f"  URL Structure Status: {eval_c['checks']['url_structure'].status.value}")
    print(f"  Headline: {eval_c['consumer_headline']}")
    assert eval_c['verdict'] == RiskVerdict.SUSPICIOUS
    assert eval_c['risk_classification'] == "SUSPICIOUS"
    assert eval_c['checks']['dns_resolution'].status == CheckStatusEnum.UNAVAILABLE
    assert eval_c['checks']['url_structure'].status == CheckStatusEnum.FLAGGED
    results["Test C"] = {
        "target": url_c,
        "verdict": eval_c['verdict'].value,
        "classification": eval_c['risk_classification'],
        "score": eval_c['risk_score'],
        "headline": eval_c['consumer_headline'],
        "status": "PASS",
    }

    # -------------------------------------------------------------------------
    # TEST D: SBI KYC Phishing Message
    # -------------------------------------------------------------------------
    msg_d = (
        "Dear SBI Customer, your YONO net banking is blocked due to pending KYC update. "
        "Click immediately: http://sbi-kyc-verify-portal.in/login within 24 hours to avoid suspension."
    )
    res_d = analyzer.analyze(msg_d)
    print(f"\n[TEST D] SBI KYC Phishing Message")
    print(f"  Verdict: {res_d.verdict}")
    print(f"  Classification: {res_d.risk_classification}")
    print(f"  Risk Score: {res_d.risk_score}")
    print(f"  Category: {res_d.scam_category}")
    print(f"  Tactics: {res_d.manipulation_tactics}")
    assert res_d.verdict in ("HIGH_RISK", "LIKELY_SCAM")
    assert res_d.risk_classification == "HIGH RISK"
    assert res_d.risk_score >= 60
    results["Test D"] = {
        "target": msg_d[:50] + "...",
        "verdict": str(res_d.verdict),
        "classification": res_d.risk_classification,
        "score": res_d.risk_score,
        "category": res_d.scam_category,
        "status": "PASS",
    }

    # -------------------------------------------------------------------------
    # TEST E: Amazon Work-from-Home ₹499 Refundable Fee
    # -------------------------------------------------------------------------
    msg_e = (
        "Congratulations! You have been selected for an Amazon work-from-home job. "
        "Earn Rs. 5,000 daily by completing simple tasks. "
        "Pay a refundable registration fee of Rs. 499 to activate your account."
    )
    res_e = analyzer.analyze(msg_e)
    print(f"\n[TEST E] Amazon WFH Advance-Fee Scam")
    print(f"  Verdict: {res_e.verdict}")
    print(f"  Classification: {res_e.risk_classification}")
    print(f"  Risk Score: {res_e.risk_score}")
    print(f"  Category: {res_e.scam_category}")
    print(f"  Tactics: {res_e.manipulation_tactics}")
    assert res_e.verdict in ("HIGH_RISK", "SUSPICIOUS")
    assert res_e.risk_classification in ("HIGH RISK", "SUSPICIOUS")
    assert res_e.risk_score >= 60
    assert "Job" in res_e.scam_category or "Recruitment" in res_e.scam_category
    results["Test E"] = {
        "target": msg_e[:50] + "...",
        "verdict": str(res_e.verdict),
        "classification": res_e.risk_classification,
        "score": res_e.risk_score,
        "category": res_e.scam_category,
        "status": "PASS",
    }

    # -------------------------------------------------------------------------
    # TEST F: Benign College Class-Rescheduling Announcement
    # -------------------------------------------------------------------------
    msg_f = (
        "Dear students, please note that tomorrow's CS101 lecture with Prof. Sharma will be held in Hall B at 11:00 AM "
        "instead of Room 204. No preparation is required."
    )
    res_f = analyzer.analyze(msg_f)
    print(f"\n[TEST F] Benign College Class Announcement")
    print(f"  Verdict: {res_f.verdict}")
    print(f"  Classification: {res_f.risk_classification}")
    print(f"  Risk Score: {res_f.risk_score}")
    print(f"  Category: {res_f.scam_category}")
    assert res_f.verdict in ("LOW_RISK", "LOOKS_SAFE")
    assert res_f.risk_classification == "LOW RISK"
    assert res_f.risk_score < 30
    results["Test F"] = {
        "target": msg_f[:50] + "...",
        "verdict": str(res_f.verdict),
        "classification": res_f.risk_classification,
        "score": res_f.risk_score,
        "category": res_f.scam_category,
        "status": "PASS",
    }

    print("\n======================================================================")
    print("ALL SIX REGRESSION TESTS PASSED CLEANLY!")
    print("======================================================================")
    return results

if __name__ == "__main__":
    run_tests()
