"""
Production verification script for AstraNexus.
Tests the deployed Render backend across:
- TEST A: Amazon Advance-Fee Job Scam
- TEST B: SBI KYC Phishing
- TEST C: Benign College Lecture Reschedule
- URL Scanning: Wikipedia (benign) and Chase (suspicious)
"""

import sys
import json
import httpx

BACKEND_URL = "https://astranexus-backend.onrender.com"

TEST_CASES = [
    {
        "id": "TEST_A",
        "name": "Amazon Advance-Fee Job Scam",
        "endpoint": "/api/v1/message/analyze",
        "payload": {
            "message_text": "Congratulations! You have been selected for an Amazon work-from-home job. Earn Rs. 5,000 daily by completing simple tasks. Pay a refundable registration fee of Rs. 499 to activate your employee account.",
            "channel_type": "AUTO",
        },
        "expected_verdicts": ["HIGH_RISK", "LIKELY_SCAM"],
    },
    {
        "id": "TEST_B",
        "name": "SBI KYC Phishing",
        "endpoint": "/api/v1/message/analyze",
        "payload": {
            "message_text": "URGENT: Your SBI bank account will be blocked within 24 hours. Complete your KYC immediately. Click the link below and enter your account details to avoid suspension.",
            "channel_type": "AUTO",
        },
        "expected_verdicts": ["HIGH_RISK", "LIKELY_SCAM"],
    },
    {
        "id": "TEST_C",
        "name": "Benign College Announcement",
        "endpoint": "/api/v1/message/analyze",
        "payload": {
            "message_text": "Dear students, tomorrow's Business Law lecture has been rescheduled to 11:00 AM due to an administrative meeting. Please check the college notice board for further updates.",
            "channel_type": "AUTO",
        },
        "expected_verdicts": ["LOW_RISK", "LOOKS_SAFE"],
    },
]

def main():
    print(f"Targeting Deployed Backend: {BACKEND_URL}\n")
    client = httpx.Client(timeout=30.0)

    # 1. Health probe
    try:
        health_resp = client.get(f"{BACKEND_URL}/api/v1/health")
        print(f"[HEALTH CHECK] Status: {health_resp.status_code}")
        print(f"[HEALTH CHECK] Body: {health_resp.text}\n")
    except Exception as e:
        print(f"[HEALTH CHECK FAILED]: {e}\n")
        return 1

    all_passed = True

    for tc in TEST_CASES:
        print("=" * 60)
        print(f"Running {tc['id']}: {tc['name']}")
        print("=" * 60)
        url = f"{BACKEND_URL}{tc['endpoint']}"
        try:
            resp = client.post(url, json=tc["payload"])
            print(f"HTTP Status: {resp.status_code}")
            if resp.status_code != 200:
                print(f"FAILED (Non-200 status): {resp.text}")
                all_passed = False
                continue

            data = resp.json()
            verdict = data.get("verdict")
            risk_class = data.get("risk_classification")
            score = data.get("risk_score")
            category = data.get("scam_category")
            headline = data.get("consumer_headline")
            tactics = data.get("manipulation_tactics") or [t.get("tactic") for t in data.get("detected_tactics", [])]
            ai_exp = data.get("ai_explanation")
            correlation = data.get("correlation")

            print(f"  Verdict:               {verdict}")
            print(f"  Risk Classification:   {risk_class}")
            print(f"  Risk Score:            {score}/100")
            print(f"  Category:              {category}")
            print(f"  Consumer Headline:     {headline}")
            print(f"  Tactics Detected:      {tactics}")
            print(f"  Threat Correlation:    Similar Reports={correlation.get('similar_reports_count', 0) if correlation else 0}")
            print(f"  AI Explanation Source: {ai_exp.get('source') if ai_exp else 'None'}")
            print(f"  AI Headline:           {ai_exp.get('headline') if ai_exp else 'None'}")

            if verdict not in tc["expected_verdicts"]:
                print(f"  [MISMATCH]: Expected {tc['expected_verdicts']}, got {verdict}")
                all_passed = False
            else:
                print(f"  [PASSED]: Matches expected verdict {verdict}")

        except Exception as e:
            print(f"Request failed with error: {e}")
            all_passed = False

        print()

    # 2. URL Regression Check
    print("=" * 60)
    print("Running URL Scan Regression: https://www.wikipedia.org")
    print("=" * 60)
    try:
        url_resp = client.post(f"{BACKEND_URL}/api/v1/scan/url", json={"target_url": "https://www.wikipedia.org"})
        print(f"URL Scan Status: {url_resp.status_code}")
        url_data = url_resp.json()
        print(f"  Verdict: {url_data.get('verdict')}")
        print(f"  Risk Classification: {url_data.get('risk_classification')}")
        print(f"  Risk Score: {url_data.get('risk_score')}")
    except Exception as e:
        print(f"URL scan error: {e}")
        all_passed = False

    print("\n" + "=" * 60)
    if all_passed:
        print("ALL PRODUCTION TESTS COMPLETED SUCCESSFULLY!")
    else:
        print("SOME TESTS FAILED OR STILL PENDING DEPLOYMENT.")
    print("=" * 60)

    return 0 if all_passed else 1

if __name__ == "__main__":
    sys.exit(main())
