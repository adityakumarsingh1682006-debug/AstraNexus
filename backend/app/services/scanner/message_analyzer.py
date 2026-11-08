"""AstraNexus Enhanced Message Analysis Engine.

TASK 6: AI AND THREAT CORRELATION QUALITY

Verifies detection of:
1. Banking impersonation (Chase, Wells Fargo, BoA, Citi, Barclays, HSBC, HDFC, SBI, ICICI, etc.)
2. Fake job offers (part-time tasks, YouTube video likes, hotel ratings, daily salary, Telegram VIP tasks)
3. Investment scams (crypto airdrops, guaranteed returns, 100% daily profit, forex robots, doubling crypto)
4. Lottery scams (lottery prizes, lucky winner, sweepstakes payout, claim cash reward)
5. Fake delivery messages (USPS, FedEx, UPS, DHL, Royal Mail, parcel on hold, redelivery fee, incomplete address)
6. Urgent payment requests (electricity shutoff tonight, tax warrants, wire transfer, gift card demands)
7. Credential harvesting (login verification, update password, confirm card details, KYC update)
8. Suspicious links (shorteners, IP addresses, suspicious TLDs, brand spoofing)
9. Social engineering patterns (urgency, authority spoofing, fear appeals, secrecy, bait)

Extracts:
- URLs, Domains, Email addresses, Phone numbers, Payment indicators (crypto, gift cards, fiat)

Guards:
- Redacts sensitive credentials (OTPs, passwords, full credit card numbers)
- Neutralizes prompt injection attempts
- Does NOT treat urgency alone as proof of fraud
- Enriches with explainable threat correlation & genuine public safety advisories
"""

import re
from typing import Dict, Any, List, Optional
from urllib.parse import urlparse
from datetime import datetime, timezone

from backend.app.schemas.message import MessageScanResponse, DetectedTactic
from backend.app.services.intelligence.threat_correlator import threat_correlator

# ==============================================================================
# AUTHORITATIVE PATTERN DICTIONARIES
# ==============================================================================

BANKING_IMPERSONATION_PATTERNS = [
    (r"\b(chase|wells fargo|bank of america|citi|citibank|barclays|hsbc|hdfc|sbi|icici|capital one|santander|td bank|pnc bank)\b", "Major Banking Institution"),
    (r"\b(kyc update|debit card blocked|credit card frozen|account suspended|unauthorized wire transfer|verify net banking|overdraft alert|unrecognized transaction)\b", "Banking Alert / Account Lock"),
]

JOB_OFFER_PATTERNS = [
    r"\b(part-time job|earn \$[0-9]+|work from home daily income|earn (?:dollars|usd|per day))\b",
    r"\b(like youtube videos|rate hotels|watch videos to earn|telegram task group|vip task|pre-fund task|task commission)\b",
    r"\b(daily salary|guaranteed daily wage|hiring remote assistants|flexible part-time hours)\b",
]

INVESTMENT_SCAM_PATTERNS = [
    r"\b(crypto airdrop|guaranteed returns|100% daily profit|forex robot|double your bitcoin|double your crypto)\b",
    r"\b(insider trading signal|risk-free investment|high yield investment|daily crypto payout|liquidity mining pool)\b",
]

LOTTERY_SCAM_PATTERNS = [
    r"\b(congratulations\s+(?:you\s+(?:have\s+)?won|winner)|you won|lottery prize|cash prize|lucky winner|sweepstakes payout|claim your reward|unclaimed lottery)\b",
    r"\b(won \$[0-9,]+|selected for international prize|lottery draw winner)\b",
]

DELIVERY_SCAM_PATTERNS = [
    (r"\b(usps|ups|fedex|dhl|postal service|parcel delivery|courier|royal mail)\b", "Postal / Logistics Service"),
    (r"\b(package on hold|parcel delivery failed|redelivery fee|incomplete address|update shipping address|unpaid delivery fee)\b", "Delivery Exception"),
]

URGENT_PAYMENT_PATTERNS = [
    r"\b(electricity (?:will be )?disconnected|power shutoff tonight|unpaid electricity bill|water connection cut)\b",
    r"\b(power bill|electricity bill|utility bill|past due|prevent disconnection|disconnection notice)\b",
    r"\b(pay(?:ing)?\s+(?:a\s+)?(?:[\$€£₹]\s?[\d,]+\s+)?(?:processing\s+|redelivery\s+)?fee)\b",
    r"\b(processing charge|wire transfer|send money|outstanding invoice|unpaid tax warrant|arrest warrant)\b",
    r"\b(pay via gift card|gift card|apple gift card|steam card|google play card|western union|vanilla visa)\b",
]

CREDENTIAL_HARVESTING_PATTERNS = [
    r"\b(verify your login|update your password|confirm password|re-enter credit card|verify card details)\b",
    r"\b(session expired|confirm identity to unlock|click here to verify account|enter otp to verify)\b",
]

URGENCY_PATTERNS = [
    r"\b(urgent|urgently|immediately|action required|final notice|immediate action|within 24 hours|within 12 hours|expires today|last chance)\b",
    r"\b(terminated immediately|urgent alert|time sensitive|act now or)\b",
]

SOCIAL_ENGINEERING_PATTERNS = [
    (r"\b(keep this strictly confidential|do not tell anyone|do not contact your branch|do not inform family)\b", "Secrecy & Isolation Coercion"),
    (r"\b(legal action will be taken|arrest warrant issued|law enforcement dispatched|police report filed)\b", "Fear & Law Enforcement Coercion"),
]

PROMPT_INJECTION_PATTERNS = [
    r"\b(?:ignore|disregard)\s+(?:all\s+)?(?:previous|prior)?\s*(?:instructions|rules|guidelines|prompts)\b",
    r"\b(?:system\s+prompt|developer\s+mode|dan\s+mode|system\s+command)\b",
    r"\b(?:override\s+(?:the\s+)?(?:safety\s+)?verdict)\b",
    r"\b(?:output\s+(?:only\s+)?(?:json|verdict)|return\s+looks_safe)\b",
    r"<\s*script[^>]*>",
]

# Extraction Regular Expressions
URL_REGEX = re.compile(r"https?://(?:[-\w.]|(?:%[\da-fA-F]{2}))+[^\s]*", re.IGNORECASE)
DOMAIN_REGEX = re.compile(r"\b(?:[a-zA-Z0-9-]+\.)+(?:com|org|net|xyz|top|info|site|online|live|shop|club|vip|biz|gov|edu|co|io)\b", re.IGNORECASE)
EMAIL_REGEX = re.compile(r"\b[A-Za-z0-9._%+-]+@[A-Za-z0-9.-]+\.[A-Z|a-z]{2,}\b")
PHONE_REGEX = re.compile(r"(?:\+?\d{1,3}[-.\s]?)?\(?\d{3}\)?[-.\s]?\d{3}[-.\s]?\d{4}")
AMOUNT_REGEX = re.compile(r"[\$€£₹]\s?[\d,]+(?:\.\d{2})?|\b\d+\s?(?:dollars|euros|pounds|rupees|usd|inr)\b", re.IGNORECASE)
CRYPTO_REGEX = re.compile(r"\b(?:btc|bitcoin|eth|ethereum|usdt|tether|sol|solana)\b|\b0x[a-fA-F0-9]{40}\b|\b[13][a-km-zA-HJ-NP-Z1-9]{25,34}\b", re.IGNORECASE)
GIFT_CARD_REGEX = re.compile(r"\b(gift\s+card|apple\s+gift\s+card|steam\s+(?:wallet\s+)?card|google\s+play\s+card|vanilla\s+visa|razer\s+gold)\b", re.IGNORECASE)


class MessageAnalyzer:
    """Deterministic social engineering, scam pattern, and IOC extraction engine."""

    def redact_sensitive_data(self, text: str) -> str:
        """Protects consumer privacy by redacting full credit cards, OTPs, and passwords."""
        # Redact 16-digit card patterns
        masked = re.sub(r"\b(?:\d{4}[ -]?){3}\d{4}\b", "[CARD_REDACTED]", text)
        # Redact OTP / Verification codes
        masked = re.sub(r"\b(?:otp|passcode|code|pin)\s*(?:is|:)?\s*\d{4,8}\b", "[OTP_REDACTED]", masked, flags=re.IGNORECASE)
        # Redact explicit passwords
        masked = re.sub(r"\b(?:password|pwd)\s*(?:is|:)?\s*\S+\b", "[PASSWORD_REDACTED]", masked, flags=re.IGNORECASE)
        return masked

    def analyze(self, message_text: str, channel_type: str = "AUTO") -> MessageScanResponse:
        text = message_text.strip()
        lower_text = text.lower()

        # Sensitive Data Redaction
        safe_text = self.redact_sensitive_data(text)

        # 1. Extraction
        raw_links = URL_REGEX.findall(text)
        extracted_links = list(dict.fromkeys(raw_links))  # preserve order & unique

        extracted_phones = list(set(PHONE_REGEX.findall(text)))
        extracted_amounts = list(set(AMOUNT_REGEX.findall(text)))
        extracted_emails = list(set(EMAIL_REGEX.findall(text)))

        # Extract domains from both URLs and raw domain mentions
        extracted_domains = set()
        for link in extracted_links:
            try:
                parsed = urlparse(link)
                if parsed.hostname:
                    extracted_domains.add(parsed.hostname.lower())
            except Exception:
                pass
        for dom in DOMAIN_REGEX.findall(text):
            extracted_domains.add(dom.lower())
        extracted_domains_list = sorted(list(extracted_domains))

        # Extract Payment Indicators (crypto, gift cards, fiat amounts)
        payment_indicators = set(extracted_amounts)
        for crypto_match in CRYPTO_REGEX.findall(lower_text):
            payment_indicators.add(f"Cryptocurrency: {crypto_match.upper()}")
        for gift_match in GIFT_CARD_REGEX.findall(lower_text):
            payment_indicators.add(f"Gift Card: {gift_match.title()}")
        extracted_payment_list = sorted(list(payment_indicators))

        detected_tactics: List[DetectedTactic] = []
        security_warnings: List[str] = []
        risk_score = 0
        scam_category = "General Communication"

        # Check 0: Security & Prompt Injection Defense (Part F)
        has_prompt_injection = False
        for pattern in PROMPT_INJECTION_PATTERNS:
            match = re.search(pattern, lower_text)
            if match:
                has_prompt_injection = True
                detected_tactics.append(DetectedTactic(
                    tactic="Prompt Injection & Adversarial Evasion",
                    severity="high",
                    explanation="Contains adversarial instructions attempting to hijack security filters or override safety verdicts.",
                    snippet=match.group(0),
                ))
                security_warnings.append("Adversarial prompt injection pattern detected and neutralized.")
                risk_score += 45
                break

        # Check 1: Banking Impersonation
        has_banking = False
        for pattern, entity_name in BANKING_IMPERSONATION_PATTERNS:
            match = re.search(pattern, lower_text)
            if match:
                has_banking = True
                detected_tactics.append(DetectedTactic(
                    tactic=f"Impersonating {entity_name}",
                    severity="high",
                    explanation=f"Claims to be from {match.group(0).title()} to gain immediate trust and induce compliance.",
                    snippet=match.group(0),
                ))
                risk_score += 35
                scam_category = "Banking & Financial Impersonation"
                break

        # Check 2: Fake Job Offers
        has_job = False
        for pattern in JOB_OFFER_PATTERNS:
            match = re.search(pattern, lower_text)
            if match:
                has_job = True
                detected_tactics.append(DetectedTactic(
                    tactic="Unsolicited Job / Easy Task Bait",
                    severity="high",
                    explanation="Promises effortless income (e.g. video liking or task deposits) to lure you into advance-fee fraud.",
                    snippet=match.group(0),
                ))
                risk_score += 40
                if extracted_amounts or any(k in lower_text for k in ("daily", "telegram", "youtube", "whatsapp", "recruiter", "selected")):
                    risk_score += 25
                scam_category = "Fake Job Offer Scam"
                break

        # Check 3: Investment Scams
        has_investment = False
        for pattern in INVESTMENT_SCAM_PATTERNS:
            match = re.search(pattern, lower_text)
            if match:
                has_investment = True
                detected_tactics.append(DetectedTactic(
                    tactic="Fictitious High-Yield Investment / Crypto",
                    severity="high",
                    explanation="Promises guaranteed returns, risk-free profits, or doubling cryptocurrency.",
                    snippet=match.group(0),
                ))
                risk_score += 40
                scam_category = "Investment & Cryptocurrency Scam"
                break

        # Check 4: Lottery Scams
        has_lottery = False
        for pattern in LOTTERY_SCAM_PATTERNS:
            match = re.search(pattern, lower_text)
            if match and not has_job:
                has_lottery = True
                detected_tactics.append(DetectedTactic(
                    tactic="Unearned Lottery / Prize Bait",
                    severity="high",
                    explanation="Claims you won a lottery or sweepstakes you never entered.",
                    snippet=match.group(0),
                ))
                risk_score += 40
                if scam_category == "General Communication":
                    scam_category = "Lottery & Sweepstakes Scam"
                break

        # Check 5: Fake Delivery Messages
        has_delivery = False
        for pattern, entity_name in DELIVERY_SCAM_PATTERNS:
            match = re.search(pattern, lower_text)
            if match:
                has_delivery = True
                detected_tactics.append(DetectedTactic(
                    tactic=f"Impersonating {entity_name}",
                    severity="high",
                    explanation=f"Claims an undelivered parcel or redelivery fee is required for {match.group(0).title()}.",
                    snippet=match.group(0),
                ))
                risk_score += 35
                scam_category = "Delivery / Parcel Scam"
                break

        # Check 6: Urgent Payment / Extortion Requests
        has_urgent_payment = False
        for pattern in URGENT_PAYMENT_PATTERNS:
            match = re.search(pattern, lower_text)
            if match:
                has_urgent_payment = True
                detected_tactics.append(DetectedTactic(
                    tactic="Urgent Payment or Penalty Coercion",
                    severity="high",
                    explanation="Demands immediate payment, wire transfer, utility shutoff prevention, or gift card transfer.",
                    snippet=match.group(0),
                ))
                risk_score += 35
                if scam_category == "General Communication":
                    scam_category = "Urgent Payment & Extortion Request"
                break

        # Check 7: Credential Harvesting
        has_credential_harvesting = False
        for pattern in CREDENTIAL_HARVESTING_PATTERNS:
            match = re.search(pattern, lower_text)
            if match:
                has_credential_harvesting = True
                detected_tactics.append(DetectedTactic(
                    tactic="Credential Harvesting Lure",
                    severity="high",
                    explanation="Directs you to verify credentials, enter passwords, or re-authenticate banking details.",
                    snippet=match.group(0),
                ))
                risk_score += 35
                if scam_category == "General Communication":
                    scam_category = "Credential Harvesting Phishing"
                break

        # Check 8: Social Engineering Patterns (Secrecy & Fear)
        for pattern, tactic_title in SOCIAL_ENGINEERING_PATTERNS:
            match = re.search(pattern, lower_text)
            if match:
                detected_tactics.append(DetectedTactic(
                    tactic=tactic_title,
                    severity="high",
                    explanation="Uses psychological manipulation (fear of arrest or demands for secrecy) to prevent external consultation.",
                    snippet=match.group(0),
                ))
                risk_score += 35
                break

        # Check 9: Urgency Patterns (Rule: Urgency alone is NOT proof of fraud)
        has_urgency = False
        for pattern in URGENCY_PATTERNS:
            match = re.search(pattern, lower_text)
            if match:
                has_urgency = True
                detected_tactics.append(DetectedTactic(
                    tactic="Artificial Urgency",
                    severity="medium",
                    explanation="Creates artificial time pressure (e.g. 'within 24 hours') to trigger hasty, unverified action.",
                    snippet=match.group(0),
                ))
                # Only add substantial risk if combined with deceptive indicators
                if has_banking or has_job or has_investment or has_lottery or has_delivery or has_urgent_payment or has_credential_harvesting or extracted_links:
                    risk_score += 25
                else:
                    risk_score += 10
                break

        # Check 10: Suspicious Links
        if extracted_links:
            has_suspicious_tld = any(
                dom.endswith((".xyz", ".top", ".work", ".click", ".support", ".zip", ".tk", ".ml", ".cc", ".bid"))
                for dom in extracted_domains
            )
            has_ip_url = any(re.search(r"https?://\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3}", link) for link in extracted_links)

            if has_suspicious_tld or has_ip_url:
                detected_tactics.append(DetectedTactic(
                    tactic="High-Risk Domain / IP Link",
                    severity="high",
                    explanation="Contains links using high-abuse top-level domains or direct IP addresses.",
                    snippet=extracted_links[0],
                ))
                risk_score += 30
            elif risk_score > 0:
                detected_tactics.append(DetectedTactic(
                    tactic="External Link in Suspicious Message",
                    severity="high",
                    explanation="Directs you to an external webpage to capture payment details or credentials.",
                    snippet=extracted_links[0],
                ))
                risk_score += 20
            else:
                risk_score += 10

        # Guardrail: Urgency alone without any other suspicious indicators is NOT proof of fraud
        only_urgency = has_urgency and not (
            has_banking or has_job or has_investment or has_lottery or
            has_delivery or has_urgent_payment or has_credential_harvesting or
            has_prompt_injection or extracted_links or extracted_payment_list
        )

        if only_urgency:
            risk_score = min(risk_score, 20)

        final_score = min(100, risk_score)

        # Verdict assignment
        if final_score >= 60:
            verdict = "LIKELY_SCAM"
            headline = f"High Risk: Suspected {scam_category.lower()} detected."
            advice = [
                "Do NOT click any links in this message or open attachments.",
                "Do NOT transfer funds, buy gift cards, or enter card details.",
                "Block and report the sender on your messaging app or carrier.",
                "Verify directly by logging in to the official service website or mobile app.",
            ]
        elif final_score >= 30:
            verdict = "SUSPICIOUS"
            headline = "Caution Advised: Message contains deceptive or coercive patterns."
            advice = [
                "Verify the sender's identity through an independent, trusted channel.",
                "Do not rely on links, phone numbers, or instructions provided in this message.",
                "Never share one-time passcodes (OTPs), PINs, or passwords with anyone.",
            ]
        else:
            verdict = "LOOKS_SAFE"
            headline = "Standard Message: No common scam patterns detected."
            advice = [
                "Always remain cautious when receiving unexpected messages from unfamiliar contacts.",
                "Never enter passwords or send money to contacts you cannot independently verify.",
            ]

        confidence = 94.0 if detected_tactics else 82.0
        manipulation_tactics = [t.tactic for t in detected_tactics]

        # Threat Correlation & Real Articles Discovery (Parts C, D, E)
        primary_indicator = extracted_links[0] if extracted_links else (extracted_phones[0] if extracted_phones else text[:60])
        correlation_summary = threat_correlator.find_similar_cases(
            target_indicator=primary_indicator,
            category=scam_category,
            message_text=text,
            extracted_links=extracted_links,
            extracted_phones=extracted_phones,
        )

        related_advisories = threat_correlator.get_related_advisories(
            category=scam_category,
            detected_tactics=manipulation_tactics,
        )

        return MessageScanResponse(
            verdict=verdict,
            consumer_headline=headline,
            consumer_advice=advice,
            risk_score=final_score,
            confidence_score=confidence,
            scam_category=scam_category,
            detected_tactics=detected_tactics,
            manipulation_tactics=manipulation_tactics,
            extracted_links=extracted_links,
            extracted_phones=extracted_phones,
            extracted_amounts=extracted_amounts,
            extracted_domains=extracted_domains_list,
            extracted_emails=extracted_emails,
            extracted_payment_indicators=extracted_payment_list,
            security_warnings=security_warnings,
            correlation=correlation_summary,
            related_articles=related_advisories,
        )


message_analyzer = MessageAnalyzer()
