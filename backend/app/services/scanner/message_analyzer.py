import re
from typing import Dict, Any, List, Optional
from backend.app.schemas.message import MessageScanResponse, DetectedTactic

# Authoritative keyword dictionaries for social engineering detection
URGENCY_PATTERNS = [
    r"\b(urgent|urgently|immediately|action required|final notice|immediate action|within 24 hours|account suspended|locked out|blocked today)\b",
    r"\b(expires today|last chance|terminated immediately|urgent alert|time sensitive)\b",
]

AUTHORITY_PATTERNS = [
    (r"\b(chase|wells fargo|bank of america|citi|citibank|barclays|hsbc|hdfc|sbi|icici)\b", "Bank / Financial Institution"),
    (r"\b(usps|ups|fedex|dhl|postal service|parcel delivery|courier)\b", "Postal / Delivery Service"),
    (r"\b(netflix|amazon|apple|microsoft|google|paypal|meta|whatsapp)\b", "Tech / Entertainment Service"),
    (r"\b(irs|tax department|police|customs|fbi|court|legal warrant)\b", "Government / Law Enforcement"),
]

PAYMENT_PATTERNS = [
    r"\b(pay fee|redelivery fee|processing charge|wire transfer|gift card|crypto|bitcoin|send money|outstanding invoice|unpaid tax)\b",
    r"\b(click here to pay|enter card|verify payment details|re-enter credit card)\b",
]

BAIT_PATTERNS = [
    r"\b(congratulations|you won|lottery prize|cash prize|refund approved|tax refund|claim your reward)\b",
    r"\b(part-time job|earn \$[0-9]+|work from home daily income|guaranteed returns|crypto airdrop)\b",
]

URL_REGEX = re.compile(r"https?://(?:[-\w.]|(?:%[\da-fA-F]{2}))+[^\s]*", re.IGNORECASE)
PHONE_REGEX = re.compile(r"(?:\+?\d{1,3}[-.\s]?)?\(?\d{3}\)?[-.\s]?\d{3}[-.\s]?\d{4}")
AMOUNT_REGEX = re.compile(r"[\$€£₹]\s?[\d,]+(?:\.\d{2})?|\b\d+\s?(?:dollars|euros|pounds|rupees|usd|inr)\b", re.IGNORECASE)


class MessageAnalyzer:
    """
    Deterministic social engineering & scam message analysis engine.
    Detects urgency, authority spoofing, financial coercion, and extracts IOCs.
    """

    def analyze(self, message_text: str, channel_type: str = "AUTO") -> MessageScanResponse:
        text = message_text.strip()
        lower_text = text.lower()

        extracted_links = URL_REGEX.findall(text)
        extracted_phones = list(set(PHONE_REGEX.findall(text)))
        extracted_amounts = list(set(AMOUNT_REGEX.findall(text)))

        detected_tactics: List[DetectedTactic] = []
        risk_score = 0
        scam_category = "General Communication"

        # Check 1: Artificial Urgency
        for pattern in URGENCY_PATTERNS:
            match = re.search(pattern, lower_text)
            if match:
                detected_tactics.append(DetectedTactic(
                    tactic="Artificial Urgency",
                    severity="high",
                    explanation="Pressures you to act fast without thinking or verifying with official channels.",
                    snippet=match.group(0)
                ))
                risk_score += 30
                break

        # Check 2: Authority Impersonation
        for pattern, entity_name in AUTHORITY_PATTERNS:
            match = re.search(pattern, lower_text)
            if match:
                detected_tactics.append(DetectedTactic(
                    tactic=f"Impersonating {entity_name}",
                    severity="high",
                    explanation=f"Claims to be from {match.group(0).title()} to gain your immediate trust.",
                    snippet=match.group(0)
                ))
                risk_score += 30
                if "bank" in entity_name.lower():
                    scam_category = "Banking & Financial Fraud"
                elif "postal" in entity_name.lower():
                    scam_category = "Delivery / Parcel Scam"
                elif "tech" in entity_name.lower():
                    scam_category = "Account Impersonation Scam"
                break

        # Check 3: Payment Pressure
        for pattern in PAYMENT_PATTERNS:
            match = re.search(pattern, lower_text)
            if match:
                detected_tactics.append(DetectedTactic(
                    tactic="Payment or Card Request",
                    severity="high",
                    explanation="Requests payment, redelivery fees, or asks for your banking credentials.",
                    snippet=match.group(0)
                ))
                risk_score += 30
                break

        # Check 4: False Bait / Prize / Easy Job
        for pattern in BAIT_PATTERNS:
            match = re.search(pattern, lower_text)
            if match:
                detected_tactics.append(DetectedTactic(
                    tactic="Unrealistic Reward or Job Bait",
                    severity="high",
                    explanation="Promises easy money, rewards, or refunds to lure you into sharing personal details.",
                    snippet=match.group(0)
                ))
                risk_score += 35
                scam_category = "Lottery, Job or Refund Scam"
                break

        # Check 5: Links inside an unsolicited message
        if extracted_links:
            if risk_score > 0:
                risk_score += 20
                detected_tactics.append(DetectedTactic(
                    tactic="Suspicious Embedded Link",
                    severity="high",
                    explanation="Directs you to an external webpage to harvest your credentials or money.",
                    snippet=extracted_links[0]
                ))
            else:
                risk_score += 15

        final_score = min(100, risk_score)

        # Verdict
        if final_score >= 60:
            verdict = "LIKELY_SCAM"
            headline = f"High Risk: This looks like a {scam_category.lower()}."
            advice = [
                "Do NOT click any links in this message.",
                "Do NOT send money, gift cards, or enter card details.",
                "Block the sender and report this message as spam.",
                "If it mentions your bank or an account, check your official mobile app directly instead."
            ]
        elif final_score >= 30:
            verdict = "SUSPICIOUS"
            headline = "Be Careful: This message shows signs of manipulation."
            advice = [
                "Verify with the official organization through their public website or official app.",
                "Do not rely on the phone number or link provided in this message.",
                "Never share OTPs, PINs, or passwords with anyone."
            ]
        else:
            verdict = "LOOKS_SAFE"
            headline = "No common scam patterns detected in this message."
            advice = [
                "Always remain cautious before clicking unknown links or sending money to unfamiliar contacts.",
                "Verify sender authenticity if they ask for sensitive personal data."
            ]

        confidence = 92.0 if detected_tactics else 80.0
        manipulation_tactics = [t.tactic for t in detected_tactics]

        return MessageScanResponse(
            verdict=verdict,
            consumer_headline=headline,
            consumer_advice=advice or [],
            risk_score=final_score,
            confidence_score=confidence,
            scam_category=scam_category,
            detected_tactics=detected_tactics or [],
            manipulation_tactics=manipulation_tactics or [],
            extracted_links=extracted_links or [],
            extracted_phones=extracted_phones or [],
            extracted_amounts=extracted_amounts or [],
        )


message_analyzer = MessageAnalyzer()
