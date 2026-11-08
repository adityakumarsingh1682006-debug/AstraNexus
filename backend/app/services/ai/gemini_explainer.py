import json
from typing import Dict, Any, List, Optional
from backend.app.core.config import settings

class GeminiExplainer:
    """
    Cognitive explanation layer powered by Google Gemini.
    Enforces Rule 4: Accepts the already-computed deterministic verdict as ground truth.
    Translates complex technical forensic telemetry into empathetic, actionable,
    plain-language guidance for non-technical users.
    """

    def __init__(self):
        self.api_key = settings.GEMINI_API_KEY
        self.model_name = settings.GEMINI_MODEL

    async def explain_url_verdict(
        self,
        target_url: str,
        domain: str,
        verdict: str,
        risk_score: int,
        threat_types: List[str],
        impersonated_brand: Optional[str] = None,
        technical_reasons: Optional[List[str]] = None,
    ) -> Dict[str, Any]:
        """
        Generates empathetic consumer explanation of a URL investigation.
        """
        # If API key is not configured, use the built-in deterministic heuristic explainer
        if not self.api_key:
            return self._heuristic_url_explanation(
                target_url, domain, verdict, risk_score, threat_types, impersonated_brand, technical_reasons
            )

        try:
            from google import genai
            from google.genai import types

            client = genai.Client(api_key=self.api_key)

            prompt = f"""
You are AstraNexus, a friendly, patient digital safety assistant helping an ordinary person (a parent, student, or elderly person).
Explain this website check result in simple, clear everyday language.

Investigation Ground Truth (MUST NOT BE CHANGED):
- Website: {domain}
- Full Link: {target_url}
- Safety Verdict: {verdict}
- Risk Score: {risk_score}/100
- Detected Threat Types: {', '.join(threat_types) if threat_types else 'None'}
- Impersonated Brand: {impersonated_brand or 'None'}
- Technical Findings: {', '.join(technical_reasons or [])}

Respond ONLY in valid JSON matching this schema:
{{
  "headline": "A short, reassuring or warning headline (max 10 words)",
  "summary": "2-3 simple sentences explaining what is happening without technical jargon.",
  "what_to_do": [
    "Step 1: Concrete action to stay safe",
    "Step 2: Concrete action",
    "Step 3: Concrete action"
  ]
}}
"""
            import asyncio
            response = await asyncio.wait_for(
                client.aio.models.generate_content(
                    model=self.model_name,
                    contents=prompt,
                    config=types.GenerateContentConfig(
                        response_mime_type="application/json",
                        temperature=0.2,
                    ),
                ),
                timeout=3.5,
            )

            if response.text:
                parsed = json.loads(response.text)
                return {
                    "source": "Gemini AI Consumer Explainer",
                    "headline": parsed.get("headline"),
                    "summary": parsed.get("summary"),
                    "what_to_do": parsed.get("what_to_do", []),
                }

        except Exception:
            # Fallback cleanly if network, quota, or parsing fails
            pass

        return self._heuristic_url_explanation(
            target_url, domain, verdict, risk_score, threat_types, impersonated_brand, technical_reasons
        )

    def _heuristic_url_explanation(
        self,
        target_url: str,
        domain: str,
        verdict: str,
        risk_score: int,
        threat_types: List[str],
        impersonated_brand: Optional[str] = None,
        technical_reasons: Optional[List[str]] = None,
    ) -> Dict[str, Any]:
        """
        Deterministic, rule-based plain-English explanation fallback.
        Ensures zero dependence on external network for core functionality.
        """
        if verdict in ("MALICIOUS", "CONFIRMED_MALICIOUS", "HIGH_RISK"):
            if impersonated_brand:
                headline = f"Deceptive website copying {impersonated_brand}"
                summary = (
                    f"This website is attempting to trick you by copying the official look of {impersonated_brand}. "
                    f"It was created on an unofficial web address ({domain}) to capture your personal login or credit card details."
                )
            else:
                headline = "Dangerous website: Do not open or enter information"
                summary = (
                    f"Our safety filters confirmed this link is associated with online fraud or malicious downloads. "
                    f"Opening this link may put your personal accounts or device at risk."
                )
            what_to_do = [
                "Do NOT enter your passwords, PINs, or bank card details on this website.",
                "Delete the message, email, or post that sent you this link.",
                "If you already typed your password, immediately visit the official website and change your password.",
                "Warn friends or family if this link was shared in a group chat."
            ]
        elif verdict == "SUSPICIOUS":
            headline = "Suspicious website: Exercise caution before trusting"
            summary = (
                f"This website ({domain}) has several red flags, such as missing security protections, recent creation, "
                f"or deceptive wording. We recommend avoiding it unless you know and trust the sender."
            )
            what_to_do = [
                "Do not download any files or install software from this site.",
                "Double-check the exact address bar spelling to make sure it matches the real service.",
                "Contact the company directly through their known customer helpline or official app instead."
            ]
        else:
            headline = "Looks safe based on standard safety checks"
            summary = (
                f"We checked {domain} against known threat databases and verified its official security certificates. "
                f"No suspicious imitation or fraud patterns were found."
            )
            what_to_do = [
                "Always verify you are on the right webpage before typing sensitive passwords.",
                "Make sure the address bar shows the lock icon and the exact spelling you expect."
            ]

        return {
            "source": "AstraNexus Deterministic Safety Rules",
            "headline": headline,
            "summary": summary,
            "what_to_do": what_to_do,
        }

    async def explain_message_verdict(
        self,
        message_text: str,
        verdict: str,
        risk_score: int,
        scam_category: str,
        detected_tactics: List[str],
        extracted_links: Optional[List[str]] = None,
    ) -> Dict[str, Any]:
        """
        Generates empathetic consumer explanation of a suspicious message assessment.
        Ensures Rule 4: Accepts the already-computed deterministic verdict as ground truth.
        """
        if not self.api_key:
            return self._heuristic_message_explanation(
                verdict, risk_score, scam_category, detected_tactics, extracted_links
            )

        try:
            from google import genai
            from google.genai import types

            client = genai.Client(api_key=self.api_key)

            snippet = message_text[:280] + ("..." if len(message_text) > 280 else "")
            prompt = f"""
You are AstraNexus, a patient, protective digital safety assistant helping an everyday person understand a suspicious message.
Explain this message safety result in simple, clear everyday language.

Ground Truth Investigation Findings (MUST NOT BE OVERRULED):
- Suspicious Message: "{snippet}"
- Safety Verdict: {verdict}
- Risk Score: {risk_score}/100
- Scam Category: {scam_category}
- Psychological Tactics: {', '.join(detected_tactics) if detected_tactics else 'None detected'}
- Links Found: {', '.join(extracted_links or []) if extracted_links else 'None'}

Respond ONLY with valid JSON matching this schema:
{{
  "headline": "A short, protective warning or reassuring headline (max 10 words)",
  "summary": "2-3 simple sentences explaining what trick or pressure tactic is being used without technical jargon.",
  "what_to_do": [
    "Step 1: Concrete action to stay safe",
    "Step 2: Concrete action",
    "Step 3: Concrete action"
  ]
}}
"""
            import asyncio
            response = await asyncio.wait_for(
                client.aio.models.generate_content(
                    model=self.model_name,
                    contents=prompt,
                    config=types.GenerateContentConfig(
                        response_mime_type="application/json",
                        temperature=0.2,
                    ),
                ),
                timeout=3.5,
            )

            if response.text:
                parsed = json.loads(response.text)
                return {
                    "source": "Gemini AI Consumer Explainer",
                    "headline": parsed.get("headline") or "Message Safety Analysis",
                    "summary": parsed.get("summary") or "Analysis completed based on behavioral scam indicators.",
                    "what_to_do": parsed.get("what_to_do") if isinstance(parsed.get("what_to_do"), list) else [],
                }

        except Exception:
            # Fallback gracefully if network, quota, or JSON parse fails
            pass

        return self._heuristic_message_explanation(
            verdict, risk_score, scam_category, detected_tactics, extracted_links
        )

    def _heuristic_message_explanation(
        self,
        verdict: str,
        risk_score: int,
        scam_category: str,
        detected_tactics: List[str],
        extracted_links: Optional[List[str]] = None,
    ) -> Dict[str, Any]:
        """
        Deterministic, rule-based message explanation fallback.
        """
        if verdict in ("LIKELY_SCAM", "HIGH_RISK"):
            headline = f"High Risk: Suspected {scam_category.lower()}"
            summary = (
                f"This message exhibits social engineering manipulation tactics frequently used in online fraud. "
                f"The sender attempts to prompt an immediate emotional reaction before you have time to verify."
            )
            what_to_do = [
                "Do NOT click any links, open attachments, or call the phone number inside the message.",
                "Do NOT reply, even to say 'STOP', as this confirms your phone number or email is active.",
                "If it claims to be your bank or a service, log in directly via their official app or verified website.",
                "Block the sender number or email address on your device."
            ]
        elif verdict == "SUSPICIOUS":
            headline = "Suspicious Message: Caution advised"
            summary = (
                f"This message displays unusual patterns such as unverified links or urgency. "
                f"Exercise caution and verify the sender before responding or taking any action."
            )
            what_to_do = [
                "Verify the sender's identity through an independent, trusted channel.",
                "Never share one-time passcodes (OTPs), PINs, or banking details over text or email.",
                "Check for official contact information on the company's verified public website."
            ]
        else:
            headline = "Standard Message: No known scam patterns detected"
            summary = (
                "Our behavioral filters found no indicators of artificial urgency, fake authority impersonation, "
                "or deceptive payment requests."
            )
            what_to_do = [
                "Always remain mindful when receiving unexpected messages from unknown contacts.",
                "Ensure you never share passwords or sensitive credentials through unsecured messaging."
            ]

        return {
            "source": "AstraNexus Deterministic Safety Rules",
            "headline": headline,
            "summary": summary,
            "what_to_do": what_to_do,
        }


gemini_explainer = GeminiExplainer()
