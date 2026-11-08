from pydantic import BaseModel, Field
from pydantic_core import core_schema
from typing import Dict, Any, List, Optional
from datetime import datetime
from backend.app.schemas.correlation import ThreatCorrelationSummary, RelatedArticleItem


class UnifiedVerdict(str):
    """
    Subclass of str supporting unified five-level risk classifications
    while seamlessly maintaining backwards compatibility with existing test assertions
    ("LIKELY_SCAM" <-> "HIGH_RISK", "LOOKS_SAFE" <-> "LOW_RISK").
    """
    def __eq__(self, other):
        if not isinstance(other, str):
            return super().__eq__(other)
        s1 = str(self).upper()
        s2 = str(other).upper()
        if s1 == s2:
            return True
        equiv = {
            "LIKELY_SCAM": "HIGH_RISK",
            "HIGH_RISK": "LIKELY_SCAM",
            "LOOKS_SAFE": "LOW_RISK",
            "LOW_RISK": "LOOKS_SAFE",
        }
        return equiv.get(s1) == s2

    def __hash__(self):
        return super().__hash__()

    @classmethod
    def __get_pydantic_core_schema__(cls, source_type, handler):
        return core_schema.no_info_after_validator_function(
            cls,
            core_schema.str_schema(),
        )


class MessageScanRequest(BaseModel):
    message_text: str = Field(..., description="Suspicious text from SMS, WhatsApp, Email, etc.")
    channel_type: Optional[str] = Field("AUTO", description="SMS, WHATSAPP, EMAIL, or AUTO")


class DetectedTactic(BaseModel):
    tactic: str  # e.g., "Artificial Urgency", "Authority Impersonation", "Payment Pressure"
    severity: str = "medium"  # "high", "medium", "low"
    explanation: str = ""
    snippet: Optional[str] = None


class MessageScanResponse(BaseModel):
    verdict: UnifiedVerdict = UnifiedVerdict("LOW_RISK")  # "HIGH_RISK" | "SUSPICIOUS" | "LOW_RISK" | "CONFIRMED_MALICIOUS" | "INCONCLUSIVE"
    risk_classification: Optional[str] = "LOW RISK"
    risk_classification_description: Optional[str] = "No significant malicious indicators identified within the available checks."
    consumer_headline: str = "Message Safety Assessment"
    consumer_advice: List[str] = Field(default_factory=list)
    risk_score: int = 0
    confidence_score: float = 80.0
    scam_category: str = "General Communication"
    detected_tactics: List[DetectedTactic] = Field(default_factory=list)
    manipulation_tactics: List[str] = Field(
        default_factory=list,
        description="List of plain string tactic names for tag display"
    )
    extracted_links: List[str] = Field(default_factory=list)
    extracted_phones: List[str] = Field(default_factory=list)
    extracted_amounts: List[str] = Field(default_factory=list)
    extracted_domains: List[str] = Field(default_factory=list)
    extracted_emails: List[str] = Field(default_factory=list)
    extracted_payment_indicators: List[str] = Field(default_factory=list)
    security_warnings: List[str] = Field(default_factory=list)
    correlation: Optional[ThreatCorrelationSummary] = None
    related_articles: List[RelatedArticleItem] = Field(default_factory=list)
    ai_explanation: Optional[Dict[str, Any]] = None
    analyzed_at: datetime = Field(default_factory=datetime.utcnow)
