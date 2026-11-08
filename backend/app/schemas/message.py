from pydantic import BaseModel, Field
from typing import Dict, Any, List, Optional
from datetime import datetime
from backend.app.schemas.correlation import ThreatCorrelationSummary, RelatedArticleItem


class MessageScanRequest(BaseModel):
    message_text: str = Field(..., description="Suspicious text from SMS, WhatsApp, Email, etc.")
    channel_type: Optional[str] = Field("AUTO", description="SMS, WHATSAPP, EMAIL, or AUTO")


class DetectedTactic(BaseModel):
    tactic: str  # e.g., "Artificial Urgency", "Authority Impersonation", "Payment Pressure"
    severity: str = "medium"  # "high", "medium", "low"
    explanation: str = ""
    snippet: Optional[str] = None


class MessageScanResponse(BaseModel):
    verdict: str = "LOOKS_SAFE"  # "LIKELY_SCAM" | "SUSPICIOUS" | "LOOKS_SAFE"
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
