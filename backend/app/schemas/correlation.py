"""AstraNexus Threat Correlation & Advisory Schemas.

Covers:
- Similar scam discovery
- Verified real consumer advisories & articles
- Infrastructure and behavioral threat correlation
- Strict legal attribution disclaimers
"""

from pydantic import BaseModel, Field
from typing import List, Optional, Dict, Any
from datetime import datetime


class SimilarCaseItem(BaseModel):
    report_id: str
    target_indicator: str
    indicator_type: str  # "LINK", "PHONE", "MESSAGE", "DOMAIN"
    category: str
    match_type: str  # "EXACT_INDICATOR", "DOMAIN_INFRASTRUCTURE", "EXPLAINABLE_TEXT_SIMILARITY", "SHARED_SCAM_TECHNIQUE"
    confidence_score: float = Field(..., ge=0.0, le=1.0)
    evidence_explanation: str
    status: str = "RECEIVED"  # "RECEIVED", "INVESTIGATING", "VERIFIED_THREAT"
    created_at: datetime
    verdict: Optional[str] = None


class RelatedArticleItem(BaseModel):
    id: str
    title: str
    publisher: str
    published_date: Optional[str] = None
    original_source_url: str
    category: str
    relevance_explanation: str
    is_official_advisory: bool = True


class ThreatCorrelationSummary(BaseModel):
    similar_reports_count: int = 0
    unique_reporters_count: int = 0
    confirmed_incidents_count: int = 0
    suspected_campaign_name: Optional[str] = None
    suspected_campaign_confidence: float = 0.0
    similar_cases: List[SimilarCaseItem] = Field(default_factory=list)
    attribution_disclaimer: str = (
        "Threat correlation reflects technical infrastructure and behavioral clustering. "
        "AstraNexus does not assign real-world criminal identities without verified law enforcement attribution."
    )
