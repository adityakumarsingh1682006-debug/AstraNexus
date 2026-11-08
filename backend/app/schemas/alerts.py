from pydantic import BaseModel, Field
from typing import List, Optional
from datetime import datetime


class ScamAlert(BaseModel):
    id: str
    title: str
    category: str  # "SMS / Smishing", "Banking Fraud", "Job Offers", "Delivery Scam", "Tech Support"
    severity: str  # "HIGH", "MEDIUM", "LOW"
    summary: str
    how_it_works: List[str]
    who_is_targeted: str
    how_to_recognize: List[str]
    how_to_stay_safe: List[str]
    reported_date: str
    is_verified: bool = True
    source: str = "AstraNexus Intelligence & Verified Reports"


class CommunityReportCreate(BaseModel):
    target_indicator: str = Field(..., description="The suspicious link, phone number, or text snippet")
    indicator_type: str = Field(..., description="LINK, MESSAGE, PHONE, or OTHER")
    category: str = Field(..., description="Suspected scam category")
    description: Optional[str] = None
    reporter_contact: Optional[str] = None  # Kept private, never exposed publicly


class CommunityReportResponse(BaseModel):
    id: str
    target_indicator: str
    indicator_type: str
    category: str
    description: Optional[str] = None
    status: str  # "RECEIVED", "INVESTIGATING", "VERIFIED_THREAT", "CLOSED"
    created_at: datetime
    verdict: Optional[str] = None
    blockchain_registration: Optional[dict] = None
    commitment_hash: Optional[str] = None
