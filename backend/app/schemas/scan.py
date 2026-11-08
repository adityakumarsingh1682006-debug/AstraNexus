from pydantic import BaseModel, Field
from typing import Dict, Any, List, Optional
from datetime import datetime
from enum import Enum


class RiskVerdict(str, Enum):
    LOW_RISK = "LOW_RISK"
    SUSPICIOUS = "SUSPICIOUS"
    HIGH_RISK = "HIGH_RISK"
    CONFIRMED_MALICIOUS = "CONFIRMED_MALICIOUS"
    INCONCLUSIVE = "INCONCLUSIVE"
    PHISHING_SIMULATION = "PHISHING_SIMULATION"


class ConcernLevel(str, Enum):
    HIGH_CONCERN = "HIGH_CONCERN"
    MEDIUM_CONCERN = "MEDIUM_CONCERN"
    LOW_CONCERN = "LOW_CONCERN"
    INFORMATION = "INFORMATION"


class CheckStatusEnum(str, Enum):
    COMPLETED = "COMPLETED"
    SUSPICIOUS_FINDING = "SUSPICIOUS_FINDING"
    NO_MATCH_FOUND = "NO_MATCH_FOUND"
    UNAVAILABLE = "UNAVAILABLE"
    FAILED = "FAILED"


class CheckItem(BaseModel):
    name: str
    status: CheckStatusEnum
    summary: str
    details: Optional[Dict[str, Any]] = None


class Finding(BaseModel):
    id: str
    category: str
    title: str
    concern_level: ConcernLevel
    plain_explanation: str
    technical_evidence: Optional[Dict[str, Any]] = None
    check_status: CheckStatusEnum = CheckStatusEnum.SUSPICIOUS_FINDING


class URLScanRequest(BaseModel):
    target_url: str = Field(..., description="The suspicious URL or domain to investigate")


class TechnicalEvidence(BaseModel):
    dns_records: Optional[Dict[str, Any]] = None
    ssl_certificate: Optional[Dict[str, Any]] = None
    http_inspection: Optional[Dict[str, Any]] = None
    typosquatting: Optional[Dict[str, Any]] = None
    urlhaus_match: Optional[Dict[str, Any]] = None
    openphish_match: Optional[Dict[str, Any]] = None
    google_safebrowsing_match: Optional[Dict[str, Any]] = None
    simulation_check: Optional[Dict[str, Any]] = None
    evidence_timeline: List[Dict[str, Any]] = Field(default_factory=list)
    evidence_hash: str
    blockchain_ready: bool = True


class URLScanResponse(BaseModel):
    target_url: str
    normalized_url: str
    domain: str
    verdict: RiskVerdict
    consumer_headline: str
    consumer_advice: List[str]
    risk_score: int  # 0 to 100
    confidence_score: float
    reasons: List[str]
    concerns: List[Finding] = Field(default_factory=list)
    checks: Dict[str, CheckItem] = Field(default_factory=dict)
    recommendations: List[str] = Field(default_factory=list)
    impersonated_brand: Optional[str] = None
    threat_matches: List[str] = Field(default_factory=list)
    ai_explanation: Optional[Dict[str, Any]] = None
    scanned_at: datetime = Field(default_factory=datetime.utcnow)
    technical_evidence: TechnicalEvidence
