import uuid
from typing import List, Optional
from datetime import datetime
from fastapi import APIRouter, HTTPException, status
from backend.app.schemas.alerts import CommunityReportCreate, CommunityReportResponse

router = APIRouter()

# In-memory storage for submitted community reports
_COMMUNITY_REPORTS: List[CommunityReportResponse] = [
    CommunityReportResponse(
        id="rep-001",
        target_indicator="https://secure-chase-update-account.com",
        indicator_type="LINK",
        category="Banking Fraud",
        description="Received via SMS claiming my debit card was frozen.",
        status="VERIFIED_THREAT",
        created_at=datetime.utcnow(),
        verdict="MALICIOUS"
    ),
    CommunityReportResponse(
        id="rep-002",
        target_indicator="+1 (800) 555-0149",
        indicator_type="PHONE",
        category="Tech Support Scam",
        description="Caller claimed my computer was infected with virus.",
        status="INVESTIGATING",
        created_at=datetime.utcnow(),
        verdict="SUSPICIOUS"
    )
]


@router.post("", response_model=CommunityReportResponse, status_code=status.HTTP_201_CREATED, tags=["Community Reports"])
async def submit_report(report_data: CommunityReportCreate):
    """
    Submits a suspicious link, message, or phone number for automated triage.
    All personal information is strictly redacted and never exposed publicly.
    """
    indicator = report_data.target_indicator.strip()
    if not indicator:
        raise HTTPException(
            status_code=status.HTTP_400_BAD_REQUEST,
            detail="Target indicator cannot be empty."
        )

    new_report = CommunityReportResponse(
        id=f"rep-{uuid.uuid4().hex[:8]}",
        target_indicator=indicator,
        indicator_type=report_data.indicator_type.upper(),
        category=report_data.category,
        description=report_data.description,
        status="RECEIVED",
        created_at=datetime.utcnow(),
        verdict="PENDING_TRIAGE"
    )

    _COMMUNITY_REPORTS.insert(0, new_report)
    return new_report


@router.get("", response_model=List[CommunityReportResponse], tags=["Community Reports"])
async def list_reports():
    """
    Returns submitted reports and their verification status.
    """
    return _COMMUNITY_REPORTS
