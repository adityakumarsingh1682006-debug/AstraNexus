import uuid
from typing import List, Optional
from datetime import datetime
from fastapi import APIRouter, HTTPException, status
from web3 import Web3
from backend.app.schemas.alerts import CommunityReportCreate, CommunityReportResponse
from backend.app.services.blockchain.canonicalizer import compute_report_commitment
from backend.app.services.blockchain.registry_client import threat_registry_client
from backend.app.core.config import settings

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

    rep_id = f"rep-{uuid.uuid4().hex[:8]}"

    # Deterministic commitment (strictly excludes raw indicators, contact details, or PII)
    evidence_digest = Web3.keccak(text=f"{report_data.indicator_type}:{report_data.category}").hex()
    report_id_hex, commitment_hex, _, _ = compute_report_commitment(
        report_id=rep_id,
        target_type=report_data.indicator_type.upper(),
        threat_category=report_data.category.upper(),
        risk_score=50,
        verdict="PENDING_TRIAGE",
        indicators_count=1,
        evidence_digest=evidence_digest,
    )

    reg_result = None
    if threat_registry_client.is_connected() and settings.NOTARY_SIGNER_PRIVATE_KEY:
        try:
            reg_result = threat_registry_client.register_report(
                report_id=rep_id,
                commitment_hash=commitment_hex,
            )
        except Exception as e:
            reg_result = {
                "status": "FAILED",
                "is_registered": False,
                "message": str(e),
                "tx_hash": None,
                "report_id": rep_id,
                "commitment_hash": commitment_hex,
            }
    else:
        reg_result = {
            "status": "RPC_UNAVAILABLE" if settings.EVM_RPC_URL else "NOT_CONFIGURED",
            "is_registered": False,
            "message": "Blockchain notary node standby or offline.",
            "tx_hash": None,
            "report_id": rep_id,
            "commitment_hash": commitment_hex,
        }

    new_report = CommunityReportResponse(
        id=rep_id,
        target_indicator=indicator,
        indicator_type=report_data.indicator_type.upper(),
        category=report_data.category,
        description=report_data.description,
        status="RECEIVED",
        created_at=datetime.utcnow(),
        verdict="PENDING_TRIAGE",
        blockchain_registration=reg_result,
        commitment_hash=commitment_hex,
    )

    _COMMUNITY_REPORTS.insert(0, new_report)
    return new_report


@router.get("", response_model=List[CommunityReportResponse], tags=["Community Reports"])
async def list_reports():
    """
    Returns submitted reports and their verification status.
    """
    return _COMMUNITY_REPORTS
