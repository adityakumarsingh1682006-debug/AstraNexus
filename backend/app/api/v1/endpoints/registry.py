from fastapi import APIRouter, HTTPException, status
from pydantic import BaseModel, Field
from typing import Optional, Dict, Any, List

from backend.app.services.blockchain.registry_client import threat_registry_client, ThreatRegistryClient
from backend.app.services.blockchain.canonicalizer import (
    compute_report_commitment,
    verify_canonical_commitment,
    build_canonical_payload,
)
from backend.app.core.config import settings
from eth_account import Account

router = APIRouter()


class RegisterCommitmentRequest(BaseModel):
    report_id: str = Field(..., description="Unique report identifier")
    target_type: str = Field("URL", description="URL, MESSAGE, or DOMAIN")
    threat_category: str = Field("PHISHING", description="Threat category")
    risk_score: int = Field(..., ge=0, le=100, description="Risk score 0-100")
    verdict: str = Field(..., description="Verdict classification")
    indicators_count: int = Field(0, description="Number of observed indicators")
    evidence_digest: str = Field(..., description="Evidence SHA-256 digest")
    salt: Optional[str] = Field(None, description="Optional 256-bit salt; generated automatically if omitted")


class VerifyReportRequest(BaseModel):
    report_id: str = Field(..., description="Report identifier")
    expected_commitment_hash: str = Field(..., description="Expected commitment hash")


class DisputeReportRequest(BaseModel):
    report_id: str = Field(..., description="Report identifier")
    reason_evidence: str = Field(..., description="Dispute reasoning evidence")


@router.get("/status", tags=["Threat Registry Notary"])
async def get_registry_status():
    """Returns the operational status of the on-chain Threat Registry Notary.

    Strictly protects security credentials: never exposes private keys.
    """
    is_connected = threat_registry_client.is_connected()
    signer_address = None
    if settings.NOTARY_SIGNER_PRIVATE_KEY:
        try:
            account = Account.from_key(settings.NOTARY_SIGNER_PRIVATE_KEY)
            signer_address = account.address
        except Exception:
            signer_address = "INVALID_KEY_FORMAT"

    chain_id = None
    if is_connected and threat_registry_client._get_web3():
        try:
            chain_id = threat_registry_client._get_web3().eth.chain_id
        except Exception:
            chain_id = None

    return {
        "is_operational": is_connected and bool(settings.ASTRA_REGISTRY_CONTRACT_ADDRESS),
        "rpc_connected": is_connected,
        "rpc_endpoint": settings.EVM_RPC_URL if settings.EVM_RPC_URL else "NOT_CONFIGURED",
        "contract_address": settings.ASTRA_REGISTRY_CONTRACT_ADDRESS or "NOT_CONFIGURED",
        "chain_id": chain_id,
        "notary_signer_address": signer_address or "NOT_CONFIGURED",
        "tamper_evident_enabled": True,
    }


@router.post("/register", tags=["Threat Registry Notary"])
async def register_report_commitment(req: RegisterCommitmentRequest):
    """Deterministically serializes report parameters, computes salted commitment,

    and registers it on the EVM ThreatRegistry smart contract.
    """
    report_id_hex, commitment_hex, canonical_payload, _ = compute_report_commitment(
        report_id=req.report_id,
        target_type=req.target_type,
        threat_category=req.threat_category,
        risk_score=req.risk_score,
        verdict=req.verdict,
        indicators_count=req.indicators_count,
        evidence_digest=req.evidence_digest,
        salt=req.salt,
    )

    reg_result = threat_registry_client.register_report(
        report_id=req.report_id,
        commitment_hash=commitment_hex,
    )

    return {
        "registration": reg_result,
        "canonical_commitment": commitment_hex,
        "canonical_payload": canonical_payload,
        "report_id": req.report_id,
    }


@router.post("/verify", tags=["Threat Registry Notary"])
async def verify_report_on_chain(req: VerifyReportRequest):
    """Verifies that a report's commitment exists on-chain and has not been altered."""
    verification_result = threat_registry_client.verify_report(
        report_id=req.report_id,
        expected_commitment_hash=req.expected_commitment_hash,
    )
    return verification_result


@router.get("/report/{report_id}", tags=["Threat Registry Notary"])
async def get_on_chain_report(report_id: str):
    """Queries on-chain registry for report state, timestamps, and dispute status."""
    result = threat_registry_client.verify_report(
        report_id=report_id,
        expected_commitment_hash="0x" + "0" * 64,  # Query state
    )
    return result
