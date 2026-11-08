"""Automated Tests for AstraNexus Standalone Independent Report Verifier.

TASK 5 Verification Engine Test Suite.
Validates:
- Case A: Original report verifies successfully (VERIFIED).
- Case B: Modified report fails verification (MISMATCH).
- Case C: Unknown report is not found (NOT FOUND).
- Case D: Blockchain RPC unavailable (UNAVAILABLE).
- Case E: Revised report verifies against its correct registered version.
- Case F: Verification works completely independently of AstraNexus backend
  (pure client-side / CLI query directly to EVM node).
"""

import os
import sys
import json
import secrets
import subprocess
import tempfile
import pytest

# Ensure workspace root and tools directory are importable
WORKSPACE_ROOT = os.path.abspath(os.path.join(os.path.dirname(__file__), "..", ".."))
if WORKSPACE_ROOT not in sys.path:
    sys.path.insert(0, WORKSPACE_ROOT)

from tools.verify_report import (
    verify_report_data,
    calculate_commitment,
    canonical_serialize,
    call_rpc,
)
from backend.app.services.blockchain.registry_client import (
    ThreatRegistryClient,
    BlockchainRegistrationStatus,
)
from backend.app.services.blockchain.canonicalizer import (
    compute_report_commitment,
)

RPC_URL = os.getenv("EVM_RPC_URL", "http://127.0.0.1:8545")
CONTRACT_ADDRESS = os.getenv("ASTRA_REGISTRY_CONTRACT_ADDRESS", "0x5FbDB2315678afecb367f032d93F642f64180aa3")
DEV_PRIVATE_KEY = "0xac0974bec39a17e36ba4a6b4d238ff944bacb478cbed5efcae784d7bf4f2ff80"


@pytest.fixture(scope="module")
def registry_client():
    client = ThreatRegistryClient(
        rpc_url=RPC_URL,
        contract_address=CONTRACT_ADDRESS,
        private_key=DEV_PRIVATE_KEY,
    )
    if not client.is_connected():
        pytest.skip("Local Hardhat node is not accessible on port 8545")
    return client


def test_case_a_original_report_verifies_successfully(registry_client):
    """Case A: An unaltered report payload produces an exact match with the on-chain commitment."""
    unique_id = f"test-audit-case-a-{secrets.token_hex(6)}"
    _, commitment_hex, canonical_payload, _ = compute_report_commitment(
        report_id=unique_id,
        target_type="URL",
        threat_category="PHISHING",
        risk_score=92,
        verdict="CONFIRMED_THREAT",
        indicators_count=3,
        evidence_digest="0x" + "a" * 64,
    )

    # 1. Register report on blockchain
    reg_res = registry_client.register_report(unique_id, commitment_hex)
    assert reg_res["status"] == BlockchainRegistrationStatus.CONFIRMED.value
    assert reg_res["is_registered"] is True

    # 2. Standalone Independent Verification (directly querying RPC, no backend API)
    result = verify_report_data(
        report_data={"canonical_payload": canonical_payload},
        rpc_url=RPC_URL,
        contract_address=CONTRACT_ADDRESS,
    )

    assert result["verdict"] == "VERIFIED"
    assert result["report_id"] == unique_id
    assert result["calculated_commitment"].lower() == commitment_hex.lower()
    assert result["on_chain_commitment"].lower() == commitment_hex.lower()
    assert result["matching_revision"] == 0
    assert "Integrity confirmed" in result["message"]


def test_case_b_modified_report_fails_verification(registry_client):
    """Case B: A modified report payload produces a commitment hash mismatch (tamper detection)."""
    unique_id = f"test-audit-case-b-{secrets.token_hex(6)}"
    _, commitment_hex, canonical_payload, _ = compute_report_commitment(
        report_id=unique_id,
        target_type="URL",
        threat_category="MALWARE_DISTRIBUTION",
        risk_score=98,
        verdict="CONFIRMED_THREAT",
        indicators_count=5,
        evidence_digest="0x" + "b" * 64,
    )

    # 1. Register legitimate report
    reg_res = registry_client.register_report(unique_id, commitment_hex)
    assert reg_res["is_registered"] is True

    # 2. Tamper with the report payload (e.g. malicious actor lowers risk_score to 10)
    tampered_payload = dict(canonical_payload)
    tampered_payload["risk_score"] = 10
    tampered_payload["threat_category"] = "BENIGN"

    # 3. Independent Verification
    result = verify_report_data(
        report_data={"canonical_payload": tampered_payload},
        rpc_url=RPC_URL,
        contract_address=CONTRACT_ADDRESS,
    )

    assert result["verdict"] == "MISMATCH"
    assert result["report_id"] == unique_id
    assert result["calculated_commitment"].lower() != commitment_hex.lower()
    assert result["on_chain_commitment"].lower() == commitment_hex.lower()
    assert "Tampering or data corruption detected" in result["message"]


def test_case_c_unknown_report_not_found(registry_client):
    """Case C: A report ID that was never registered returns NOT FOUND."""
    unregistered_id = f"test-unregistered-{secrets.token_hex(8)}"
    dummy_payload = {
        "report_id": unregistered_id,
        "target_type": "URL",
        "threat_category": "UNKNOWN",
        "risk_score": 50,
        "verdict": "SUSPICIOUS",
        "indicators_count": 0,
        "evidence_digest": "0x" + "0" * 64,
        "salt": "0x" + "0" * 64,
        "version": "1.0",
        "timestamp": "2026-11-08T12:00:00Z",
    }

    result = verify_report_data(
        report_data={"canonical_payload": dummy_payload},
        rpc_url=RPC_URL,
        contract_address=CONTRACT_ADDRESS,
    )

    assert result["verdict"] == "NOT FOUND"
    assert result["report_id"] == unregistered_id
    assert "No matching registration exists" in result["message"]


def test_case_d_rpc_unavailable_handling():
    """Case D: Unreachable blockchain node returns UNAVAILABLE without crashing."""
    offline_rpc = "http://127.0.0.1:19999"
    dummy_payload = {
        "report_id": "test-offline-node",
        "target_type": "URL",
        "threat_category": "PHISHING",
        "risk_score": 85,
        "verdict": "MALICIOUS",
        "indicators_count": 1,
        "evidence_digest": "0x" + "d" * 64,
        "salt": "0x" + "d" * 64,
        "version": "1.0",
        "timestamp": "2026-11-08T12:00:00Z",
    }

    result = verify_report_data(
        report_data={"canonical_payload": dummy_payload},
        rpc_url=offline_rpc,
        contract_address=CONTRACT_ADDRESS,
    )

    assert result["verdict"] == "UNAVAILABLE"
    assert "Direct blockchain query failed" in result["message"] or "RPC unavailable" in result["message"]


def test_case_e_revision_history_verification(registry_client):
    """Case E: Revised report verifies against its historical registered version."""
    unique_id = f"test-audit-case-e-{secrets.token_hex(6)}"

    # Initial report (Revision #0)
    _, initial_hash, initial_payload, _ = compute_report_commitment(
        report_id=unique_id,
        target_type="URL",
        threat_category="SUSPICIOUS_REDIRECT",
        risk_score=60,
        verdict="SUSPICIOUS",
        indicators_count=1,
        evidence_digest="0x" + "e1" * 32,
    )

    # Revised report (Revision #1)
    _, revised_hash, revised_payload, _ = compute_report_commitment(
        report_id=unique_id,
        target_type="URL",
        threat_category="CONFIRMED_CREDENTIAL_HARVESTER",
        risk_score=95,
        verdict="MALICIOUS",
        indicators_count=4,
        evidence_digest="0x" + "e2" * 32,
    )

    # 1. Register initial
    reg_res = registry_client.register_report(unique_id, initial_hash)
    assert reg_res["is_registered"] is True

    # 2. Submit revision
    rev_res = registry_client.revise_report(unique_id, revised_hash)
    assert rev_res["is_registered"] is True

    # 3. Verify revised payload (matches latest on-chain commitment)
    revised_verify = verify_report_data(
        report_data={"canonical_payload": revised_payload},
        rpc_url=RPC_URL,
        contract_address=CONTRACT_ADDRESS,
    )
    assert revised_verify["verdict"] == "VERIFIED"
    assert revised_verify["calculated_commitment"].lower() == revised_hash.lower()
    assert revised_verify["on_chain_commitment"].lower() == revised_hash.lower()
    assert revised_verify["revision_count"] >= 1

    # 4. Verify historical initial payload (matches Revision #0)
    initial_verify = verify_report_data(
        report_data={"canonical_payload": initial_payload},
        rpc_url=RPC_URL,
        contract_address=CONTRACT_ADDRESS,
    )
    assert initial_verify["verdict"] == "VERIFIED"
    assert initial_verify["calculated_commitment"].lower() == initial_hash.lower()
    assert initial_verify["matching_revision"] == 0
    assert "Revision #0" in initial_verify["message"]


def test_case_f_zero_backend_trust_cli_execution(registry_client):
    """Case F: Standalone CLI runs as a separate process and verifies reports without the backend."""
    unique_id = f"test-audit-case-f-{secrets.token_hex(6)}"
    _, commitment_hex, canonical_payload, _ = compute_report_commitment(
        report_id=unique_id,
        target_type="URL",
        threat_category="IMPERSONATION",
        risk_score=88,
        verdict="CONFIRMED_THREAT",
        indicators_count=2,
        evidence_digest="0x" + "f" * 64,
    )

    # Register on blockchain
    reg_res = registry_client.register_report(unique_id, commitment_hex)
    assert reg_res["is_registered"] is True

    # Create verifiable export JSON on disk
    certificate = {
        "report_id": unique_id,
        "commitment_hash": commitment_hex,
        "network": "EVM Localnet (Chain 31337)",
        "contract_address": CONTRACT_ADDRESS,
        "canonical_payload": canonical_payload,
    }

    with tempfile.NamedTemporaryFile("w", suffix=".json", delete=False, encoding="utf-8") as f:
        json.dump(certificate, f, indent=2)
        temp_cert_path = f.name

    try:
        # Run CLI verification tool as an independent external process
        cli_path = os.path.join(WORKSPACE_ROOT, "tools", "verify_report.py")
        cmd = [
            sys.executable,
            cli_path,
            "--report", temp_cert_path,
            "--rpc", RPC_URL,
            "--contract", CONTRACT_ADDRESS,
            "--json",
        ]

        proc = subprocess.run(
            cmd,
            stdout=subprocess.PIPE,
            stderr=subprocess.PIPE,
            text=True,
            timeout=15,
        )

        assert proc.returncode == 0, f"CLI stderr: {proc.stderr}"
        output_data = json.loads(proc.stdout)

        assert output_data["verdict"] == "VERIFIED"
        assert output_data["report_id"] == unique_id
        assert output_data["calculated_commitment"].lower() == commitment_hex.lower()
        assert output_data["on_chain_commitment"].lower() == commitment_hex.lower()
    finally:
        if os.path.exists(temp_cert_path):
            os.remove(temp_cert_path)
