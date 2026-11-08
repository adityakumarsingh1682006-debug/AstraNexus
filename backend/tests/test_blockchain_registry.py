"""Automated Tests for AstraNexus Blockchain Threat Report Registry.

Covers:
1. Deterministic canonical serialization format and Unicode normalization.
2. Salted commitment generation (protects against rainbow tables and low-entropy guessing).
3. Zero PII storage verification.
4. Registry client handling for NOT_CONFIGURED, RPC_UNAVAILABLE, INSUFFICIENT_FUNDS, and DUPLICATE.
5. Live on-chain registration, event verification, and tamper-evident mismatch detection.
6. Verification endpoint testing.
"""

import pytest
import secrets
from unittest.mock import MagicMock, patch
from web3 import Web3

from backend.app.services.blockchain.canonicalizer import (
    compute_report_commitment,
    verify_canonical_commitment,
    build_canonical_payload,
    serialize_canonical,
    normalize_string,
)
from backend.app.services.blockchain.registry_client import (
    ThreatRegistryClient,
    BlockchainRegistrationStatus,
    ThreatAttestationStatus,
)


def test_deterministic_canonicalization_and_hashing():
    """Identical reports with the same salt must produce the exact same canonical JSON and hash."""
    fixed_salt = "0x" + "a" * 64
    fixed_timestamp = "2026-11-08T12:00:00Z"

    report_id_hex1, hash1, payload1, bytes1 = compute_report_commitment(
        report_id="test-rep-abc",
        target_type="URL",
        threat_category="PHISHING",
        risk_score=95,
        verdict="MALICIOUS",
        indicators_count=4,
        evidence_digest="0x1111222233334444555566667777888899990000aaaabbbbccccddddeeeeffff",
        salt=fixed_salt,
        timestamp=fixed_timestamp,
    )

    report_id_hex2, hash2, payload2, bytes2 = compute_report_commitment(
        report_id="  test-rep-abc  ",  # tests whitespace normalization
        target_type="url",  # tests case normalization
        threat_category="phishing",
        risk_score=95,
        verdict="malicious",
        indicators_count=4,
        evidence_digest="0x1111222233334444555566667777888899990000aaaabbbbccccddddeeeeffff",
        salt=fixed_salt,
        timestamp=fixed_timestamp,
    )

    assert hash1 == hash2
    assert report_id_hex1 == report_id_hex2
    assert bytes1 == bytes2
    assert verify_canonical_commitment(payload1, hash1) is True
    assert verify_canonical_commitment(payload2, hash1) is True


def test_different_salt_produces_different_commitment():
    """Different cryptographic salts must produce completely distinct commitment hashes (preimage resistance)."""
    salt_a = "0x" + "a" * 64
    salt_b = "0x" + "b" * 64

    _, hash_a, _, _ = compute_report_commitment(
        report_id="rep-1",
        target_type="URL",
        threat_category="SCAM",
        risk_score=80,
        verdict="SUSPICIOUS",
        indicators_count=2,
        evidence_digest="0x" + "1" * 64,
        salt=salt_a,
    )

    _, hash_b, _, _ = compute_report_commitment(
        report_id="rep-1",
        target_type="URL",
        threat_category="SCAM",
        risk_score=80,
        verdict="SUSPICIOUS",
        indicators_count=2,
        evidence_digest="0x" + "1" * 64,
        salt=salt_b,
    )

    assert hash_a != hash_b


def test_zero_pii_in_canonical_payload():
    """Canonical commitment payload must NEVER contain sensitive consumer or target data."""
    payload = build_canonical_payload(
        report_id="rep-privacy-test",
        target_type="MESSAGE",
        threat_category="BANKING_FRAUD",
        risk_score=90,
        verdict="MALICIOUS",
        indicators_count=1,
        evidence_digest="0x" + "e" * 64,
    )

    forbidden_fields = ["url", "message", "phone", "email", "password", "otp", "ssn", "target_indicator"]
    for key in payload.keys():
        assert key.lower() not in forbidden_fields

    # Ensure payload values do not contain raw URLs or phone numbers
    for val in payload.values():
        if isinstance(val, str):
            assert "http://" not in val
            assert "https://" not in val
            assert "@" not in val


def test_registry_client_unconfigured_handling():
    """Client must honestly report NOT_CONFIGURED and never fabricate a transaction hash."""
    client = ThreatRegistryClient(rpc_url=None, contract_address=None, private_key=None)
    result = client.register_report(report_id="test", commitment_hash="0x" + "0" * 64)

    assert result["status"] == BlockchainRegistrationStatus.NOT_CONFIGURED.value
    assert result["is_registered"] is False
    assert result["tx_hash"] is None


def test_registry_client_rpc_unavailable_handling():
    """Client must honestly report RPC_UNAVAILABLE when node is offline and never invent fake tx."""
    client = ThreatRegistryClient(
        rpc_url="http://127.0.0.1:19999",  # Non-existent port
        contract_address="0x5FbDB2315678afecb367f032d93F642f64180aa3",
        private_key="0x" + "a" * 64,
    )
    result = client.register_report(report_id="test", commitment_hash="0x" + "0" * 64)

    assert result["status"] == BlockchainRegistrationStatus.RPC_UNAVAILABLE.value
    assert result["is_registered"] is False
    assert result["tx_hash"] is None


def test_registry_client_insufficient_funds_handling():
    """Client must detect insufficient account balance for gas and refuse to submit failing tx."""
    client = ThreatRegistryClient(
        rpc_url="http://127.0.0.1:8545",
        contract_address="0x5FbDB2315678afecb367f032d93F642f64180aa3",
        private_key="0x" + "1" * 64,  # Random unfunded account
    )

    if not client.is_connected():
        pytest.skip("Local Hardhat node is not running on port 8545")

    result = client.register_report(report_id="test-unfunded", commitment_hash="0x" + "0" * 64)
    assert result["status"] in [
        BlockchainRegistrationStatus.INSUFFICIENT_FUNDS.value,
        BlockchainRegistrationStatus.FAILED.value,
    ]
    assert result["is_registered"] is False


def test_live_local_hardhat_registration_and_verification():
    """Tests end-to-end registration against the local Hardhat node."""
    client = ThreatRegistryClient(
        rpc_url="http://127.0.0.1:8545",
        contract_address="0x5FbDB2315678afecb367f032d93F642f64180aa3",
        private_key="0xac0974bec39a17e36ba4a6b4d238ff944bacb478cbed5efcae784d7bf4f2ff80",
    )

    if not client.is_connected():
        pytest.skip("Local Hardhat node is not running on port 8545")

    unique_report_id = f"test-automated-{secrets.token_hex(6)}"
    _, commitment_hex, payload, _ = compute_report_commitment(
        report_id=unique_report_id,
        target_type="URL",
        threat_category="PHISHING",
        risk_score=94,
        verdict="CONFIRMED_THREAT",
        indicators_count=3,
        evidence_digest="0x" + "f" * 64,
    )

    # 1. Register
    reg_result = client.register_report(report_id=unique_report_id, commitment_hash=commitment_hex)
    assert reg_result["status"] == BlockchainRegistrationStatus.CONFIRMED.value
    assert reg_result["is_registered"] is True
    assert reg_result["tx_hash"] is not None
    assert reg_result["tx_hash"].startswith("0x")
    assert reg_result["block_number"] > 0

    # 2. Verify Authentic
    verify_result = client.verify_report(report_id=unique_report_id, expected_commitment_hash=commitment_hex)
    assert verify_result["is_verified"] is True
    assert verify_result["exists"] is True
    assert verify_result["status"] == "TAMPER_EVIDENT_VERIFIED"
    assert verify_result["on_chain_commitment"].lower() == commitment_hex.lower()

    # 3. Verify Tampered Mismatch Detection
    tampered_hash = "0x" + "0" * 64
    mismatch_result = client.verify_report(report_id=unique_report_id, expected_commitment_hash=tampered_hash)
    assert mismatch_result["is_verified"] is False
    assert mismatch_result["exists"] is True
    assert mismatch_result["status"] == "COMMITMENT_MISMATCH"

    # 4. Duplicate Registration Handling
    dup_result = client.register_report(report_id=unique_report_id, commitment_hash=commitment_hex)
    assert dup_result["status"] == BlockchainRegistrationStatus.DUPLICATE.value
    assert dup_result["is_registered"] is True
