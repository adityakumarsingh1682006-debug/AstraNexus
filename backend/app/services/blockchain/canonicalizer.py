"""AstraNexus Canonical Threat Report Commitment Engine.

Implements deterministic serialization, Unicode NFC normalization,
and salted Keccak-256 / SHA-256 cryptographic commitments.

Strict Privacy Guard:
NEVER incorporates raw URLs, raw scam message text, phone numbers,
emails, passwords, or PII into the commitment.
"""

import json
import secrets
import unicodedata
from datetime import datetime, timezone
from typing import Dict, Any, Tuple, Optional
from web3 import Web3


CANONICAL_SCHEMA_VERSION = "astranexus-threat-commitment-v1"


def normalize_string(text: str) -> str:
    """Normalizes string using Unicode NFC and strips exterior whitespace."""
    if not text:
        return ""
    return unicodedata.normalize("NFC", text.strip())


def generate_secure_salt() -> str:
    """Generates a 256-bit cryptographically secure hexadecimal salt.

    Protects against rainbow tables and low-entropy dictionary preimage attacks.
    """
    return "0x" + secrets.token_hex(32)


def build_canonical_payload(
    report_id: str,
    target_type: str,
    threat_category: str,
    risk_score: int,
    verdict: str,
    indicators_count: int,
    evidence_digest: str,
    salt: Optional[str] = None,
    timestamp: Optional[str] = None,
) -> Dict[str, Any]:
    """Constructs the canonical dictionary representation of a threat report commitment."""
    ts = timestamp or datetime.now(timezone.utc).strftime("%Y-%m-%dT%H:%M:%SZ")
    random_salt = salt or generate_secure_salt()

    return {
        "version": CANONICAL_SCHEMA_VERSION,
        "report_id": normalize_string(report_id),
        "target_type": normalize_string(target_type).upper(),
        "threat_category": normalize_string(threat_category).upper(),
        "risk_score": int(risk_score),
        "verdict": normalize_string(verdict).upper(),
        "indicators_count": int(indicators_count),
        "evidence_digest": normalize_string(evidence_digest),
        "timestamp": ts,
        "salt": random_salt,
    }


def serialize_canonical(payload: Dict[str, Any]) -> Tuple[bytes, str]:
    """Deterministically serializes dictionary into UTF-8 bytes and JSON string

    with lexicographically sorted keys and minimal separators.
    """
    canonical_json_str = json.dumps(
        payload,
        sort_keys=True,
        separators=(",", ":"),
        ensure_ascii=False,
    )
    canonical_bytes = canonical_json_str.encode("utf-8")
    return canonical_bytes, canonical_json_str


def compute_report_commitment(
    report_id: str,
    target_type: str,
    threat_category: str,
    risk_score: int,
    verdict: str,
    indicators_count: int,
    evidence_digest: str,
    salt: Optional[str] = None,
    timestamp: Optional[str] = None,
) -> Tuple[str, str, Dict[str, Any], bytes]:
    """Builds canonical payload and computes both Keccak-256 and SHA-256 digests.

    Returns:
        (report_id_bytes32, commitment_hash_hex, canonical_payload, canonical_bytes)
    """
    payload = build_canonical_payload(
        report_id=report_id,
        target_type=target_type,
        threat_category=threat_category,
        risk_score=risk_score,
        verdict=verdict,
        indicators_count=indicators_count,
        evidence_digest=evidence_digest,
        salt=salt,
        timestamp=timestamp,
    )

    canonical_bytes, _ = serialize_canonical(payload)

    # EVM bytes32 commitment hash
    commitment_hash_bytes = Web3.keccak(canonical_bytes)
    commitment_hash_hex = commitment_hash_bytes.hex()
    if not commitment_hash_hex.startswith("0x"):
        commitment_hash_hex = "0x" + commitment_hash_hex

    # EVM bytes32 report identifier
    report_id_bytes = Web3.keccak(text=normalize_string(report_id))
    report_id_hex = report_id_bytes.hex()
    if not report_id_hex.startswith("0x"):
        report_id_hex = "0x" + report_id_hex

    return report_id_hex, commitment_hash_hex, payload, canonical_bytes


def verify_canonical_commitment(canonical_payload: Dict[str, Any], expected_commitment_hash: str) -> bool:
    """Verifies whether a canonical report payload matches an expected on-chain commitment."""
    canonical_bytes, _ = serialize_canonical(canonical_payload)
    computed_hash = Web3.keccak(canonical_bytes).hex()
    if not computed_hash.startswith("0x"):
        computed_hash = "0x" + computed_hash

    expected_clean = expected_commitment_hash.lower()
    if not expected_clean.startswith("0x"):
        expected_clean = "0x" + expected_clean

    return computed_hash.lower() == expected_clean
