#!/usr/bin/env python3
"""AstraNexus Standalone Report Integrity Verification Tool.

DOES NOT TRUST OR RELY ON THE ASTRANEXUS BACKEND.
Directly calculates cryptographic commitments locally and queries
the EVM blockchain via standard JSON-RPC.

Supports:
- Canonical JSON serialization
- High-entropy salt hashing (Keccak-256)
- Direct JSON-RPC eth_call communication
- Revision history audit
- Distinction between data integrity and allegation truth

Usage:
    python tools/verify_report.py --report certificate.json --rpc http://127.0.0.1:8545 --contract 0x5FbDB2315678afecb367f032d93F642f64180aa3
"""

import sys
import os
import json
import argparse
import unicodedata
from datetime import datetime, timezone
from typing import Dict, Any, Tuple, Optional
import urllib.request
import urllib.error

# Use web3 if available; fallback to hashlib/pysha3/pure-python if necessary
try:
    from web3 import Web3
    HAS_WEB3 = True
except ImportError:
    HAS_WEB3 = False


DEFAULT_RPC = os.getenv("EVM_RPC_URL", "http://127.0.0.1:8545")
DEFAULT_CONTRACT = os.getenv("ASTRA_REGISTRY_CONTRACT_ADDRESS", "0x5FbDB2315678afecb367f032d93F642f64180aa3")

DISCLAIMER = (
    "================================================================================\n"
    "INTEGRITY VERIFICATION NOTICE:\n"
    "Cryptographic verification proves that this report has NOT been altered, corrupted,\n"
    "or tampered with since its notarization on the EVM blockchain.\n"
    "Integrity verification guarantees document provenance and mathematical non-tampering;\n"
    "it does NOT constitute a judicial determination of scam allegations.\n"
    "================================================================================"
)

STATUS_MAP = {
    0: "UNVERIFIED",
    1: "CONFIRMED_THREAT",
    2: "BENIGN_CLEARED",
    3: "DISPUTED",
    4: "REVOKED",
}


def normalize_text(text: str) -> str:
    if not text:
        return ""
    return unicodedata.normalize("NFC", str(text).strip())


def keccak256(data: bytes) -> str:
    """Computes Keccak-256 hash using Web3 or sha3."""
    if HAS_WEB3:
        h = Web3.keccak(data).hex()
        return "0x" + h if not h.startswith("0x") else h
    else:
        # Fallback to standard hashlib if available (Python 3.11+ hashlib.sha3_256 or Crypto)
        try:
            from Crypto.Hash import keccak
            k = keccak.new(digest_bits=256)
            k.update(data)
            return "0x" + k.hexdigest()
        except ImportError:
            import hashlib
            # As a last resort fallback for testing environments without web3/pycryptodome
            return "0x" + hashlib.sha256(data).hexdigest()


def canonical_serialize(obj: Dict[str, Any]) -> Tuple[bytes, str]:
    """Deterministically serializes payload with sorted keys and minimal separators."""
    s = json.dumps(obj, sort_keys=True, separators=(",", ":"), ensure_ascii=False)
    return s.encode("utf-8"), s


def calculate_commitment(payload: Dict[str, Any]) -> Tuple[str, str, bytes]:
    """Calculates reportId bytes32 and commitmentHash bytes32 from canonical dictionary."""
    normalized_payload = {}
    for k, v in payload.items():
        if isinstance(v, str):
            normalized_payload[k] = normalize_text(v)
        else:
            normalized_payload[k] = v

    canonical_bytes, _ = canonical_serialize(normalized_payload)
    commitment_hash = keccak256(canonical_bytes)

    report_id = normalized_payload.get("report_id", "")
    if report_id.startswith("0x") and len(report_id) == 66:
        report_id_bytes32 = report_id
    else:
        report_id_bytes32 = keccak256(normalize_text(report_id).encode("utf-8"))

    return report_id_bytes32, commitment_hash, canonical_bytes


def call_rpc(rpc_url: str, method: str, params: list) -> Dict[str, Any]:
    """Direct JSON-RPC call over HTTP without requiring external libraries."""
    req_payload = json.dumps({
        "jsonrpc": "2.0",
        "method": method,
        "params": params,
        "id": 1
    }).encode("utf-8")

    req = urllib.request.Request(
        rpc_url,
        data=req_payload,
        headers={"Content-Type": "application/json"}
    )

    with urllib.request.urlopen(req, timeout=5) as response:
        resp_data = json.loads(response.read().decode("utf-8"))
        if "error" in resp_data:
            raise RuntimeError(f"RPC Error: {resp_data['error']}")
        return resp_data


def query_contract_reports(rpc_url: str, contract_address: str, report_id_bytes32: str) -> Optional[Dict[str, Any]]:
    """Queries `reports(bytes32)` directly from EVM blockchain without backend intermediary."""
    # Function selector for reports(bytes32): keccak256("reports(bytes32)")[:4] = 0xb39c4897
    clean_id = report_id_bytes32[2:] if report_id_bytes32.startswith("0x") else report_id_bytes32
    call_data = "0xb39c4897" + clean_id.rjust(64, "0")

    result = call_rpc(rpc_url, "eth_call", [{"to": contract_address, "data": call_data}, "latest"])
    hex_data = result.get("result", "")
    if not hex_data or hex_data == "0x":
        return None

    # Decode tuple (bytes32 reportId, bytes32 commitmentHash, uint256 initialTimestamp, address reporter, uint8 status, uint256 disputeCount, bool exists)
    # 7 words of 32 bytes (64 hex chars each):
    raw = hex_data[2:]
    if len(raw) < 64 * 7:
        return None

    word0_id = "0x" + raw[0:64]
    word1_commitment = "0x" + raw[64:128]
    word2_timestamp = int(raw[128:192], 16)
    word3_reporter = "0x" + raw[192:256][-40:]
    word4_status = int(raw[256:320], 16)
    word5_disputes = int(raw[320:384], 16)
    word6_exists = int(raw[384:448], 16) == 1

    return {
        "reportId": word0_id,
        "commitmentHash": word1_commitment,
        "initialTimestamp": word2_timestamp,
        "reporter": word3_reporter,
        "status": word4_status,
        "disputeCount": word5_disputes,
        "exists": word6_exists,
    }


def query_contract_revisions(rpc_url: str, contract_address: str, report_id_bytes32: str) -> list:
    """Queries revision history directly from EVM blockchain."""
    clean_id = report_id_bytes32[2:] if report_id_bytes32.startswith("0x") else report_id_bytes32
    # selector for getRevisionCount(bytes32): 0x64228857
    call_data = "0x64228857" + clean_id.rjust(64, "0")
    try:
        res = call_rpc(rpc_url, "eth_call", [{"to": contract_address, "data": call_data}, "latest"])
        count_hex = res.get("result", "0x0")
        count = int(count_hex, 16) if count_hex != "0x" else 0
    except Exception:
        return []

    revisions = []
    # selector for getRevision(bytes32,uint256): 0xbfb713a5
    for i in range(count):
        idx_hex = hex(i)[2:].rjust(64, "0")
        rev_call = "0xbfb713a5" + clean_id.rjust(64, "0") + idx_hex
        try:
            rev_res = call_rpc(rpc_url, "eth_call", [{"to": contract_address, "data": rev_call}, "latest"])
            rev_raw = rev_res.get("result", "")[2:]
            if len(rev_raw) >= 64 * 4:
                comm = "0x" + rev_raw[0:64]
                ts = int(rev_raw[64:128], 16)
                blk = int(rev_raw[128:192], 16)
                revised_by = "0x" + rev_raw[192:256][-40:]
                revisions.append({
                    "revision_index": i,
                    "commitment_hash": comm,
                    "timestamp": ts,
                    "block_number": blk,
                    "revised_by": revised_by,
                })
        except Exception:
            break

    return revisions


def verify_report_data(
    report_data: Dict[str, Any],
    rpc_url: str = DEFAULT_RPC,
    contract_address: str = DEFAULT_CONTRACT,
    report_id_override: Optional[str] = None,
) -> Dict[str, Any]:
    """Core verification function. Does NOT rely on AstraNexus backend."""
    # 1. Extract canonical payload
    if "canonical_payload" in report_data:
        canonical_payload = report_data["canonical_payload"]
    elif "version" in report_data and "report_id" in report_data:
        canonical_payload = report_data
    else:
        # Check if it has a technical_evidence dictionary or similar
        canonical_payload = report_data

    # Optional report_id override
    if report_id_override:
        canonical_payload["report_id"] = report_id_override

    # 2. Independently compute local commitment
    try:
        report_id_bytes32, calculated_commitment, _ = calculate_commitment(canonical_payload)
    except Exception as e:
        return {
            "verdict": "UNAVAILABLE",
            "message": f"Failed to calculate canonical commitment: {str(e)}",
            "report_id": canonical_payload.get("report_id"),
        }

    # 3. Query blockchain directly
    try:
        on_chain_record = query_contract_reports(rpc_url, contract_address, report_id_bytes32)
    except Exception as e:
        return {
            "verdict": "UNAVAILABLE",
            "message": f"Direct blockchain query failed (RPC unavailable or invalid contract): {str(e)}",
            "rpc_url": rpc_url,
            "contract_address": contract_address,
            "report_id": canonical_payload.get("report_id"),
            "calculated_commitment": calculated_commitment,
        }

    # 4. Analyze on-chain presence
    if not on_chain_record or not on_chain_record["exists"]:
        return {
            "verdict": "NOT FOUND",
            "message": "No matching registration exists on the ThreatRegistry contract.",
            "report_id": canonical_payload.get("report_id"),
            "report_id_bytes32": report_id_bytes32,
            "calculated_commitment": calculated_commitment,
            "contract_address": contract_address,
            "rpc_url": rpc_url,
        }

    on_chain_hash = on_chain_record["commitmentHash"].lower()
    local_hash = calculated_commitment.lower()

    # 5. Retrieve revision history
    revisions = query_contract_revisions(rpc_url, contract_address, report_id_bytes32)

    # 6. Evaluate verdict
    if on_chain_hash == local_hash:
        verdict = "VERIFIED"
        message = "Report perfectly matches current on-chain cryptographic commitment. Integrity confirmed."
        matching_revision = len(revisions) - 1 if revisions else 0
    else:
        # Check if matches an earlier revision
        found_rev = next((r for r in revisions if r["commitment_hash"].lower() == local_hash), None)
        if found_rev:
            verdict = "VERIFIED"
            message = f"Report matches on-chain commitment from Revision #{found_rev['revision_index']} (Superseded by later revision)."
            matching_revision = found_rev["revision_index"]
        else:
            verdict = "MISMATCH"
            message = "Report differs from registered on-chain version. Tampering or data corruption detected!"
            matching_revision = None

    return {
        "verdict": verdict,
        "message": message,
        "report_id": canonical_payload.get("report_id"),
        "report_id_bytes32": report_id_bytes32,
        "calculated_commitment": calculated_commitment,
        "on_chain_commitment": on_chain_record["commitmentHash"],
        "initial_timestamp": on_chain_record["initialTimestamp"],
        "initial_datetime": datetime.fromtimestamp(on_chain_record["initialTimestamp"], timezone.utc).isoformat() if on_chain_record["initialTimestamp"] else None,
        "reporter_address": on_chain_record["reporter"],
        "attestation_status": STATUS_MAP.get(on_chain_record["status"], "UNKNOWN"),
        "dispute_count": on_chain_record["disputeCount"],
        "contract_address": contract_address,
        "rpc_url": rpc_url,
        "revision_count": len(revisions),
        "matching_revision": matching_revision,
        "revisions": revisions,
    }


def main():
    parser = argparse.ArgumentParser(
        description="AstraNexus Independent Report Integrity Verifier (Zero Backend Reliance)",
        epilog=DISCLAIMER,
        formatter_class=argparse.RawDescriptionHelpFormatter,
    )
    parser.add_argument("--report", "-r", required=True, help="Path to report JSON export or '-' for stdin")
    parser.add_argument("--report-id", "-i", default=None, help="Optional override for report identifier")
    parser.add_argument("--rpc", default=DEFAULT_RPC, help=f"EVM JSON-RPC URL (default: {DEFAULT_RPC})")
    parser.add_argument("--contract", "-c", default=DEFAULT_CONTRACT, help=f"ThreatRegistry contract address (default: {DEFAULT_CONTRACT})")
    parser.add_argument("--json", action="store_true", help="Output machine-readable JSON")

    args = parser.parse_args()

    # Load report payload
    try:
        if args.report == "-":
            raw_content = sys.stdin.read()
        else:
            with open(args.report, "r", encoding="utf-8") as f:
                raw_content = f.read()
        report_data = json.loads(raw_content)
    except Exception as e:
        print(f"Error reading report data: {e}", file=sys.stderr)
        sys.exit(1)

    result = verify_report_data(
        report_data=report_data,
        rpc_url=args.rpc,
        contract_address=args.contract,
        report_id_override=args.report_id,
    )

    if args.json:
        print(json.dumps(result, indent=2))
        return

    # User-friendly Terminal Output
    print("\n" + "=" * 80)
    print(" ASTRANEXUS INDEPENDENT REPORT INTEGRITY AUDIT")
    print(" Verification executed directly against EVM blockchain (Zero Backend Reliance)")
    print("=" * 80)

    verdict = result["verdict"]
    color_code = {
        "VERIFIED": "\033[92m",   # Green
        "MISMATCH": "\033[91m",   # Red
        "NOT FOUND": "\033[93m",  # Yellow
        "UNAVAILABLE": "\033[90m" # Gray
    }.get(verdict, "")
    reset_code = "\033[0m"

    print(f"\nAUDIT VERDICT: {color_code}[{verdict}]{reset_code}")
    print(f"Details:       {result['message']}")
    print("-" * 80)
    print(f"Report ID:     {result.get('report_id')}")
    print(f"Contract:      {result.get('contract_address')}")
    print(f"RPC Endpoint:  {result.get('rpc_url')}")

    if "calculated_commitment" in result:
        print(f"Local Digest:  {result['calculated_commitment']}")
    if "on_chain_commitment" in result:
        print(f"On-Chain Hash: {result['on_chain_commitment']}")
    if "initial_datetime" in result and result["initial_datetime"]:
        print(f"Timestamp:     {result['initial_datetime']}")
    if "attestation_status" in result:
        print(f"Attestation:   {result['attestation_status']}")
    if "dispute_count" in result:
        print(f"Disputes:      {result['dispute_count']}")
    if "revision_count" in result:
        print(f"Revisions:     {result['revision_count']} recorded")

    print("\n" + DISCLAIMER + "\n")

    if verdict == "VERIFIED":
        sys.exit(0)
    elif verdict == "MISMATCH":
        sys.exit(2)
    elif verdict == "NOT FOUND":
        sys.exit(3)
    else:
        sys.exit(4)


if __name__ == "__main__":
    main()
