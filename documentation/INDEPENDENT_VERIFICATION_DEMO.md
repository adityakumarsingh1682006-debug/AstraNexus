# AstraNexus: Independent Report Integrity Verification Demonstration

This document provides a technical walkthrough and empirical demonstration of the **AstraNexus Independent Report Integrity Verifier** (Task 5).

---

## 1. Zero Backend Trust Architecture

AstraNexus guarantees that **no third party or auditor needs to trust or contact the AstraNexus backend** to determine whether a report is authentic.

```
[Auditor Machine / Browser / Terminal]
         │
         │  1. Parse Canonical Export JSON (Local)
         │  2. Compute Keccak-256 Digest (Local)
         │  3. Direct JSON-RPC eth_call (Port 8545 / Public Node)
         ▼
[EVM Blockchain Ledger (ThreatRegistry Smart Contract)]
   Address: 0x5FbDB2315678afecb367f032d93F642f64180aa3
```

- **No API reliance:** AstraNexus port `8000` is completely bypassed.
- **Pure local mathematics:** The report commitment is calculated deterministically via Unicode NFC normalization and sorted canonical JSON serialization.
- **Direct on-chain lookup:** Reads `reports(bytes32)` and `getRevision(bytes32, uint256)` via standard EVM JSON-RPC calls.

---

## 2. Tools Available for Independent Verification

### A. Standalone Python CLI Tool (`tools/verify_report.py`)
- Independent Python script with standard-library HTTP fallback (`urllib.request`).
- Calculates canonical Keccak-256 commitment.
- Direct EVM RPC querying.
- Outputs human-readable or structured JSON (`--json`).

### B. In-Browser Standalone UI (`http://localhost:3000/verify`)
- Built using `ethers` v6 directly inside the user's browser.
- Accepts exported JSON files or manual Report ID + Commitment entry.
- Direct browser-to-node Web3 JSON-RPC calls with zero intermediary server traffic.

---

## 3. Empirical Test Demonstrations (Cases A – F)

### Case A: Original Authentic Report Verification
**Command:**
```bash
python tools/verify_report.py --report demo_authentic_report.json --rpc http://127.0.0.1:8545 --contract 0x5FbDB2315678afecb367f032d93F642f64180aa3
```
**Output:**
```
================================================================================
 ASTRANEXUS INDEPENDENT REPORT INTEGRITY AUDIT
 Verification executed directly against EVM blockchain (Zero Backend Reliance)
================================================================================

AUDIT VERDICT: [VERIFIED]
Details:       Report perfectly matches current on-chain cryptographic commitment. Integrity confirmed.
--------------------------------------------------------------------------------
Report ID:     rep-demo-integrity-001
Contract:      0x5FbDB2315678afecb367f032d93F642f64180aa3
RPC Endpoint:  http://127.0.0.1:8545
Local Digest:  0xe3af1752e95083b9d70ced57a56c05f9bfd8a05cce897a5e44cdf28d5c6cd7b2
On-Chain Hash: 0xe3af1752e95083b9d70ced57a56c05f9bfd8a05cce897a5e44cdf28d5c6cd7b2
Timestamp:     2026-11-08T13:17:38+00:00
Attestation:   UNVERIFIED
Disputes:      0
Revisions:     1 recorded

================================================================================
INTEGRITY VERIFICATION NOTICE:
Cryptographic verification proves that this report has NOT been altered, corrupted,
or tampered with since its notarization on the EVM blockchain.
Integrity verification guarantees document provenance and mathematical non-tampering;
it does NOT constitute a judicial determination of scam allegations.
================================================================================
```
*Result: Exit Code 0. Authentic commitment match confirmed.*

---

### Case B: Modified / Tampered Report Detection
**Scenario:** A malicious actor attempts to edit the report payload by lowering the risk score from `95` to `10` and switching verdict to `SAFE`.
**Command:**
```bash
python tools/verify_report.py --report demo_tampered_report.json
```
**Output:**
```
================================================================================
 ASTRANEXUS INDEPENDENT REPORT INTEGRITY AUDIT
 Verification executed directly against EVM blockchain (Zero Backend Reliance)
================================================================================

AUDIT VERDICT: [MISMATCH]
Details:       Report differs from registered on-chain version. Tampering or data corruption detected!
--------------------------------------------------------------------------------
Report ID:     rep-demo-integrity-001
Contract:      0x5FbDB2315678afecb367f032d93F642f64180aa3
RPC Endpoint:  http://127.0.0.1:8545
Local Digest:  0xc4939b852fa70316eb0407c7c4e4c47b6d17f451cd87e6146a075f685b67090a
On-Chain Hash: 0xe3af1752e95083b9d70ced57a56c05f9bfd8a05cce897a5e44cdf28d5c6cd7b2
Timestamp:     2026-11-08T13:17:38+00:00
Attestation:   UNVERIFIED
Disputes:      0
Revisions:     1 recorded

================================================================================
INTEGRITY VERIFICATION NOTICE:
Cryptographic verification proves that this report has NOT been altered, corrupted,
or tampered with since its notarization on the EVM blockchain.
Integrity verification guarantees document provenance and mathematical non-tampering;
it does NOT constitute a judicial determination of scam allegations.
================================================================================
```
*Result: Exit Code 1. Tampering detected immediately; local digest does not match immutable ledger hash.*

---

### Case C: Unknown / Unregistered Report Lookup
**Scenario:** An investigator attempts to verify a report ID that was never registered in the smart contract.
**Command:**
```bash
python tools/verify_report.py --report demo_authentic_report.json --report-id rep-unknown-nonexistent
```
**Output:**
```
================================================================================
 ASTRANEXUS INDEPENDENT REPORT INTEGRITY AUDIT
 Verification executed directly against EVM blockchain (Zero Backend Reliance)
================================================================================

AUDIT VERDICT: [NOT FOUND]
Details:       No matching registration exists on the ThreatRegistry contract.
--------------------------------------------------------------------------------
Report ID:     rep-unknown-nonexistent
Contract:      0x5FbDB2315678afecb367f032d93F642f64180aa3
RPC Endpoint:  http://127.0.0.1:8545
Local Digest:  0x5da2bc04444f3e3987cb6564a601c13f6991482aaec59b8a4b14bd9a7241339c
```
*Result: Exit Code 1. Explicit `NOT FOUND` verdict without crashes or ambiguity.*

---

### Case D: Blockchain RPC Unavailable Handling
**Scenario:** An auditor runs the tool with an offline or invalid RPC node (`port 19999`).
**Command:**
```bash
python tools/verify_report.py --report demo_authentic_report.json --rpc http://127.0.0.1:19999
```
**Output:**
```
================================================================================
 ASTRANEXUS INDEPENDENT REPORT INTEGRITY AUDIT
 Verification executed directly against EVM blockchain (Zero Backend Reliance)
================================================================================

AUDIT VERDICT: [UNAVAILABLE]
Details:       Direct blockchain query failed (RPC unavailable or invalid contract): <urlopen error [WinError 10061] No connection could be made because the target machine actively refused it>
--------------------------------------------------------------------------------
Report ID:     rep-demo-integrity-001
Contract:      0x5FbDB2315678afecb367f032d93F642f64180aa3
RPC Endpoint:  http://127.0.0.1:19999
Local Digest:  0xe3af1752e95083b9d70ced57a56c05f9bfd8a05cce897a5e44cdf28d5c6cd7b2
```
*Result: Exit Code 1. Returns clear `UNAVAILABLE` verdict with connection troubleshooting diagnostics.*

---

### Case E: Report Revision History Audit
**Scenario:** A threat report undergoes an update (e.g. initial suspicious redirect escalated to confirmed credential harvester).
1. Initial Commitment: `0xe3af1752...`
2. Revised Commitment: `0xa45f3a6b...` (Registered via `reviseReport` in tx `0xd247f299a5f502deaa5396e0beba5e97e2033d3aebd174fef689aeed93a52523`)

**Verification of Historical Revision #0:**
```bash
python tools/verify_report.py --report demo_authentic_report.json
```
**Output:**
```
AUDIT VERDICT: [VERIFIED]
Details:       Report matches on-chain commitment from Revision #0 (Superseded by later revision).
Revisions:     2 recorded
```

**Verification of Current Revision #1:**
```bash
python tools/verify_report.py --report demo_revised_report.json
```
**Output:**
```
AUDIT VERDICT: [VERIFIED]
Details:       Report perfectly matches current on-chain cryptographic commitment. Integrity confirmed.
Revisions:     2 recorded
```
*Result: The audit tool maintains full cryptographic accountability across all historical iterations.*

---

### Case F: Backend Independence Verification
- The CLI tool `tools/verify_report.py` executes in a fresh, isolated Python process.
- No imports from `backend.app` or FastAPI.
- Uses direct HTTP JSON-RPC `eth_call` queries to the blockchain.
- Verified in automated test `test_case_f_zero_backend_trust_cli_execution` in `backend/tests/test_independent_verifier.py`.

---

## 4. Distinction Between Integrity and Factual Truth

AstraNexus clearly demarcates technical data integrity from legal or factual truth:

> **Data Integrity:** Guarantees via SHA-256 and Keccak-256 commitments that the digital text and metadata of a report have not been modified, forged, or altered since their notarization block.
>
> **Allegation Truth:** Whether an allegation against a domain or entity is legally or objectively true cannot be mathematically proven by a blockchain ledger. AstraNexus provides attestation flags (`UNVERIFIED`, `CONFIRMED_THREAT`, `BENIGN_CLEARED`, `DISPUTED`) and on-chain dispute mechanisms (`disputeReport`) to preserve due process and objective adjudication.

---

## 5. Automated Test Suite Results

```text
======================== 82 passed in 25.38s ========================
- test_independent_verifier.py::test_case_a_original_report_verifies_successfully PASSED
- test_independent_verifier.py::test_case_b_modified_report_fails_verification PASSED
- test_independent_verifier.py::test_case_c_unknown_report_not_found PASSED
- test_independent_verifier.py::test_case_d_rpc_unavailable_handling PASSED
- test_independent_verifier.py::test_case_e_revision_history_verification PASSED
- test_independent_verifier.py::test_case_f_zero_backend_trust_cli_execution PASSED
- test_blockchain_registry.py (7 passed)
- 17 Hardhat smart contract tests (17 passed)
- Next.js production build (15/15 static pages compiled successfully)
```
