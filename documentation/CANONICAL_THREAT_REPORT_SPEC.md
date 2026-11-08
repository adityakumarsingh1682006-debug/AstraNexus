# AstraNexus Canonical Threat Report Commitment Specification (v1.0)

## 1. Objective & Threat Model
The AstraNexus Threat Registry provides immutable, tamper-evident proof of security detections and threat intelligence findings without exposing sensitive consumer or target data to public ledgers.

### Critical Privacy Guarantees
- **Zero Sensitive Data on Ledger**: Raw URLs, user-submitted scam texts, phone numbers, email addresses, OTPs, credentials, and IP addresses are **never** written to the smart contract or emitted in blockchain event logs.
- **Salted Commitments**: Unsalted hashes of low-entropy target data (such as domains or short phone numbers) can be susceptible to rainbow-table and dictionary-preimage attacks. AstraNexus enforces high-entropy, 256-bit cryptographically secure salts (`secrets.token_hex(32)`) in every report commitment.

---

## 2. Canonical Serialization Format (`astranexus-threat-commitment-v1`)

To ensure deterministic verification across different operating systems, programming languages, and EVM clients, the report payload MUST adhere to strict canonical formatting:

### Schema Definition
```json
{
  "version": "astranexus-threat-commitment-v1",
  "report_id": "<canonical-string-id>",
  "target_type": "URL | MESSAGE | DOMAIN",
  "threat_category": "PHISHING | SCAM | MALWARE | IMPERSONATION | BENIGN | UNKNOWN",
  "risk_score": 0,
  "verdict": "CLEAN | CAUTION | SUSPICIOUS | MALICIOUS | PHISHING_SIMULATION",
  "indicators_count": 0,
  "timestamp": "YYYY-MM-DDTHH:MM:SSZ",
  "evidence_digest": "0x<sha256-hex-of-forensic-telemetry>",
  "salt": "0x<256-bit-cryptographic-salt-hex>"
}
```

### Canonicalization Rules
1. **Key Sorting**: All JSON keys must be sorted lexicographically in ascending ASCII order.
2. **Whitespace**: Eliminates all extraneous whitespace: no newlines, no indentation; key-value separator is `:` and element separator is `,` (`separators=(',', ':')`).
3. **String Normalization**: All string fields must be normalized to Unicode Normalization Form C (`NFC`).
4. **Timestamp Format**: Timestamps must be in ISO-8601 UTC format terminating with `Z` (no microsecond jitter).
5. **Encoding**: Character encoding is strictly UTF-8 without byte-order mark (BOM).

---

## 3. Cryptographic Hashing Algorithms
- **Evidence Digest**: `SHA-256` hash of non-PII technical forensic evidence (TLS parameters, DNS status, HTTP response status).
- **On-Chain Report Identifier (`reportId`)**:
  $$\text{reportId} = \text{keccak256}(\text{UTF-8}(\text{report\_id})) \in \text{bytes32}$$
- **Commitment Hash (`commitmentHash`)**:
  $$\text{commitmentHash} = \text{keccak256}(\text{CanonicalJSONBytes}) \in \text{bytes32}$$

---

## 4. Verification Procedure

Anyone in possession of the original report verification certificate (including the salt and metadata) can independently verify its authenticity on-chain:

1. **Step 1 — Serialize**: Parse the report metadata and serialize into the canonical JSON format using the rules above.
2. **Step 2 — Hash**: Compute the Keccak-256 hash of the UTF-8 bytes of the canonical JSON string.
3. **Step 3 — Query Contract**: Call `ThreatRegistry.reports(reportId)` on the EVM blockchain.
4. **Step 4 — Compare**:
   - If `reports[reportId].exists == false`: Status is `UNREGISTERED`.
   - If `reports[reportId].commitmentHash == computedCommitment`: Status is `VERIFIED_AUTHENTIC` (tamper-evident proof confirmed).
   - If `reports[reportId].commitmentHash != computedCommitment`: Status is `TAMPERED_OR_CORRUPT`.
5. **Step 5 — Check Attestation & Dispute State**: Check `reports[reportId].status` and `reports[reportId].disputeCount` for community validation.
