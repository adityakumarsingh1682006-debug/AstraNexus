# AstraNexus Known Limitations & Technical Boundaries

## 1. Ethical Transparency

In alignment with responsible cybersecurity engineering, AstraNexus explicitly documents its operational boundaries and forensic constraints. AstraNexus does not over-promise detection capabilities.

---

## 2. Technical Limitations & Edge Cases

### 2.1 Passive Inspection Boundary
- **Description**: AstraNexus operates strictly as a **passive reconnaissance and defensive inspection gateway**.
- **Impact**: It does not perform active vulnerability exploitation, credential brute-forcing, or authenticated application fuzzing.
- **Remediation**: Passive inspection guarantees zero legal liability and zero service interruption to scanned hosts, but deep application-layer vulnerabilities behind authentication gates cannot be inspected.

### 2.2 Newly Registered Domains (NRDs) & Fast-Flux Phishing
- **Description**: Modern phishing syndicates generate temporary domains active for less than 30 minutes before cycling to new hosts.
- **Impact**: External threat feeds (URLhaus, OpenPhish) may have a propagation latency of 15 to 60 minutes.
- **Mitigation**: AstraNexus compensates using structural typosquatting heuristics, brand keyword tokenization, and DNS entropy scoring to flag high-risk combosquatting even before blocklists ingest the domain.

### 2.3 End-to-End Encrypted Messaging (WhatsApp, Signal, Telegram)
- **Description**: AstraNexus does not intercept private user communications.
- **Impact**: The message analyzer requires the user or organization to explicitly copy and paste the suspicious communication for triage.
- **Privacy Benefit**: This model protects user privacy by avoiding pervasive device snooping or TLS-breaking proxies.

### 2.4 Blockchain Scalability & Gas Considerations
- **Description**: On public Ethereum mainnet, registering individual reports would incur substantial gas fees ($1 to $15 per report depending on congestion).
- **Architecture Solution**:
  - In hackathon / development mode, AstraNexus operates on a local reproducible Hardhat node with zero cost.
  - In production deployment, AstraNexus targets Layer-2 rollups (Arbitrum, Base, or Optimism) where commitment transactions cost fractions of a cent (< $0.005).

### 2.5 External API Quotas & Offline Resilience
- **Description**: Google Gemini and Google Safe Browsing APIs enforce rate limits and require operational network connectivity.
- **Mitigation**: When quotas are reached or API keys are absent, AstraNexus seamlessly falls back to:
  - In-memory threat feed caches.
  - Deterministic heuristic safety rules.
  - Clearly labeled deterministic guidance (`source: AstraNexus Deterministic Safety Rules`).

### 2.6 Forensic Non-Attribution Limitation
- **Description**: Threat campaign clustering groups shared infrastructure patterns, not verified real-world criminal identities.
- **Legal Compliance**: AstraNexus explicitly emits attribution disclaimers: *"Campaign clusters represent structural and textual similarities. AstraNexus does not make legal claims regarding the real-world identity of threat actors without verified law enforcement attribution."*
