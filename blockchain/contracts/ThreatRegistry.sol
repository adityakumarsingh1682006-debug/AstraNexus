// SPDX-License-Identifier: MIT
pragma solidity ^0.8.20;

/**
 * @title ThreatRegistry
 * @dev Tamper-evident cryptographic registry for AstraNexus threat reports.
 *
 * CRITICAL PRIVACY ASSURANCE:
 * This contract NEVER stores raw URLs, raw scam messages, phone numbers,
 * email addresses, passwords, OTPs, or any personally identifiable information (PII).
 * It stores only deterministic cryptographic commitments (bytes32 hashes)
 * and minimal non-sensitive audit metadata.
 */
contract ThreatRegistry {
    // Validation or attestation status of a registered threat commitment
    enum AttestationStatus {
        UNVERIFIED,        // Initial registration state
        CONFIRMED_THREAT,  // Verified as active scam / phishing threat
        BENIGN_CLEARED,    // Formally reviewed and marked clean
        DISPUTED,          // Under review following legitimate dispute
        REVOKED            // Formally invalidated or retracted
    }

    struct Revision {
        bytes32 commitmentHash;
        uint256 timestamp;
        uint256 blockNumber;
        address revisedBy;
    }

    struct ThreatReport {
        bytes32 reportId;          // Canonical identifier
        bytes32 commitmentHash;    // Current cryptographic commitment
        uint256 initialTimestamp;  // Timestamp of first registration
        address reporter;          // Address of registering agent / notary node
        AttestationStatus status;  // Current attestation/validation status
        uint256 disputeCount;      // Number of filed disputes
        bool exists;               // Existence check
    }

    struct Dispute {
        address disputer;
        bytes32 reasonHash;        // Hash of canonical dispute evidence
        uint256 timestamp;
    }

    // State mappings
    mapping(bytes32 => ThreatReport) public reports;
    mapping(bytes32 => Revision[]) private reportRevisions;
    mapping(bytes32 => Dispute[]) private reportDisputes;

    // Authorized security attestors (e.g., vetted security nodes, threat intelligence feeds)
    mapping(address => bool) public authorizedAttestors;
    address public owner;

    // Events
    event ReportRegistered(
        bytes32 indexed reportId,
        bytes32 indexed commitmentHash,
        address indexed reporter,
        uint256 timestamp
    );

    event ReportRevised(
        bytes32 indexed reportId,
        bytes32 indexed newCommitmentHash,
        uint256 revisionIndex,
        address revisedBy,
        uint256 timestamp
    );

    event ReportDisputed(
        bytes32 indexed reportId,
        address indexed disputer,
        bytes32 reasonHash,
        uint256 timestamp
    );

    event ReportAttested(
        bytes32 indexed reportId,
        AttestationStatus status,
        address indexed attestor,
        uint256 timestamp
    );

    event AttestorAuthorized(address indexed attestor, bool authorized);

    // Access control modifiers
    modifier onlyOwner() {
        require(msg.sender == owner, "Only owner can call this");
        _;
    }

    modifier onlyAttestor() {
        require(authorizedAttestors[msg.sender] || msg.sender == owner, "Caller is not an authorized attestor");
        _;
    }

    constructor() {
        owner = msg.sender;
        authorizedAttestors[msg.sender] = true;
    }

    /**
     * @notice Grants or revokes attestation authority for an address.
     */
    function setAttestor(address attestor, bool authorized) external onlyOwner {
        require(attestor != address(0), "Invalid attestor address");
        authorizedAttestors[attestor] = authorized;
        emit AttestorAuthorized(attestor, authorized);
    }

    /**
     * @notice Registers a new tamper-evident threat report commitment.
     * @param reportId Unique canonical report identifier (keccak256 hash of report metadata).
     * @param commitmentHash Cryptographic commitment hash of canonical report payload.
     */
    function registerReport(bytes32 reportId, bytes32 commitmentHash) external {
        require(reportId != bytes32(0), "Invalid report ID");
        require(commitmentHash != bytes32(0), "Invalid commitment hash");
        require(!reports[reportId].exists, "Report already registered");

        reports[reportId] = ThreatReport({
            reportId: reportId,
            commitmentHash: commitmentHash,
            initialTimestamp: block.timestamp,
            reporter: msg.sender,
            status: AttestationStatus.UNVERIFIED,
            disputeCount: 0,
            exists: true
        });

        reportRevisions[reportId].push(Revision({
            commitmentHash: commitmentHash,
            timestamp: block.timestamp,
            blockNumber: block.number,
            revisedBy: msg.sender
        }));

        emit ReportRegistered(reportId, commitmentHash, msg.sender, block.timestamp);
    }

    /**
     * @notice Adds a revision to an existing threat report.
     * Only the original reporter or contract owner may submit revisions.
     * @param reportId The report identifier.
     * @param newCommitmentHash Updated cryptographic commitment.
     */
    function reviseReport(bytes32 reportId, bytes32 newCommitmentHash) external {
        ThreatReport storage report = reports[reportId];
        require(report.exists, "Report does not exist");
        require(msg.sender == report.reporter || msg.sender == owner, "Unauthorized: Only reporter can revise");
        require(newCommitmentHash != bytes32(0), "Invalid commitment hash");
        require(newCommitmentHash != report.commitmentHash, "New commitment matches current commitment");

        report.commitmentHash = newCommitmentHash;
        uint256 revIndex = reportRevisions[reportId].length;

        reportRevisions[reportId].push(Revision({
            commitmentHash: newCommitmentHash,
            timestamp: block.timestamp,
            blockNumber: block.number,
            revisedBy: msg.sender
        }));

        emit ReportRevised(reportId, newCommitmentHash, revIndex, msg.sender, block.timestamp);
    }

    /**
     * @notice Files a formal dispute against a registered threat report.
     * Anyone may file a dispute providing a valid commitment to their dispute evidence.
     * @param reportId The report identifier being disputed.
     * @param reasonHash Cryptographic hash of the dispute justification evidence.
     */
    function disputeReport(bytes32 reportId, bytes32 reasonHash) external {
        ThreatReport storage report = reports[reportId];
        require(report.exists, "Report does not exist");
        require(reasonHash != bytes32(0), "Reason hash required");

        report.disputeCount += 1;
        if (report.status != AttestationStatus.REVOKED) {
            report.status = AttestationStatus.DISPUTED;
        }

        reportDisputes[reportId].push(Dispute({
            disputer: msg.sender,
            reasonHash: reasonHash,
            timestamp: block.timestamp
        }));

        emit ReportDisputed(reportId, msg.sender, reasonHash, block.timestamp);
    }

    /**
     * @notice Updates the attestation/validation status of a report.
     * Restricted to authorized attestors or contract owner.
     * @param reportId The report identifier.
     * @param newStatus The updated attestation status.
     */
    function attestReport(bytes32 reportId, AttestationStatus newStatus) external onlyAttestor {
        ThreatReport storage report = reports[reportId];
        require(report.exists, "Report does not exist");

        report.status = newStatus;
        emit ReportAttested(reportId, newStatus, msg.sender, block.timestamp);
    }

    /**
     * @notice Retrieves total revision count for a given report.
     */
    function getRevisionCount(bytes32 reportId) external view returns (uint256) {
        require(reports[reportId].exists, "Report does not exist");
        return reportRevisions[reportId].length;
    }

    /**
     * @notice Retrieves a specific revision record.
     */
    function getRevision(bytes32 reportId, uint256 index) external view returns (
        bytes32 commitmentHash,
        uint256 timestamp,
        uint256 blockNumber,
        address revisedBy
    ) {
        require(reports[reportId].exists, "Report does not exist");
        require(index < reportRevisions[reportId].length, "Revision index out of bounds");
        Revision memory rev = reportRevisions[reportId][index];
        return (rev.commitmentHash, rev.timestamp, rev.blockNumber, rev.revisedBy);
    }

    /**
     * @notice Retrieves total dispute count for a given report.
     */
    function getDisputeCount(bytes32 reportId) external view returns (uint256) {
        require(reports[reportId].exists, "Report does not exist");
        return reportDisputes[reportId].length;
    }

    /**
     * @notice Retrieves a specific dispute record.
     */
    function getDispute(bytes32 reportId, uint256 index) external view returns (
        address disputer,
        bytes32 reasonHash,
        uint256 timestamp
    ) {
        require(reports[reportId].exists, "Report does not exist");
        require(index < reportDisputes[reportId].length, "Dispute index out of bounds");
        Dispute memory disp = reportDisputes[reportId][index];
        return (disp.disputer, disp.reasonHash, disp.timestamp);
    }
}
