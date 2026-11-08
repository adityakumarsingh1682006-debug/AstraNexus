const { expect } = require("chai");
const { ethers } = require("hardhat");

describe("ThreatRegistry Smart Contract", function () {
  let ThreatRegistry, registry;
  let owner, reporter, attestor, disputer, randomUser;

  const mockReportId = ethers.keccak256(ethers.toUtf8Bytes("report-id-astranexus-2026-001"));
  const mockCommitmentHash = ethers.keccak256(ethers.toUtf8Bytes("canonical-threat-payload-commitment-v1"));
  const mockNewCommitmentHash = ethers.keccak256(ethers.toUtf8Bytes("canonical-threat-payload-commitment-v2"));
  const mockDisputeReasonHash = ethers.keccak256(ethers.toUtf8Bytes("dispute-evidence-false-positive-cert"));

  beforeEach(async function () {
    [owner, reporter, attestor, disputer, randomUser] = await ethers.getSigners();
    ThreatRegistry = await ethers.getContractFactory("ThreatRegistry");
    registry = await ThreatRegistry.deploy();
    await registry.waitForDeployment();
  });

  describe("Deployment & Authorization", function () {
    it("should set deployer as owner and initial authorized attestor", async function () {
      expect(await registry.owner()).to.equal(owner.address);
      expect(await registry.authorizedAttestors(owner.address)).to.be.true;
    });

    it("should allow owner to authorize and revoke attestors", async function () {
      await expect(registry.connect(owner).setAttestor(attestor.address, true))
        .to.emit(registry, "AttestorAuthorized")
        .withArgs(attestor.address, true);

      expect(await registry.authorizedAttestors(attestor.address)).to.be.true;

      await registry.connect(owner).setAttestor(attestor.address, false);
      expect(await registry.authorizedAttestors(attestor.address)).to.be.false;
    });

    it("should reject non-owner attempting to authorize attestors", async function () {
      await expect(
        registry.connect(randomUser).setAttestor(attestor.address, true)
      ).to.be.revertedWith("Only owner can call this");
    });
  });

  describe("1. Report Registration", function () {
    it("should successfully register a report commitment and emit ReportRegistered", async function () {
      const tx = await registry.connect(reporter).registerReport(mockReportId, mockCommitmentHash);
      const receipt = await tx.wait();
      const block = await ethers.provider.getBlock(receipt.blockNumber);

      await expect(tx)
        .to.emit(registry, "ReportRegistered")
        .withArgs(mockReportId, mockCommitmentHash, reporter.address, block.timestamp);

      const report = await registry.reports(mockReportId);
      expect(report.exists).to.be.true;
      expect(report.reportId).to.equal(mockReportId);
      expect(report.commitmentHash).to.equal(mockCommitmentHash);
      expect(report.reporter).to.equal(reporter.address);
      expect(report.status).to.equal(0); // AttestationStatus.UNVERIFIED
      expect(report.disputeCount).to.equal(0);

      // Check revision 0
      expect(await registry.getRevisionCount(mockReportId)).to.equal(1);
      const rev = await registry.getRevision(mockReportId, 0);
      expect(rev.commitmentHash).to.equal(mockCommitmentHash);
      expect(rev.revisedBy).to.equal(reporter.address);
    });

    it("should reject duplicate registration of same reportId", async function () {
      await registry.connect(reporter).registerReport(mockReportId, mockCommitmentHash);

      await expect(
        registry.connect(reporter).registerReport(mockReportId, mockCommitmentHash)
      ).to.be.revertedWith("Report already registered");

      // Also reject different reporter using same reportId
      await expect(
        registry.connect(randomUser).registerReport(mockReportId, mockNewCommitmentHash)
      ).to.be.revertedWith("Report already registered");
    });

    it("should reject registration with empty/zero hashes", async function () {
      await expect(
        registry.connect(reporter).registerReport(ethers.ZeroHash, mockCommitmentHash)
      ).to.be.revertedWith("Invalid report ID");

      await expect(
        registry.connect(reporter).registerReport(mockReportId, ethers.ZeroHash)
      ).to.be.revertedWith("Invalid commitment hash");
    });
  });

  describe("2. Report Revision", function () {
    beforeEach(async function () {
      await registry.connect(reporter).registerReport(mockReportId, mockCommitmentHash);
    });

    it("should allow original reporter to revise the commitment", async function () {
      const tx = await registry.connect(reporter).reviseReport(mockReportId, mockNewCommitmentHash);
      const receipt = await tx.wait();
      const block = await ethers.provider.getBlock(receipt.blockNumber);

      await expect(tx)
        .to.emit(registry, "ReportRevised")
        .withArgs(mockReportId, mockNewCommitmentHash, 1, reporter.address, block.timestamp);

      const report = await registry.reports(mockReportId);
      expect(report.commitmentHash).to.equal(mockNewCommitmentHash);

      expect(await registry.getRevisionCount(mockReportId)).to.equal(2);
      const rev1 = await registry.getRevision(mockReportId, 1);
      expect(rev1.commitmentHash).to.equal(mockNewCommitmentHash);
      expect(rev1.revisedBy).to.equal(reporter.address);
    });

    it("should allow contract owner to submit administrative revision", async function () {
      await expect(registry.connect(owner).reviseReport(mockReportId, mockNewCommitmentHash))
        .to.emit(registry, "ReportRevised");
    });

    it("should reject unauthorized third party attempting revision", async function () {
      await expect(
        registry.connect(randomUser).reviseReport(mockReportId, mockNewCommitmentHash)
      ).to.be.revertedWith("Unauthorized: Only reporter can revise");
    });

    it("should reject revision with identical commitment", async function () {
      await expect(
        registry.connect(reporter).reviseReport(mockReportId, mockCommitmentHash)
      ).to.be.revertedWith("New commitment matches current commitment");
    });

    it("should reject revision on non-existent report", async function () {
      const nonExistentId = ethers.keccak256(ethers.toUtf8Bytes("random-id-999"));
      await expect(
        registry.connect(reporter).reviseReport(nonExistentId, mockNewCommitmentHash)
      ).to.be.revertedWith("Report does not exist");
    });
  });

  describe("3. Report Disputes", function () {
    beforeEach(async function () {
      await registry.connect(reporter).registerReport(mockReportId, mockCommitmentHash);
    });

    it("should record a dispute, transition status to DISPUTED, and emit ReportDisputed", async function () {
      const tx = await registry.connect(disputer).disputeReport(mockReportId, mockDisputeReasonHash);
      const receipt = await tx.wait();
      const block = await ethers.provider.getBlock(receipt.blockNumber);

      await expect(tx)
        .to.emit(registry, "ReportDisputed")
        .withArgs(mockReportId, disputer.address, mockDisputeReasonHash, block.timestamp);

      const report = await registry.reports(mockReportId);
      expect(report.status).to.equal(3); // AttestationStatus.DISPUTED
      expect(report.disputeCount).to.equal(1);

      expect(await registry.getDisputeCount(mockReportId)).to.equal(1);
      const disp = await registry.getDispute(mockReportId, 0);
      expect(disp.disputer).to.equal(disputer.address);
      expect(disp.reasonHash).to.equal(mockDisputeReasonHash);
      expect(disp.timestamp).to.equal(block.timestamp);
    });

    it("should reject dispute without reason hash", async function () {
      await expect(
        registry.connect(disputer).disputeReport(mockReportId, ethers.ZeroHash)
      ).to.be.revertedWith("Reason hash required");
    });

    it("should reject dispute on non-existent report", async function () {
      const fakeId = ethers.keccak256(ethers.toUtf8Bytes("does-not-exist"));
      await expect(
        registry.connect(disputer).disputeReport(fakeId, mockDisputeReasonHash)
      ).to.be.revertedWith("Report does not exist");
    });
  });

  describe("4. Report Attestation & Validation Status", function () {
    beforeEach(async function () {
      await registry.connect(reporter).registerReport(mockReportId, mockCommitmentHash);
      await registry.connect(owner).setAttestor(attestor.address, true);
    });

    it("should allow authorized attestor to confirm threat status", async function () {
      // 1 = CONFIRMED_THREAT
      const tx = await registry.connect(attestor).attestReport(mockReportId, 1);
      const receipt = await tx.wait();
      const block = await ethers.provider.getBlock(receipt.blockNumber);

      await expect(tx)
        .to.emit(registry, "ReportAttested")
        .withArgs(mockReportId, 1, attestor.address, block.timestamp);

      const report = await registry.reports(mockReportId);
      expect(report.status).to.equal(1);
    });

    it("should allow authorized attestor to clear false positive (BENIGN_CLEARED)", async function () {
      // 2 = BENIGN_CLEARED
      await registry.connect(attestor).attestReport(mockReportId, 2);
      const report = await registry.reports(mockReportId);
      expect(report.status).to.equal(2);
    });

    it("should reject non-attestor attempting status change", async function () {
      await expect(
        registry.connect(randomUser).attestReport(mockReportId, 1)
      ).to.be.revertedWith("Caller is not an authorized attestor");
    });
  });
});
