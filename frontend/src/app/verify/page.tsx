"use client";

import React, { useState } from "react";
import {
  FileCheck2,
  CheckCircle2,
  Shield,
  Search,
  ExternalLink,
  Lock,
  Hash,
  AlertCircle,
  AlertTriangle,
  RotateCcw,
  Copy,
  Check,
  ChevronDown,
  ChevronUp,
  History,
  FileCode,
  ShieldAlert,
  Info,
} from "lucide-react";
import { cn } from "@/lib/utils";
import { ethers } from "ethers";

// Default local and testnet configuration
const DEFAULT_RPC = "http://127.0.0.1:8545";
const DEFAULT_CONTRACT = "0x5FbDB2315678afecb367f032d93F642f64180aa3";

// Minimal ThreatRegistry ABI for direct browser-to-chain queries
const REGISTRY_ABI = [
  "function reports(bytes32) view returns (bytes32 reportId, bytes32 commitmentHash, uint256 initialTimestamp, address reporter, uint8 status, uint256 disputeCount, bool exists)",
  "function getRevisionCount(bytes32 reportId) view returns (uint256)",
  "function getRevision(bytes32 reportId, uint256 index) view returns (bytes32 commitmentHash, uint256 timestamp, uint256 blockNumber, address revisedBy)",
  "function getDisputeCount(bytes32 reportId) view returns (uint256)",
];

const ATTESTATION_STATUS_LABELS: Record<number, string> = {
  0: "UNVERIFIED",
  1: "CONFIRMED_THREAT",
  2: "BENIGN_CLEARED",
  3: "DISPUTED",
  4: "REVOKED",
};

/**
 * Deterministically sorts keys and formats minimal JSON string.
 */
function canonicalizeJson(obj: any): string {
  if (obj === null || typeof obj !== "object") {
    return JSON.stringify(obj);
  }
  if (Array.isArray(obj)) {
    return "[" + obj.map(canonicalizeJson).join(",") + "]";
  }
  const sortedKeys = Object.keys(obj).sort();
  const pairs = sortedKeys.map((key) => {
    const val = obj[key];
    const normVal = typeof val === "string" ? val.normalize("NFC").trim() : val;
    return JSON.stringify(key) + ":" + canonicalizeJson(normVal);
  });
  return "{" + pairs.join(",") + "}";
}

export default function VerifyPage() {
  const [inputMode, setInputMode] = useState<"json" | "manual">("json");
  const [jsonInput, setJsonInput] = useState("");
  const [manualReportId, setManualReportId] = useState("");
  const [manualCommitment, setManualCommitment] = useState("");

  // Custom network connection controls
  const [showConfig, setShowConfig] = useState(false);
  const [rpcUrl, setRpcUrl] = useState(DEFAULT_RPC);
  const [contractAddress, setContractAddress] = useState(DEFAULT_CONTRACT);

  // Verification state
  const [isVerifying, setIsVerifying] = useState(false);
  const [auditResult, setAuditResult] = useState<any>(null);
  const [copiedHash, setCopiedHash] = useState(false);

  /**
   * Pure client-side independent verification.
   * Completely bypasses AstraNexus backend and queries the EVM JSON-RPC directly!
   */
  const executeIndependentVerification = async () => {
    setIsVerifying(true);
    setAuditResult(null);

    try {
      let targetReportId = "";
      let calculatedCommitment = "";
      let canonicalString = "";

      if (inputMode === "json") {
        if (!jsonInput.trim()) {
          throw new Error("Please paste a verifiable report JSON export or canonical payload.");
        }
        let parsed: any;
        try {
          parsed = JSON.parse(jsonInput);
        } catch {
          throw new Error("Invalid JSON format. Please ensure valid JSON syntax.");
        }

        const payloadToHash = parsed.canonical_payload || parsed;
        targetReportId = parsed.report_id || payloadToHash.report_id || "";

        if (!targetReportId) {
          throw new Error("Report data must contain a 'report_id' field.");
        }

        // Canonicalize JSON locally in JavaScript
        canonicalString = canonicalizeJson(payloadToHash);
        // Calculate Keccak-256 commitment hash locally
        calculatedCommitment = ethers.keccak256(ethers.toUtf8Bytes(canonicalString));
      } else {
        if (!manualReportId.trim()) {
          throw new Error("Please enter a valid Report ID.");
        }
        targetReportId = manualReportId.trim();
        calculatedCommitment = manualCommitment.trim().toLowerCase();
        if (calculatedCommitment && !calculatedCommitment.startsWith("0x")) {
          calculatedCommitment = "0x" + calculatedCommitment;
        }
      }

      // Convert reportId to bytes32 format
      let reportIdBytes32: string;
      if (targetReportId.startsWith("0x") && targetReportId.length === 66) {
        reportIdBytes32 = targetReportId;
      } else {
        reportIdBytes32 = ethers.keccak256(ethers.toUtf8Bytes(targetReportId.normalize("NFC").trim()));
      }

      // 1. Direct Web3 EVM connection (Zero Backend Trust)
      let provider: ethers.JsonRpcProvider;
      try {
        provider = new ethers.JsonRpcProvider(rpcUrl.trim(), undefined, { staticNetwork: true });
        // Test connection with timeout
        await Promise.race([
          provider.getBlockNumber(),
          new Promise((_, reject) => setTimeout(() => reject(new Error("RPC Connection Timeout (5s)")), 5000)),
        ]);
      } catch (err: any) {
        setAuditResult({
          verdict: "UNAVAILABLE",
          message: `Unable to connect directly to EVM blockchain node at ${rpcUrl}. (${err.message})`,
          reportId: targetReportId,
          calculatedCommitment,
          rpcUrl,
          contractAddress,
        });
        setIsVerifying(false);
        return;
      }

      // 2. Query smart contract directly
      const contract = new ethers.Contract(contractAddress.trim(), REGISTRY_ABI, provider);
      let onChainRecord: any;
      try {
        onChainRecord = await contract.reports(reportIdBytes32);
      } catch (err: any) {
        setAuditResult({
          verdict: "UNAVAILABLE",
          message: `Smart contract call failed at ${contractAddress}. Please verify address and ABI. (${err.message})`,
          reportId: targetReportId,
          calculatedCommitment,
          rpcUrl,
          contractAddress,
        });
        setIsVerifying(false);
        return;
      }

      // onChainRecord: [reportId, commitmentHash, initialTimestamp, reporter, status, disputeCount, exists]
      const exists = Boolean(onChainRecord[6]);
      if (!exists) {
        setAuditResult({
          verdict: "NOT FOUND",
          message: "No matching registration exists on the ThreatRegistry smart contract for this report ID.",
          reportId: targetReportId,
          reportIdBytes32,
          calculatedCommitment,
          rpcUrl,
          contractAddress,
        });
        setIsVerifying(false);
        return;
      }

      const onChainCommitment = onChainRecord[1].toLowerCase();
      const initialTimestamp = Number(onChainRecord[2]);
      const reporter = onChainRecord[3];
      const statusCode = Number(onChainRecord[4]);
      const disputeCount = Number(onChainRecord[5]);

      // 3. Query revision history directly
      let revisions: any[] = [];
      try {
        const revCount = Number(await contract.getRevisionCount(reportIdBytes32));
        for (let i = 0; i < revCount; i++) {
          const rev = await contract.getRevision(reportIdBytes32, i);
          revisions.push({
            index: i,
            commitmentHash: rev[0],
            timestamp: Number(rev[1]),
            blockNumber: Number(rev[2]),
            revisedBy: rev[3],
          });
        }
      } catch {
        // Optional revision retrieval failure
      }

      // 4. Evaluate verdict
      const localClean = calculatedCommitment.toLowerCase();
      let verdict: "VERIFIED" | "MISMATCH" = "MISMATCH";
      let message = "";
      let matchedRevision: number | null = null;

      if (localClean && onChainCommitment === localClean) {
        verdict = "VERIFIED";
        message = "Report perfectly matches current on-chain cryptographic commitment. Integrity confirmed.";
        matchedRevision = revisions.length > 0 ? revisions.length - 1 : 0;
      } else if (localClean) {
        // Check if it matches an earlier revision
        const foundRev = revisions.find((r) => r.commitmentHash.toLowerCase() === localClean);
        if (foundRev) {
          verdict = "VERIFIED";
          message = `Report matches on-chain commitment from Revision #${foundRev.index} (Superseded by later revision).`;
          matchedRevision = foundRev.index;
        } else {
          verdict = "MISMATCH";
          message = "Locally calculated commitment does NOT match the registered on-chain commitment. Tampering or data corruption detected!";
        }
      } else {
        // Query-only mode
        verdict = "VERIFIED";
        message = "Report record found on-chain. Registered commitment retrieved successfully.";
      }

      setAuditResult({
        verdict,
        message,
        reportId: targetReportId,
        reportIdBytes32,
        calculatedCommitment,
        onChainCommitment,
        initialTimestamp,
        reporter,
        attestationStatus: ATTESTATION_STATUS_LABELS[statusCode] || "UNKNOWN",
        disputeCount,
        revisions,
        matchedRevision,
        rpcUrl,
        contractAddress,
      });
    } catch (err: any) {
      setAuditResult({
        verdict: "UNAVAILABLE",
        message: err.message || "An unexpected error occurred during client-side verification.",
      });
    } finally {
      setIsVerifying(false);
    }
  };

  const loadSampleReport = () => {
    const sample = {
      version: "astranexus-threat-commitment-v1",
      report_id: "scan-0xe155e65c9d16a4",
      target_type: "URL",
      threat_category: "PHISHING_SIMULATION",
      risk_score: 95,
      verdict: "PHISHING_SIMULATION",
      indicators_count: 5,
      evidence_digest: "0xe155e65c9d16a4ef3018274a12345678",
      timestamp: "2026-11-08T12:00:00Z",
      salt: "0x1234567890abcdef1234567890abcdef1234567890abcdef1234567890abcdef",
    };
    setJsonInput(JSON.stringify(sample, null, 2));
  };

  return (
    <div className="space-y-6 max-w-5xl mx-auto px-4 py-8">
      {/* Header */}
      <div className="consumer-card p-6 sm:p-8 rounded-2xl relative overflow-hidden border border-slate-200 dark:border-slate-800">
        <div className="space-y-2">
          <div className="inline-flex items-center gap-2 px-3 py-1 rounded-full bg-purple-500/10 border border-purple-500/20 text-xs font-mono font-semibold text-purple-600 dark:text-purple-400">
            <FileCheck2 className="w-3.5 h-3.5" />
            <span>STANDALONE CLIENT-SIDE VERIFIER</span>
          </div>
          <h1 className="text-2xl sm:text-3xl font-extrabold text-slate-900 dark:text-white">
            Independent Report Integrity Verification
          </h1>
          <p className="text-xs sm:text-sm text-slate-600 dark:text-slate-300 max-w-3xl leading-relaxed">
            Verify whether an AstraNexus threat report has been modified or tampered with. This tool operates <strong>completely independently of the AstraNexus backend</strong>: it computes the cryptographic commitment locally in your browser and queries the EVM blockchain node directly.
          </p>
        </div>
      </div>

      {/* Prominent Legal & Forensic Disclaimer */}
      <div className="p-4 rounded-2xl bg-amber-500/10 border border-amber-500/30 flex items-start gap-3.5 text-xs text-amber-900 dark:text-amber-200 leading-relaxed">
        <Info className="w-4 h-4 text-amber-600 dark:text-amber-400 shrink-0 mt-0.5" />
        <div>
          <strong className="block font-semibold mb-0.5 text-amber-950 dark:text-amber-100 uppercase tracking-wider text-[11px]">
            Integrity Verification vs. Truth of Allegation:
          </strong>
          Cryptographic verification mathematically proves that this report has <strong>not been altered or modified</strong> since its registration on the blockchain. It verifies document authenticity, provenance, and data integrity; it does <strong>not</strong> constitute judicial proof or establish the legal guilt of an accused third party.
        </div>
      </div>

      {/* Verification Workspace Card */}
      <div className="consumer-card p-6 sm:p-7 rounded-2xl border-slate-200 dark:border-slate-800 space-y-5">
        {/* Input Mode Toggle */}
        <div className="flex items-center justify-between border-b border-slate-200 dark:border-slate-800 pb-3 flex-wrap gap-2">
          <div className="flex items-center gap-2">
            <button
              type="button"
              onClick={() => setInputMode("json")}
              className={cn(
                "px-3.5 py-1.5 rounded-xl text-xs font-semibold transition-all",
                inputMode === "json"
                  ? "bg-purple-600 text-white shadow-sm"
                  : "bg-slate-100 dark:bg-slate-800 text-slate-600 dark:text-slate-300 hover:bg-slate-200 dark:hover:bg-slate-700"
              )}
            >
              Paste Report Export (JSON)
            </button>
            <button
              type="button"
              onClick={() => setInputMode("manual")}
              className={cn(
                "px-3.5 py-1.5 rounded-xl text-xs font-semibold transition-all",
                inputMode === "manual"
                  ? "bg-purple-600 text-white shadow-sm"
                  : "bg-slate-100 dark:bg-slate-800 text-slate-600 dark:text-slate-300 hover:bg-slate-200 dark:hover:bg-slate-700"
              )}
            >
              Manual Hash & ID Entry
            </button>
          </div>

          <button
            type="button"
            onClick={() => setShowConfig(!showConfig)}
            className="inline-flex items-center gap-1.5 text-xs text-slate-500 hover:text-slate-800 dark:hover:text-slate-200 font-mono"
          >
            <span>Network & Contract Settings</span>
            {showConfig ? <ChevronUp className="w-3.5 h-3.5" /> : <ChevronDown className="w-3.5 h-3.5" />}
          </button>
        </div>

        {/* Expandable Blockchain Network & Contract Configuration */}
        {showConfig && (
          <div className="p-4 rounded-xl bg-slate-50 dark:bg-slate-900 border border-slate-200 dark:border-slate-800 grid grid-cols-1 sm:grid-cols-2 gap-3 text-xs">
            <div>
              <label className="block text-slate-400 font-mono text-[11px] mb-1">
                EVM JSON-RPC Endpoint (Direct Query)
              </label>
              <input
                type="text"
                value={rpcUrl}
                onChange={(e) => setRpcUrl(e.target.value)}
                placeholder="http://127.0.0.1:8545 or https://rpc.sepolia.org"
                className="w-full px-3 py-2 rounded-lg bg-white dark:bg-slate-800 border border-slate-300 dark:border-slate-700 font-mono text-xs text-slate-800 dark:text-slate-200"
              />
            </div>
            <div>
              <label className="block text-slate-400 font-mono text-[11px] mb-1">
                ThreatRegistry Contract Address
              </label>
              <input
                type="text"
                value={contractAddress}
                onChange={(e) => setContractAddress(e.target.value)}
                placeholder="0x..."
                className="w-full px-3 py-2 rounded-lg bg-white dark:bg-slate-800 border border-slate-300 dark:border-slate-700 font-mono text-xs text-slate-800 dark:text-slate-200"
              />
            </div>
          </div>
        )}

        {/* Input Mode 1: JSON Export */}
        {inputMode === "json" ? (
          <div className="space-y-2">
            <div className="flex items-center justify-between">
              <label className="block text-xs font-semibold text-slate-700 dark:text-slate-300">
                Verifiable Report Export / Canonical Payload (JSON)
              </label>
              <button
                type="button"
                onClick={loadSampleReport}
                className="text-xs text-purple-600 dark:text-purple-400 hover:underline font-mono"
              >
                Load Sample Report
              </button>
            </div>
            <textarea
              rows={8}
              value={jsonInput}
              onChange={(e) => setJsonInput(e.target.value)}
              placeholder='{\n  "version": "astranexus-threat-commitment-v1",\n  "report_id": "scan-0xe155e65c9d16a4",\n  "target_type": "URL",\n  "threat_category": "PHISHING",\n  "risk_score": 95,\n  "verdict": "CONFIRMED_THREAT",\n  "salt": "0x..."\n}'
              className="w-full p-3.5 rounded-xl bg-slate-50 dark:bg-slate-900 border border-slate-300 dark:border-slate-700 font-mono text-xs text-slate-800 dark:text-slate-200 placeholder-slate-400 focus:outline-none focus:ring-2 focus:ring-purple-500"
            />
          </div>
        ) : (
          /* Input Mode 2: Manual Entry */
          <div className="space-y-3">
            <div>
              <label className="block text-xs font-semibold text-slate-700 dark:text-slate-300 mb-1">
                Report Identifier (e.g. scan-0xe155e65c9d16a4)
              </label>
              <input
                type="text"
                value={manualReportId}
                onChange={(e) => setManualReportId(e.target.value)}
                placeholder="scan-0xe155e65c9d16a4"
                className="w-full px-3.5 py-2.5 rounded-xl bg-slate-50 dark:bg-slate-900 border border-slate-300 dark:border-slate-700 font-mono text-xs text-slate-800 dark:text-slate-200"
              />
            </div>
            <div>
              <label className="block text-xs font-semibold text-slate-700 dark:text-slate-300 mb-1">
                Expected Salted Keccak-256 Commitment (Optional for query-only)
              </label>
              <input
                type="text"
                value={manualCommitment}
                onChange={(e) => setManualCommitment(e.target.value)}
                placeholder="0xfe955a9104c7fda93f05e37605dd5352b95ec307a0b6da87982a063d763dd261"
                className="w-full px-3.5 py-2.5 rounded-xl bg-slate-50 dark:bg-slate-900 border border-slate-300 dark:border-slate-700 font-mono text-xs text-slate-800 dark:text-slate-200"
              />
            </div>
          </div>
        )}

        {/* Verification Trigger Button */}
        <button
          type="button"
          disabled={isVerifying}
          onClick={executeIndependentVerification}
          className="w-full py-3 px-4 rounded-xl bg-purple-600 hover:bg-purple-700 text-white font-bold text-sm tracking-wide transition-all shadow-md flex items-center justify-center gap-2 disabled:opacity-50"
        >
          {isVerifying ? (
            <>
              <RotateCcw className="w-4 h-4 animate-spin" />
              <span>QUERYING EVM BLOCKCHAIN DIRECTLY...</span>
            </>
          ) : (
            <>
              <FileCheck2 className="w-4 h-4" />
              <span>EXECUTE INDEPENDENT AUDIT</span>
            </>
          )}
        </button>
      </div>

      {/* Verification Result Card */}
      {auditResult && (
        <div
          className={cn(
            "consumer-card p-6 sm:p-7 rounded-2xl border space-y-5",
            auditResult.verdict === "VERIFIED"
              ? "border-emerald-500/40 bg-emerald-50/20 dark:bg-emerald-950/20"
              : auditResult.verdict === "MISMATCH"
              ? "border-rose-500/40 bg-rose-50/20 dark:bg-rose-950/20"
              : auditResult.verdict === "NOT FOUND"
              ? "border-amber-500/40 bg-amber-50/20 dark:bg-amber-950/20"
              : "border-slate-500/40 bg-slate-50/20 dark:bg-slate-900/20"
          )}
        >
          {/* Status Header */}
          <div className="flex flex-col sm:flex-row sm:items-center justify-between pb-4 border-b border-slate-200 dark:border-slate-800 gap-2">
            <div className="flex items-center gap-2.5">
              {auditResult.verdict === "VERIFIED" && (
                <CheckCircle2 className="w-6 h-6 text-emerald-600 dark:text-emerald-400 shrink-0" />
              )}
              {auditResult.verdict === "MISMATCH" && (
                <ShieldAlert className="w-6 h-6 text-rose-600 dark:text-rose-400 shrink-0" />
              )}
              {auditResult.verdict === "NOT FOUND" && (
                <AlertTriangle className="w-6 h-6 text-amber-600 dark:text-amber-400 shrink-0" />
              )}
              {auditResult.verdict === "UNAVAILABLE" && (
                <AlertCircle className="w-6 h-6 text-slate-500 shrink-0" />
              )}
              <div>
                <h2 className="text-lg font-bold text-slate-900 dark:text-white">
                  Audit Verdict: {auditResult.verdict}
                </h2>
                <p className="text-xs text-slate-600 dark:text-slate-300 mt-0.5">
                  {auditResult.message}
                </p>
              </div>
            </div>

            <span
              className={cn(
                "px-3 py-1 rounded-full text-xs font-mono font-bold uppercase self-start sm:self-auto border",
                auditResult.verdict === "VERIFIED"
                  ? "bg-emerald-500/15 text-emerald-600 dark:text-emerald-400 border-emerald-500/30"
                  : auditResult.verdict === "MISMATCH"
                  ? "bg-rose-500/15 text-rose-600 dark:text-rose-400 border-rose-500/30"
                  : auditResult.verdict === "NOT FOUND"
                  ? "bg-amber-500/15 text-amber-600 dark:text-amber-400 border-amber-500/30"
                  : "bg-slate-500/15 text-slate-600 dark:text-slate-400 border-slate-500/30"
              )}
            >
              {auditResult.verdict === "VERIFIED"
                ? "TAMPER-EVIDENT CONFIRMED"
                : auditResult.verdict === "MISMATCH"
                ? "TAMPERING DETECTED"
                : auditResult.verdict}
            </span>
          </div>

          {/* Hashes Comparison Table */}
          {(auditResult.calculatedCommitment || auditResult.onChainCommitment) && (
            <div className="space-y-2 text-xs font-mono">
              <span className="font-bold uppercase tracking-wider text-slate-400 text-[10px]">
                Cryptographic Commitment Comparison
              </span>

              {auditResult.calculatedCommitment && (
                <div className="p-3 rounded-xl bg-white dark:bg-slate-900 border border-slate-200 dark:border-slate-800 space-y-1">
                  <span className="text-[10px] text-slate-400 block font-sans">
                    Locally Calculated Digest (from provided report payload):
                  </span>
                  <div className="text-purple-600 dark:text-purple-400 break-all font-semibold select-all">
                    {auditResult.calculatedCommitment}
                  </div>
                </div>
              )}

              {auditResult.onChainCommitment && (
                <div className="p-3 rounded-xl bg-white dark:bg-slate-900 border border-slate-200 dark:border-slate-800 space-y-1">
                  <span className="text-[10px] text-slate-400 block font-sans">
                    On-Chain Registered Commitment (directly from contract):
                  </span>
                  <div className="text-emerald-600 dark:text-emerald-400 break-all font-semibold select-all">
                    {auditResult.onChainCommitment}
                  </div>
                </div>
              )}
            </div>
          )}

          {/* On-Chain Evidence Details */}
          {auditResult.initialTimestamp && (
            <div className="grid grid-cols-1 sm:grid-cols-2 lg:grid-cols-4 gap-3 text-xs">
              <div className="p-3 rounded-xl bg-white dark:bg-slate-900 border border-slate-200 dark:border-slate-800">
                <span className="text-[10px] uppercase font-bold text-slate-400 block">
                  Notarization Date
                </span>
                <span className="font-semibold text-slate-800 dark:text-slate-200 mt-1 block">
                  {new Date(auditResult.initialTimestamp * 1000).toLocaleDateString()}
                </span>
                <span className="text-[11px] text-slate-500 block truncate">
                  {new Date(auditResult.initialTimestamp * 1000).toLocaleTimeString()} UTC
                </span>
              </div>

              <div className="p-3 rounded-xl bg-white dark:bg-slate-900 border border-slate-200 dark:border-slate-800">
                <span className="text-[10px] uppercase font-bold text-slate-400 block">
                  Attestation Status
                </span>
                <span className="font-semibold text-slate-800 dark:text-slate-200 mt-1 block">
                  {auditResult.attestationStatus}
                </span>
                <span className="text-[11px] text-slate-500 block">Vetted Security State</span>
              </div>

              <div className="p-3 rounded-xl bg-white dark:bg-slate-900 border border-slate-200 dark:border-slate-800">
                <span className="text-[10px] uppercase font-bold text-slate-400 block">
                  Registered Reporter
                </span>
                <span className="font-mono text-slate-700 dark:text-slate-300 mt-1 block truncate">
                  {auditResult.reporter}
                </span>
                <span className="text-[11px] text-slate-500 block">Notary Public Address</span>
              </div>

              <div className="p-3 rounded-xl bg-white dark:bg-slate-900 border border-slate-200 dark:border-slate-800">
                <span className="text-[10px] uppercase font-bold text-slate-400 block">
                  Disputes Filed
                </span>
                <span className="font-semibold text-slate-800 dark:text-slate-200 mt-1 block">
                  {auditResult.disputeCount} Filed
                </span>
                <span className="text-[11px] text-slate-500 block">
                  {auditResult.disputeCount === 0 ? "Zero Active Disputes" : "Under Formal Dispute"}
                </span>
              </div>
            </div>
          )}

          {/* Revision History Trace */}
          {auditResult.revisions && auditResult.revisions.length > 0 && (
            <div className="space-y-2 pt-2 border-t border-slate-200 dark:border-slate-800">
              <div className="flex items-center gap-1.5 text-xs font-bold uppercase tracking-wider text-slate-400">
                <History className="w-3.5 h-3.5" />
                <span>On-Chain Revision History ({auditResult.revisions.length} Revisions Recorded)</span>
              </div>
              <div className="space-y-1.5">
                {auditResult.revisions.map((rev: any) => (
                  <div
                    key={rev.index}
                    className={cn(
                      "p-3 rounded-xl border text-xs font-mono flex flex-col sm:flex-row sm:items-center justify-between gap-2",
                      auditResult.matchedRevision === rev.index
                        ? "bg-emerald-500/10 border-emerald-500/30 text-emerald-950 dark:text-emerald-200"
                        : "bg-white dark:bg-slate-900 border-slate-200 dark:border-slate-800 text-slate-700 dark:text-slate-300"
                    )}
                  >
                    <div>
                      <span className="font-bold mr-2">Revision #{rev.index}:</span>
                      <span className="truncate">{rev.commitmentHash}</span>
                    </div>
                    <div className="text-[11px] text-slate-500 shrink-0 font-sans">
                      Block #{rev.blockNumber} • {new Date(rev.timestamp * 1000).toLocaleString()}
                    </div>
                  </div>
                ))}
              </div>
            </div>
          )}
        </div>
      )}
    </div>
  );
}
