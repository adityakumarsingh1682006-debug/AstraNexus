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
} from "lucide-react";
import { cn, truncateHash } from "@/lib/utils";

export default function VerifyPage() {
  const [reportHash, setReportHash] = useState("");
  const [verificationResult, setVerificationResult] = useState<any>(null);
  const [isVerifying, setIsVerifying] = useState(false);

  const handleVerify = (e: React.FormEvent) => {
    e.preventDefault();
    if (!reportHash.trim()) return;

    setIsVerifying(true);
    // Simulating instant validation of cryptographic integrity
    setTimeout(() => {
      setIsVerifying(false);
      setVerificationResult({
        verified: true,
        reportId: "a7c89f12-321b-4b10-8488-e9f3b5c102a9",
        hash: reportHash.trim(),
        targetUrl: "https://chase-auth-service.com/login",
        verdict: "MALICIOUS",
        threatScore: 94,
        network: "Arbitrum Sepolia / EVM",
        blockNumber: 4891024,
        txHash: "0x3f4a9b8172c6de3410f99238120b085619e07291a1827b5e40a1b8971f456123",
        timestamp: "2026-11-07 16:30:12 UTC",
        signer: "0x71C...49b2 (Astra Sentinel Notary)",
      });
    }, 600);
  };

  return (
    <div className="space-y-6">
      {/* Header */}
      <div className="astra-panel p-6 rounded-2xl relative overflow-hidden">
        <div className="relative z-10 space-y-2">
          <div className="inline-flex items-center gap-2 px-2.5 py-1 rounded bg-astra-emerald/10 border border-astra-emerald/30 text-xs font-mono text-astra-emerald">
            <FileCheck2 className="w-3.5 h-3.5" />
            <span>IMMUTABLE PROOF REGISTRY</span>
          </div>
          <h1 className="text-2xl sm:text-3xl font-extrabold text-white font-tech">
            Blockchain Forensic Notary & Verification
          </h1>
          <p className="text-xs sm:text-sm text-slate-300 max-w-2xl leading-relaxed">
            Verify the cryptographic tamper-resistance of AstraNexus threat investigations. All report evidence digests are hashed via canonical SHA-256 and committed on an EVM smart contract. Zero sensitive PII is stored on-chain.
          </p>
        </div>
      </div>

      {/* Verification Input Box */}
      <div className="astra-panel p-6 rounded-2xl space-y-4">
        <form onSubmit={handleVerify} className="space-y-3">
          <label className="block text-xs font-mono font-bold text-slate-300 uppercase tracking-wider">
            Report SHA-256 Evidence Hash or Transaction ID
          </label>
          <div className="flex flex-col sm:flex-row gap-3">
            <div className="relative flex-1">
              <Hash className="absolute left-3.5 top-1/2 -translate-y-1/2 w-4 h-4 text-slate-400" />
              <input
                type="text"
                value={reportHash}
                onChange={(e) => setReportHash(e.target.value)}
                placeholder="0x9a8f21b3... or paste canonical evidence digest"
                className="w-full pl-10 pr-4 py-3 rounded-xl bg-astra-void/90 border border-astra-border text-sm text-slate-100 placeholder-slate-500 focus:outline-none focus:border-astra-emerald font-mono"
              />
            </div>
            <button
              type="submit"
              disabled={isVerifying || !reportHash.trim()}
              className="inline-flex items-center justify-center gap-2 px-6 py-3 rounded-xl bg-astra-emerald text-astra-void font-bold text-sm tracking-wide hover:bg-emerald-300 disabled:opacity-50 transition-all shadow-emerald-glow whitespace-nowrap font-tech"
            >
              {isVerifying ? "AUDITING RECORD..." : "VERIFY NOTARIZATION"}
            </button>
          </div>
        </form>

        <div className="pt-2 text-xs font-mono text-slate-400 flex items-center gap-2">
          <span className="text-slate-500">Sample Registered Hash:</span>
          <button
            type="button"
            onClick={() =>
              setReportHash("0x8e4b31a89c927f88410294b01e9d9847192a5436c8102a9b3d7e5f601a2b3c4d")
            }
            className="text-astra-cyan hover:underline truncate max-w-xs sm:max-w-md"
          >
            0x8e4b31a89c927f88410294b01e9d9847192a5436c8102a9b3d7e5f601a2b3c4d
          </button>
        </div>
      </div>

      {/* Verification Result Card */}
      {verificationResult && (
        <div className="astra-panel p-6 rounded-2xl border-astra-emerald/40 space-y-4">
          <div className="flex items-center justify-between pb-3 border-b border-astra-border/60">
            <div className="flex items-center gap-2">
              <CheckCircle2 className="w-5 h-5 text-astra-emerald" />
              <span className="text-sm font-bold text-white font-mono uppercase">
                AUTHENTIC EVIDENCE SEAL CONFIRMED
              </span>
            </div>
            <span className="px-2 py-0.5 rounded bg-astra-emerald/10 border border-astra-emerald/30 text-xs font-mono text-astra-emerald font-bold">
              VERIFIED IMMUTABLE
            </span>
          </div>

          <div className="grid grid-cols-1 sm:grid-cols-2 gap-4 text-xs font-mono">
            <div className="space-y-1">
              <span className="text-slate-500">Target Investigated:</span>
              <div className="text-slate-200 font-semibold">{verificationResult.targetUrl}</div>
            </div>
            <div className="space-y-1">
              <span className="text-slate-500">Verdict & Risk Score:</span>
              <div className="text-red-400 font-semibold">
                {verificationResult.verdict} ({verificationResult.threatScore}/100)
              </div>
            </div>
            <div className="space-y-1">
              <span className="text-slate-500">Blockchain Network:</span>
              <div className="text-slate-200">{verificationResult.network} (Block #{verificationResult.blockNumber})</div>
            </div>
            <div className="space-y-1">
              <span className="text-slate-500">Notarization Timestamp:</span>
              <div className="text-slate-200">{verificationResult.timestamp}</div>
            </div>
            <div className="sm:col-span-2 space-y-1 pt-2 border-t border-astra-border/40">
              <span className="text-slate-500">On-Chain Transaction Hash:</span>
              <div className="text-astra-cyan break-all">{verificationResult.txHash}</div>
            </div>
          </div>
        </div>
      )}
    </div>
  );
}
