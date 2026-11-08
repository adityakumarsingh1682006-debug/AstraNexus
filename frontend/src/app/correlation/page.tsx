"use client";

import React, { useState, useEffect } from "react";
import {
  Network,
  Share2,
  Server,
  Globe,
  Lock,
  Layers,
  ZoomIn,
  ZoomOut,
  Maximize2,
  ShieldAlert,
  Info,
  Clock,
  CheckCircle2,
} from "lucide-react";
import { cn } from "@/lib/utils";

interface CorrelatedNode {
  id: string;
  label: string;
  type: string;
  category: string;
  matchType: string;
  confidence: number;
  evidence: string;
  timestamp: string;
}

const STATIC_NODES: CorrelatedNode[] = [
  {
    id: "campaign-1",
    label: "Campaign: 'LethalLure-FinTech' (Cluster #FIN-2026)",
    type: "CAMPAIGN",
    category: "Banking Fraud",
    matchType: "DOMAIN_INFRASTRUCTURE",
    confidence: 0.94,
    evidence: "Shared ASN 44050 bulletproof hosting, co-located DNS records, and cloned Chase/Wells Fargo login templates.",
    timestamp: "2026-11-08T12:00:00Z",
  },
  {
    id: "domain1",
    label: "secure-chase-update-account.com",
    type: "PHISH_DOMAIN",
    category: "Banking Fraud",
    matchType: "EXACT_INDICATOR",
    confidence: 1.0,
    evidence: "Direct indicator reported in community registry; matches high-risk credential harvesting signature.",
    timestamp: "2026-11-08T11:45:00Z",
  },
  {
    id: "domain2",
    label: "wellsfargo-verify.xyz",
    type: "PHISH_DOMAIN",
    category: "Banking Fraud",
    matchType: "DOMAIN_INFRASTRUCTURE",
    confidence: 0.92,
    evidence: "Co-hosted on IP 185.220.101.4; identical Let's Encrypt R3 TLS certificate SAN extensions.",
    timestamp: "2026-11-08T10:30:00Z",
  },
  {
    id: "ip1",
    label: "185.220.101.4 (AS44050 Hosting)",
    type: "SHARED_HOST",
    category: "Infrastructure",
    matchType: "DOMAIN_INFRASTRUCTURE",
    confidence: 0.95,
    evidence: "Host resolving 14 known financial phishing domains within 72 hours.",
    timestamp: "2026-11-08T09:15:00Z",
  },
  {
    id: "cert1",
    label: "Let's Encrypt R3 (Fingerprint SHA256: 7a8f...39b2)",
    type: "CERTIFICATE",
    category: "TLS Fingerprint",
    matchType: "EXPLAINABLE_TEXT_SIMILARITY",
    confidence: 0.88,
    evidence: "Shared TLS certificate Subject Alternative Names covering both spoofed brands.",
    timestamp: "2026-11-08T08:00:00Z",
  },
];

export default function CorrelationPage() {
  const [nodes, setNodes] = useState<CorrelatedNode[]>(STATIC_NODES);
  const [selectedNodeId, setSelectedNodeId] = useState<string>("campaign-1");
  const [liveReports, setLiveReports] = useState<any[]>([]);

  useEffect(() => {
    fetch("/api/v1/reports")
      .then((res) => res.json())
      .then((data) => {
        if (Array.isArray(data) && data.length > 0) {
          setLiveReports(data);
        }
      })
      .catch(() => {});
  }, []);

  const selectedNode = nodes.find((n) => n.id === selectedNodeId) || nodes[0];

  return (
    <div className="space-y-6">
      {/* Header */}
      <div className="astra-panel p-6 rounded-2xl relative overflow-hidden">
        <div className="relative z-10 space-y-2">
          <div className="inline-flex items-center gap-2 px-2.5 py-1 rounded bg-astra-cyan/10 border border-astra-cyan/30 text-xs font-mono text-astra-cyan">
            <Network className="w-3.5 h-3.5" />
            <span>INFRASTRUCTURE TOPOLOGY & CAMPAIGN CORRELATION</span>
          </div>
          <h1 className="text-2xl sm:text-3xl font-extrabold text-white font-tech">
            Threat Infrastructure & Scam Campaign Correlation
          </h1>
          <p className="text-xs sm:text-sm text-slate-300 max-w-2xl leading-relaxed">
            Correlate isolated phishing domains, scam SMS payloads, and malicious hosts across shared Autonomous System Numbers (ASNs), DNS nameservers, and TLS certificate fingerprints.
          </p>
        </div>
      </div>

      {/* Graph Visualizer Canvas Area */}
      <div className="astra-panel rounded-2xl border border-astra-border p-6 min-h-[480px] relative overflow-hidden flex flex-col justify-between">
        {/* Controls Overlay */}
        <div className="flex items-center justify-between pb-4 border-b border-astra-border/60 z-10">
          <div className="flex items-center gap-2 text-xs font-mono">
            <span className="text-slate-400">Campaign Fingerprint:</span>
            <span className="text-astra-cyan font-bold">#FIN-PHISH-2026-B</span>
          </div>
          <div className="flex items-center gap-1.5 text-slate-400">
            <button className="p-1.5 rounded hover:bg-slate-800 text-slate-300 hover:text-white" title="Zoom In">
              <ZoomIn className="w-4 h-4" />
            </button>
            <button className="p-1.5 rounded hover:bg-slate-800 text-slate-300 hover:text-white" title="Zoom Out">
              <ZoomOut className="w-4 h-4" />
            </button>
            <button className="p-1.5 rounded hover:bg-slate-800 text-slate-300 hover:text-white" title="Fit to Screen">
              <Maximize2 className="w-4 h-4" />
            </button>
          </div>
        </div>

        {/* Visual Interactive Topology Graph */}
        <div className="relative w-full h-[360px] flex items-center justify-center">
          <svg className="absolute inset-0 w-full h-full pointer-events-none">
            <line x1="50%" y1="20%" x2="30%" y2="50%" stroke="rgba(0, 240, 255, 0.4)" strokeWidth="1.5" strokeDasharray="4 2" />
            <line x1="50%" y1="20%" x2="70%" y2="50%" stroke="rgba(0, 240, 255, 0.4)" strokeWidth="1.5" strokeDasharray="4 2" />
            <line x1="30%" y1="50%" x2="40%" y2="80%" stroke="rgba(139, 92, 246, 0.4)" strokeWidth="1.5" />
            <line x1="70%" y1="50%" x2="40%" y2="80%" stroke="rgba(139, 92, 246, 0.4)" strokeWidth="1.5" />
            <line x1="30%" y1="50%" x2="60%" y2="80%" stroke="rgba(16, 185, 129, 0.4)" strokeWidth="1.5" />
            <line x1="70%" y1="50%" x2="60%" y2="80%" stroke="rgba(16, 185, 129, 0.4)" strokeWidth="1.5" />
          </svg>

          {/* Top Campaign Node */}
          <div
            onClick={() => setSelectedNodeId("campaign-1")}
            className={cn(
              "absolute top-[12%] left-1/2 -translate-x-1/2 p-3 rounded-xl border bg-astra-deep/90 cursor-pointer hover:scale-105 transition-all text-center z-10",
              selectedNodeId === "campaign-1"
                ? "border-red-500 shadow-crimson-glow scale-105 ring-2 ring-red-500/50"
                : "border-red-500/50"
            )}
          >
            <div className="text-[10px] font-mono text-red-400 font-bold uppercase">Target Campaign</div>
            <div className="text-xs font-mono text-slate-100 font-bold">LethalLure-FinTech</div>
          </div>

          {/* Domain 1 Node */}
          <div
            onClick={() => setSelectedNodeId("domain1")}
            className={cn(
              "absolute top-[44%] left-[20%] p-3 rounded-xl border bg-astra-deep/90 cursor-pointer hover:scale-105 transition-all z-10",
              selectedNodeId === "domain1"
                ? "border-amber-500 shadow-[0_0_15px_rgba(245,158,11,0.4)] scale-105 ring-2 ring-amber-500/50"
                : "border-amber-500/50"
            )}
          >
            <div className="text-[10px] font-mono text-amber-400 font-bold uppercase">Phish URL</div>
            <div className="text-xs font-mono text-slate-100">secure-chase-update-account.com</div>
          </div>

          {/* Domain 2 Node */}
          <div
            onClick={() => setSelectedNodeId("domain2")}
            className={cn(
              "absolute top-[44%] right-[20%] p-3 rounded-xl border bg-astra-deep/90 cursor-pointer hover:scale-105 transition-all z-10",
              selectedNodeId === "domain2"
                ? "border-amber-500 shadow-[0_0_15px_rgba(245,158,11,0.4)] scale-105 ring-2 ring-amber-500/50"
                : "border-amber-500/50"
            )}
          >
            <div className="text-[10px] font-mono text-amber-400 font-bold uppercase">Phish URL</div>
            <div className="text-xs font-mono text-slate-100">wellsfargo-verify.xyz</div>
          </div>

          {/* Shared IP Node */}
          <div
            onClick={() => setSelectedNodeId("ip1")}
            className={cn(
              "absolute bottom-[10%] left-[30%] p-3 rounded-xl border bg-astra-deep/90 cursor-pointer hover:scale-105 transition-all z-10",
              selectedNodeId === "ip1"
                ? "border-astra-cyan shadow-cyan-glow scale-105 ring-2 ring-astra-cyan/50"
                : "border-astra-cyan/50"
            )}
          >
            <div className="text-[10px] font-mono text-astra-cyan font-bold uppercase">Shared Host IP</div>
            <div className="text-xs font-mono text-slate-100">185.220.101.4 (AS44050)</div>
          </div>

          {/* Shared Cert Node */}
          <div
            onClick={() => setSelectedNodeId("cert1")}
            className={cn(
              "absolute bottom-[10%] right-[30%] p-3 rounded-xl border bg-astra-deep/90 cursor-pointer hover:scale-105 transition-all z-10",
              selectedNodeId === "cert1"
                ? "border-astra-violet shadow-violet-glow scale-105 ring-2 ring-astra-violet/50"
                : "border-astra-violet/50"
            )}
          >
            <div className="text-[10px] font-mono text-astra-violet font-bold uppercase">Shared SSL Fingerprint</div>
            <div className="text-xs font-mono text-slate-100">SHA256: 7a8f...39b2</div>
          </div>
        </div>

        {/* Selected Node Inspector Drawer (Part E) */}
        <div className="pt-4 border-t border-astra-border/60 space-y-3">
          <div className="flex flex-col sm:flex-row items-start sm:items-center justify-between text-xs font-mono text-slate-400 gap-2">
            <div>
              <span>Inspecting Node: </span>
              <strong className="text-slate-200">{selectedNode.label}</strong>
            </div>
            <div className="flex items-center gap-3">
              <span className="text-[10px] px-2 py-0.5 rounded bg-slate-800 text-slate-300 border border-slate-700">
                Match Type: {selectedNode.matchType}
              </span>
              <span className="text-astra-cyan font-bold">
                Confidence: {Math.round(selectedNode.confidence * 100)}%
              </span>
            </div>
          </div>

          <div className="p-3 rounded-xl bg-slate-900/80 border border-astra-border/60 text-xs font-mono text-slate-300 space-y-1">
            <div className="text-[10px] text-slate-400 uppercase font-bold">Correlation Evidence:</div>
            <p className="leading-relaxed">{selectedNode.evidence}</p>
          </div>

          {/* Legal Non-Attribution Disclaimer */}
          <div className="p-3 rounded-xl bg-slate-900/40 border border-slate-800 text-[11px] text-slate-400 flex items-start gap-2">
            <Info className="w-4 h-4 text-slate-500 shrink-0 mt-0.5" />
            <p className="leading-relaxed">
              <strong>Attribution Notice:</strong> Threat relationships represent technical infrastructure and behavioral clustering. AstraNexus does not identify or publish real-world individual identities without verified law enforcement attribution.
            </p>
          </div>
        </div>
      </div>
    </div>
  );
}
