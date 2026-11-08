"use client";

import React, { useState } from "react";
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
} from "lucide-react";
import { cn } from "@/lib/utils";

// Sample campaign nodes for interactive demonstration
const MOCK_NODES = [
  { id: "campaign", label: "Campaign: 'LethalLure-Fin'", type: "CAMPAIGN", x: 400, y: 150, color: "text-red-400 border-red-500 bg-red-500/10" },
  { id: "domain1", label: "chase-auth-service.com", type: "DOMAIN", x: 200, y: 280, color: "text-amber-400 border-amber-500 bg-amber-500/10" },
  { id: "domain2", label: "wellsfargo-verify.xyz", type: "DOMAIN", x: 600, y: 280, color: "text-amber-400 border-amber-500 bg-amber-500/10" },
  { id: "ip1", label: "185.220.101.4 (Bulletproof ASN)", type: "IP", x: 300, y: 420, color: "text-astra-cyan border-astra-cyan bg-astra-cyan/10" },
  { id: "cert1", label: "Let's Encrypt R3 (Shared SAN)", type: "CERT", x: 500, y: 420, color: "text-astra-violet border-astra-violet bg-astra-violet/10" },
];

export default function CorrelationPage() {
  const [selectedNode, setSelectedNode] = useState<string | null>("campaign");

  return (
    <div className="space-y-6">
      {/* Header */}
      <div className="astra-panel p-6 rounded-2xl relative overflow-hidden">
        <div className="relative z-10 space-y-2">
          <div className="inline-flex items-center gap-2 px-2.5 py-1 rounded bg-astra-cyan/10 border border-astra-cyan/30 text-xs font-mono text-astra-cyan">
            <Network className="w-3.5 h-3.5" />
            <span>INFRASTRUCTURE TOPOLOGY GRAPH</span>
          </div>
          <h1 className="text-2xl sm:text-3xl font-extrabold text-white font-tech">
            Threat Actor & Infrastructure Correlation
          </h1>
          <p className="text-xs sm:text-sm text-slate-300 max-w-2xl leading-relaxed">
            Link isolated phishing domains, scam SMS payloads, and malicious hosts across shared Autonomous System Numbers (ASNs), DNS nameservers, and TLS certificate subject fingerprints.
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

        {/* Visual Simulated SVG Interactive Topology Graph */}
        <div className="relative w-full h-[360px] flex items-center justify-center">
          <svg className="absolute inset-0 w-full h-full pointer-events-none">
            {/* Connecting Edges */}
            <line x1="50%" y1="20%" x2="30%" y2="50%" stroke="rgba(0, 240, 255, 0.3)" strokeWidth="1.5" strokeDasharray="4 2" />
            <line x1="50%" y1="20%" x2="70%" y2="50%" stroke="rgba(0, 240, 255, 0.3)" strokeWidth="1.5" strokeDasharray="4 2" />
            <line x1="30%" y1="50%" x2="40%" y2="80%" stroke="rgba(139, 92, 246, 0.3)" strokeWidth="1.5" />
            <line x1="70%" y1="50%" x2="40%" y2="80%" stroke="rgba(139, 92, 246, 0.3)" strokeWidth="1.5" />
            <line x1="30%" y1="50%" x2="60%" y2="80%" stroke="rgba(16, 185, 129, 0.3)" strokeWidth="1.5" />
            <line x1="70%" y1="50%" x2="60%" y2="80%" stroke="rgba(16, 185, 129, 0.3)" strokeWidth="1.5" />
          </svg>

          {/* Nodes */}
          {/* Top Campaign Node */}
          <div
            onClick={() => setSelectedNode("campaign")}
            className="absolute top-[12%] left-1/2 -translate-x-1/2 p-3 rounded-xl border border-red-500/50 bg-astra-deep/90 shadow-crimson-glow cursor-pointer hover:scale-105 transition-all text-center z-10"
          >
            <div className="text-[10px] font-mono text-red-400 font-bold uppercase">Target Campaign</div>
            <div className="text-xs font-mono text-slate-100 font-bold">LethalLure-FinTech</div>
          </div>

          {/* Domain 1 Node */}
          <div
            onClick={() => setSelectedNode("domain1")}
            className="absolute top-[44%] left-[24%] p-3 rounded-xl border border-amber-500/50 bg-astra-deep/90 shadow-[0_0_15px_rgba(245,158,11,0.2)] cursor-pointer hover:scale-105 transition-all z-10"
          >
            <div className="text-[10px] font-mono text-amber-400 font-bold uppercase">Phish URL</div>
            <div className="text-xs font-mono text-slate-100">chase-auth-service.com</div>
          </div>

          {/* Domain 2 Node */}
          <div
            onClick={() => setSelectedNode("domain2")}
            className="absolute top-[44%] right-[24%] p-3 rounded-xl border border-amber-500/50 bg-astra-deep/90 shadow-[0_0_15px_rgba(245,158,11,0.2)] cursor-pointer hover:scale-105 transition-all z-10"
          >
            <div className="text-[10px] font-mono text-amber-400 font-bold uppercase">Phish URL</div>
            <div className="text-xs font-mono text-slate-100">wellsfargo-verify.xyz</div>
          </div>

          {/* Shared IP Node */}
          <div
            onClick={() => setSelectedNode("ip1")}
            className="absolute bottom-[10%] left-[32%] p-3 rounded-xl border border-astra-cyan/50 bg-astra-deep/90 shadow-cyan-glow cursor-pointer hover:scale-105 transition-all z-10"
          >
            <div className="text-[10px] font-mono text-astra-cyan font-bold uppercase">Shared Host IP</div>
            <div className="text-xs font-mono text-slate-100">185.220.101.4 (AS44050)</div>
          </div>

          {/* Shared Cert Node */}
          <div
            onClick={() => setSelectedNode("cert1")}
            className="absolute bottom-[10%] right-[32%] p-3 rounded-xl border border-astra-violet/50 bg-astra-deep/90 shadow-violet-glow cursor-pointer hover:scale-105 transition-all z-10"
          >
            <div className="text-[10px] font-mono text-astra-violet font-bold uppercase">Shared SSL Fingerprint</div>
            <div className="text-xs font-mono text-slate-100">SHA256: 7a8f...39b2</div>
          </div>
        </div>

        {/* Selected Node Inspector Drawer */}
        <div className="pt-4 border-t border-astra-border/60 flex flex-col sm:flex-row items-start sm:items-center justify-between text-xs font-mono text-slate-400">
          <span>Active Selection: <strong className="text-slate-200">{selectedNode || "None"}</strong></span>
          <span className="text-astra-cyan">Correlation Score: 94% High Confidence Cluster</span>
        </div>
      </div>
    </div>
  );
}
