"use client";

import React, { useState, useEffect, Suspense } from "react";
import { useSearchParams } from "next/navigation";
import {
  Globe,
  MessageSquareWarning,
  Search,
  CheckCircle2,
  AlertTriangle,
  XCircle,
  HelpCircle,
  ShieldCheck,
  ChevronDown,
  ChevronUp,
  ArrowRight,
  ExternalLink,
  Copy,
  Check,
  Lock,
  Server,
  FileCheck2,
  AlertCircle,
  RotateCcw,
  MinusCircle,
  Info,
  ShieldAlert,
  FlaskConical,
  Sparkles,
  Download,
} from "lucide-react";
import { cn } from "@/lib/utils";

// Progress steps for URL scan
const SCAN_STEPS = [
  "Checking link address and safety filters...",
  "Validating security certificates (HTTPS & SSL)...",
  "Checking for fake brand impersonation & subdomains...",
  "Interrogating global threat databases (URLhaus & OpenPhish)...",
  "Synthesizing easy-to-understand safety report...",
];

export interface DetectedTacticItem {
  tactic: string;
  severity?: string;
  explanation?: string;
  snippet?: string;
}

export interface MessageAnalysisData {
  verdict: string;
  consumer_headline: string;
  consumer_advice: string[];
  risk_score: number;
  confidence_score: number;
  scam_category: string;
  detected_tactics: DetectedTacticItem[];
  manipulation_tactics: string[];
  extracted_links: string[];
  extracted_phones: string[];
  extracted_amounts: string[];
  ai_explanation?: {
    source?: string;
    headline?: string;
    summary?: string;
    what_to_do?: string[];
  } | null;
  analyzed_at?: string;
}

function CheckContent() {
  const searchParams = useSearchParams();

  const tabParam = searchParams.get("tab") || "url";
  const initialTarget = searchParams.get("target") || "";
  const initialText = searchParams.get("text") || "";

  const [activeTab, setActiveTab] = useState<"url" | "message">(
    tabParam === "message" ? "message" : "url"
  );

  // URL Checker States
  const [targetUrl, setTargetUrl] = useState(initialTarget);
  const [isUrlScanning, setIsUrlScanning] = useState(false);
  const [currentStepIndex, setCurrentStepIndex] = useState(0);
  const [urlScanResult, setUrlScanResult] = useState<any>(null);
  const [urlScanError, setUrlScanError] = useState<string | null>(null);
  const [showTechnicalEvidence, setShowTechnicalEvidence] = useState(false);
  const [showCertificateDetails, setShowCertificateDetails] = useState(false);
  const [showWebsiteSecurityDetails, setShowWebsiteSecurityDetails] = useState(false);
  const [expandedSecurityFindings, setExpandedSecurityFindings] = useState<Record<string, boolean>>({});
  const [expandedConcernId, setExpandedConcernId] = useState<string | null>(null);
  const [copiedHash, setCopiedHash] = useState(false);
  const [copiedTxHash, setCopiedTxHash] = useState(false);
  const [isVerifyingOnChain, setIsVerifyingOnChain] = useState(false);
  const [liveVerificationResult, setLiveVerificationResult] = useState<any>(null);

  const handleVerifyOnChain = async (reportId: string, commitmentHash: string) => {
    setIsVerifyingOnChain(true);
    setLiveVerificationResult(null);
    try {
      const res = await fetch("/api/v1/registry/verify", {
        method: "POST",
        headers: { "Content-Type": "application/json" },
        body: JSON.stringify({
          report_id: reportId,
          expected_commitment_hash: commitmentHash,
        }),
      });
      const data = await res.json();
      setLiveVerificationResult(data);
    } catch (e: any) {
      setLiveVerificationResult({ is_verified: false, message: e.message || "Failed to query on-chain registry." });
    } finally {
      setIsVerifyingOnChain(false);
    }
  };

  const handleDownloadExport = () => {
    if (!urlScanResult) return;
    const exportData = urlScanResult.technical_evidence?.verifiable_export || {
      report_id:
        urlScanResult.technical_evidence?.blockchain_registration?.report_id ||
        `scan-${urlScanResult.technical_evidence?.evidence_hash?.slice(0, 16) || "unknown"}`,
      commitment_hash: urlScanResult.technical_evidence?.blockchain_registration?.commitment_hash,
      network:
        urlScanResult.technical_evidence?.blockchain_registration?.network || "EVM Localnet (Chain 31337)",
      contract_address:
        urlScanResult.technical_evidence?.blockchain_registration?.contract_address ||
        "0x5FbDB2315678afecb367f032d93F642f64180aa3",
      canonical_payload: {
        canonical_url: urlScanResult.url,
        risk_score: urlScanResult.risk_score,
        risk_level: urlScanResult.risk_level,
        timestamp: urlScanResult.scanned_at || new Date().toISOString(),
        threat_found: urlScanResult.risk_level === "DANGER" || urlScanResult.risk_level === "SUSPICIOUS",
      },
    };
    const blob = new Blob([JSON.stringify(exportData, null, 2)], { type: "application/json" });
    const url = URL.createObjectURL(blob);
    const a = document.createElement("a");
    a.href = url;
    a.download = `astranexus-report-${exportData.report_id || "export"}.json`;
    document.body.appendChild(a);
    a.click();
    document.body.removeChild(a);
    URL.revokeObjectURL(url);
  };

  const toggleSecurityFinding = (id: string) => {
    setExpandedSecurityFindings((prev) => ({
      ...prev,
      [id]: !prev[id],
    }));
  };

  // Message Analyzer States
  const [messageText, setMessageText] = useState(initialText);
  const [isMessageAnalyzing, setIsMessageAnalyzing] = useState(false);
  const [messageResult, setMessageResult] = useState<MessageAnalysisData | null>(null);
  const [messageError, setMessageError] = useState<string | null>(null);

  // Sync tab with URL
  useEffect(() => {
    if (tabParam === "message" && activeTab !== "message") {
      setActiveTab("message");
    } else if (tabParam === "url" && activeTab !== "url") {
      setActiveTab("url");
    }
  }, [tabParam]);

  // Handle auto-scan if target query param was passed from homepage
  useEffect(() => {
    if (initialTarget && !urlScanResult && !isUrlScanning) {
      setTargetUrl(initialTarget);
      performUrlScan(initialTarget);
    }
  }, [initialTarget]);

  useEffect(() => {
    if (initialText && !messageResult && !isMessageAnalyzing) {
      setMessageText(initialText);
      performMessageAnalysis(initialText);
    }
  }, [initialText]);

  // URL Scan execution
  const performUrlScan = async (urlToScan: string) => {
    const clean = urlToScan.trim();
    if (!clean) return;

    setIsUrlScanning(true);
    setUrlScanResult(null);
    setUrlScanError(null);
    setCurrentStepIndex(0);

    // Realistic progressive feedback
    const interval = setInterval(() => {
      setCurrentStepIndex((prev) => (prev < SCAN_STEPS.length - 1 ? prev + 1 : prev));
    }, 600);

    try {
      const response = await fetch("/api/v1/scan/url", {
        method: "POST",
        headers: { "Content-Type": "application/json" },
        body: JSON.stringify({ target_url: clean }),
      });

      clearInterval(interval);

      if (!response.ok) {
        const errorData = await response.json().catch(() => ({}));
        throw new Error(errorData.detail || "Unable to complete security scan at this time.");
      }

      const data = await response.json();
      setUrlScanResult(data);
    } catch (err: any) {
      clearInterval(interval);
      setUrlScanError(err.message || "Failed to scan link. Please check the spelling and try again.");
    } finally {
      setIsUrlScanning(false);
    }
  };

  // Message Analysis execution
  const performMessageAnalysis = async (textToScan: string) => {
    const clean = textToScan?.trim() || "";
    if (!clean) {
      setMessageError("Please enter or paste a message to analyze.");
      return;
    }

    setIsMessageAnalyzing(true);
    setMessageResult(null);
    setMessageError(null);

    try {
      const response = await fetch("/api/v1/message/analyze", {
        method: "POST",
        headers: { "Content-Type": "application/json" },
        body: JSON.stringify({ message_text: clean, channel_type: "AUTO" }),
      });

      if (!response.ok) {
        const errorData = await response.json().catch(() => ({}));
        throw new Error(errorData.detail || "Unable to analyze message at this time.");
      }

      const data = await response.json();

      if (!data || typeof data !== "object") {
        throw new Error("Invalid response format received from message analysis engine.");
      }

      // Safe normalization of all properties with robust defaults
      const safeResult: MessageAnalysisData = {
        verdict: typeof data.verdict === "string" ? data.verdict : "LOOKS_SAFE",
        consumer_headline:
          typeof data.consumer_headline === "string" && data.consumer_headline.trim()
            ? data.consumer_headline
            : "Message Safety Assessment",
        consumer_advice: Array.isArray(data.consumer_advice)
          ? data.consumer_advice.filter((item: any) => typeof item === "string" && item.trim())
          : [],
        risk_score: typeof data.risk_score === "number" ? Math.max(0, Math.min(100, data.risk_score)) : 0,
        confidence_score: typeof data.confidence_score === "number" ? data.confidence_score : 80.0,
        scam_category: typeof data.scam_category === "string" ? data.scam_category : "General Communication",
        detected_tactics: Array.isArray(data.detected_tactics) ? data.detected_tactics : [],
        manipulation_tactics:
          Array.isArray(data.manipulation_tactics) && data.manipulation_tactics.length > 0
            ? data.manipulation_tactics
            : Array.isArray(data.detected_tactics)
            ? data.detected_tactics
                .map((t: any) => (typeof t === "string" ? t : t?.tactic || ""))
                .filter(Boolean)
            : [],
        extracted_links: Array.isArray(data.extracted_links)
          ? data.extracted_links.filter((l: any) => typeof l === "string" && l.trim())
          : [],
        extracted_phones: Array.isArray(data.extracted_phones)
          ? data.extracted_phones.filter((p: any) => typeof p === "string" && p.trim())
          : [],
        extracted_amounts: Array.isArray(data.extracted_amounts)
          ? data.extracted_amounts.filter((a: any) => typeof a === "string" && a.trim())
          : [],
        ai_explanation:
          data.ai_explanation && typeof data.ai_explanation === "object" ? data.ai_explanation : null,
        analyzed_at: data.analyzed_at || new Date().toISOString(),
      };

      setMessageResult(safeResult);
    } catch (err: any) {
      setMessageError(err.message || "Failed to analyze message. Please try again.");
    } finally {
      setIsMessageAnalyzing(false);
    }
  };

  const switchTab = (newTab: "url" | "message") => {
    setActiveTab(newTab);
    if (typeof window !== "undefined") {
      const url = new URL(window.location.href);
      url.searchParams.set("tab", newTab);
      window.history.replaceState(null, "", url.toString());
    }
  };

  const handleScanExtractedLink = (link: string) => {
    setTargetUrl(link);
    setActiveTab("url");
    performUrlScan(link);
    if (typeof window !== "undefined") {
      const url = new URL(window.location.href);
      url.searchParams.set("tab", "url");
      url.searchParams.set("target", link);
      window.history.replaceState(null, "", url.toString());
    }
  };

  const handleCopyHash = (hash: string) => {
    navigator.clipboard.writeText(hash);
    setCopiedHash(true);
    setTimeout(() => setCopiedHash(false), 2000);
  };

  // Helper for check status pill and icons
  const getCheckStatusBadge = (status: string) => {
    switch (status) {
      case "COMPLETED":
        return {
          icon: <CheckCircle2 className="w-4 h-4 text-emerald-600 shrink-0" />,
          label: "Completed",
          classes: "bg-emerald-50 text-emerald-700 border-emerald-200 dark:bg-emerald-950/40 dark:text-emerald-300 dark:border-emerald-800",
        };
      case "SUSPICIOUS_FINDING":
        return {
          icon: <AlertTriangle className="w-4 h-4 text-amber-600 shrink-0" />,
          label: "Suspicious finding",
          classes: "bg-amber-50 text-amber-700 border-amber-200 dark:bg-amber-950/40 dark:text-amber-300 dark:border-amber-800",
        };
      case "NO_MATCH_FOUND":
        return {
          icon: <Check className="w-4 h-4 text-sky-600 shrink-0" />,
          label: "No match found",
          classes: "bg-sky-50 text-sky-700 border-sky-200 dark:bg-sky-950/40 dark:text-sky-300 dark:border-sky-800",
        };
      case "UNAVAILABLE":
        return {
          icon: <MinusCircle className="w-4 h-4 text-slate-400 shrink-0" />,
          label: "Unavailable",
          classes: "bg-slate-100 text-slate-600 border-slate-200 dark:bg-slate-800 dark:text-slate-400 dark:border-slate-700",
        };
      case "FAILED":
      default:
        return {
          icon: <XCircle className="w-4 h-4 text-rose-500 shrink-0" />,
          label: "Failed",
          classes: "bg-rose-50 text-rose-700 border-rose-200 dark:bg-rose-950/40 dark:text-rose-300 dark:border-rose-800",
        };
    }
  };

  // Helper for Concern Level badge
  const getConcernBadge = (level: string) => {
    switch (level) {
      case "HIGH_CONCERN":
        return {
          label: "HIGH CONCERN",
          classes: "bg-rose-100 text-rose-800 dark:bg-rose-900/60 dark:text-rose-200 border-rose-200 dark:border-rose-800",
          dot: "bg-rose-500",
        };
      case "MEDIUM_CONCERN":
        return {
          label: "MEDIUM CONCERN",
          classes: "bg-amber-100 text-amber-800 dark:bg-amber-900/60 dark:text-amber-200 border-amber-200 dark:border-amber-800",
          dot: "bg-amber-500",
        };
      case "LOW_CONCERN":
        return {
          label: "LOW CONCERN",
          classes: "bg-blue-100 text-blue-800 dark:bg-blue-900/60 dark:text-blue-200 border-blue-200 dark:border-blue-800",
          dot: "bg-blue-500",
        };
      case "INFORMATION":
      default:
        return {
          label: "INFORMATION",
          classes: "bg-slate-100 text-slate-700 dark:bg-slate-800 dark:text-slate-300 border-slate-200 dark:border-slate-700",
          dot: "bg-slate-400",
        };
    }
  };

  // Helper for Verdict Styling
  const getVerdictPresentation = (verdict: string) => {
    switch (verdict) {
      case "CONFIRMED_MALICIOUS":
        return {
          border: "border-l-rose-600 bg-rose-50/40 dark:bg-rose-950/30",
          icon: <XCircle className="w-8 h-8 text-rose-600 shrink-0" />,
          badge: "bg-rose-100 text-rose-800 dark:bg-rose-900/60 dark:text-rose-200 border-rose-300",
          title: "Confirmed Malicious",
        };
      case "PHISHING_SIMULATION":
        return {
          border: "border-l-indigo-600 bg-indigo-50/40 dark:bg-indigo-950/30",
          icon: <FlaskConical className="w-8 h-8 text-indigo-600 shrink-0" />,
          badge: "bg-indigo-100 text-indigo-800 dark:bg-indigo-900/60 dark:text-indigo-200 border-indigo-300",
          title: "Phishing Simulation",
        };
      case "HIGH_RISK":
        return {
          border: "border-l-rose-500 bg-rose-50/30 dark:bg-rose-950/20",
          icon: <AlertTriangle className="w-8 h-8 text-rose-500 shrink-0" />,
          badge: "bg-rose-100 text-rose-800 dark:bg-rose-900/60 dark:text-rose-200 border-rose-300",
          title: "High Risk",
        };
      case "SUSPICIOUS":
        return {
          border: "border-l-amber-500 bg-amber-50/30 dark:bg-amber-950/20",
          icon: <AlertTriangle className="w-8 h-8 text-amber-500 shrink-0" />,
          badge: "bg-amber-100 text-amber-800 dark:bg-amber-900/60 dark:text-amber-200 border-amber-300",
          title: "Suspicious",
        };
      case "INCONCLUSIVE":
        return {
          border: "border-l-slate-400 bg-slate-50/60 dark:bg-slate-900/40",
          icon: <HelpCircle className="w-8 h-8 text-slate-500 shrink-0" />,
          badge: "bg-slate-200 text-slate-800 dark:bg-slate-800 dark:text-slate-200 border-slate-300",
          title: "Inconclusive",
        };
      case "LOW_RISK":
      case "LOOKS_SAFE":
      default:
        return {
          border: "border-l-emerald-500 bg-emerald-50/30 dark:bg-emerald-950/20",
          icon: <CheckCircle2 className="w-8 h-8 text-emerald-600 shrink-0" />,
          badge: "bg-emerald-100 text-emerald-800 dark:bg-emerald-900/60 dark:text-emerald-200 border-emerald-300",
          title: "Low Risk",
        };
    }
  };

  return (
    <div className="space-y-8 max-w-4xl mx-auto">
      {/* Top Header */}
      <div className="text-center space-y-2">
        <h1 className="text-2xl sm:text-4xl font-extrabold text-slate-900 dark:text-white">
          Digital Safety Checker
        </h1>
        <p className="text-sm text-slate-600 dark:text-slate-400 max-w-xl mx-auto">
          Paste any website link or suspicious message to get a plain-English safety verdict within seconds.
        </p>
      </div>

      {/* Primary Tab Switcher */}
      <div className="flex justify-center">
        <div className="inline-flex p-1 rounded-2xl bg-slate-200/80 dark:bg-slate-800 border border-slate-300/60 dark:border-slate-700">
          <button
            onClick={() => switchTab("url")}
            className={cn(
              "flex items-center gap-2 px-5 py-2.5 rounded-xl text-sm font-semibold transition-all min-h-[44px]",
              activeTab === "url"
                ? "bg-white text-slate-900 shadow-sm dark:bg-slate-900 dark:text-white"
                : "text-slate-600 hover:text-slate-900 dark:text-slate-400 dark:hover:text-white"
            )}
          >
            <Globe className="w-4 h-4 text-brand-600" />
            <span>Check a Link</span>
          </button>

          <button
            onClick={() => switchTab("message")}
            className={cn(
              "flex items-center gap-2 px-5 py-2.5 rounded-xl text-sm font-semibold transition-all min-h-[44px]",
              activeTab === "message"
                ? "bg-white text-slate-900 shadow-sm dark:bg-slate-900 dark:text-white"
                : "text-slate-600 hover:text-slate-900 dark:text-slate-400 dark:hover:text-white"
            )}
          >
            <MessageSquareWarning className="w-4 h-4 text-purple-600" />
            <span>Check a Message</span>
          </button>
        </div>
      </div>

      {/* ========================================================================= */}
      {/* TAB 1: URL CHECKER */}
      {/* ========================================================================= */}
      {activeTab === "url" && (
        <div className="space-y-6">
          {/* URL Input Form */}
          <div className="consumer-card p-6 sm:p-7 space-y-4">
            <label className="block text-sm font-semibold text-slate-900 dark:text-white">
              Website or Link to Check
            </label>
            <form
              onSubmit={(e) => {
                e.preventDefault();
                performUrlScan(targetUrl);
              }}
              className="flex flex-col sm:flex-row gap-3"
            >
              <div className="relative flex-1">
                <Globe className="absolute left-3.5 top-1/2 -translate-y-1/2 w-4 h-4 text-slate-400" />
                <input
                  type="text"
                  value={targetUrl}
                  onChange={(e) => setTargetUrl(e.target.value)}
                  placeholder="Paste website link (e.g. paypal.com.security-check.example.com/login or https://example.com)"
                  className="w-full pl-10 pr-4 py-3 rounded-xl bg-slate-50 border border-slate-200 text-sm text-slate-900 placeholder-slate-400 focus:outline-none focus:ring-2 focus:ring-brand-500 focus:bg-white dark:bg-slate-900 dark:border-slate-700 dark:text-white dark:placeholder-slate-500"
                />
              </div>
              <button
                type="submit"
                disabled={isUrlScanning || !targetUrl.trim()}
                className="inline-flex items-center justify-center gap-2 px-6 py-3 rounded-xl bg-brand-600 text-white font-semibold text-sm hover:bg-brand-700 disabled:opacity-50 transition-colors shadow-sm shrink-0 min-h-[44px]"
              >
                {isUrlScanning ? (
                  <>
                    <span className="w-4 h-4 border-2 border-white/30 border-t-white rounded-full animate-spin" />
                    <span>Checking Link...</span>
                  </>
                ) : (
                  <>
                    <Search className="w-4 h-4" />
                    <span>Check Link</span>
                  </>
                )}
              </button>
            </form>

            {/* Presets */}
            <div className="flex flex-wrap items-center gap-2 text-xs text-slate-500 pt-1">
              <span>Try checking:</span>
              <button
                type="button"
                onClick={() => {
                  const url = "http://testsafebrowsing.appspot.com/s/phishing.html";
                  setTargetUrl(url);
                  performUrlScan(url);
                }}
                className="px-2.5 py-1 rounded-lg border border-slate-200 hover:border-indigo-500 hover:text-indigo-600 dark:border-slate-700 dark:hover:text-indigo-400 transition-colors font-medium bg-indigo-50/50 dark:bg-indigo-950/20"
              >
                Google Phishing Test Page
              </button>
              <button
                type="button"
                onClick={() => {
                  const url = "http://paypal.com.security-check.example.com/login";
                  setTargetUrl(url);
                  performUrlScan(url);
                }}
                className="px-2.5 py-1 rounded-lg border border-slate-200 hover:border-amber-500 hover:text-amber-600 dark:border-slate-700 dark:hover:text-amber-400 transition-colors font-medium"
              >
                PayPal Subdomain (Test 1)
              </button>
              <button
                type="button"
                onClick={() => {
                  const url = "https://chase-auth-service.com/login";
                  setTargetUrl(url);
                  performUrlScan(url);
                }}
                className="px-2.5 py-1 rounded-lg border border-slate-200 hover:border-brand-500 hover:text-brand-600 dark:border-slate-700 dark:hover:text-brand-400 transition-colors font-medium"
              >
                Combosquatting Lure
              </button>
              <button
                type="button"
                onClick={() => {
                  const url = "http://nonexistent-random-domain-xyz987654321.com";
                  setTargetUrl(url);
                  performUrlScan(url);
                }}
                className="px-2.5 py-1 rounded-lg border border-slate-200 hover:border-slate-500 hover:text-slate-700 dark:border-slate-700 dark:hover:text-slate-300 transition-colors font-medium"
              >
                Unresolvable Domain
              </button>
              <button
                type="button"
                onClick={() => {
                  const url = "https://example.com";
                  setTargetUrl(url);
                  performUrlScan(url);
                }}
                className="px-2.5 py-1 rounded-lg border border-slate-200 hover:border-emerald-500 hover:text-emerald-600 dark:border-slate-700 dark:hover:text-emerald-400 transition-colors font-medium"
              >
                Clean Domain
              </button>
            </div>
          </div>

          {/* Scanning Progress Feedback */}
          {isUrlScanning && (
            <div className="consumer-card p-6 border-brand-200 dark:border-brand-900/60 bg-brand-50/40 dark:bg-brand-950/30 space-y-4 text-center">
              <div className="w-10 h-10 rounded-full border-3 border-brand-500 border-t-transparent animate-spin mx-auto" />
              <div className="space-y-1">
                <h3 className="font-bold text-slate-900 dark:text-white text-base">
                  Analyzing Safety Telemetry
                </h3>
                <p className="text-xs text-brand-700 dark:text-brand-300 font-medium">
                  {SCAN_STEPS[currentStepIndex]}
                </p>
              </div>
            </div>
          )}

          {/* Scan Error Message */}
          {urlScanError && (
            <div className="consumer-card p-5 border-rose-200 bg-rose-50 text-rose-800 dark:bg-rose-950/40 dark:border-rose-900 dark:text-rose-200 flex items-start gap-3">
              <AlertCircle className="w-5 h-5 text-rose-600 shrink-0 mt-0.5" />
              <div className="space-y-1 text-sm">
                <strong className="block font-semibold">Check Blocked or Failed</strong>
                <p className="text-xs leading-relaxed">{urlScanError}</p>
              </div>
            </div>
          )}

          {/* Understandable Safety Result */}
          {urlScanResult && !isUrlScanning && (
            <div className="space-y-6">
              {/* 1. Overall Risk Assessment Header */}
              {(() => {
                const presentation = getVerdictPresentation(urlScanResult.verdict);
                return (
                  <div
                    className={cn(
                      "consumer-card p-6 sm:p-7 border-l-8 space-y-4",
                      presentation.border
                    )}
                  >
                    <div className="flex flex-col sm:flex-row sm:items-center justify-between gap-3">
                      <div className="flex items-start sm:items-center gap-3">
                        {presentation.icon}
                        <div>
                          <div className="flex items-center gap-2 flex-wrap">
                            <span
                              className={cn(
                                "px-2.5 py-0.5 rounded-full text-xs font-bold uppercase tracking-wider inline-block border",
                                presentation.badge
                              )}
                            >
                              {presentation.title}
                            </span>
                            <span className="text-xs text-slate-500 font-medium">
                              Confidence: {Math.round(urlScanResult.confidence_score)}%
                            </span>
                          </div>
                          <h2 className="text-xl sm:text-2xl font-bold text-slate-900 dark:text-white mt-1 leading-snug">
                            {urlScanResult.consumer_headline}
                          </h2>
                        </div>
                      </div>

                      <button
                        onClick={() => performUrlScan(targetUrl)}
                        className="inline-flex items-center gap-1.5 px-3 py-1.5 rounded-lg border border-slate-300 text-xs font-medium text-slate-700 hover:bg-slate-100 dark:border-slate-700 dark:text-slate-300 dark:hover:bg-slate-800 shrink-0 self-start sm:self-center min-h-[36px]"
                      >
                        <RotateCcw className="w-3.5 h-3.5" />
                        <span>Re-check</span>
                      </button>
                    </div>

                    <div className="text-xs text-slate-500 dark:text-slate-400 font-mono break-all pt-1 flex items-center gap-2 flex-wrap">
                      <span className="font-semibold text-slate-600 dark:text-slate-300">Checked Address:</span>
                      <span>{urlScanResult.normalized_url}</span>
                    </div>
                  </div>
                );
              })()}

              {/* 2. Why We're Concerned (Structured Findings with Badges & Explanations) */}
              {urlScanResult.concerns && urlScanResult.concerns.length > 0 && (
                <div className="consumer-card p-6 sm:p-7 space-y-4 border-amber-200/60 dark:border-amber-900/40">
                  <div className="flex items-center gap-2.5">
                    <ShieldAlert className="w-5 h-5 text-amber-600 shrink-0" />
                    <div>
                      <h3 className="font-bold text-slate-900 dark:text-white text-base">
                        Why We're Concerned
                      </h3>
                      <p className="text-xs text-slate-500 dark:text-slate-400">
                        Evidence and deceptive indicators identified during forensic analysis.
                      </p>
                    </div>
                  </div>

                  <div className="space-y-3 pt-1">
                    {urlScanResult.concerns.map((concern: any) => {
                      const badge = getConcernBadge(concern.concern_level);
                      const isExpanded = expandedConcernId === concern.id;

                      return (
                        <div
                          key={concern.id}
                          className="p-4 rounded-xl border border-slate-200/80 dark:border-slate-800 bg-white dark:bg-slate-900/60 space-y-2.5 transition-all"
                        >
                          <div className="flex flex-col sm:flex-row sm:items-center justify-between gap-2">
                            <div className="flex items-center gap-2 flex-wrap">
                              <span
                                className={cn(
                                  "px-2 py-0.5 rounded-md text-[10px] font-bold tracking-wider inline-flex items-center gap-1.5 border",
                                  badge.classes
                                )}
                              >
                                <span className={cn("w-1.5 h-1.5 rounded-full", badge.dot)} />
                                {badge.label}
                              </span>
                              <h4 className="font-bold text-sm text-slate-900 dark:text-white">
                                {concern.title}
                              </h4>
                            </div>

                            {concern.technical_evidence && (
                              <button
                                type="button"
                                onClick={() => setExpandedConcernId(isExpanded ? null : concern.id)}
                                className="text-xs text-slate-500 hover:text-brand-600 dark:hover:text-brand-400 flex items-center gap-1 self-start sm:self-center font-medium"
                              >
                                <span>{isExpanded ? "Hide evidence" : "View technical evidence"}</span>
                                {isExpanded ? <ChevronUp className="w-3.5 h-3.5" /> : <ChevronDown className="w-3.5 h-3.5" />}
                              </button>
                            )}
                          </div>

                          <p className="text-sm text-slate-700 dark:text-slate-300 leading-relaxed">
                            {concern.plain_explanation}
                          </p>

                          {/* Expandable Technical Evidence Details */}
                          {isExpanded && concern.technical_evidence && (
                            <div className="p-3 rounded-lg bg-slate-50 dark:bg-slate-950/80 border border-slate-200/60 dark:border-slate-800 text-xs font-mono text-slate-600 dark:text-slate-400 space-y-1">
                              <span className="text-[10px] uppercase font-bold text-slate-400 block">
                                Technical Forensic Attributes
                              </span>
                              <pre className="overflow-x-auto whitespace-pre-wrap">
                                {JSON.stringify(concern.technical_evidence, null, 2)}
                              </pre>
                            </div>
                          )}
                        </div>
                      );
                    })}
                  </div>
                </div>
              )}

              {/* 3. What You Should Do (Actionable Step-by-Step Guidance) */}
              <div className="consumer-card p-6 sm:p-7 space-y-4">
                <div className="flex items-center gap-2.5">
                  <ShieldCheck className="w-5 h-5 text-brand-600 shrink-0" />
                  <div>
                    <h3 className="font-bold text-slate-900 dark:text-white text-base">
                      What Should You Do?
                    </h3>
                    <p className="text-xs text-slate-500 dark:text-slate-400">
                      Concrete steps to protect your personal information and devices.
                    </p>
                  </div>
                </div>

                <div className="grid grid-cols-1 gap-2.5 pt-1">
                  {(urlScanResult.recommendations && urlScanResult.recommendations.length > 0
                    ? urlScanResult.recommendations
                    : urlScanResult.consumer_advice
                  ).map((rec: string, idx: number) => (
                    <div
                      key={idx}
                      className="p-3.5 rounded-xl border border-slate-200/70 dark:border-slate-800 bg-slate-50/50 dark:bg-slate-900/40 flex items-start gap-3"
                    >
                      <span className="w-6 h-6 rounded-full bg-brand-100 text-brand-700 dark:bg-brand-950 dark:text-brand-300 font-bold text-xs flex items-center justify-center shrink-0 mt-0.5">
                        {idx + 1}
                      </span>
                      <p className="text-sm text-slate-800 dark:text-slate-200 font-medium leading-relaxed">
                        {rec}
                      </p>
                    </div>
                  ))}
                </div>
              </div>

              {/* 4. What We Checked (Transparency Status Grid) */}
              {urlScanResult.checks && Object.keys(urlScanResult.checks).length > 0 && (
                <div className="consumer-card p-6 sm:p-7 space-y-4">
                  <div>
                    <h3 className="font-bold text-slate-900 dark:text-white text-base">
                      What We Checked
                    </h3>
                    <p className="text-xs text-slate-500 dark:text-slate-400">
                      Every scan performs multi-layer static, infrastructure, and intelligence checks.
                    </p>
                  </div>

                  <div className="grid grid-cols-1 md:grid-cols-2 gap-3 pt-1">
                    {Object.entries(urlScanResult.checks).map(([key, checkItem]: [string, any]) => {
                      const statusBadge = getCheckStatusBadge(checkItem.status);

                      return (
                        <div
                          key={key}
                          className="p-3.5 rounded-xl border border-slate-200/70 dark:border-slate-800 bg-white dark:bg-slate-900/50 space-y-1.5"
                        >
                          <div className="flex items-center justify-between gap-2">
                            <span className="font-bold text-xs sm:text-sm text-slate-900 dark:text-white">
                              {checkItem.name}
                            </span>
                            <span
                              className={cn(
                                "inline-flex items-center gap-1.5 px-2 py-0.5 rounded-md text-[10px] font-bold border",
                                statusBadge.classes
                              )}
                            >
                              {statusBadge.icon}
                              <span>{statusBadge.label}</span>
                            </span>
                          </div>
                          <p className="text-xs text-slate-600 dark:text-slate-400 leading-normal">
                            {checkItem.summary}
                          </p>
                        </div>
                      );
                    })}
                  </div>
                </div>
              )}

              {/* 5. Digital Trust & Security Certificate */}
              {urlScanResult.technical_evidence?.ssl_certificate && (
                <div className="consumer-card p-6 sm:p-7 space-y-4">
                  <div className="flex flex-col sm:flex-row sm:items-center justify-between gap-3">
                    <div className="flex items-start sm:items-center gap-2.5">
                      <div
                        className={cn(
                          "w-9 h-9 rounded-xl flex items-center justify-center shrink-0 mt-0.5 sm:mt-0",
                          urlScanResult.technical_evidence.ssl_certificate.has_ssl
                            ? urlScanResult.technical_evidence.ssl_certificate.chain_verified &&
                              !urlScanResult.technical_evidence.ssl_certificate.is_expired &&
                              !urlScanResult.technical_evidence.ssl_certificate.hostname_mismatch
                              ? "bg-emerald-50 text-emerald-600 dark:bg-emerald-950/40 dark:text-emerald-400 border border-emerald-200/60 dark:border-emerald-800/60"
                              : "bg-amber-50 text-amber-600 dark:bg-amber-950/40 dark:text-amber-400 border border-amber-200/60 dark:border-amber-800/60"
                            : "bg-rose-50 text-rose-600 dark:bg-rose-950/40 dark:text-rose-400 border border-rose-200/60 dark:border-rose-800/60"
                        )}
                      >
                        <Lock className="w-5 h-5" />
                      </div>
                      <div>
                        <h3 className="font-bold text-slate-900 dark:text-white text-base">
                          Digital Trust & TLS Certificate
                        </h3>
                        <p className="text-xs text-slate-600 dark:text-slate-400 font-medium">
                          {urlScanResult.technical_evidence.ssl_certificate.consumer_explanation ||
                            "Your connection to this website is encrypted, but this does not guarantee the website is legitimate."}
                        </p>
                      </div>
                    </div>

                    <button
                      type="button"
                      onClick={() => setShowCertificateDetails(!showCertificateDetails)}
                      className="inline-flex items-center gap-1.5 px-3 py-1.5 rounded-lg border border-slate-200 dark:border-slate-800 text-xs font-semibold text-slate-700 dark:text-slate-300 hover:bg-slate-50 dark:hover:bg-slate-800 transition-colors shrink-0 self-start sm:self-auto"
                    >
                      <span>{showCertificateDetails ? "Hide Certificate Details" : "View Certificate Details"}</span>
                      {showCertificateDetails ? (
                        <ChevronUp className="w-3.5 h-3.5" />
                      ) : (
                        <ChevronDown className="w-3.5 h-3.5" />
                      )}
                    </button>
                  </div>

                  {showCertificateDetails && (
                    <div className="pt-3 border-t border-slate-100 dark:border-slate-800 space-y-4 text-xs">
                      {/* Certificate Validity Grid */}
                      <div className="grid grid-cols-1 sm:grid-cols-2 lg:grid-cols-3 gap-3">
                        {/* Validity Status */}
                        <div className="p-3 rounded-xl bg-slate-50/80 dark:bg-slate-900/60 border border-slate-200/80 dark:border-slate-800 space-y-1">
                          <span className="text-[10px] font-bold uppercase tracking-wider text-slate-400 block">
                            Certificate Status
                          </span>
                          <div className="font-semibold text-slate-900 dark:text-white">
                            {urlScanResult.technical_evidence.ssl_certificate.validity_status || "UNKNOWN"}
                          </div>
                          <div className="text-[11px] text-slate-500">
                            {urlScanResult.technical_evidence.ssl_certificate.days_remaining != null
                              ? `${urlScanResult.technical_evidence.ssl_certificate.days_remaining} days remaining`
                              : "Validity duration unavailable"}
                          </div>
                        </div>

                        {/* Issuer & Authority */}
                        <div className="p-3 rounded-xl bg-slate-50/80 dark:bg-slate-900/60 border border-slate-200/80 dark:border-slate-800 space-y-1">
                          <span className="text-[10px] font-bold uppercase tracking-wider text-slate-400 block">
                            Certificate Authority
                          </span>
                          <div className="font-semibold text-slate-900 dark:text-white truncate">
                            {urlScanResult.technical_evidence.ssl_certificate.issuer_organization ||
                              urlScanResult.technical_evidence.ssl_certificate.issuer_common_name ||
                              "Standard CA"}
                          </div>
                          <div className="text-[11px] text-slate-500">
                            Chain: {urlScanResult.technical_evidence.ssl_certificate.chain_verified ? "Verified against trust roots" : "Unverified / Custom chain"}
                          </div>
                        </div>

                        {/* Cryptographic Key */}
                        <div className="p-3 rounded-xl bg-slate-50/80 dark:bg-slate-900/60 border border-slate-200/80 dark:border-slate-800 space-y-1">
                          <span className="text-[10px] font-bold uppercase tracking-wider text-slate-400 block">
                            Cryptographic Security
                          </span>
                          <div className="font-semibold text-slate-900 dark:text-white">
                            {urlScanResult.technical_evidence.ssl_certificate.public_key_algorithm || "RSA"} (
                            {urlScanResult.technical_evidence.ssl_certificate.public_key_size || 2048} bits)
                          </div>
                          <div className="text-[11px] text-slate-500">
                            Rating: {urlScanResult.technical_evidence.ssl_certificate.crypto_security_level || "STANDARD"}
                          </div>
                        </div>

                        {/* Hostname Match */}
                        <div className="p-3 rounded-xl bg-slate-50/80 dark:bg-slate-900/60 border border-slate-200/80 dark:border-slate-800 space-y-1">
                          <span className="text-[10px] font-bold uppercase tracking-wider text-slate-400 block">
                            Hostname Verification
                          </span>
                          <div className="font-semibold text-slate-900 dark:text-white">
                            {urlScanResult.technical_evidence.ssl_certificate.hostname_matches
                              ? "Matches Requested Host"
                              : urlScanResult.technical_evidence.ssl_certificate.hostname_mismatch
                              ? "Address Mismatch"
                              : "Not Verified"}
                          </div>
                          <div className="text-[11px] text-slate-500 truncate">
                            CN: {urlScanResult.technical_evidence.ssl_certificate.subject_common_name || "N/A"}
                          </div>
                        </div>

                        {/* Certificate Transparency */}
                        <div className="p-3 rounded-xl bg-slate-50/80 dark:bg-slate-900/60 border border-slate-200/80 dark:border-slate-800 space-y-1">
                          <span className="text-[10px] font-bold uppercase tracking-wider text-slate-400 block">
                            Certificate Transparency
                          </span>
                          <div className="font-semibold text-slate-900 dark:text-white">
                            {urlScanResult.technical_evidence.ssl_certificate.has_embedded_scts
                              ? `${urlScanResult.technical_evidence.ssl_certificate.embedded_scts_count} Embedded SCTs`
                              : "No Embedded SCTs"}
                          </div>
                          <div className="text-[11px] text-slate-500">
                            Audit log compliance (RFC 6962)
                          </div>
                        </div>

                        {/* Revocation Status */}
                        <div className="p-3 rounded-xl bg-slate-50/80 dark:bg-slate-900/60 border border-slate-200/80 dark:border-slate-800 space-y-1">
                          <span className="text-[10px] font-bold uppercase tracking-wider text-slate-400 block">
                            Revocation Status
                          </span>
                          <div className="font-semibold text-slate-900 dark:text-white">
                            {urlScanResult.technical_evidence.ssl_certificate.revocation_status || "UNVERIFIED"}
                          </div>
                          <div className="text-[11px] text-slate-500">
                            {urlScanResult.technical_evidence.ssl_certificate.revocation_message ||
                              "Revocation status could not be verified."}
                          </div>
                        </div>
                      </div>

                      {/* Subject Alternative Names (SANs) */}
                      {((urlScanResult.technical_evidence.ssl_certificate.subject_alt_names || []).length > 0) && (
                        <div className="p-3 rounded-xl bg-slate-50/80 dark:bg-slate-900/60 border border-slate-200/80 dark:border-slate-800 space-y-1">
                          <span className="text-[10px] font-bold uppercase tracking-wider text-slate-400 block">
                            Subject Alternative Names (SANs) - {urlScanResult.technical_evidence.ssl_certificate.subject_alt_names.length} addresses
                          </span>
                          <div className="font-mono text-[11px] text-slate-600 dark:text-slate-300 break-all leading-relaxed">
                            {urlScanResult.technical_evidence.ssl_certificate.subject_alt_names.slice(0, 10).join(", ")}
                            {urlScanResult.technical_evidence.ssl_certificate.subject_alt_names.length > 10 && " ... and more"}
                          </div>
                        </div>
                      )}
                    </div>
                  )}
                </div>
              )}

              {/* 5b. Website Security Assessment (Passive Hygiene & Defenses) */}
              {urlScanResult.technical_evidence?.website_security && (
                <div className="consumer-card p-5 sm:p-6 rounded-2xl border-slate-200 dark:border-slate-800 space-y-4">
                  <div className="flex flex-col sm:flex-row sm:items-center justify-between gap-3">
                    <div className="flex items-center gap-3">
                      <div className="p-2.5 rounded-xl bg-blue-50 dark:bg-blue-900/30 text-blue-600 dark:text-blue-400 border border-blue-200/50 dark:border-blue-800/50">
                        <ShieldCheck className="w-5 h-5" />
                      </div>
                      <div>
                        <div className="flex items-center gap-2">
                          <h3 className="font-bold text-slate-900 dark:text-white text-base">
                            Website Security & Configuration Hygiene
                          </h3>
                          <span
                            className={cn(
                              "text-xs font-bold px-2.5 py-0.5 rounded-full border font-mono",
                              ["A+", "A"].includes(urlScanResult.technical_evidence.website_security.grade)
                                ? "bg-emerald-500/10 text-emerald-600 dark:text-emerald-400 border-emerald-500/30"
                                : ["B", "C"].includes(urlScanResult.technical_evidence.website_security.grade)
                                ? "bg-amber-500/10 text-amber-600 dark:text-amber-400 border-amber-500/30"
                                : "bg-rose-500/10 text-rose-600 dark:text-rose-400 border-rose-500/30"
                            )}
                          >
                            Grade: {urlScanResult.technical_evidence.website_security.grade} ({urlScanResult.technical_evidence.website_security.score}/100)
                          </span>
                        </div>
                        <p className="text-xs text-slate-500 dark:text-slate-400 mt-0.5">
                          Safe passive assessment of HTTP security headers, transport encryption, and redirect paths
                        </p>
                      </div>
                    </div>

                    <button
                      type="button"
                      onClick={() => setShowWebsiteSecurityDetails(!showWebsiteSecurityDetails)}
                      className="inline-flex items-center justify-center gap-1.5 px-3 py-1.5 rounded-xl text-xs font-medium bg-slate-100 hover:bg-slate-200 dark:bg-slate-800 dark:hover:bg-slate-700 text-slate-700 dark:text-slate-200 transition-colors self-start sm:self-auto"
                    >
                      <span>{showWebsiteSecurityDetails ? "Hide Technical Details" : "View Full Security Details"}</span>
                      {showWebsiteSecurityDetails ? (
                        <ChevronUp className="w-3.5 h-3.5" />
                      ) : (
                        <ChevronDown className="w-3.5 h-3.5" />
                      )}
                    </button>
                  </div>

                  {/* Consumer explanation & distinction banner */}
                  <div className="p-3.5 rounded-xl bg-slate-50/80 dark:bg-slate-900/60 border border-slate-200/80 dark:border-slate-800 flex items-start gap-3">
                    <Info className="w-4 h-4 text-blue-500 shrink-0 mt-0.5" />
                    <div className="text-xs text-slate-600 dark:text-slate-300 leading-relaxed">
                      <strong className="text-slate-900 dark:text-white font-medium block mb-0.5">
                        Understanding Security Hygiene vs. Scam Detection:
                      </strong>
                      {urlScanResult.technical_evidence.website_security.consumer_explanation}
                    </div>
                  </div>

                  {/* Summary Metric Badges */}
                  <div className="grid grid-cols-2 sm:grid-cols-4 gap-2.5">
                    <div className="p-3 rounded-xl bg-slate-50/60 dark:bg-slate-900/40 border border-slate-200/60 dark:border-slate-800/80">
                      <div className="text-[10px] uppercase font-bold tracking-wider text-slate-400">Transport</div>
                      <div className="text-xs font-semibold text-slate-900 dark:text-white mt-1 flex items-center gap-1.5">
                        <Lock className={cn("w-3.5 h-3.5", urlScanResult.technical_evidence.website_security.transport_security?.is_https ? "text-emerald-500" : "text-rose-500")} />
                        {urlScanResult.technical_evidence.website_security.transport_security?.is_https ? "HTTPS Secure" : "Insecure HTTP"}
                      </div>
                    </div>

                    <div className="p-3 rounded-xl bg-slate-50/60 dark:bg-slate-900/40 border border-slate-200/60 dark:border-slate-800/80">
                      <div className="text-[10px] uppercase font-bold tracking-wider text-slate-400">Security Headers</div>
                      <div className="text-xs font-semibold text-slate-900 dark:text-white mt-1">
                        {urlScanResult.technical_evidence.website_security.security_headers?.configured_count || 0} / {urlScanResult.technical_evidence.website_security.security_headers?.total_evaluated || 5} Configured
                      </div>
                    </div>

                    <div className="p-3 rounded-xl bg-slate-50/60 dark:bg-slate-900/40 border border-slate-200/60 dark:border-slate-800/80">
                      <div className="text-[10px] uppercase font-bold tracking-wider text-slate-400">Redirect Hops</div>
                      <div className="text-xs font-semibold text-slate-900 dark:text-white mt-1">
                        {urlScanResult.technical_evidence.website_security.redirect_analysis?.has_redirects
                          ? `${urlScanResult.technical_evidence.website_security.redirect_analysis.redirect_count} Hop(s)`
                          : "Direct (0 Hops)"}
                      </div>
                    </div>

                    <div className="p-3 rounded-xl bg-slate-50/60 dark:bg-slate-900/40 border border-slate-200/60 dark:border-slate-800/80">
                      <div className="text-[10px] uppercase font-bold tracking-wider text-slate-400">Mixed Content</div>
                      <div className={cn(
                        "text-xs font-semibold mt-1",
                        urlScanResult.technical_evidence.website_security.mixed_content?.detected ? "text-rose-600 dark:text-rose-400" : "text-emerald-600 dark:text-emerald-400"
                      )}>
                        {urlScanResult.technical_evidence.website_security.mixed_content?.detected ? "Detected (Insecure)" : "None Detected"}
                      </div>
                    </div>
                  </div>

                  {/* Expandable Technical Details */}
                  {showWebsiteSecurityDetails && (
                    <div className="pt-3 border-t border-slate-200 dark:border-slate-800 space-y-4">
                      {/* Security Headers Breakdown */}
                      {urlScanResult.technical_evidence.website_security.security_headers?.headers && (
                        <div>
                          <h4 className="text-xs font-bold uppercase tracking-wider text-slate-500 dark:text-slate-400 mb-2.5">
                            HTTP Security Headers Audit
                          </h4>
                          <div className="grid grid-cols-1 md:grid-cols-2 gap-2">
                            {Object.entries(urlScanResult.technical_evidence.website_security.security_headers.headers).map(
                              ([key, header]: [string, any]) => (
                                <div
                                  key={key}
                                  className="p-3 rounded-xl bg-slate-50/80 dark:bg-slate-900/60 border border-slate-200/80 dark:border-slate-800 text-xs space-y-1"
                                >
                                  <div className="flex items-center justify-between">
                                    <span className="font-mono font-semibold text-slate-900 dark:text-white">
                                      {header.standard_header}
                                    </span>
                                    <span
                                      className={cn(
                                        "text-[10px] font-bold px-2 py-0.5 rounded-full border",
                                        header.is_present
                                          ? "bg-emerald-500/10 text-emerald-600 dark:text-emerald-400 border-emerald-500/20"
                                          : "bg-rose-500/10 text-rose-600 dark:text-rose-400 border-rose-500/20"
                                      )}
                                    >
                                      {header.is_present ? "CONFIGURED" : "MISSING"}
                                    </span>
                                  </div>
                                  <p className="text-[11px] text-slate-500 dark:text-slate-400">
                                    {header.description}
                                  </p>
                                  {header.is_present && header.raw_value && (
                                    <div className="font-mono text-[10px] bg-slate-100 dark:bg-slate-800/80 p-1.5 rounded text-slate-700 dark:text-slate-300 truncate">
                                      {header.raw_value}
                                    </div>
                                  )}
                                  {!header.is_present && header.recommended_directive && (
                                    <div className="text-[10px] text-slate-400">
                                      Recommended: <code className="font-mono text-slate-600 dark:text-slate-300">{header.recommended_directive}</code>
                                    </div>
                                  )}
                                </div>
                              )
                            )}
                          </div>
                        </div>
                      )}

                      {/* Redirect Path Trace */}
                      {urlScanResult.technical_evidence.website_security.redirect_analysis?.has_redirects && (
                        <div>
                          <h4 className="text-xs font-bold uppercase tracking-wider text-slate-500 dark:text-slate-400 mb-2">
                            Redirect Chain Audit ({urlScanResult.technical_evidence.website_security.redirect_analysis.redirect_count} Hops)
                          </h4>
                          <div className="space-y-1.5 p-3 rounded-xl bg-slate-50/80 dark:bg-slate-900/60 border border-slate-200/80 dark:border-slate-800 font-mono text-[11px]">
                            {urlScanResult.technical_evidence.website_security.redirect_analysis.hops?.map((hop: any, idx: number) => (
                              <div key={idx} className="flex items-center gap-2 text-slate-700 dark:text-slate-300 flex-wrap">
                                <span className="font-bold text-slate-400">#{hop.hop_index}</span>
                                <span className="px-1.5 py-0.5 rounded bg-slate-200 dark:bg-slate-800 text-[10px] font-semibold">
                                  {hop.status_code}
                                </span>
                                <span className="truncate max-w-xs">{hop.from_url}</span>
                                <ArrowRight className="w-3 h-3 text-slate-400 shrink-0" />
                                <span className="truncate max-w-xs text-blue-600 dark:text-blue-400">{hop.to_url}</span>
                                {hop.is_cross_domain && (
                                  <span className="text-[9px] px-1.5 py-0.2 rounded bg-amber-500/10 text-amber-600 border border-amber-500/20">
                                    Cross-Domain
                                  </span>
                                )}
                                {hop.is_downgrade && (
                                  <span className="text-[9px] px-1.5 py-0.2 rounded bg-rose-500/10 text-rose-600 border border-rose-500/20 font-bold">
                                    Downgrade to HTTP
                                  </span>
                                )}
                              </div>
                            ))}
                            <div className="pt-1 text-[11px] text-slate-500">
                              Final Destination: <span className="text-slate-900 dark:text-white font-semibold">{urlScanResult.technical_evidence.website_security.redirect_analysis.final_destination}</span>
                            </div>
                          </div>
                        </div>
                      )}

                      {/* Disclosed Software & Banners */}
                      {(urlScanResult.technical_evidence.website_security.software_exposure?.server_banner ||
                        urlScanResult.technical_evidence.website_security.software_exposure?.x_powered_by ||
                        urlScanResult.technical_evidence.website_security.software_exposure?.meta_generator) && (
                        <div>
                          <h4 className="text-xs font-bold uppercase tracking-wider text-slate-500 dark:text-slate-400 mb-2">
                            Server & Software Headers
                          </h4>
                          <div className="p-3 rounded-xl bg-slate-50/80 dark:bg-slate-900/60 border border-slate-200/80 dark:border-slate-800 text-xs space-y-1">
                            {urlScanResult.technical_evidence.website_security.software_exposure.server_banner && (
                              <div className="flex items-center gap-2">
                                <span className="text-slate-400 font-mono text-[11px]">Server:</span>
                                <code className="font-mono text-slate-700 dark:text-slate-300 font-semibold">{urlScanResult.technical_evidence.website_security.software_exposure.server_banner}</code>
                              </div>
                            )}
                            {urlScanResult.technical_evidence.website_security.software_exposure.x_powered_by && (
                              <div className="flex items-center gap-2">
                                <span className="text-slate-400 font-mono text-[11px]">X-Powered-By:</span>
                                <code className="font-mono text-slate-700 dark:text-slate-300 font-semibold">{urlScanResult.technical_evidence.website_security.software_exposure.x_powered_by}</code>
                              </div>
                            )}
                            {urlScanResult.technical_evidence.website_security.software_exposure.meta_generator && (
                              <div className="flex items-center gap-2">
                                <span className="text-slate-400 font-mono text-[11px]">Meta Generator:</span>
                                <code className="font-mono text-slate-700 dark:text-slate-300 font-semibold">{urlScanResult.technical_evidence.website_security.software_exposure.meta_generator}</code>
                              </div>
                            )}
                          </div>
                        </div>
                      )}

                      {/* Technical Findings List (Expandable items) */}
                      {((urlScanResult.technical_evidence.website_security.findings || []).length > 0) && (
                        <div>
                          <h4 className="text-xs font-bold uppercase tracking-wider text-slate-500 dark:text-slate-400 mb-2.5">
                            Specific Findings & Hardening Recommendations ({urlScanResult.technical_evidence.website_security.findings.length})
                          </h4>
                          <div className="space-y-2">
                            {urlScanResult.technical_evidence.website_security.findings.map((f: any) => {
                              const isExpanded = !!expandedSecurityFindings[f.id];
                              return (
                                <div
                                  key={f.id}
                                  className="rounded-xl border border-slate-200 dark:border-slate-800 overflow-hidden bg-white dark:bg-slate-900/70"
                                >
                                  <button
                                    type="button"
                                    onClick={() => toggleSecurityFinding(f.id)}
                                    className="w-full p-3 flex items-center justify-between text-left hover:bg-slate-50 dark:hover:bg-slate-800/50 transition-colors"
                                  >
                                    <div className="flex items-center gap-2.5">
                                      <span
                                        className={cn(
                                          "text-[10px] font-bold px-2 py-0.5 rounded-full border font-mono uppercase",
                                          f.severity === "CRITICAL"
                                            ? "bg-rose-500/15 text-rose-600 dark:text-rose-400 border-rose-500/30"
                                            : f.severity === "HIGH"
                                            ? "bg-orange-500/15 text-orange-600 dark:text-orange-400 border-orange-500/30"
                                            : f.severity === "MEDIUM"
                                            ? "bg-amber-500/15 text-amber-600 dark:text-amber-400 border-amber-500/30"
                                            : "bg-blue-500/15 text-blue-600 dark:text-blue-400 border-blue-500/30"
                                        )}
                                      >
                                        {f.severity}
                                      </span>
                                      <span className="text-xs font-semibold text-slate-900 dark:text-white">
                                        {f.title}
                                      </span>
                                    </div>
                                    {isExpanded ? (
                                      <ChevronUp className="w-4 h-4 text-slate-400 shrink-0" />
                                    ) : (
                                      <ChevronDown className="w-4 h-4 text-slate-400 shrink-0" />
                                    )}
                                  </button>

                                  {isExpanded && (
                                    <div className="p-3.5 bg-slate-50/60 dark:bg-slate-900/40 border-t border-slate-200 dark:border-slate-800 space-y-2.5 text-xs">
                                      <div>
                                        <span className="font-bold text-[10px] uppercase tracking-wider text-slate-400 block mb-0.5">
                                          Technical Evidence
                                        </span>
                                        <div className="font-mono text-[11px] text-slate-700 dark:text-slate-300 bg-slate-100 dark:bg-slate-800 p-2 rounded break-all whitespace-pre-wrap">
                                          {typeof f.technical_evidence === "object"
                                            ? JSON.stringify(f.technical_evidence, null, 2)
                                            : String(f.technical_evidence)}
                                        </div>
                                      </div>

                                      <div>
                                        <span className="font-bold text-[10px] uppercase tracking-wider text-slate-400 block mb-0.5">
                                          Potential Impact
                                        </span>
                                        <div className="text-slate-600 dark:text-slate-300">
                                          {f.potential_impact}
                                        </div>
                                      </div>

                                      <div>
                                        <span className="font-bold text-[10px] uppercase tracking-wider text-slate-400 block mb-0.5">
                                          Recommended Remediation
                                        </span>
                                        <div className="text-emerald-700 dark:text-emerald-400 font-mono text-[11px] bg-emerald-500/5 p-2 rounded border border-emerald-500/20">
                                          {f.recommended_remediation}
                                        </div>
                                      </div>

                                      <div>
                                        <span className="font-bold text-[10px] uppercase tracking-wider text-slate-400 block mb-0.5">
                                          Assessment Limitations
                                        </span>
                                        <div className="text-[11px] text-slate-500 italic">
                                          {f.limitations}
                                        </div>
                                      </div>
                                    </div>
                                  )}
                                </div>
                              );
                            })}
                          </div>
                        </div>
                      )}
                    </div>
                  )}
                </div>
              )}

              {/* 5c. Tamper-Evident Report Verification (Blockchain Threat Registry) */}
              {urlScanResult.technical_evidence?.blockchain_registration && (
                <div className="consumer-card p-5 sm:p-6 rounded-2xl border-slate-200 dark:border-slate-800 space-y-4">
                  <div className="flex flex-col sm:flex-row sm:items-center justify-between gap-3">
                    <div className="flex items-center gap-3">
                      <div className="p-2.5 rounded-xl bg-purple-50 dark:bg-purple-900/30 text-purple-600 dark:text-purple-400 border border-purple-200/50 dark:border-purple-800/50">
                        <FileCheck2 className="w-5 h-5" />
                      </div>
                      <div>
                        <div className="flex items-center gap-2">
                          <h3 className="font-bold text-slate-900 dark:text-white text-base">
                            Verify This Report
                          </h3>
                          <span
                            className={cn(
                              "text-[10px] font-bold px-2 py-0.5 rounded-full border font-mono uppercase",
                              urlScanResult.technical_evidence.blockchain_registration.status === "CONFIRMED"
                                ? "bg-emerald-500/10 text-emerald-600 dark:text-emerald-400 border-emerald-500/20"
                                : urlScanResult.technical_evidence.blockchain_registration.status === "DUPLICATE"
                                ? "bg-blue-500/10 text-blue-600 dark:text-blue-400 border-blue-500/20"
                                : "bg-slate-500/10 text-slate-600 dark:text-slate-400 border-slate-500/20"
                            )}
                          >
                            {urlScanResult.technical_evidence.blockchain_registration.status === "CONFIRMED"
                              ? "IMMUTABLE AUDIT SEAL"
                              : urlScanResult.technical_evidence.blockchain_registration.status === "DUPLICATE"
                              ? "PREVIOUSLY REGISTERED"
                              : "CANONICAL COMMITMENT READY"}
                          </span>
                        </div>
                        <p className="text-xs text-slate-500 dark:text-slate-400 mt-0.5">
                          Cryptographic proof of investigation authenticity and tamper-evident audit trail
                        </p>
                      </div>
                    </div>

                    <div className="flex flex-wrap items-center gap-2 self-start sm:self-auto">
                      {urlScanResult.technical_evidence.blockchain_registration.commitment_hash && (
                        <button
                          type="button"
                          disabled={isVerifyingOnChain}
                          onClick={() =>
                            handleVerifyOnChain(
                              urlScanResult.technical_evidence.blockchain_registration.report_id ||
                                `scan-${urlScanResult.technical_evidence.evidence_hash.slice(0, 16)}`,
                              urlScanResult.technical_evidence.blockchain_registration.commitment_hash
                            )
                          }
                          className="inline-flex items-center justify-center gap-1.5 px-3 py-1.5 rounded-xl text-xs font-semibold bg-purple-600 hover:bg-purple-700 text-white transition-colors disabled:opacity-60 shadow-sm"
                        >
                          {isVerifyingOnChain ? (
                            <>
                              <RotateCcw className="w-3.5 h-3.5 animate-spin" />
                              <span>Verifying On-Chain...</span>
                            </>
                          ) : (
                            <>
                              <ShieldCheck className="w-3.5 h-3.5" />
                              <span>Verify On-Chain Integrity</span>
                            </>
                          )}
                        </button>
                      )}

                      <button
                        type="button"
                        onClick={handleDownloadExport}
                        className="inline-flex items-center justify-center gap-1.5 px-3 py-1.5 rounded-xl text-xs font-semibold bg-slate-100 hover:bg-slate-200 dark:bg-slate-800 dark:hover:bg-slate-700 text-slate-700 dark:text-slate-300 transition-colors shadow-sm border border-slate-200 dark:border-slate-700"
                        title="Download canonical verifiable certificate JSON for offline or external audits"
                      >
                        <Download className="w-3.5 h-3.5 text-slate-500" />
                        <span>Export Certificate (.json)</span>
                      </button>

                      <a
                        href="/verify"
                        target="_blank"
                        rel="noopener noreferrer"
                        className="inline-flex items-center justify-center gap-1.5 px-3 py-1.5 rounded-xl text-xs font-semibold bg-indigo-50 hover:bg-indigo-100 dark:bg-indigo-950/50 dark:hover:bg-indigo-900/50 text-indigo-700 dark:text-indigo-300 transition-colors shadow-sm border border-indigo-200/60 dark:border-indigo-800/60"
                        title="Open independent browser verifier that queries EVM nodes directly without AstraNexus backend"
                      >
                        <ExternalLink className="w-3.5 h-3.5 text-indigo-500" />
                        <span>Standalone Verifier</span>
                      </a>
                    </div>
                  </div>

                  {/* Verification Results Banner if queried */}
                  {liveVerificationResult && (
                    <div
                      className={cn(
                        "p-3.5 rounded-xl border text-xs space-y-1.5",
                        liveVerificationResult.is_verified
                          ? "bg-emerald-50/80 dark:bg-emerald-950/40 border-emerald-200 dark:border-emerald-800/60 text-emerald-900 dark:text-emerald-200"
                          : "bg-rose-50/80 dark:bg-rose-950/40 border-rose-200 dark:border-rose-800/60 text-rose-900 dark:text-rose-200"
                      )}
                    >
                      <div className="flex items-center gap-2 font-bold">
                        {liveVerificationResult.is_verified ? (
                          <CheckCircle2 className="w-4 h-4 text-emerald-600 dark:text-emerald-400 shrink-0" />
                        ) : (
                          <AlertTriangle className="w-4 h-4 text-rose-600 dark:text-rose-400 shrink-0" />
                        )}
                        <span>
                          {liveVerificationResult.is_verified
                            ? "On-Chain Audit Verified: Cryptographic Commitment Matches Live Ledger Exactly"
                            : "Integrity Warning: On-Chain Commitment Mismatch or Unregistered Report"}
                        </span>
                      </div>
                      <div className="font-mono text-[11px] opacity-90">
                        Status: <strong>{liveVerificationResult.status}</strong>
                        {liveVerificationResult.network && ` | Network: ${liveVerificationResult.network}`}
                        {liveVerificationResult.attestation_status && ` | Attestation: ${liveVerificationResult.attestation_status}`}
                        {liveVerificationResult.initial_timestamp && ` | Block Timestamp: ${new Date(liveVerificationResult.initial_timestamp * 1000).toLocaleString()}`}
                      </div>
                    </div>
                  )}

                  {/* Audit Metadata Grid */}
                  <div className="grid grid-cols-1 sm:grid-cols-2 lg:grid-cols-4 gap-3 text-xs">
                    <div className="p-3 rounded-xl bg-slate-50/80 dark:bg-slate-900/60 border border-slate-200/80 dark:border-slate-800">
                      <span className="text-[10px] uppercase font-bold text-slate-400 block tracking-wider">
                        Registration Status
                      </span>
                      <span className="font-bold text-slate-800 dark:text-slate-200 mt-1 block">
                        {urlScanResult.technical_evidence.blockchain_registration.status}
                      </span>
                      <span className="text-[11px] text-slate-500 block truncate mt-0.5">
                        {urlScanResult.technical_evidence.blockchain_registration.message || "Recorded in local ledger"}
                      </span>
                    </div>

                    <div className="p-3 rounded-xl bg-slate-50/80 dark:bg-slate-900/60 border border-slate-200/80 dark:border-slate-800">
                      <span className="text-[10px] uppercase font-bold text-slate-400 block tracking-wider">
                        Ledger Network
                      </span>
                      <span className="font-bold text-slate-800 dark:text-slate-200 mt-1 block">
                        {urlScanResult.technical_evidence.blockchain_registration.network || "EVM Localnet (Chain 31337)"}
                      </span>
                      <span className="text-[11px] text-slate-500 block truncate mt-0.5">
                        Block #{urlScanResult.technical_evidence.blockchain_registration.block_number ?? "Mined"}
                      </span>
                    </div>

                    <div className="p-3 rounded-xl bg-slate-50/80 dark:bg-slate-900/60 border border-slate-200/80 dark:border-slate-800">
                      <span className="text-[10px] uppercase font-bold text-slate-400 block tracking-wider">
                        Investigation Timestamp
                      </span>
                      <span className="font-bold text-slate-800 dark:text-slate-200 mt-1 block">
                        {new Date(urlScanResult.scanned_at || Date.now()).toLocaleDateString()}
                      </span>
                      <span className="text-[11px] text-slate-500 block truncate mt-0.5">
                        {new Date(urlScanResult.scanned_at || Date.now()).toLocaleTimeString()} UTC
                      </span>
                    </div>

                    <div className="p-3 rounded-xl bg-slate-50/80 dark:bg-slate-900/60 border border-slate-200/80 dark:border-slate-800">
                      <span className="text-[10px] uppercase font-bold text-slate-400 block tracking-wider">
                        Verification Status
                      </span>
                      <span className="font-bold text-emerald-600 dark:text-emerald-400 mt-1 flex items-center gap-1">
                        <CheckCircle2 className="w-3.5 h-3.5 shrink-0" />
                        {urlScanResult.technical_evidence.blockchain_registration.is_registered
                          ? "On-Chain Verified"
                          : "Audit Ready"}
                      </span>
                      <span className="text-[11px] text-slate-500 block truncate mt-0.5">
                        Tamper-Evident Standard
                      </span>
                    </div>
                  </div>

                  {/* Cryptographic Hashes & Tx Reference */}
                  <div className="space-y-2 pt-1 font-mono text-[11px]">
                    {urlScanResult.technical_evidence.blockchain_registration.tx_hash && (
                      <div className="p-2.5 rounded-lg bg-slate-100 dark:bg-slate-900 border border-slate-200 dark:border-slate-800 flex items-center justify-between gap-2">
                        <div className="truncate">
                          <span className="text-slate-400 mr-2 font-sans text-xs">Transaction Reference:</span>
                          <span className="text-slate-800 dark:text-slate-200 font-semibold select-all">
                            {urlScanResult.technical_evidence.blockchain_registration.tx_hash}
                          </span>
                        </div>
                        <button
                          type="button"
                          onClick={() => {
                            if (typeof navigator !== "undefined") {
                              navigator.clipboard.writeText(urlScanResult.technical_evidence.blockchain_registration.tx_hash);
                              setCopiedTxHash(true);
                              setTimeout(() => setCopiedTxHash(false), 2000);
                            }
                          }}
                          className="px-2 py-1 rounded bg-white dark:bg-slate-800 border border-slate-200 dark:border-slate-700 text-[10px] shrink-0 font-sans flex items-center gap-1 hover:bg-slate-50 dark:hover:bg-slate-700 transition-colors"
                        >
                          {copiedTxHash ? <Check className="w-3 h-3 text-emerald-500" /> : <Copy className="w-3 h-3" />}
                          <span>{copiedTxHash ? "Copied" : "Copy"}</span>
                        </button>
                      </div>
                    )}

                    {urlScanResult.technical_evidence.blockchain_registration.commitment_hash && (
                      <div className="p-2.5 rounded-lg bg-slate-100 dark:bg-slate-900 border border-slate-200 dark:border-slate-800 flex items-center justify-between gap-2">
                        <div className="truncate">
                          <span className="text-slate-400 mr-2 font-sans text-xs">Report Commitment:</span>
                          <span className="text-purple-600 dark:text-purple-400 font-semibold select-all">
                            {urlScanResult.technical_evidence.blockchain_registration.commitment_hash}
                          </span>
                        </div>
                        <span className="text-[10px] text-slate-400 font-sans shrink-0 hidden sm:inline">
                          Salted Keccak-256
                        </span>
                      </div>
                    )}
                  </div>
                </div>
              )}

              {/* 6. Optional Technical Details & Cryptographic Notary (Expandable for IT & Verification) */}
              <div className="consumer-card rounded-2xl overflow-hidden border-slate-200 dark:border-slate-800">
                <button
                  type="button"
                  onClick={() => setShowTechnicalEvidence(!showTechnicalEvidence)}
                  className="w-full p-4 sm:p-5 flex items-center justify-between text-left hover:bg-slate-50 dark:hover:bg-slate-800/40 transition-colors"
                >
                  <div className="flex items-center gap-2">
                    <Server className="w-4 h-4 text-slate-500" />
                    <span className="text-xs sm:text-sm font-bold text-slate-900 dark:text-white">
                      Technical Forensic Telemetry & Cryptographic Seal
                    </span>
                    <span className="text-[10px] text-slate-400 font-mono hidden sm:inline">
                      (For IT & Security Verification)
                    </span>
                  </div>
                  {showTechnicalEvidence ? (
                    <ChevronUp className="w-5 h-5 text-slate-400" />
                  ) : (
                    <ChevronDown className="w-5 h-5 text-slate-400" />
                  )}
                </button>

                {showTechnicalEvidence && (
                  <div className="p-5 border-t border-slate-100 dark:border-slate-800 bg-slate-50/50 dark:bg-slate-950/50 space-y-5 text-xs font-mono">
                    {/* Cryptographic SHA-256 Seal */}
                    <div className="p-3.5 rounded-xl bg-white dark:bg-slate-900 border border-slate-200 dark:border-slate-800 flex flex-col sm:flex-row sm:items-center justify-between gap-2">
                      <div className="space-y-0.5">
                        <span className="text-[10px] text-slate-400 font-bold uppercase">
                          Tamper-Proof Evidence Seal (SHA-256)
                        </span>
                        <div className="text-brand-600 dark:text-brand-400 truncate max-w-sm sm:max-w-md">
                          {urlScanResult.technical_evidence.evidence_hash}
                        </div>
                      </div>
                      <button
                        type="button"
                        onClick={() => handleCopyHash(urlScanResult.technical_evidence.evidence_hash)}
                        className="inline-flex items-center gap-1.5 px-2.5 py-1.5 rounded-lg border border-slate-200 hover:bg-slate-100 dark:border-slate-700 dark:hover:bg-slate-800 shrink-0 font-sans text-xs"
                      >
                        {copiedHash ? <Check className="w-3.5 h-3.5 text-emerald-600" /> : <Copy className="w-3.5 h-3.5" />}
                        <span>{copiedHash ? "Copied" : "Copy Hash"}</span>
                      </button>
                    </div>

                    {/* Telemetry Breakdown */}
                    <div className="grid grid-cols-1 sm:grid-cols-2 gap-4">
                      {/* DNS */}
                      <div className="p-3 rounded-xl bg-white dark:bg-slate-900 border border-slate-200 dark:border-slate-800 space-y-1">
                        <strong className="text-slate-800 dark:text-slate-200 block font-sans">
                          DNS Records
                        </strong>
                        <div className="text-slate-600 dark:text-slate-400">
                          IPs: {urlScanResult.technical_evidence.dns_records?.a_records?.join(", ") || "None / Unresolvable"}
                        </div>
                        <div className="text-slate-600 dark:text-slate-400">
                          MX Mail: {urlScanResult.technical_evidence.dns_records?.has_mx ? "Configured" : "None"}
                        </div>
                        <div className="text-slate-600 dark:text-slate-400">
                          Latency: {urlScanResult.technical_evidence.dns_records?.resolution_time_ms ?? "N/A"} ms
                        </div>
                      </div>

                      {/* SSL */}
                      <div className="p-3 rounded-xl bg-white dark:bg-slate-900 border border-slate-200 dark:border-slate-800 space-y-1">
                        <strong className="text-slate-800 dark:text-slate-200 block font-sans">
                          TLS Certificate
                        </strong>
                        <div className="text-slate-600 dark:text-slate-400">
                          Issuer: {urlScanResult.technical_evidence.ssl_certificate?.issuer_organization || "None"}
                        </div>
                        <div className="text-slate-600 dark:text-slate-400">
                          Self-Signed: {urlScanResult.technical_evidence.ssl_certificate?.is_self_signed ? "Yes (Untrusted)" : "No"}
                        </div>
                        <div className="text-slate-600 dark:text-slate-400">
                          Days Left: {urlScanResult.technical_evidence.ssl_certificate?.days_remaining ?? "N/A"}
                        </div>
                      </div>
                    </div>

                    {/* Evidence Timeline */}
                    <div className="space-y-1.5">
                      <strong className="text-slate-800 dark:text-slate-200 block font-sans">
                        Chronological Forensic Audit Steps
                      </strong>
                      <div className="space-y-1">
                        {urlScanResult.technical_evidence.evidence_timeline.map((step: any, sIdx: number) => (
                          <div
                            key={sIdx}
                            className="p-2 rounded bg-white dark:bg-slate-900 border border-slate-200/80 dark:border-slate-800 flex items-center justify-between text-[11px]"
                          >
                            <span className="font-semibold text-slate-700 dark:text-slate-300">
                              {step.phase}: <span className="font-normal text-slate-500">{step.detail}</span>
                            </span>
                            <span
                              className={cn(
                                "px-1.5 py-0.5 rounded text-[10px] font-bold uppercase shrink-0 ml-2",
                                step.status === "pass"
                                  ? "text-emerald-700 bg-emerald-50 dark:bg-emerald-950 dark:text-emerald-300"
                                  : step.status === "warn"
                                  ? "text-amber-700 bg-amber-50 dark:bg-amber-950 dark:text-amber-300"
                                  : "text-rose-700 bg-rose-50 dark:bg-rose-950 dark:text-rose-300"
                              )}
                            >
                              {step.status}
                            </span>
                          </div>
                        ))}
                      </div>
                    </div>
                  </div>
                )}
              </div>
            </div>
          )}
        </div>
      )}

      {/* ========================================================================= */}
      {/* TAB 2: MESSAGE ANALYZER */}
      {/* ========================================================================= */}
      {activeTab === "message" && (
        <div className="space-y-6">
          {/* Message Input Form */}
          <div className="consumer-card p-6 sm:p-7 space-y-4">
            <label className="block text-sm font-semibold text-slate-900 dark:text-white">
              Paste Suspicious Message (SMS, WhatsApp, Email, Job Offer, Bank Alert)
            </label>
            <form
              onSubmit={(e) => {
                e.preventDefault();
                performMessageAnalysis(messageText);
              }}
              className="space-y-3"
            >
              <textarea
                rows={4}
                value={messageText}
                onChange={(e) => setMessageText(e.target.value)}
                placeholder="Paste the suspicious text here (e.g. 'URGENT: Your bank account is locked. Pay $1.85 redelivery fee...')"
                className="w-full p-4 rounded-xl bg-slate-50 border border-slate-200 text-sm text-slate-900 placeholder-slate-400 focus:outline-none focus:ring-2 focus:ring-purple-500 focus:bg-white dark:bg-slate-900 dark:border-slate-700 dark:text-white dark:placeholder-slate-500 resize-none leading-relaxed"
              />
              <button
                type="submit"
                disabled={isMessageAnalyzing || !messageText.trim()}
                className="w-full sm:w-auto inline-flex items-center justify-center gap-2 px-6 py-3 rounded-xl bg-purple-600 text-white font-semibold text-sm hover:bg-purple-700 disabled:opacity-50 transition-colors shadow-sm min-h-[44px]"
              >
                {isMessageAnalyzing ? (
                  <>
                    <span className="w-4 h-4 border-2 border-white/30 border-t-white rounded-full animate-spin" />
                    <span>Analyzing Message Tactics...</span>
                  </>
                ) : (
                  <>
                    <MessageSquareWarning className="w-4 h-4" />
                    <span>Analyze Message</span>
                  </>
                )}
              </button>
            </form>

            {/* Presets */}
            <div className="flex flex-wrap items-center gap-2 text-xs text-slate-500 pt-1">
              <span>Try checking:</span>
              <button
                type="button"
                onClick={() => {
                  const sample = "USPS: Your package could not be delivered due to missing house number. Please update here: http://usps-parcel-redelivery.info/track";
                  setMessageText(sample);
                  performMessageAnalysis(sample);
                }}
                className="px-2.5 py-1 rounded-lg border border-slate-200 hover:border-purple-500 hover:text-purple-600 dark:border-slate-700 dark:hover:text-purple-400 transition-colors"
              >
                Delivery Scam
              </button>
              <button
                type="button"
                onClick={() => {
                  const sample = "URGENT from Chase Bank: A transaction of $842.19 was made from your account. If this was not you, call 1-800-FAKE immediately or verify at http://chase-auth-service.com/login";
                  setMessageText(sample);
                  performMessageAnalysis(sample);
                }}
                className="px-2.5 py-1 rounded-lg border border-slate-200 hover:border-purple-500 hover:text-purple-600 dark:border-slate-700 dark:hover:text-purple-400 transition-colors"
              >
                Bank Urgent Alert
              </button>
            </div>
          </div>

          {/* Message Progress */}
          {isMessageAnalyzing && (
            <div className="consumer-card p-6 border-purple-200 dark:border-purple-900/60 bg-purple-50/40 dark:bg-purple-950/30 space-y-3 text-center">
              <div className="w-10 h-10 rounded-full border-3 border-purple-500 border-t-transparent animate-spin mx-auto" />
              <div className="space-y-1">
                <h3 className="font-bold text-slate-900 dark:text-white text-base">
                  Analyzing Psychological & Social Engineering Tactics
                </h3>
                <p className="text-xs text-purple-700 dark:text-purple-300 font-medium">
                  Scanning for false urgency, authority impersonation, payment pressure, and deceptive links...
                </p>
              </div>
            </div>
          )}

          {/* Message Error */}
          {messageError && (
            <div className="consumer-card p-5 border-rose-200 bg-rose-50 text-rose-800 dark:bg-rose-950/40 dark:border-rose-900 dark:text-rose-200 flex items-start gap-3">
              <AlertCircle className="w-5 h-5 text-rose-600 shrink-0 mt-0.5" />
              <div className="space-y-1 text-sm">
                <strong className="block font-semibold">Analysis Failed</strong>
                <p className="text-xs leading-relaxed">{messageError}</p>
              </div>
            </div>
          )}

          {/* Message Results */}
          {messageResult && !isMessageAnalyzing && (
            <div className="space-y-6">
              {/* Verdict Header */}
              <div
                className={cn(
                  "consumer-card p-6 sm:p-7 border-l-8 space-y-4",
                  messageResult.verdict === "LIKELY_SCAM"
                    ? "border-l-rose-500 bg-rose-50/30 dark:bg-rose-950/20"
                    : messageResult.verdict === "SUSPICIOUS"
                    ? "border-l-amber-500 bg-amber-50/30 dark:bg-amber-950/20"
                    : "border-l-emerald-500 bg-emerald-50/30 dark:bg-emerald-950/20"
                )}
              >
                <div className="flex flex-col sm:flex-row sm:items-center justify-between gap-3">
                  <div className="flex items-center gap-3">
                    {messageResult.verdict === "LIKELY_SCAM" ? (
                      <XCircle className="w-8 h-8 text-rose-600 shrink-0" />
                    ) : messageResult.verdict === "SUSPICIOUS" ? (
                      <AlertTriangle className="w-8 h-8 text-amber-600 shrink-0" />
                    ) : (
                      <CheckCircle2 className="w-8 h-8 text-emerald-600 shrink-0" />
                    )}

                    <div>
                      <span
                        className={cn(
                          "px-2.5 py-0.5 rounded-full text-xs font-bold uppercase tracking-wider inline-block",
                          messageResult.verdict === "LIKELY_SCAM"
                            ? "bg-rose-100 text-rose-800 dark:bg-rose-900/60 dark:text-rose-200"
                            : messageResult.verdict === "SUSPICIOUS"
                            ? "bg-amber-100 text-amber-800 dark:bg-amber-900/60 dark:text-amber-200"
                            : "bg-emerald-100 text-emerald-800 dark:bg-emerald-900/60 dark:text-emerald-200"
                        )}
                      >
                        {messageResult.verdict.replace(/_/g, " ")}
                      </span>
                      <h2 className="text-xl sm:text-2xl font-bold text-slate-900 dark:text-white mt-1">
                        {messageResult.consumer_headline}
                      </h2>
                    </div>
                  </div>

                  <button
                    onClick={() => performMessageAnalysis(messageText)}
                    className="inline-flex items-center gap-1.5 px-3 py-1.5 rounded-lg border border-slate-300 text-xs font-medium text-slate-700 hover:bg-slate-100 dark:border-slate-700 dark:text-slate-300 dark:hover:bg-slate-800 shrink-0 self-start sm:self-center"
                  >
                    <RotateCcw className="w-3.5 h-3.5" />
                    <span>Re-analyze</span>
                  </button>
                </div>
              </div>

              {/* What You Should Do & Tactics */}
              <div className="grid grid-cols-1 md:grid-cols-2 gap-6">
                <div className="consumer-card p-6 space-y-3">
                  <h3 className="font-bold text-slate-900 dark:text-white text-base flex items-center gap-2">
                    <ShieldCheck className="w-5 h-5 text-purple-600" />
                    <span>Recommended Action</span>
                  </h3>
                  {(messageResult.consumer_advice || []).length > 0 ? (
                    <ul className="space-y-2.5 text-sm text-slate-700 dark:text-slate-300">
                      {messageResult.consumer_advice.map((adv: string, idx: number) => (
                        <li key={idx} className="flex items-start gap-2.5">
                          <span className="w-1.5 h-1.5 rounded-full bg-purple-500 shrink-0 mt-2" />
                          <span className="leading-snug">{adv}</span>
                        </li>
                      ))}
                    </ul>
                  ) : (
                    <p className="text-xs text-slate-500 dark:text-slate-400">
                      No urgent action needed. Stay cautious before sending money or private info.
                    </p>
                  )}
                </div>

                <div className="consumer-card p-6 space-y-3">
                  <h3 className="font-bold text-slate-900 dark:text-white text-base flex items-center gap-2">
                    <HelpCircle className="w-5 h-5 text-slate-600" />
                    <span>Manipulative Signals Detected</span>
                  </h3>
                  <div className="flex flex-wrap gap-2 pt-1">
                    {(messageResult.detected_tactics || []).length > 0 ? (
                      messageResult.detected_tactics.map((item, idx) => (
                        <div
                          key={idx}
                          className="px-2.5 py-1.5 rounded-lg text-xs font-semibold bg-rose-50 text-rose-800 border border-rose-200 dark:bg-rose-950/40 dark:text-rose-200 dark:border-rose-900"
                        >
                          <div>{item.tactic}</div>
                          {item.explanation && (
                            <p className="text-[11px] font-normal text-rose-600 dark:text-rose-300 mt-0.5">
                              {item.explanation}
                            </p>
                          )}
                        </div>
                      ))
                    ) : (messageResult.manipulation_tactics || []).length > 0 ? (
                      messageResult.manipulation_tactics.map((tactic: string, idx: number) => (
                        <span
                          key={idx}
                          className="px-2.5 py-1 rounded-lg text-xs font-semibold bg-rose-50 text-rose-700 border border-rose-200 dark:bg-rose-950/40 dark:text-rose-300 dark:border-rose-900"
                        >
                          {tactic}
                        </span>
                      ))
                    ) : (
                      <span className="text-xs text-slate-500">
                        No aggressive social engineering signals found.
                      </span>
                    )}
                  </div>
                </div>
              </div>

              {/* Embedded Links Detected inside Message */}
              {(messageResult.extracted_links || []).length > 0 && (
                <div className="consumer-card p-6 space-y-3 border-amber-200 dark:border-amber-900/60 bg-amber-50/20 dark:bg-amber-950/10">
                  <div className="flex items-center justify-between">
                    <h3 className="font-bold text-slate-900 dark:text-white text-base flex items-center gap-2">
                      <Globe className="w-5 h-5 text-amber-600" />
                      <span>Embedded Links in Message ({messageResult.extracted_links.length})</span>
                    </h3>
                  </div>
                  <p className="text-xs text-slate-600 dark:text-slate-400">
                    Fraudulent messages almost always direct victims to external harvest links. You can inspect any of these links safely:
                  </p>
                  <div className="space-y-2 pt-1">
                    {messageResult.extracted_links.map((link, idx) => (
                      <div
                        key={idx}
                        className="flex flex-col sm:flex-row sm:items-center justify-between gap-2 p-3 rounded-xl bg-white dark:bg-slate-900 border border-slate-200 dark:border-slate-800 text-xs"
                      >
                        <span className="font-mono text-slate-800 dark:text-slate-200 truncate select-all">
                          {link}
                        </span>
                        <button
                          type="button"
                          onClick={() => handleScanExtractedLink(link)}
                          className="inline-flex items-center gap-1.5 px-3 py-1.5 rounded-lg bg-brand-600 text-white font-medium hover:bg-brand-700 transition-colors shrink-0 self-start sm:self-auto"
                        >
                          <span>Scan Link</span>
                          <ArrowRight className="w-3 h-3" />
                        </button>
                      </div>
                    ))}
                  </div>
                </div>
              )}

              {/* Extracted Phone Numbers or Amounts */}
              {((messageResult.extracted_phones || []).length > 0 ||
                (messageResult.extracted_amounts || []).length > 0) && (
                <div className="consumer-card p-5 space-y-2 text-xs">
                  <span className="font-bold text-slate-900 dark:text-white uppercase tracking-wider text-[11px]">
                    Extracted Message Telemetry
                  </span>
                  <div className="flex flex-wrap gap-4 pt-1 text-slate-700 dark:text-slate-300">
                    {(messageResult.extracted_phones || []).length > 0 && (
                      <div>
                        <strong className="text-slate-500 dark:text-slate-400 block text-[10px] uppercase">
                          Contact Phone Numbers:
                        </strong>
                        <span className="font-mono">{messageResult.extracted_phones.join(", ")}</span>
                      </div>
                    )}
                    {(messageResult.extracted_amounts || []).length > 0 && (
                      <div>
                        <strong className="text-slate-500 dark:text-slate-400 block text-[10px] uppercase">
                          Amounts Demanded / Claimed:
                        </strong>
                        <span className="font-mono text-rose-600 dark:text-rose-400 font-semibold">
                          {messageResult.extracted_amounts.join(", ")}
                        </span>
                      </div>
                    )}
                  </div>
                </div>
              )}

              {/* AI Guidance Card */}
              {messageResult.ai_explanation && (
                <div className="consumer-card p-6 border-purple-200 dark:border-purple-900/60 bg-purple-50/30 dark:bg-purple-950/20 space-y-3">
                  <div className="flex items-center gap-2">
                    <Sparkles className="w-4 h-4 text-purple-600" />
                    <span className="text-xs font-bold uppercase tracking-wider text-purple-700 dark:text-purple-300">
                      {messageResult.ai_explanation.source || "AI Safety Guidance"}
                    </span>
                  </div>
                  {messageResult.ai_explanation.headline && (
                    <h4 className="font-bold text-slate-900 dark:text-white text-sm">
                      {messageResult.ai_explanation.headline}
                    </h4>
                  )}
                  {messageResult.ai_explanation.summary && (
                    <p className="text-xs text-slate-700 dark:text-slate-300 leading-relaxed">
                      {messageResult.ai_explanation.summary}
                    </p>
                  )}
                </div>
              )}
            </div>
          )}
        </div>
      )}
    </div>
  );
}

export default function CheckPage() {
  return (
    <Suspense
      fallback={
        <div className="flex justify-center items-center py-24">
          <div className="w-8 h-8 rounded-full border-2 border-brand-500 border-t-transparent animate-spin" />
        </div>
      }
    >
      <CheckContent />
    </Suspense>
  );
}
