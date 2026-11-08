"use client";

import React, { useState, useEffect } from "react";
import {
  FileText,
  Send,
  CheckCircle2,
  AlertTriangle,
  Clock,
  Shield,
  HelpCircle,
  Plus,
} from "lucide-react";
import { cn } from "@/lib/utils";
import { getApiEndpoint } from "@/lib/api";

interface ReportItem {
  id: string;
  target_indicator: string;
  indicator_type: string;
  category: string;
  description?: string;
  status: string;
  created_at: string;
  verdict?: string;
}

export default function ReportsPage() {
  const [reports, setReports] = useState<ReportItem[]>([]);
  const [loading, setLoading] = useState(true);

  // Form State
  const [targetIndicator, setTargetIndicator] = useState("");
  const [indicatorType, setIndicatorType] = useState<"LINK" | "MESSAGE" | "PHONE">("LINK");
  const [category, setCategory] = useState("Banking Fraud");
  const [description, setDescription] = useState("");
  const [isSubmitting, setIsSubmitting] = useState(false);
  const [submitSuccess, setSubmitSuccess] = useState(false);
  const [formError, setFormError] = useState<string | null>(null);

  // Fetch submitted reports
  const fetchReports = () => {
    fetch(getApiEndpoint("/api/v1/reports"))
      .then((res) => {
        if (!res.ok) throw new Error("Failed to load reports");
        return res.json();
      })
      .then((data) => {
        // Also merge any local reports saved in localStorage
        const saved = localStorage.getItem("astranexus-local-reports");
        let localReports: ReportItem[] = [];
        if (saved) {
          try {
            localReports = JSON.parse(saved);
          } catch (e) {}
        }
        // Deduplicate by ID
        const combined = [...localReports, ...data];
        const unique = Array.from(new Map(combined.map((item) => [item.id, item])).values());
        setReports(unique);
        setLoading(false);
      })
      .catch(() => {
        setLoading(false);
      });
  };

  useEffect(() => {
    fetchReports();
  }, []);

  const handleSubmit = async (e: React.FormEvent) => {
    e.preventDefault();
    const cleanIndicator = targetIndicator.trim();
    if (!cleanIndicator) {
      setFormError("Please enter the suspicious link, message, or phone number.");
      return;
    }

    setIsSubmitting(true);
    setFormError(null);

    try {
      const response = await fetch(getApiEndpoint("/api/v1/reports"), {
        method: "POST",
        headers: { "Content-Type": "application/json" },
        body: JSON.stringify({
          target_indicator: cleanIndicator,
          indicator_type: indicatorType,
          category,
          description: description.trim() || undefined,
        }),
      });

      if (!response.ok) {
        throw new Error("Unable to submit report. Please try again.");
      }

      const created: ReportItem = await response.json();

      // Save to localStorage for client-side persistence
      const saved = localStorage.getItem("astranexus-local-reports");
      const existing: ReportItem[] = saved ? JSON.parse(saved) : [];
      localStorage.setItem("astranexus-local-reports", JSON.stringify([created, ...existing]));

      setReports((prev) => [created, ...prev]);
      setSubmitSuccess(true);
      setTargetIndicator("");
      setDescription("");
    } catch (err: any) {
      setFormError(err.message || "Failed to submit report.");
    } finally {
      setIsSubmitting(false);
    }
  };

  return (
    <div className="space-y-8 max-w-4xl mx-auto">
      {/* Header */}
      <div className="text-center space-y-2">
        <div className="inline-flex items-center gap-1.5 px-3 py-1 rounded-full bg-brand-50 text-brand-700 text-xs font-semibold dark:bg-brand-950/60 dark:text-brand-300">
          <FileText className="w-3.5 h-3.5" />
          <span>Community Threat Defense</span>
        </div>
        <h1 className="text-2xl sm:text-4xl font-extrabold text-slate-900 dark:text-white">
          My Reports & Submissions
        </h1>
        <p className="text-sm text-slate-600 dark:text-slate-400 max-w-xl mx-auto">
          Report suspicious links and scam messages to help protect others. Track the investigation status of your reports below.
        </p>
      </div>

      {/* Submission Form Card */}
      <div className="consumer-card p-6 sm:p-7 space-y-5">
        <h2 className="text-lg font-bold text-slate-900 dark:text-white flex items-center gap-2">
          <Plus className="w-5 h-5 text-brand-600" />
          <span>Submit a Suspicious Link or Message</span>
        </h2>

        {submitSuccess ? (
          <div className="p-5 rounded-xl bg-emerald-50 dark:bg-emerald-950/30 border border-emerald-200 dark:border-emerald-800 text-center space-y-3">
            <CheckCircle2 className="w-8 h-8 text-emerald-600 mx-auto" />
            <h3 className="font-bold text-emerald-900 dark:text-emerald-100 text-base">
              Report Submitted Successfully
            </h3>
            <p className="text-xs text-emerald-700 dark:text-emerald-300 max-w-md mx-auto leading-relaxed">
              Thank you for keeping the digital world safer. Your report has been added to our triage queue below.
            </p>
            <button
              onClick={() => setSubmitSuccess(false)}
              className="px-4 py-2 rounded-xl bg-emerald-600 text-white font-semibold text-xs hover:bg-emerald-700 transition-colors"
            >
              Submit Another Scam
            </button>
          </div>
        ) : (
          <form onSubmit={handleSubmit} className="space-y-4">
            {/* Indicator Type Switcher */}
            <div className="space-y-1.5">
              <label className="block text-xs font-semibold text-slate-700 dark:text-slate-300 uppercase">
                What are you reporting?
              </label>
              <div className="flex gap-2">
                {(["LINK", "MESSAGE", "PHONE"] as const).map((type) => (
                  <button
                    key={type}
                    type="button"
                    onClick={() => setIndicatorType(type)}
                    className={cn(
                      "px-4 py-2 rounded-xl text-xs font-semibold transition-all min-h-[40px]",
                      indicatorType === type
                        ? "bg-slate-900 text-white dark:bg-white dark:text-slate-900 shadow-sm"
                        : "bg-slate-100 text-slate-600 hover:bg-slate-200 dark:bg-slate-800 dark:text-slate-300 dark:hover:bg-slate-700"
                    )}
                  >
                    {type === "LINK" ? "Suspicious Website" : type === "MESSAGE" ? "Scam Message" : "Phone Number"}
                  </button>
                ))}
              </div>
            </div>

            {/* Target Indicator */}
            <div className="space-y-1.5">
              <label className="block text-xs font-semibold text-slate-700 dark:text-slate-300">
                {indicatorType === "LINK"
                  ? "Website Address or Link"
                  : indicatorType === "MESSAGE"
                  ? "Message Snippet or Text"
                  : "Phone Number"}
              </label>
              <input
                type="text"
                required
                value={targetIndicator}
                onChange={(e) => setTargetIndicator(e.target.value)}
                placeholder={
                  indicatorType === "LINK"
                    ? "e.g. https://scam-bank-login.xyz"
                    : indicatorType === "MESSAGE"
                    ? "e.g. Your electricity will be disconnected tonight at 9 PM..."
                    : "e.g. +1 (800) 555-0199"
                }
                className="w-full px-4 py-3 rounded-xl bg-slate-50 border border-slate-200 text-sm text-slate-900 placeholder-slate-400 focus:outline-none focus:ring-2 focus:ring-brand-500 focus:bg-white dark:bg-slate-900 dark:border-slate-700 dark:text-white dark:placeholder-slate-500"
              />
            </div>

            {/* Category */}
            <div className="space-y-1.5">
              <label className="block text-xs font-semibold text-slate-700 dark:text-slate-300">
                Suspected Category
              </label>
              <select
                value={category}
                onChange={(e) => setCategory(e.target.value)}
                className="w-full px-4 py-2.5 rounded-xl bg-slate-50 border border-slate-200 text-sm text-slate-900 focus:outline-none focus:ring-2 focus:ring-brand-500 dark:bg-slate-900 dark:border-slate-700 dark:text-white"
              >
                <option value="Banking Fraud">Banking Fraud / Fake Login</option>
                <option value="Delivery Scam">Delivery Scam / Package Fee</option>
                <option value="Job Offers">Fake Job Offer / Work from Home</option>
                <option value="Utility Scam">Electricity or Bill Disconnection</option>
                <option value="Lottery or Prize">Lottery / Unclaimed Prize</option>
                <option value="Other">Other Suspicious Request</option>
              </select>
            </div>

            {/* Optional Details */}
            <div className="space-y-1.5">
              <label className="block text-xs font-semibold text-slate-700 dark:text-slate-300">
                Optional Notes (How did you receive this?)
              </label>
              <textarea
                rows={2}
                value={description}
                onChange={(e) => setDescription(e.target.value)}
                placeholder="e.g. Received via text message this morning claiming to be from Chase..."
                className="w-full p-3 rounded-xl bg-slate-50 border border-slate-200 text-sm text-slate-900 placeholder-slate-400 focus:outline-none focus:ring-2 focus:ring-brand-500 focus:bg-white dark:bg-slate-900 dark:border-slate-700 dark:text-white dark:placeholder-slate-500 resize-none"
              />
            </div>

            {formError && (
              <p className="text-xs text-rose-600 font-medium">{formError}</p>
            )}

            <button
              type="submit"
              disabled={isSubmitting || !targetIndicator.trim()}
              className="inline-flex items-center justify-center gap-2 px-6 py-3 rounded-xl bg-brand-600 text-white font-semibold text-sm hover:bg-brand-700 disabled:opacity-50 transition-colors shadow-sm min-h-[44px]"
            >
              {isSubmitting ? "Submitting Report..." : "Submit Report"}
              <Send className="w-4 h-4" />
            </button>
          </form>
        )}
      </div>

      {/* Reports List */}
      <div className="space-y-4">
        <h2 className="text-lg font-bold text-slate-900 dark:text-white">
          Report Status & History
        </h2>

        {loading ? (
          <div className="consumer-card p-8 text-center text-xs text-slate-500">
            Loading your reports...
          </div>
        ) : reports.length === 0 ? (
          <div className="consumer-card p-8 text-center text-xs text-slate-500 space-y-2">
            <p className="font-semibold text-slate-700 dark:text-slate-300">No reports submitted yet.</p>
            <p>When you encounter a suspicious link or text, submit it above to track its status.</p>
          </div>
        ) : (
          <div className="space-y-3">
            {reports.map((report) => (
              <div
                key={report.id}
                className="consumer-card p-5 flex flex-col sm:flex-row sm:items-center justify-between gap-4"
              >
                <div className="space-y-1.5 flex-1 min-w-0">
                  <div className="flex flex-wrap items-center gap-2">
                    <span className="px-2 py-0.5 rounded text-[11px] font-semibold bg-slate-100 text-slate-700 dark:bg-slate-800 dark:text-slate-300">
                      {report.category}
                    </span>
                    <span
                      className={cn(
                        "px-2 py-0.5 rounded text-[11px] font-bold uppercase",
                        report.status === "VERIFIED_THREAT"
                          ? "bg-rose-50 text-rose-700 dark:bg-rose-950 dark:text-rose-300"
                          : report.status === "INVESTIGATING"
                          ? "bg-amber-50 text-amber-700 dark:bg-amber-950 dark:text-amber-300"
                          : "bg-brand-50 text-brand-700 dark:bg-brand-950 dark:text-brand-300"
                      )}
                    >
                      {report.status.replace(/_/g, " ")}
                    </span>
                  </div>

                  <div className="text-sm font-semibold text-slate-900 dark:text-white truncate">
                    {report.target_indicator}
                  </div>

                  {report.description && (
                    <p className="text-xs text-slate-500 dark:text-slate-400 line-clamp-2">
                      {report.description}
                    </p>
                  )}
                </div>

                <div className="text-[11px] text-slate-400 font-mono shrink-0">
                  ID: #{report.id}
                </div>
              </div>
            ))}
          </div>
        )}
      </div>
    </div>
  );
}
