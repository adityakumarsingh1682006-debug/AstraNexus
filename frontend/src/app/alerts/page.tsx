"use client";

import React, { useState, useEffect } from "react";
import {
  Bell,
  Search,
  AlertTriangle,
  ShieldCheck,
  CheckCircle2,
  ChevronDown,
  ChevronUp,
  Tag,
  Users,
  ExternalLink,
} from "lucide-react";
import { cn } from "@/lib/utils";
import { getApiEndpoint } from "@/lib/api";

interface ScamAlert {
  id: string;
  title: string;
  category: string;
  severity: string;
  summary: string;
  how_it_works: string[];
  who_is_targeted: string;
  how_to_recognize: string[];
  how_to_stay_safe: string[];
  reported_date: string;
  is_verified: boolean;
  source: string;
}

const CATEGORIES = ["All", "Delivery Scam", "Banking Fraud", "Job Offers", "Utility Scam"];

export default function ScamAlertsPage() {
  const [alerts, setAlerts] = useState<ScamAlert[]>([]);
  const [loading, setLoading] = useState(true);
  const [selectedCategory, setSelectedCategory] = useState("All");
  const [searchQuery, setSearchQuery] = useState("");
  const [expandedAlertId, setExpandedAlertId] = useState<string | null>("alert-2026-001");

  useEffect(() => {
    fetch(getApiEndpoint("/api/v1/alerts"))
      .then((res) => {
        if (!res.ok) throw new Error("Failed to load alerts");
        return res.json();
      })
      .then((data) => {
        if (Array.isArray(data)) {
          setAlerts(data);
        }
        setLoading(false);
      })
      .catch(() => {
        setLoading(false);
      });
  }, []);

  const filteredAlerts = alerts.filter((alert) => {
    const matchesCategory =
      selectedCategory === "All" || alert.category.toLowerCase() === selectedCategory.toLowerCase();
    const matchesSearch =
      alert.title.toLowerCase().includes(searchQuery.toLowerCase()) ||
      alert.summary.toLowerCase().includes(searchQuery.toLowerCase()) ||
      alert.category.toLowerCase().includes(searchQuery.toLowerCase());
    return matchesCategory && matchesSearch;
  });

  return (
    <div className="space-y-8 max-w-4xl mx-auto">
      {/* Header */}
      <div className="text-center space-y-2">
        <div className="inline-flex items-center gap-1.5 px-3 py-1 rounded-full bg-rose-50 text-rose-700 text-xs font-semibold dark:bg-rose-950/60 dark:text-rose-300">
          <Bell className="w-3.5 h-3.5" />
          <span>Active Threat Directory</span>
        </div>
        <h1 className="text-2xl sm:text-4xl font-extrabold text-slate-900 dark:text-white">
          Scams Circulating Right Now
        </h1>
        <p className="text-sm text-slate-600 dark:text-slate-400 max-w-xl mx-auto">
          Understand how fraudsters are attempting to deceive ordinary people and how you can spot their tricks.
        </p>
      </div>

      {/* Search & Filter Bar */}
      <div className="space-y-4">
        <div className="relative">
          <Search className="absolute left-3.5 top-1/2 -translate-y-1/2 w-4 h-4 text-slate-400" />
          <input
            type="text"
            value={searchQuery}
            onChange={(e) => setSearchQuery(e.target.value)}
            placeholder="Search alerts (e.g. delivery fee, bank KYC, job offer, electricity bill)..."
            className="w-full pl-10 pr-4 py-3 rounded-xl bg-white border border-slate-200 text-sm text-slate-900 placeholder-slate-400 focus:outline-none focus:ring-2 focus:ring-brand-500 dark:bg-slate-900 dark:border-slate-800 dark:text-white dark:placeholder-slate-500 shadow-subtle"
          />
        </div>

        {/* Category Pills */}
        <div className="flex items-center gap-2 overflow-x-auto pb-1 text-xs">
          {CATEGORIES.map((cat) => (
            <button
              key={cat}
              onClick={() => setSelectedCategory(cat)}
              className={cn(
                "px-3.5 py-1.5 rounded-full font-medium whitespace-nowrap transition-colors min-h-[36px]",
                selectedCategory === cat
                  ? "bg-slate-900 text-white dark:bg-white dark:text-slate-900"
                  : "bg-white border border-slate-200 text-slate-600 hover:bg-slate-100 dark:bg-slate-900 dark:border-slate-800 dark:text-slate-400 dark:hover:bg-slate-800"
              )}
            >
              {cat}
            </button>
          ))}
        </div>
      </div>

      {/* Alert Cards List */}
      {loading ? (
        <div className="consumer-card p-12 text-center text-sm text-slate-500 space-y-3">
          <div className="w-8 h-8 border-3 border-brand-500 border-t-transparent rounded-full animate-spin mx-auto" />
          <p>Loading verified scam alerts...</p>
        </div>
      ) : filteredAlerts.length === 0 ? (
        <div className="consumer-card p-12 text-center text-sm text-slate-500 space-y-2">
          <ShieldCheck className="w-8 h-8 text-slate-400 mx-auto" />
          <p className="font-semibold text-slate-700 dark:text-slate-300">No alerts match your filter</p>
          <p className="text-xs">Try selecting 'All' or clearing your search keywords.</p>
        </div>
      ) : (
        <div className="space-y-4">
          {filteredAlerts.map((alert) => {
            const isExpanded = expandedAlertId === alert.id;
            return (
              <div
                key={alert.id}
                className="consumer-card overflow-hidden border-slate-200 dark:border-slate-800 transition-all"
              >
                {/* Header Summary Row */}
                <div
                  onClick={() => setExpandedAlertId(isExpanded ? null : alert.id)}
                  className="p-5 sm:p-6 cursor-pointer hover:bg-slate-50/60 dark:hover:bg-slate-850/60 transition-colors flex items-start justify-between gap-4"
                >
                  <div className="space-y-2 flex-1">
                    <div className="flex flex-wrap items-center gap-2">
                      <span className="px-2.5 py-0.5 rounded-full text-[11px] font-bold uppercase tracking-wide bg-rose-50 text-rose-700 dark:bg-rose-950 dark:text-rose-300">
                        {alert.category}
                      </span>
                      <span className="px-2 py-0.5 rounded-full text-[11px] font-semibold bg-emerald-50 text-emerald-700 dark:bg-emerald-950 dark:text-emerald-300 flex items-center gap-1">
                        <CheckCircle2 className="w-3 h-3" />
                        <span>Verified Alert</span>
                      </span>
                      <span className="text-xs text-slate-400 font-medium">{alert.reported_date}</span>
                    </div>

                    <h2 className="text-lg sm:text-xl font-bold text-slate-900 dark:text-white">
                      {alert.title}
                    </h2>

                    <p className="text-sm text-slate-600 dark:text-slate-300 leading-relaxed">
                      {alert.summary}
                    </p>
                  </div>

                  <button
                    type="button"
                    className="p-2 rounded-lg text-slate-400 hover:text-slate-600 dark:hover:text-slate-200 shrink-0"
                    aria-label={isExpanded ? "Collapse alert details" : "Expand alert details"}
                  >
                    {isExpanded ? <ChevronUp className="w-5 h-5" /> : <ChevronDown className="w-5 h-5" />}
                  </button>
                </div>

                {/* Expanded In-Depth Guidance */}
                {isExpanded && (
                  <div className="p-5 sm:p-6 border-t border-slate-100 dark:border-slate-800 bg-slate-50/40 dark:bg-slate-950/40 space-y-6">
                    {/* Who is targeted */}
                    <div className="p-3.5 rounded-xl bg-white dark:bg-slate-900 border border-slate-200/80 dark:border-slate-800 flex items-center gap-2.5 text-xs text-slate-700 dark:text-slate-300">
                      <Users className="w-4 h-4 text-brand-600 shrink-0" />
                      <div>
                        <strong>Primary Target Group:</strong> {alert.who_is_targeted}
                      </div>
                    </div>

                    {/* How It Works */}
                    <div className="space-y-3">
                      <h3 className="text-sm font-bold text-slate-900 dark:text-white uppercase tracking-wider text-xs">
                        How This Scam Works (Step by Step)
                      </h3>
                      <ol className="space-y-2 text-sm text-slate-700 dark:text-slate-300">
                        {alert.how_it_works.map((step, idx) => (
                          <li key={idx} className="flex items-start gap-3">
                            <span className="flex items-center justify-center w-5 h-5 rounded-full bg-slate-200 text-slate-800 font-bold text-xs shrink-0 mt-0.5 dark:bg-slate-800 dark:text-slate-200">
                              {idx + 1}
                            </span>
                            <span className="leading-snug">{step}</span>
                          </li>
                        ))}
                      </ol>
                    </div>

                    {/* Recognition Red Flags & Safety Advice */}
                    <div className="grid grid-cols-1 sm:grid-cols-2 gap-4">
                      {/* Red flags */}
                      <div className="p-4 rounded-xl bg-rose-50/60 dark:bg-rose-950/30 border border-rose-200 dark:border-rose-900/60 space-y-2">
                        <strong className="text-xs font-bold text-rose-800 dark:text-rose-200 uppercase tracking-wider block">
                          Warning Signs to Recognize
                        </strong>
                        <ul className="space-y-1.5 text-xs text-rose-900 dark:text-rose-200">
                          {alert.how_to_recognize.map((item, idx) => (
                            <li key={idx} className="flex items-start gap-2">
                              <span className="w-1.5 h-1.5 rounded-full bg-rose-500 shrink-0 mt-1.5" />
                              <span className="leading-relaxed">{item}</span>
                            </li>
                          ))}
                        </ul>
                      </div>

                      {/* Safety Habits */}
                      <div className="p-4 rounded-xl bg-emerald-50/60 dark:bg-emerald-950/30 border border-emerald-200 dark:border-emerald-900/60 space-y-2">
                        <strong className="text-xs font-bold text-emerald-800 dark:text-emerald-200 uppercase tracking-wider block">
                          How to Stay 100% Safe
                        </strong>
                        <ul className="space-y-1.5 text-xs text-emerald-900 dark:text-emerald-200">
                          {alert.how_to_stay_safe.map((item, idx) => (
                            <li key={idx} className="flex items-start gap-2">
                              <CheckCircle2 className="w-3.5 h-3.5 text-emerald-600 shrink-0 mt-0.5" />
                              <span className="leading-relaxed">{item}</span>
                            </li>
                          ))}
                        </ul>
                      </div>
                    </div>

                    {/* Source Footnote */}
                    <div className="pt-2 text-[11px] text-slate-400 font-medium">
                      Source: {alert.source}
                    </div>
                  </div>
                )}
              </div>
            );
          })}
        </div>
      )}
    </div>
  );
}
