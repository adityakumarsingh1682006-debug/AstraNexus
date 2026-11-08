"use client";

import React, { useState, useEffect } from "react";
import {
  Settings,
  Sun,
  Moon,
  Shield,
  Lock,
  Bell,
  Trash2,
  Info,
  CheckCircle2,
  Check,
} from "lucide-react";
import { useTheme } from "@/context/ThemeContext";
import { cn } from "@/lib/utils";

export default function SettingsPage() {
  const { theme, setTheme } = useTheme();

  // Local preferences
  const [autoCheckOnPaste, setAutoCheckOnPaste] = useState(true);
  const [warnOnRedirects, setWarnOnRedirects] = useState(true);
  const [receiveHighRiskAlerts, setReceiveHighRiskAlerts] = useState(true);
  const [clearedDataMessage, setClearedDataMessage] = useState(false);

  useEffect(() => {
    const savedAutoCheck = localStorage.getItem("astranexus-pref-autocheck");
    if (savedAutoCheck !== null) setAutoCheckOnPaste(savedAutoCheck === "true");

    const savedRedirects = localStorage.getItem("astranexus-pref-redirects");
    if (savedRedirects !== null) setWarnOnRedirects(savedRedirects === "true");
  }, []);

  const handleToggleAutoCheck = () => {
    const nextVal = !autoCheckOnPaste;
    setAutoCheckOnPaste(nextVal);
    localStorage.setItem("astranexus-pref-autocheck", String(nextVal));
  };

  const handleToggleRedirects = () => {
    const nextVal = !warnOnRedirects;
    setWarnOnRedirects(nextVal);
    localStorage.setItem("astranexus-pref-redirects", String(nextVal));
  };

  const handleClearLocalData = () => {
    if (confirm("Are you sure you want to clear your local search history and locally saved reports?")) {
      localStorage.removeItem("astranexus-local-reports");
      setClearedDataMessage(true);
      setTimeout(() => setClearedDataMessage(false), 3000);
    }
  };

  return (
    <div className="space-y-8 max-w-3xl mx-auto">
      {/* Header */}
      <div className="text-center space-y-2">
        <div className="inline-flex items-center gap-1.5 px-3 py-1 rounded-full bg-slate-100 text-slate-700 text-xs font-semibold dark:bg-slate-800 dark:text-slate-300">
          <Settings className="w-3.5 h-3.5" />
          <span>App Preferences</span>
        </div>
        <h1 className="text-2xl sm:text-4xl font-extrabold text-slate-900 dark:text-white">
          Settings & Privacy
        </h1>
        <p className="text-sm text-slate-600 dark:text-slate-400 max-w-md mx-auto">
          Manage your interface theme, device preferences, and learn how we protect your personal privacy.
        </p>
      </div>

      {/* 1. Theme Preferences */}
      <div className="consumer-card p-6 sm:p-7 space-y-4">
        <div className="space-y-1">
          <h2 className="text-base font-bold text-slate-900 dark:text-white">
            Display Theme
          </h2>
          <p className="text-xs text-slate-500 dark:text-slate-400">
            AstraNexus is designed with a light theme for optimal daytime readability. You can switch to dark theme anytime.
          </p>
        </div>

        <div className="grid grid-cols-2 gap-3 pt-2">
          {/* Light Mode Option */}
          <button
            type="button"
            onClick={() => setTheme("light")}
            className={cn(
              "p-4 rounded-xl border text-left flex items-start gap-3 transition-all min-h-[44px]",
              theme === "light"
                ? "border-brand-600 bg-brand-50/60 dark:border-brand-500 text-slate-900 shadow-sm"
                : "border-slate-200 dark:border-slate-800 hover:bg-slate-50 dark:hover:bg-slate-900 text-slate-600 dark:text-slate-400"
            )}
          >
            <Sun className={cn("w-5 h-5 mt-0.5", theme === "light" ? "text-brand-600" : "text-slate-400")} />
            <div>
              <strong className="block text-sm font-semibold text-slate-900 dark:text-white">
                Light Theme
              </strong>
              <span className="text-xs text-slate-500">Default & Recommended</span>
            </div>
          </button>

          {/* Dark Mode Option */}
          <button
            type="button"
            onClick={() => setTheme("dark")}
            className={cn(
              "p-4 rounded-xl border text-left flex items-start gap-3 transition-all min-h-[44px]",
              theme === "dark"
                ? "border-brand-600 bg-brand-950/60 text-white shadow-sm"
                : "border-slate-200 dark:border-slate-800 hover:bg-slate-50 dark:hover:bg-slate-900 text-slate-600 dark:text-slate-400"
            )}
          >
            <Moon className={cn("w-5 h-5 mt-0.5", theme === "dark" ? "text-brand-400" : "text-slate-400")} />
            <div>
              <strong className="block text-sm font-semibold text-slate-900 dark:text-white">
                Dark Theme
              </strong>
              <span className="text-xs text-slate-500">Night mode friendly</span>
            </div>
          </button>
        </div>
      </div>

      {/* 2. Device & Checker Preferences */}
      <div className="consumer-card p-6 sm:p-7 space-y-4">
        <h2 className="text-base font-bold text-slate-900 dark:text-white">
          Checker Behavior
        </h2>

        <div className="space-y-4 divide-y divide-slate-100 dark:divide-slate-800">
          <div className="flex items-center justify-between pt-2">
            <div className="space-y-0.5 max-w-md">
              <strong className="text-sm font-medium text-slate-900 dark:text-white block">
                Automatic link checking on paste
              </strong>
              <span className="text-xs text-slate-500 dark:text-slate-400">
                Immediately start the safety check when you paste a link into the checker.
              </span>
            </div>
            <button
              type="button"
              onClick={handleToggleAutoCheck}
              className={cn(
                "relative inline-flex h-6 w-11 shrink-0 cursor-pointer rounded-full border-2 border-transparent transition-colors duration-200 ease-in-out focus:outline-none",
                autoCheckOnPaste ? "bg-brand-600" : "bg-slate-300 dark:bg-slate-700"
              )}
            >
              <span
                className={cn(
                  "pointer-events-none inline-block h-5 w-5 transform rounded-full bg-white shadow ring-0 transition duration-200 ease-in-out",
                  autoCheckOnPaste ? "translate-x-5" : "translate-x-0"
                )}
              />
            </button>
          </div>

          <div className="flex items-center justify-between pt-4">
            <div className="space-y-0.5 max-w-md">
              <strong className="text-sm font-medium text-slate-900 dark:text-white block">
                Warn about multiple external redirects
              </strong>
              <span className="text-xs text-slate-500 dark:text-slate-400">
                Flag links that jump through several different domains before reaching the target.
              </span>
            </div>
            <button
              type="button"
              onClick={handleToggleRedirects}
              className={cn(
                "relative inline-flex h-6 w-11 shrink-0 cursor-pointer rounded-full border-2 border-transparent transition-colors duration-200 ease-in-out focus:outline-none",
                warnOnRedirects ? "bg-brand-600" : "bg-slate-300 dark:bg-slate-700"
              )}
            >
              <span
                className={cn(
                  "pointer-events-none inline-block h-5 w-5 transform rounded-full bg-white shadow ring-0 transition duration-200 ease-in-out",
                  warnOnRedirects ? "translate-x-5" : "translate-x-0"
                )}
              />
            </button>
          </div>
        </div>
      </div>

      {/* 3. Privacy Pledge */}
      <div className="consumer-card p-6 sm:p-7 space-y-4 border-emerald-200 dark:border-emerald-950/60 bg-emerald-50/20 dark:bg-emerald-950/10">
        <div className="flex items-center gap-2 text-emerald-800 dark:text-emerald-300">
          <Lock className="w-5 h-5 text-emerald-600" />
          <h2 className="text-base font-bold">Our Plain-English Privacy Commitment</h2>
        </div>

        <ul className="space-y-2 text-xs text-slate-700 dark:text-slate-300">
          <li className="flex items-start gap-2">
            <CheckCircle2 className="w-4 h-4 text-emerald-600 shrink-0 mt-0.5" />
            <span>We NEVER store or ask for your personal account passwords, PINs, or banking logins.</span>
          </li>
          <li className="flex items-start gap-2">
            <CheckCircle2 className="w-4 h-4 text-emerald-600 shrink-0 mt-0.5" />
            <span>Private messages pasted into the message analyzer are evaluated securely and never published publicly.</span>
          </li>
          <li className="flex items-start gap-2">
            <CheckCircle2 className="w-4 h-4 text-emerald-600 shrink-0 mt-0.5" />
            <span>We never sell your browsing history, IP address, or contact details to third-party advertisers.</span>
          </li>
        </ul>

        {/* Clear Data Button */}
        <div className="pt-3 border-t border-emerald-100 dark:border-emerald-900/60 flex items-center justify-between">
          <span className="text-xs text-slate-500">Need to remove your search history on this browser?</span>
          <button
            type="button"
            onClick={handleClearLocalData}
            className="inline-flex items-center gap-1.5 px-3 py-1.5 rounded-lg border border-slate-300 dark:border-slate-700 text-xs text-slate-700 dark:text-slate-300 hover:bg-slate-100 dark:hover:bg-slate-800 transition-colors"
          >
            <Trash2 className="w-3.5 h-3.5 text-rose-500" />
            <span>Clear Local Data</span>
          </button>
        </div>

        {clearedDataMessage && (
          <p className="text-xs text-emerald-600 font-semibold pt-1">
            Local search history and saved submissions have been cleared.
          </p>
        )}
      </div>

      {/* 4. About AstraNexus */}
      <div className="consumer-card p-6 sm:p-7 space-y-3">
        <h2 className="text-base font-bold text-slate-900 dark:text-white flex items-center gap-2">
          <Info className="w-4 h-4 text-slate-500" />
          <span>About AstraNexus</span>
        </h2>
        <p className="text-xs text-slate-600 dark:text-slate-400 leading-relaxed">
          AstraNexus was created to bridge the digital safety divide. We believe ordinary families, students, and elders should not need a degree in cybersecurity to navigate the modern internet without fear of fraud.
        </p>
        <div className="pt-2 text-[11px] text-slate-400 font-mono">
          AstraNexus Version 1.0 (Consumer Safety Edition) • Realtime Threat Ingestion Active
        </div>
      </div>
    </div>
  );
}
