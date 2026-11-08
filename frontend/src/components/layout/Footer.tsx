import React from "react";
import Link from "next/link";
import { ShieldCheck, Heart, Lock, ExternalLink } from "lucide-react";

export function Footer() {
  return (
    <footer className="w-full border-t border-slate-200 bg-white dark:bg-slate-900/60 dark:border-slate-800 mt-auto py-10 transition-colors">
      <div className="max-w-6xl mx-auto px-4 sm:px-6 lg:px-8">
        <div className="grid grid-cols-1 md:grid-cols-4 gap-8">
          {/* Brand description */}
          <div className="md:col-span-1 space-y-3">
            <div className="flex items-center gap-2">
              <div className="w-7 h-7 rounded-lg bg-brand-50 border border-brand-200 text-brand-600 flex items-center justify-center dark:bg-brand-950 dark:border-brand-800 dark:text-brand-400">
                <ShieldCheck className="w-4 h-4" />
              </div>
              <span className="font-bold text-slate-900 dark:text-white">AstraNexus</span>
            </div>
            <p className="text-xs text-slate-500 dark:text-slate-400 leading-relaxed">
              Making online safety simple and approachable for families, students, professionals, and seniors.
            </p>
          </div>

          {/* Quick Tools */}
          <div className="space-y-2 text-xs">
            <span className="font-semibold text-slate-900 dark:text-white uppercase tracking-wider text-[11px]">
              Safety Tools
            </span>
            <ul className="space-y-2 text-slate-600 dark:text-slate-400">
              <li>
                <Link href="/check?tab=url" className="hover:text-brand-600 dark:hover:text-brand-400 transition-colors">
                  Check a Link
                </Link>
              </li>
              <li>
                <Link href="/check?tab=message" className="hover:text-brand-600 dark:hover:text-brand-400 transition-colors">
                  Check a Message
                </Link>
              </li>
              <li>
                <Link href="/alerts" className="hover:text-brand-600 dark:hover:text-brand-400 transition-colors">
                  Latest Scam Alerts
                </Link>
              </li>
              <li>
                <Link href="/reports" className="hover:text-brand-600 dark:hover:text-brand-400 transition-colors">
                  Report a Scam
                </Link>
              </li>
            </ul>
          </div>

          {/* Privacy & Safety */}
          <div className="space-y-2 text-xs">
            <span className="font-semibold text-slate-900 dark:text-white uppercase tracking-wider text-[11px]">
              Our Privacy Promise
            </span>
            <ul className="space-y-2 text-slate-600 dark:text-slate-400">
              <li className="flex items-center gap-1.5">
                <Lock className="w-3.5 h-3.5 text-emerald-600" />
                <span>Zero personal data sold</span>
              </li>
              <li className="flex items-center gap-1.5">
                <Lock className="w-3.5 h-3.5 text-emerald-600" />
                <span>No password or OTP logging</span>
              </li>
              <li>
                <Link href="/settings" className="hover:text-brand-600 dark:hover:text-brand-400 transition-colors">
                  Privacy & Settings
                </Link>
              </li>
            </ul>
          </div>

          {/* Philosophy */}
          <div className="space-y-2 text-xs">
            <span className="font-semibold text-slate-900 dark:text-white uppercase tracking-wider text-[11px]">
              Community
            </span>
            <p className="text-slate-500 dark:text-slate-400 leading-relaxed">
              Every verified link report helps protect thousands of other people from falling victim to digital fraud.
            </p>
          </div>
        </div>

        <div className="mt-8 pt-6 border-t border-slate-100 dark:border-slate-800 flex flex-col sm:flex-row items-center justify-between text-xs text-slate-400 gap-3">
          <span>&copy; {new Date().getFullYear()} AstraNexus Digital Safety. All rights reserved.</span>
          <div className="flex items-center gap-4">
            <Link href="/settings" className="hover:text-slate-600 dark:hover:text-slate-300">
              Settings & Theme
            </Link>
            <Link href="/reports" className="hover:text-slate-600 dark:hover:text-slate-300">
              Submit a Scam
            </Link>
          </div>
        </div>
      </div>
    </footer>
  );
}
