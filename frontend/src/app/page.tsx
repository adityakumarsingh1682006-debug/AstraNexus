"use client";

import React, { useState } from "react";
import Link from "next/link";
import { useRouter } from "next/navigation";
import {
  ShieldCheck,
  Globe,
  MessageSquareWarning,
  ArrowRight,
  AlertTriangle,
  CheckCircle2,
  Lock,
  ChevronRight,
  Sparkles,
  PhoneCall,
  Search,
  ExternalLink,
} from "lucide-react";

export default function HomePage() {
  const router = useRouter();
  const [quickLink, setQuickLink] = useState("");
  const [quickMessage, setQuickMessage] = useState("");

  const handleLinkSubmit = (e: React.FormEvent) => {
    e.preventDefault();
    if (!quickLink.trim()) return;
    router.push(`/check?tab=url&target=${encodeURIComponent(quickLink.trim())}`);
  };

  const handleMessageSubmit = (e: React.FormEvent) => {
    e.preventDefault();
    if (!quickMessage.trim()) return;
    router.push(`/check?tab=message&text=${encodeURIComponent(quickMessage.trim())}`);
  };

  return (
    <div className="space-y-16">
      {/* 1. Hero Section */}
      <section className="text-center max-w-3xl mx-auto space-y-5 pt-4 sm:pt-8">
        <div className="inline-flex items-center gap-2 px-3 py-1 rounded-full bg-brand-50 border border-brand-200 text-brand-700 text-xs font-semibold dark:bg-brand-950/70 dark:border-brand-800 dark:text-brand-300">
          <ShieldCheck className="w-3.5 h-3.5" />
          <span>Simple & Free Digital Safety for Everyone</span>
        </div>

        <h1 className="text-3xl sm:text-5xl font-extrabold tracking-tight text-slate-900 dark:text-white leading-[1.15]">
          Stay one step ahead of <span className="text-brand-600 dark:text-brand-400">online scams.</span>
        </h1>

        <p className="text-base sm:text-lg text-slate-600 dark:text-slate-300 leading-relaxed max-w-2xl mx-auto">
          Check suspicious links and messages before you trust them. Understand exactly what is safe, what is deceitful, and what you should do next.
        </p>
      </section>

      {/* 2. The Two Most Prominent Actions */}
      <section className="grid grid-cols-1 md:grid-cols-2 gap-6 max-w-4xl mx-auto">
        {/* Action 1: Check a Link */}
        <div className="consumer-card p-6 sm:p-7 flex flex-col justify-between space-y-5 border-t-4 border-t-brand-500">
          <div className="space-y-3">
            <div className="w-11 h-11 rounded-2xl bg-brand-50 border border-brand-200 text-brand-600 dark:bg-brand-950 dark:border-brand-800 dark:text-brand-400 flex items-center justify-center">
              <Globe className="w-5 h-5" />
            </div>
            <h2 className="text-xl font-bold text-slate-900 dark:text-white">
              Check a Link
            </h2>
            <p className="text-sm text-slate-600 dark:text-slate-400 leading-relaxed">
              Wondering if a website or link sent to you is genuine? Paste it here to verify its safety certificates and check for fake bank or brand copies.
            </p>
          </div>

          <form onSubmit={handleLinkSubmit} className="space-y-3 pt-2">
            <div className="relative">
              <input
                type="text"
                value={quickLink}
                onChange={(e) => setQuickLink(e.target.value)}
                placeholder="e.g. login-bank-verify.com"
                className="w-full px-4 py-3 rounded-xl bg-slate-50 border border-slate-200 text-sm text-slate-900 placeholder-slate-400 focus:outline-none focus:ring-2 focus:ring-brand-500 focus:bg-white dark:bg-slate-900 dark:border-slate-700 dark:text-white dark:placeholder-slate-500 transition-all"
              />
            </div>
            <button
              type="submit"
              className="w-full inline-flex items-center justify-center gap-2 px-5 py-3 rounded-xl bg-brand-600 text-white font-semibold text-sm hover:bg-brand-700 transition-colors shadow-sm"
            >
              <span>Check This Link</span>
              <ArrowRight className="w-4 h-4" />
            </button>
          </form>

          {/* Presets */}
          <div className="pt-2 border-t border-slate-100 dark:border-slate-800 text-xs text-slate-500 flex items-center gap-2 flex-wrap">
            <span>Examples:</span>
            <button
              type="button"
              onClick={() => setQuickLink("https://chase-auth-service.com/login")}
              className="text-brand-600 dark:text-brand-400 hover:underline"
            >
              Fake Chase Login
            </button>
            <span>•</span>
            <button
              type="button"
              onClick={() => setQuickLink("https://google.com")}
              className="text-brand-600 dark:text-brand-400 hover:underline"
            >
              Real Google Site
            </button>
          </div>
        </div>

        {/* Action 2: Check a Message */}
        <div className="consumer-card p-6 sm:p-7 flex flex-col justify-between space-y-5 border-t-4 border-t-purple-500">
          <div className="space-y-3">
            <div className="w-11 h-11 rounded-2xl bg-purple-50 border border-purple-200 text-purple-600 dark:bg-purple-950 dark:border-purple-800 dark:text-purple-400 flex items-center justify-center">
              <MessageSquareWarning className="w-5 h-5" />
            </div>
            <h2 className="text-xl font-bold text-slate-900 dark:text-white">
              Check a Message
            </h2>
            <p className="text-sm text-slate-600 dark:text-slate-400 leading-relaxed">
              Received a strange SMS, WhatsApp message, job offer, or email demanding urgent payment? Paste the text to see if it uses common scam tricks.
            </p>
          </div>

          <form onSubmit={handleMessageSubmit} className="space-y-3 pt-2">
            <div className="relative">
              <textarea
                rows={2}
                value={quickMessage}
                onChange={(e) => setQuickMessage(e.target.value)}
                placeholder="Paste the SMS, WhatsApp text, or email here..."
                className="w-full px-4 py-2.5 rounded-xl bg-slate-50 border border-slate-200 text-sm text-slate-900 placeholder-slate-400 focus:outline-none focus:ring-2 focus:ring-purple-500 focus:bg-white dark:bg-slate-900 dark:border-slate-700 dark:text-white dark:placeholder-slate-500 transition-all resize-none"
              />
            </div>
            <button
              type="submit"
              className="w-full inline-flex items-center justify-center gap-2 px-5 py-3 rounded-xl bg-purple-600 text-white font-semibold text-sm hover:bg-purple-700 transition-colors shadow-sm"
            >
              <span>Analyze Message</span>
              <ArrowRight className="w-4 h-4" />
            </button>
          </form>

          {/* Presets */}
          <div className="pt-2 border-t border-slate-100 dark:border-slate-800 text-xs text-slate-500 flex items-center gap-2 flex-wrap">
            <span>Examples:</span>
            <button
              type="button"
              onClick={() => setQuickMessage("URGENT: Your package delivery is on hold. Pay $1.85 fee at usps-redelivery.info")}
              className="text-purple-600 dark:text-purple-400 hover:underline"
            >
              Delivery Fee SMS
            </button>
          </div>
        </div>
      </section>

      {/* 3. Recent Scam Alerts */}
      <section className="space-y-6">
        <div className="flex flex-col sm:flex-row sm:items-end justify-between gap-3">
          <div className="space-y-1">
            <span className="text-xs font-bold text-brand-600 dark:text-brand-400 uppercase tracking-wider">
              Alerts & Warnings
            </span>
            <h2 className="text-2xl font-bold text-slate-900 dark:text-white">
              Recent Scams Circulating Right Now
            </h2>
            <p className="text-sm text-slate-500 dark:text-slate-400">
              Stay aware of the latest tricks fraudsters are sending to ordinary phones and inboxes.
            </p>
          </div>
          <Link
            href="/alerts"
            className="inline-flex items-center gap-1.5 text-sm font-semibold text-brand-600 hover:text-brand-700 dark:text-brand-400"
          >
            <span>View All Alerts</span>
            <ArrowRight className="w-4 h-4" />
          </Link>
        </div>

        <div className="grid grid-cols-1 md:grid-cols-3 gap-5">
          {[
            {
              title: "Fake Postal Package Delivery Fee ($1.85)",
              category: "Delivery SMS",
              who: "Online shoppers, households",
              summary: "Texts claiming a package cannot be delivered until you pay a tiny fee. The link steals credit card numbers.",
              actionUrl: "/alerts",
            },
            {
              title: "Bank Account Suspension & KYC Threat",
              category: "Banking Fraud",
              who: "Bank account & debit card holders",
              summary: "Urgent SMS claiming your bank account is locked. Asks for OTP, password, and card CVV on a cloned login screen.",
              actionUrl: "/alerts",
            },
            {
              title: "WhatsApp 'Like YouTube Videos' Job Scam",
              category: "Job Offers",
              who: "Students & homemakers seeking work",
              summary: "Promises $300 daily for liking videos. Once you join, they demand that you deposit funds to unlock commissions.",
              actionUrl: "/alerts",
            },
          ].map((item, idx) => (
            <Link
              key={idx}
              href={item.actionUrl}
              className="consumer-card p-5 flex flex-col justify-between space-y-4 hover:border-brand-300 dark:hover:border-slate-700 transition-all group"
            >
              <div className="space-y-2">
                <div className="flex items-center justify-between">
                  <span className="px-2.5 py-0.5 rounded-full text-[11px] font-semibold bg-rose-50 text-rose-700 dark:bg-rose-950/60 dark:text-rose-300">
                    {item.category}
                  </span>
                  <span className="text-xs text-slate-400 font-medium">Verified Alert</span>
                </div>
                <h3 className="text-base font-bold text-slate-900 dark:text-white group-hover:text-brand-600 dark:group-hover:text-brand-400 transition-colors">
                  {item.title}
                </h3>
                <p className="text-xs text-slate-600 dark:text-slate-400 leading-relaxed">
                  {item.summary}
                </p>
              </div>

              <div className="pt-3 border-t border-slate-100 dark:border-slate-800 flex items-center justify-between text-xs text-brand-600 dark:text-brand-400 font-semibold">
                <span>How to recognize & avoid it</span>
                <ChevronRight className="w-4 h-4 group-hover:translate-x-1 transition-transform" />
              </div>
            </Link>
          ))}
        </div>
      </section>

      {/* 4. Common Online Scams (How They Work) */}
      <section className="space-y-6 pt-4">
        <div className="space-y-1 text-center max-w-2xl mx-auto">
          <span className="text-xs font-bold text-brand-600 dark:text-brand-400 uppercase tracking-wider">
            Knowledge is Protection
          </span>
          <h2 className="text-2xl sm:text-3xl font-bold text-slate-900 dark:text-white">
            How Scammers Try to Trick You
          </h2>
          <p className="text-sm text-slate-500 dark:text-slate-400">
            Almost all modern scams rely on psychological pressure rather than complex hacking.
          </p>
        </div>

        <div className="grid grid-cols-1 sm:grid-cols-2 lg:grid-cols-4 gap-4">
          {[
            {
              title: "1. The False Urgency",
              desc: "They claim your account will be suspended in 24 hours, or you'll be fined. They force you to panic before you think.",
              icon: AlertTriangle,
              color: "text-amber-600 bg-amber-50 dark:bg-amber-950/50",
            },
            {
              title: "2. The Clone Website",
              desc: "The link looks almost real (e.g. login-chase.com instead of chase.com). The page copies your bank's exact design.",
              icon: Globe,
              color: "text-brand-600 bg-brand-50 dark:bg-brand-950/50",
            },
            {
              title: "3. The Fake Problem",
              desc: "An unexpected delivery problem, tax refund, or lottery prize. It requires paying a tiny $1–$2 fee to unlock.",
              icon: ShieldCheck,
              color: "text-rose-600 bg-rose-50 dark:bg-rose-950/50",
            },
            {
              title: "4. The Screen Sharing App",
              desc: "A fake customer service agent asks you to install AnyDesk or TeamViewer to 'help' you. This gives them full control.",
              icon: PhoneCall,
              color: "text-purple-600 bg-purple-50 dark:bg-purple-950/50",
            },
          ].map((item, i) => {
            const Icon = item.icon;
            return (
              <div key={i} className="consumer-card p-5 space-y-3">
                <div className={`w-9 h-9 rounded-xl ${item.color} flex items-center justify-center`}>
                  <Icon className="w-5 h-5" />
                </div>
                <h3 className="font-bold text-slate-900 dark:text-white text-sm">
                  {item.title}
                </h3>
                <p className="text-xs text-slate-600 dark:text-slate-400 leading-relaxed">
                  {item.desc}
                </p>
              </div>
            );
          })}
        </div>
      </section>

      {/* 5. Golden Rules for Digital Safety */}
      <section className="consumer-card p-6 sm:p-8 bg-gradient-to-br from-brand-50/50 to-slate-50 dark:from-slate-900 dark:to-slate-950 border-brand-100 dark:border-slate-800 space-y-6">
        <div className="space-y-1">
          <span className="text-xs font-bold text-brand-600 dark:text-brand-400 uppercase tracking-wider">
            Simple Habits
          </span>
          <h2 className="text-xl sm:text-2xl font-bold text-slate-900 dark:text-white">
            4 Golden Rules to Never Get Scammed
          </h2>
        </div>

        <div className="grid grid-cols-1 sm:grid-cols-2 gap-4 text-sm text-slate-700 dark:text-slate-300">
          <div className="flex items-start gap-3">
            <CheckCircle2 className="w-5 h-5 text-emerald-600 shrink-0 mt-0.5" />
            <div>
              <strong className="text-slate-900 dark:text-white block">Never use links to fix account problems</strong>
              <span className="text-xs text-slate-500 dark:text-slate-400">
                If an SMS says your bank or Netflix account is blocked, open your official mobile app directly.
              </span>
            </div>
          </div>

          <div className="flex items-start gap-3">
            <CheckCircle2 className="w-5 h-5 text-emerald-600 shrink-0 mt-0.5" />
            <div>
              <strong className="text-slate-900 dark:text-white block">Your OTP is exclusively for you</strong>
              <span className="text-xs text-slate-500 dark:text-slate-400">
                No bank, postal service, or company representative will ever ask you to read back your OTP.
              </span>
            </div>
          </div>

          <div className="flex items-start gap-3">
            <CheckCircle2 className="w-5 h-5 text-emerald-600 shrink-0 mt-0.5" />
            <div>
              <strong className="text-slate-900 dark:text-white block">If it sounds too good to be true, it is</strong>
              <span className="text-xs text-slate-500 dark:text-slate-400">
                Nobody gives away free lottery prizes or high-paying daily jobs for effortless mobile clicks.
              </span>
            </div>
          </div>

          <div className="flex items-start gap-3">
            <CheckCircle2 className="w-5 h-5 text-emerald-600 shrink-0 mt-0.5" />
            <div>
              <strong className="text-slate-900 dark:text-white block">Slow down and talk to someone</strong>
              <span className="text-xs text-slate-500 dark:text-slate-400">
                Scammers want you to panic. Take five minutes and check with a family member or friend first.
              </span>
            </div>
          </div>
        </div>
      </section>

      {/* 6. Report a Scam Call-To-Action Banner */}
      <section className="consumer-card p-6 sm:p-8 flex flex-col sm:flex-row items-center justify-between gap-6 border-brand-200 dark:border-brand-900/60 bg-white dark:bg-slate-900">
        <div className="space-y-1.5 text-center sm:text-left">
          <h2 className="text-xl font-bold text-slate-900 dark:text-white">
            Received a suspicious message or call?
          </h2>
          <p className="text-xs sm:text-sm text-slate-600 dark:text-slate-400 max-w-xl">
            Help protect thousands of other people by submitting it. Our system checks it and issues community warnings.
          </p>
        </div>

        <Link
          href="/reports"
          className="inline-flex items-center gap-2 px-6 py-3 rounded-xl bg-slate-900 text-white font-semibold text-sm hover:bg-slate-800 dark:bg-white dark:text-slate-900 dark:hover:bg-slate-100 transition-colors shrink-0 shadow-sm"
        >
          <span>Report a Suspicious Link</span>
          <ArrowRight className="w-4 h-4" />
        </Link>
      </section>
    </div>
  );
}
