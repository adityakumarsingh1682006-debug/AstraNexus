"use client";

import { useEffect, Suspense } from "react";
import { useRouter, useSearchParams } from "next/navigation";

function RedirectHandler() {
  const router = useRouter();
  const searchParams = useSearchParams();

  useEffect(() => {
    const text = searchParams.get("text");
    if (text) {
      router.replace(`/check?tab=message&text=${encodeURIComponent(text)}`);
    } else {
      router.replace("/check?tab=message");
    }
  }, [router, searchParams]);

  return (
    <div className="py-12 text-center text-sm text-slate-500">
      Loading Message Analyzer...
    </div>
  );
}

export default function ScamAnalyzerRedirectPage() {
  return (
    <Suspense fallback={<div className="py-12 text-center text-sm text-slate-500">Loading Message Analyzer...</div>}>
      <RedirectHandler />
    </Suspense>
  );
}
