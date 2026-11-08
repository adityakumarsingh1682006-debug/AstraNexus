"use client";

import { useEffect, Suspense } from "react";
import { useRouter, useSearchParams } from "next/navigation";

function RedirectHandler() {
  const router = useRouter();
  const searchParams = useSearchParams();

  useEffect(() => {
    const target = searchParams.get("target");
    if (target) {
      router.replace(`/check?tab=url&target=${encodeURIComponent(target)}`);
    } else {
      router.replace("/check?tab=url");
    }
  }, [router, searchParams]);

  return (
    <div className="py-12 text-center text-sm text-slate-500">
      Loading Safety Checker...
    </div>
  );
}

export default function UrlScanRedirectPage() {
  return (
    <Suspense fallback={<div className="py-12 text-center text-sm text-slate-500">Loading Safety Checker...</div>}>
      <RedirectHandler />
    </Suspense>
  );
}
