"use client";

import { useEffect } from "react";
import { useRouter } from "next/navigation";

export default function ThreatExplorerRedirectPage() {
  const router = useRouter();

  useEffect(() => {
    router.replace("/alerts");
  }, [router]);

  return (
    <div className="py-12 text-center text-sm text-slate-500">
      Opening Scam Alerts...
    </div>
  );
}
