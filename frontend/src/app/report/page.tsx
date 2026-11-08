"use client";

import { useEffect } from "react";
import { useRouter } from "next/navigation";

export default function ReportRedirectPage() {
  const router = useRouter();

  useEffect(() => {
    router.replace("/reports");
  }, [router]);

  return (
    <div className="py-12 text-center text-sm text-slate-500">
      Opening Scam Reporting...
    </div>
  );
}
