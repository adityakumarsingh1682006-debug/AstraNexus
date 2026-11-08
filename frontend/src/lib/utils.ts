import { clsx, type ClassValue } from "clsx";
import { twMerge } from "tailwind-merge";

export function cn(...inputs: ClassValue[]) {
  return twMerge(clsx(inputs));
}

export function formatRiskScore(score: number): {
  label: string;
  colorClass: string;
  bgClass: string;
  borderClass: string;
  glowClass: string;
} {
  if (score >= 80) {
    return {
      label: "CRITICAL THREAT",
      colorClass: "text-red-400",
      bgClass: "bg-red-500/10",
      borderClass: "border-red-500/40",
      glowClass: "shadow-crimson-glow",
    };
  }
  if (score >= 50) {
    return {
      label: "SUSPICIOUS",
      colorClass: "text-amber-400",
      bgClass: "bg-amber-500/10",
      borderClass: "border-amber-500/40",
      glowClass: "shadow-[0_0_20px_rgba(245,158,11,0.25)]",
    };
  }
  if (score >= 20) {
    return {
      label: "ELEVATED RISK",
      colorClass: "text-yellow-400",
      bgClass: "bg-yellow-500/10",
      borderClass: "border-yellow-500/40",
      glowClass: "shadow-[0_0_20px_rgba(234,179,8,0.2)]",
    };
  }
  return {
    label: "VERIFIED SAFE",
    colorClass: "text-emerald-400",
    bgClass: "bg-emerald-500/10",
    borderClass: "border-emerald-500/40",
    glowClass: "shadow-emerald-glow",
  };
}

export function truncateHash(hash: string, startChars: number = 6, endChars: number = 4): string {
  if (!hash) return "";
  if (hash.length <= startChars + endChars) return hash;
  return `${hash.slice(0, startChars)}...${hash.slice(-endChars)}`;
}
