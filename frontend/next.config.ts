import type { NextConfig } from "next";

function getBackendDestination(): string {
  const envUrl = process.env.NEXT_PUBLIC_API_URL || process.env.NEXT_PUBLIC_BACKEND_URL;
  if (envUrl && envUrl.trim() !== "") {
    const clean = envUrl.trim().replace(/\/+$/, "");
    if (clean.endsWith("/api/v1")) {
      return `${clean}/:path*`;
    }
    return `${clean}/api/v1/:path*`;
  }
  return "http://127.0.0.1:8000/api/v1/:path*";
}

const nextConfig: NextConfig = {
  reactStrictMode: true,
  async rewrites() {
    return [
      {
        source: "/api/v1/:path*",
        destination: getBackendDestination(),
      },
    ];
  },
};

export default nextConfig;
