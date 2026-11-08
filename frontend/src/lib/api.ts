/**
 * AstraNexus API Resolution Helper
 * 
 * Provides unified endpoint resolution across development and production environments.
 * - In Development: Defaults to relative paths (e.g. `/api/v1/scan/url`) which Next.js rewrites to local backend.
 * - In Production: If `NEXT_PUBLIC_API_URL` or `NEXT_PUBLIC_BACKEND_URL` is configured (e.g. Render backend),
 *   resolves directly to the hosted backend, bypassing serverless proxy limits.
 */

export function getApiBaseUrl(): string {
  if (typeof window !== "undefined") {
    // Client-side execution
    const clientUrl = process.env.NEXT_PUBLIC_API_URL || process.env.NEXT_PUBLIC_BACKEND_URL;
    if (clientUrl && clientUrl.trim() !== "") {
      return clientUrl.trim().replace(/\/+$/, "");
    }
  } else {
    // Server-side / SSR execution
    const serverUrl =
      process.env.NEXT_PUBLIC_API_URL ||
      process.env.NEXT_PUBLIC_BACKEND_URL ||
      process.env.BACKEND_INTERNAL_URL;
    if (serverUrl && serverUrl.trim() !== "") {
      return serverUrl.trim().replace(/\/+$/, "");
    }
  }
  return "";
}

export function getApiEndpoint(path: string): string {
  const base = getApiBaseUrl();
  const normalizedPath = path.startsWith("/") ? path : `/${path}`;

  if (!base) {
    return normalizedPath;
  }

  // Prevent duplicate /api/v1 if base URL already includes it
  if (base.endsWith("/api/v1") && normalizedPath.startsWith("/api/v1")) {
    return `${base}${normalizedPath.substring(7)}`;
  }

  return `${base}${normalizedPath}`;
}
