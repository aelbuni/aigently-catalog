import createClient from "openapi-fetch";

import type { paths } from "./generated.js";

export type { paths, components } from "./generated.js";

export type ApiClient = ReturnType<typeof createClient<paths>>;

/** Browser or server: pass the public or internal base URL (no trailing slash required). */
export function createBrowserApiClient(baseUrl: string): ApiClient {
  return createClient<paths>({ baseUrl: baseUrl.replace(/\/$/, "") });
}

/**
 * Server-side (RSC, Route Handlers): forwards session cookies when callers pass
 * `Cookie` from `headers().get("cookie")` so future session-bound API routes work.
 */
export function createServerApiClient(
  baseUrl: string,
  options?: { cookieHeader?: string | null }
): ApiClient {
  const root = baseUrl.replace(/\/$/, "");
  const cookie = options?.cookieHeader?.trim();
  return createClient<paths>({
    baseUrl: root,
    ...(cookie ? { headers: { Cookie: cookie } } : {}),
  });
}
