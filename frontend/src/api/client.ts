import { accessToken, refreshAccessToken } from "../auth/oidc";
import { reportMfaRequired } from "../lib/mfa";
import { isMockMode, transport } from "./transport";

export { isMockMode };

// Every API response is common-go's envelope: { data, error, meta }.
export interface ApiErrorBody {
  code: string;
  message: string;
  metadata?: Record<string, unknown>;
}

export interface Envelope<T> {
  data: T | null;
  error: ApiErrorBody | null;
  meta?: { request_id?: string; trace_id?: string };
}

/** Client-side codes for failures that never reached (or never came back from) the API. */
export const NETWORK_ERROR = "NETWORK_ERROR";
export const HTTP_ERROR = "HTTP_ERROR";

export class ApiError extends Error {
  constructor(
    readonly status: number,
    readonly body: ApiErrorBody,
    readonly requestId?: string,
    /** Seconds, from a 429's Retry-After header. */
    readonly retryAfter?: number,
  ) {
    super(body.message);
    this.name = "ApiError";
  }

  get code(): string {
    return this.body.code;
  }
}

export function isApiError(err: unknown, code?: string): err is ApiError {
  return err instanceof ApiError && (code === undefined || err.code === code);
}

export type QueryValue = string | number | boolean | null | undefined | readonly string[];
export type QueryParams = Record<string, QueryValue>;

/** Builds "?a=1&status=x&status=y". Empty values and `false` are left out. */
export function buildQuery(params: QueryParams | undefined): string {
  if (!params) return "";
  const sp = new URLSearchParams();
  for (const [key, value] of Object.entries(params)) {
    if (value === undefined || value === null || value === "" || value === false) continue;
    if (Array.isArray(value)) {
      for (const v of value) sp.append(key, v);
    } else {
      sp.append(key, String(value));
    }
  }
  const s = sp.toString();
  return s ? `?${s}` : "";
}

export interface ApiOptions {
  method?: "GET" | "POST" | "PUT" | "PATCH" | "DELETE";
  body?: unknown;
  query?: QueryParams;
  signal?: AbortSignal;
}

export interface ApiDeps {
  getToken(): Promise<string | null>;
  refreshToken(): Promise<string | null>;
}

const defaultDeps: ApiDeps = {
  getToken: () => (isMockMode ? Promise.resolve(null) : accessToken()),
  refreshToken: () => (isMockMode ? Promise.resolve(null) : refreshAccessToken()),
};

/** Sends the request with the bearer token, refreshing it once on 401 (DESIGN.md). The token
 *  only ever travels in the Authorization header, never in the URL. */
async function request(path: string, opts: ApiOptions, deps: ApiDeps, accept: string): Promise<Response> {
  const send = async (token: string | null): Promise<Response> => {
    const headers: Record<string, string> = { Accept: accept };
    if (opts.body !== undefined) headers["Content-Type"] = "application/json";
    if (token) headers.Authorization = `Bearer ${token}`;
    try {
      return await transport(`/api/v1${path}${buildQuery(opts.query)}`, {
        method: opts.method ?? "GET",
        headers,
        body: opts.body === undefined ? undefined : JSON.stringify(opts.body),
        signal: opts.signal,
        // The API is same-origin and uses bearer tokens, not cookies.
        credentials: "omit",
      });
    } catch (err) {
      if (err instanceof DOMException && err.name === "AbortError") throw err;
      throw new ApiError(0, { code: NETWORK_ERROR, message: "network error" });
    }
  };

  const token = await deps.getToken();
  let res = await send(token);
  // DESIGN.md: on 401 try one silent token refresh and repeat the request once.
  if (res.status === 401 && token) {
    const fresh = await deps.refreshToken();
    if (fresh) res = await send(fresh);
  }
  return res;
}

function errorFrom(res: Response, env: Envelope<unknown> | null, path: string): ApiError {
  // The org's MFA rule: the org layout swaps in its full-page explanation (lib/mfa.ts).
  if (env?.error?.code === "MFA_REQUIRED") reportMfaRequired(path);
  return new ApiError(
    res.status,
    env?.error ?? { code: HTTP_ERROR, message: res.statusText || `HTTP ${res.status}` },
    env?.meta?.request_id ?? res.headers.get("X-Request-ID") ?? undefined,
    parseRetryAfter(res.headers.get("Retry-After")),
  );
}

async function readEnvelope<T>(res: Response): Promise<Envelope<T> | null> {
  try {
    return (await res.json()) as Envelope<T>;
  } catch {
    // Not JSON (e.g. a proxy error page). Never surface its body: treat it as a bare HTTP error.
    return null;
  }
}

export async function api<T>(path: string, opts: ApiOptions = {}, deps: ApiDeps = defaultDeps): Promise<T> {
  const res = await request(path, opts, deps, "application/json");
  if (res.status === 204) return undefined as T;
  const env = await readEnvelope<T>(res);
  if (!res.ok || !env || env.error) throw errorFrom(res, env, path);
  return env.data as T;
}

/** v0.5: a file the API answers with (the issue list as CSV). The body is handed back as a Blob
 *  and never read or parsed here; errors still come as the JSON envelope. */
export async function apiFile(
  path: string,
  opts: ApiOptions & { accept: string },
  deps: ApiDeps = defaultDeps,
): Promise<{ blob: Blob; headers: Headers }> {
  const res = await request(path, opts, deps, opts.accept);
  if (!res.ok) throw errorFrom(res, await readEnvelope(res), path);
  return { blob: await res.blob(), headers: res.headers };
}

/** Retry-After in seconds (the API sends seconds; an HTTP date is also accepted). */
export function parseRetryAfter(value: string | null, now: number = Date.now()): number | undefined {
  if (!value) return undefined;
  if (/^\d+$/.test(value.trim())) return Number(value.trim());
  const at = Date.parse(value);
  return Number.isNaN(at) ? undefined : Math.max(0, Math.ceil((at - now) / 1000));
}
