import { accessToken, refreshAccessToken } from "../auth/oidc";

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

// Dev-only mock transport (VITE_MOCK=1 with `npm run dev`). `import.meta.env.DEV` is replaced by
// `false` in production builds, so this branch and the dynamic import of the fixtures are removed
// from the bundle; `npm run build` must never contain mock data (checked in the build notes).
const MOCK = import.meta.env.DEV && import.meta.env.VITE_MOCK === "1";
let mockFetch: Promise<typeof fetch> | undefined;

function transport(url: string, init: RequestInit): Promise<Response> {
  if (MOCK) {
    mockFetch ??= import("./mock/server").then((m) => m.mockFetch);
    return mockFetch.then((f) => f(url, init));
  }
  return fetch(url, init);
}

export const isMockMode = MOCK;

export interface ApiDeps {
  getToken(): Promise<string | null>;
  refreshToken(): Promise<string | null>;
}

const defaultDeps: ApiDeps = {
  getToken: () => (MOCK ? Promise.resolve(null) : accessToken()),
  refreshToken: () => (MOCK ? Promise.resolve(null) : refreshAccessToken()),
};

export async function api<T>(path: string, opts: ApiOptions = {}, deps: ApiDeps = defaultDeps): Promise<T> {
  const send = async (token: string | null): Promise<Response> => {
    const headers: Record<string, string> = { Accept: "application/json" };
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

  if (res.status === 204) return undefined as T;

  let env: Envelope<T> | null = null;
  try {
    env = (await res.json()) as Envelope<T>;
  } catch {
    // Not JSON (e.g. a proxy error page). Never surface its body: treat it as a bare HTTP error.
  }
  if (!res.ok || !env || env.error) {
    throw new ApiError(
      res.status,
      env?.error ?? { code: HTTP_ERROR, message: res.statusText || `HTTP ${res.status}` },
      env?.meta?.request_id ?? res.headers.get("X-Request-ID") ?? undefined,
      parseRetryAfter(res.headers.get("Retry-After")),
    );
  }
  return env.data as T;
}

/** Retry-After in seconds (the API sends seconds; an HTTP date is also accepted). */
export function parseRetryAfter(value: string | null, now: number = Date.now()): number | undefined {
  if (!value) return undefined;
  if (/^\d+$/.test(value.trim())) return Number(value.trim());
  const at = Date.parse(value);
  return Number.isNaN(at) ? undefined : Math.max(0, Math.ceil((at - now) / 1000));
}
