import { accessToken } from "../auth/oidc";

// Every API response is an envelope: { data, error, meta }.
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

export class ApiError extends Error {
  constructor(
    readonly status: number,
    readonly body: ApiErrorBody,
    readonly requestId?: string,
  ) {
    super(body.message);
  }
}

export async function api<T>(path: string, init: RequestInit = {}): Promise<T> {
  const token = await accessToken();
  const res = await fetch(`/api/v1${path}`, {
    ...init,
    headers: {
      Accept: "application/json",
      ...(init.body ? { "Content-Type": "application/json" } : {}),
      ...(token ? { Authorization: `Bearer ${token}` } : {}),
      ...init.headers,
    },
  });
  const env = (await res.json()) as Envelope<T>;
  if (!res.ok || env.error) {
    throw new ApiError(res.status, env.error ?? { code: "HTTP_ERROR", message: res.statusText }, env.meta?.request_id);
  }
  return env.data as T;
}
