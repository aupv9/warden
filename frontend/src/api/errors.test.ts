import { afterEach, describe, expect, it, vi } from "vitest";
import { api, ApiError, buildQuery, NETWORK_ERROR, parseRetryAfter } from "./client";
import {
  errorMessage,
  fieldErrors,
  isForbidden,
  isNotFound,
  isToastedActionError,
  leftoverFieldErrors,
  supportReference,
  waitText,
} from "./errors";

const err = (status: number, code: string, extra: Partial<{ requestId: string; retryAfter: number; metadata: Record<string, unknown> }> = {}) =>
  new ApiError(status, { code, message: "server text that must not be shown", metadata: extra.metadata }, extra.requestId, extra.retryAfter);

describe("error code → message", () => {
  it("maps each contract code to readable text, never the server's message", () => {
    for (const code of ["UNAUTHORIZED", "FORBIDDEN", "NOT_FOUND", "VALIDATION_FAILED", "CONFLICT", "VERSION_CONFLICT", "INVALID_TRANSITION", "USER_NOT_FOUND", "UPLOAD_MISMATCH", "RATE_LIMITED"]) {
      const m = errorMessage(err(400, code));
      expect(m).not.toContain("server text");
      expect(m.length).toBeGreaterThan(10);
    }
  });

  it("keeps sign-in failures generic", () => {
    expect(errorMessage(err(401, "UNAUTHORIZED"))).toBe("We couldn't sign you in. Try again.");
  });

  it("uses the design's wording for conflicts", () => {
    expect(errorMessage(err(409, "VERSION_CONFLICT"))).toMatch(/^Someone changed this issue while you had it open\./);
    expect(errorMessage(err(404, "USER_NOT_FOUND"))).toMatch(/signed in to Warden yet/);
  });

  it("lets a screen override a code", () => {
    expect(errorMessage(err(409, "CONFLICT"), { CONFLICT: "A project with key WEB already exists." })).toBe("A project with key WEB already exists.");
  });

  it("says when to retry after a 429", () => {
    expect(errorMessage(err(429, "RATE_LIMITED", { retryAfter: 120 }))).toBe("Too many requests in a short time. Try again in 2 minutes.");
    expect(waitText(30)).toBe("30 seconds");
    expect(waitText(61)).toBe("2 minutes");
  });

  it("network and 5xx: one message plus the request ID for the operator", () => {
    const e5 = err(503, "INTERNAL", { requestId: "01JBK7" });
    expect(errorMessage(e5)).toMatch(/Warden didn't answer/);
    expect(supportReference(e5)).toBe("01JBK7");
    expect(supportReference(err(403, "FORBIDDEN", { requestId: "x" }))).toBeUndefined();
    expect(errorMessage(new ApiError(0, { code: NETWORK_ERROR, message: "" }))).toMatch(/Warden didn't answer/);
  });

  it("unknown errors and non-API errors get a generic text", () => {
    expect(errorMessage(new Error("boom <script>"))).toBe("Something went wrong. Try again.");
    expect(errorMessage(err(418, "TEAPOT"))).toBe("Something went wrong. Try again.");
  });

  it("splits toasted action errors from inline ones", () => {
    expect(isToastedActionError(err(403, "FORBIDDEN"))).toBe(true);
    expect(isToastedActionError(err(404, "NOT_FOUND"))).toBe(true);
    expect(isToastedActionError(err(429, "RATE_LIMITED"))).toBe(true);
    expect(isToastedActionError(err(500, "INTERNAL"))).toBe(true);
    expect(isToastedActionError(err(409, "VERSION_CONFLICT"))).toBe(false);
    expect(isToastedActionError(err(422, "VALIDATION_FAILED"))).toBe(false);
    expect(isToastedActionError(err(404, "USER_NOT_FOUND"))).toBe(false);
    expect(isNotFound(err(404, "USER_NOT_FOUND"))).toBe(false);
    expect(isForbidden(err(403, "FORBIDDEN"))).toBe(true);
  });

  it("reads per-field messages and keeps only strings", () => {
    const e = err(422, "VALIDATION_FAILED", { metadata: { fields: { key: "bad key", name: 3, extra: "unknown field" } } });
    expect(fieldErrors(e)).toEqual({ key: "bad key", extra: "unknown field" });
    expect(leftoverFieldErrors(e, ["key", "name"])).toEqual(["extra: unknown field"]);
    expect(fieldErrors(err(409, "CONFLICT"))).toEqual({});
  });
});

describe("api() envelope handling", () => {
  afterEach(() => vi.unstubAllGlobals());

  const json = (status: number, body: unknown, headers: Record<string, string> = {}) =>
    new Response(JSON.stringify(body), { status, headers: { "Content-Type": "application/json", ...headers } });

  it("returns data and sends the bearer token, JSON body and no cookies", async () => {
    const fetchMock = vi.fn(async (_url: string, _init: RequestInit) => json(200, { data: { ok: 1 }, error: null, meta: { request_id: "r1" } }));
    vi.stubGlobal("fetch", fetchMock);
    const out = await api<{ ok: number }>("/orgs/o1/projects", { method: "POST", body: { key: "WEB" }, query: { a: "1" } }, {
      getToken: async () => "tok",
      refreshToken: async () => null,
    });
    expect(out).toEqual({ ok: 1 });
    const [url, init] = fetchMock.mock.calls[0]!;
    expect(url).toBe("/api/v1/orgs/o1/projects?a=1");
    expect((init.headers as Record<string, string>).Authorization).toBe("Bearer tok");
    expect(init.body).toBe('{"key":"WEB"}');
    expect(init.credentials).toBe("omit");
  });

  it("throws ApiError with code, status, request ID and Retry-After", async () => {
    vi.stubGlobal("fetch", async () => json(429, { data: null, error: { code: "RATE_LIMITED", message: "x" }, meta: { request_id: "r2" } }, { "Retry-After": "90" }));
    const e = (await api("/x", {}, { getToken: async () => null, refreshToken: async () => null }).catch((x) => x)) as ApiError;
    expect(e).toBeInstanceOf(ApiError);
    expect([e.status, e.code, e.requestId, e.retryAfter]).toEqual([429, "RATE_LIMITED", "r2", 90]);
  });

  it("treats a non-JSON error page as an HTTP error without exposing its body", async () => {
    vi.stubGlobal("fetch", async () => new Response("<html>bad gateway</html>", { status: 502 }));
    const e = (await api("/x").catch((x) => x)) as ApiError;
    expect(e.code).toBe("HTTP_ERROR");
    expect(e.message).not.toContain("<html>");
  });

  it("maps a failed fetch to NETWORK_ERROR", async () => {
    vi.stubGlobal("fetch", async () => {
      throw new TypeError("Failed to fetch");
    });
    const e = (await api("/x").catch((x) => x)) as ApiError;
    expect(e.code).toBe(NETWORK_ERROR);
  });

  it("on 401 refreshes the token once and repeats the request", async () => {
    const seen: string[] = [];
    vi.stubGlobal("fetch", async (_u: string, init: RequestInit) => {
      const auth = (init.headers as Record<string, string>).Authorization ?? "";
      seen.push(auth);
      return auth === "Bearer fresh"
        ? json(200, { data: 1, error: null })
        : json(401, { data: null, error: { code: "UNAUTHORIZED", message: "expired" } });
    });
    const refresh = vi.fn(async () => "fresh");
    expect(await api("/x", {}, { getToken: async () => "old", refreshToken: refresh })).toBe(1);
    expect(seen).toEqual(["Bearer old", "Bearer fresh"]);
    expect(refresh).toHaveBeenCalledOnce();
  });

  it("gives up after one failed refresh", async () => {
    const fetchMock = vi.fn(async () => json(401, { data: null, error: { code: "UNAUTHORIZED", message: "expired" } }));
    vi.stubGlobal("fetch", fetchMock);
    const e = (await api("/x", {}, { getToken: async () => "old", refreshToken: async () => null }).catch((x) => x)) as ApiError;
    expect(e.code).toBe("UNAUTHORIZED");
    expect(fetchMock).toHaveBeenCalledOnce();
  });

  it("returns undefined for 204", async () => {
    vi.stubGlobal("fetch", async () => new Response(null, { status: 204 }));
    expect(await api("/x", { method: "DELETE" })).toBeUndefined();
  });
});

describe("helpers", () => {
  it("buildQuery skips empty values and repeats arrays", () => {
    expect(buildQuery({ a: "", b: undefined, c: false, d: ["x", "y"], e: 0, f: true })).toBe("?d=x&d=y&e=0&f=true");
  });
  it("parseRetryAfter reads seconds and HTTP dates", () => {
    expect(parseRetryAfter("120")).toBe(120);
    expect(parseRetryAfter(new Date(10_000 + 30_000).toUTCString(), 10_000)).toBe(30);
    expect(parseRetryAfter("soon")).toBeUndefined();
    expect(parseRetryAfter(null)).toBeUndefined();
  });
});
