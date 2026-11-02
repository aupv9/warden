import { describe, expect, it, vi } from "vitest";
import type { Fetcher, WebConfigRules } from "./webConfig";
import { loadWebConfig, parseWebConfig, WebConfigError } from "./webConfig";

// GET /web-config decides where the browser sends people to sign in, so a hostile or broken
// answer (a proxy page, a tampered body, a plain-http issuer) must never become a UserManager.

const PROD: WebConfigRules = { allowLoopbackHttp: false };
const DEV: WebConfigRules = { allowLoopbackHttp: true };

const good = { issuer: "https://id.example.com/realms/warden", client_id: "warden-web", scope: "openid profile email", audience: null };
const env = (data: unknown, extra: Record<string, unknown> = {}) => ({ data, error: null, meta: { request_id: "r1" }, ...extra });
const withField = (k: string, v: unknown) => env({ ...good, [k]: v });
const without = (k: string) => {
  const d: Record<string, unknown> = { ...good };
  delete d[k];
  return env(d);
};

function json(body: unknown, init: ResponseInit = {}): Response {
  return new Response(JSON.stringify(body), { status: 200, headers: { "Content-Type": "application/json" }, ...init });
}

describe("parseWebConfig", () => {
  it("accepts the contract's shape", () => {
    expect(parseWebConfig(env(good), PROD)).toEqual(good);
    const auth0 = { ...good, issuer: "https://acme.eu.auth0.com/", scope: "openid profile email api://warden/access", audience: "https://warden.acme.example/api" };
    expect(parseWebConfig(env(auth0), PROD)).toEqual(auth0);
  });

  it("ignores unknown extra fields and returns only the four it knows", () => {
    expect(parseWebConfig(env({ ...good, extra: "<script>" }), PROD)).toEqual(good);
  });

  it("allows a plain-http issuer only on a loopback host, and only when the rules allow it", () => {
    for (const issuer of ["http://localhost:8180/realms/warden", "http://127.0.0.1:8180/realms/warden", "http://[::1]:8180/realms/warden"]) {
      expect(parseWebConfig(withField("issuer", issuer), DEV).issuer).toBe(issuer);
      expect(() => parseWebConfig(withField("issuer", issuer), PROD)).toThrow(WebConfigError);
    }
    for (const issuer of ["http://id.example.com/realms/warden", "http://localhost.evil.example/", "http://127.0.0.1.nip.io/", "http://10.0.0.5/"]) {
      expect(() => parseWebConfig(withField("issuer", issuer), DEV)).toThrow(WebConfigError);
    }
  });

  const bad: [string, unknown][] = [
    ["not an object", "issuer=https://id.example.com"],
    ["null", null],
    ["an array", [env(good)]],
    ["an error envelope", { data: null, error: { code: "INTERNAL", message: "x" } }],
    ["data and an error", env(good, { error: { code: "INTERNAL", message: "x" } })],
    ["no data", { error: null }],
    ["data null", env(null)],
    ["data an array", env([good])],
    ["data a string", env(JSON.stringify(good))],
    // issuer
    ["issuer missing", without("issuer")],
    ["issuer null", withField("issuer", null)],
    ["issuer a number", withField("issuer", 1)],
    ["issuer empty", withField("issuer", "")],
    ["issuer not a URL", withField("issuer", "id.example.com/realms/warden")],
    ["issuer relative", withField("issuer", "/realms/warden")],
    ["issuer javascript:", withField("issuer", "javascript:alert(1)//https://id.example.com")],
    ["issuer data:", withField("issuer", "data:text/html,<script>alert(1)</script>")],
    ["issuer ftp:", withField("issuer", "ftp://id.example.com/")],
    ["issuer plain http", withField("issuer", "http://id.example.com/realms/warden")],
    ["issuer with credentials", withField("issuer", "https://user:pw@id.example.com/realms/warden")],
    ["issuer with a user only", withField("issuer", "https://evil.example@id.example.com/")],
    ["issuer with a query", withField("issuer", "https://id.example.com/realms/warden?x=1")],
    ["issuer with an empty query", withField("issuer", "https://id.example.com/realms/warden?")],
    ["issuer with a fragment", withField("issuer", "https://id.example.com/realms/warden#x")],
    ["issuer with leading space", withField("issuer", " https://id.example.com/")],
    ["issuer with a newline", withField("issuer", "https://id.example.com/\nrealms")],
    ["issuer with a tab", withField("issuer", "https://id.exa\tmple.com/")],
    ["issuer too long", withField("issuer", `https://id.example.com/${"a".repeat(2100)}`)],
    // client_id
    ["client_id missing", without("client_id")],
    ["client_id null", withField("client_id", null)],
    ["client_id empty", withField("client_id", "")],
    ["client_id a number", withField("client_id", 7)],
    ["client_id with leading space", withField("client_id", " warden-web")],
    ["client_id with a control char", withField("client_id", "warden\u0000web")],
    ["client_id with a newline", withField("client_id", "warden\nweb")],
    ["client_id non-ASCII", withField("client_id", "wardén")],
    ["client_id too long", withField("client_id", "a".repeat(256))],
    // scope
    ["scope missing", without("scope")],
    ["scope null", withField("scope", null)],
    ["scope empty", withField("scope", "")],
    ["scope an array", withField("scope", ["openid"])],
    ["scope without openid", withField("scope", "profile email")],
    ["scope with openid only as part of a word", withField("scope", "openidx profile")],
    ["scope with two spaces", withField("scope", "openid  profile")],
    ["scope with a trailing space", withField("scope", "openid ")],
    ["scope with a tab", withField("scope", "openid\tprofile")],
    ["scope with a quote", withField("scope", 'openid "profile"')],
    ["scope with a backslash", withField("scope", "openid pro\\file")],
    ["scope too long", withField("scope", `openid ${"a".repeat(1100)}`)],
    // audience
    ["audience missing", without("audience")],
    ["audience empty", withField("audience", "")],
    ["audience a number", withField("audience", 1)],
    ["audience an object", withField("audience", {})],
    ["audience false", withField("audience", false)],
    ["audience with surrounding space", withField("audience", " warden-api ")],
    ["audience with a newline", withField("audience", "warden\napi")],
    ["audience too long", withField("audience", "a".repeat(1025))],
  ];

  it.each(bad)("rejects %s", (_name, body) => {
    expect(() => parseWebConfig(body, DEV)).toThrow(WebConfigError);
  });

  it("the error carries no detail from the response", () => {
    let err: unknown;
    try {
      parseWebConfig(withField("issuer", "http://attacker.example/secret-path"), PROD);
    } catch (e) {
      err = e;
    }
    expect(err).toBeInstanceOf(WebConfigError);
    expect(String(err)).not.toContain("attacker");
    expect(JSON.stringify(err)).not.toContain("attacker");
  });
});

describe("loadWebConfig", () => {
  it("asks the same origin, with no token and no cookies, and refuses redirects", async () => {
    const f = vi.fn<Fetcher>(async () => json(env(good)));
    await expect(loadWebConfig(f, PROD)).resolves.toEqual(good);
    expect(f).toHaveBeenCalledTimes(1);
    const [url, init] = f.mock.calls[0]!;
    expect(url).toBe("/api/v1/web-config");
    expect(init.method).toBe("GET");
    expect(init.credentials).toBe("omit");
    expect(init.redirect).toBe("error");
    expect(init.signal).toBeInstanceOf(AbortSignal);
    const headers = new Headers(init.headers);
    expect(headers.has("Authorization")).toBe(false);
    expect(headers.has("Cookie")).toBe(false);
  });

  it("network failure, a redirect refused by fetch, or a timeout is a WebConfigError", async () => {
    await expect(loadWebConfig(async () => Promise.reject(new TypeError("Failed to fetch")), PROD)).rejects.toBeInstanceOf(WebConfigError);
    await expect(loadWebConfig(async () => Promise.reject(new DOMException("timed out", "TimeoutError")), PROD)).rejects.toBeInstanceOf(WebConfigError);
  });

  it.each([
    ["a 500", () => json({ data: null, error: { code: "INTERNAL", message: "x" } }, { status: 500 })],
    ["a 404 (an older server)", () => json({ data: null, error: { code: "NOT_FOUND", message: "x" } }, { status: 404 })],
    ["a 204", () => new Response(null, { status: 204 })],
    ["a 201 with a valid body", () => json(env(good), { status: 201 })],
    ["an HTML page with status 200 (a proxy or the SPA fallback)", () => new Response("<!doctype html><title>Login</title>", { status: 200, headers: { "Content-Type": "text/html" } })],
    ["JSON with no Content-Type", () => new Response(JSON.stringify(env(good)), { status: 200 })],
    ["broken JSON", () => new Response("{", { status: 200, headers: { "Content-Type": "application/json" } })],
    ["an invalid body", () => json(withField("issuer", "http://id.example.com/"))],
  ])("%s is a WebConfigError", async (_name, res) => {
    await expect(loadWebConfig(async () => res(), DEV)).rejects.toBeInstanceOf(WebConfigError);
  });
});
