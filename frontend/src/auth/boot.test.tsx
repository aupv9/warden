import { InMemoryWebStorage, UserManager } from "oidc-client-ts";
import { renderToString } from "react-dom/server";
import { afterEach, beforeEach, describe, expect, it, vi } from "vitest";
import { AuthBoot } from "./AuthGate";
import type { Boot } from "./boot";
import { createBoot, runBoot } from "./boot";
import { createUserManager, getUserManager } from "./oidc";

// src/test/setup.ts replaces auth/oidc for the screen tests; here the real one runs against a
// stubbed fetch, so this is the startup path the browser takes.
vi.unmock("./oidc");

const flush = () => new Promise((r) => setTimeout(r, 0));
const good = { issuer: "https://id.example.com/realms/warden", client_id: "warden-web", scope: "openid profile email", audience: "warden-api" };
const ok = () => new Response(JSON.stringify({ data: good, error: null }), { status: 200, headers: { "Content-Type": "application/json" } });

const text = (html: string) => html.replace(/<[^>]+>/g, " ").replace(/&#x27;/g, "'").replace(/\s+/g, " ");
const page = (boot: Boot) => renderToString(<AuthBoot boot={boot}>{(failed) => <p>app ready, sign-in failed: {String(failed)}</p>}</AuthBoot>);

let fetchMock: ReturnType<typeof vi.fn<typeof fetch>>;
let logged: unknown[];

beforeEach(() => {
  vi.stubGlobal("window", {
    location: { origin: "https://warden.example.com", hostname: "warden.example.com", search: "", pathname: "/" },
    localStorage: new InMemoryWebStorage(),
    sessionStorage: new InMemoryWebStorage(),
    history: { replaceState: vi.fn() },
  });
  fetchMock = vi.fn<typeof fetch>();
  vi.stubGlobal("fetch", fetchMock);
  logged = [];
  for (const level of ["log", "info", "warn", "error", "debug"] as const) {
    vi.spyOn(console, level).mockImplementation((...a) => logged.push(a));
  }
});

afterEach(() => {
  vi.restoreAllMocks();
  vi.unstubAllGlobals();
});

describe("createBoot", () => {
  it("starts once, even if asked twice (StrictMode runs effects twice)", async () => {
    const run = vi.fn(async () => ({ authFailed: false }));
    const boot = createBoot(run);
    expect(boot.getState()).toEqual({ status: "loading" });
    boot.start();
    boot.start();
    await flush();
    expect(run).toHaveBeenCalledTimes(1);
    expect(boot.getState()).toEqual({ status: "ready", authFailed: false });
    boot.retry(); // not after success
    expect(run).toHaveBeenCalledTimes(1);
  });

  it("a failure shows the error state; Try again runs again and notifies", async () => {
    const run = vi.fn<() => Promise<{ authFailed: boolean }>>().mockRejectedValueOnce(new Error("boom")).mockResolvedValueOnce({ authFailed: true });
    const boot = createBoot(run);
    const seen: string[] = [];
    boot.subscribe(() => seen.push(boot.getState().status));
    boot.start();
    await flush();
    expect(boot.getState()).toEqual({ status: "error" });
    boot.retry();
    expect(boot.getState()).toEqual({ status: "loading" });
    await flush();
    expect(boot.getState()).toEqual({ status: "ready", authFailed: true });
    expect(seen).toEqual(["error", "loading", "ready"]);
  });
});

describe("startup against GET /web-config", () => {
  it("network failure → the error page; Try again → the app, with a UserManager built from the answer", async () => {
    fetchMock.mockRejectedValueOnce(new TypeError("Failed to fetch"));
    const boot = createBoot(runBoot);
    expect(text(page(boot))).toContain("Loading Warden");

    boot.start();
    await flush();
    expect(boot.getState().status).toBe("error");
    const html = page(boot);
    const t = text(html);
    expect(t).toContain("Can't reach the server's sign-in settings");
    expect(t).toContain("contact your Warden operator");
    expect(t).toContain("Try again");
    expect(html).toContain('role="alert"');
    // No technical detail on the page, and nothing logged.
    expect(t).not.toMatch(/Failed to fetch|TypeError|web-config|\/api\//);
    expect(logged).toEqual([]);

    fetchMock.mockResolvedValueOnce(ok());
    boot.retry();
    await flush();
    expect(boot.getState()).toEqual({ status: "ready", authFailed: false });
    expect(text(page(boot))).toContain("app ready, sign-in failed: false");

    // Same origin, no token, no cookies.
    expect(fetchMock).toHaveBeenCalledTimes(2);
    const [url, init] = fetchMock.mock.calls[1]!;
    expect(url).toBe("/api/v1/web-config");
    expect(init?.credentials).toBe("omit");
    expect(new Headers(init?.headers).has("Authorization")).toBe(false);

    // The UserManager uses exactly the server's values; tokens stay in memory.
    const um = await getUserManager();
    expect(um).toBeInstanceOf(UserManager);
    expect(um.settings.authority).toBe(good.issuer);
    expect(um.settings.client_id).toBe(good.client_id);
    expect(um.settings.scope).toBe(good.scope);
    expect(um.settings.extraQueryParams).toEqual({ audience: "warden-api" });
    expect(um.settings.redirect_uri).toBe("https://warden.example.com/");
    expect(um.settings.response_type).toBe("code");
    expect((um.settings.userStore as unknown as { _store: unknown })._store).toBeInstanceOf(InMemoryWebStorage);
    // Fetched once: later callers share it.
    expect(await getUserManager()).toBe(um);
    expect(fetchMock).toHaveBeenCalledTimes(2);
  });

  it("a sign-in redirect that can't be completed is the generic sign-in failure, and the code leaves the URL", async () => {
    // getUserManager() is already built by the test above; no stored state matches this one.
    window.location.search = "?code=abc&state=nope";
    const boot = createBoot(runBoot);
    boot.start();
    await vi.waitFor(() => expect(boot.getState().status).toBe("ready"));
    expect(boot.getState()).toEqual({ status: "ready", authFailed: true });
    expect(window.history.replaceState).toHaveBeenCalledWith({}, "", "/");
    expect(logged).toEqual([]);
  });

  it("audience null sends no audience parameter", () => {
    const um = createUserManager({ ...good, audience: null });
    expect(um.settings.extraQueryParams).toEqual({});
  });
});

describe("startup with a bad answer", () => {
  it.each([
    ["a 500", () => new Response(JSON.stringify({ data: null, error: { code: "INTERNAL", message: "x" } }), { status: 500, headers: { "Content-Type": "application/json" } })],
    ["a plain-http issuer", () => new Response(JSON.stringify({ data: { ...good, issuer: "http://id.example.com/" }, error: null }), { status: 200, headers: { "Content-Type": "application/json" } })],
    ["an HTML page", () => new Response("<html></html>", { status: 200, headers: { "Content-Type": "text/html" } })],
  ])("%s → the error page", async (_name, res) => {
    vi.resetModules();
    const fresh = await import("./boot");
    const AuthGate = await import("./AuthGate");
    fetchMock.mockResolvedValueOnce(res());
    const boot = fresh.createBoot(fresh.runBoot);
    boot.start();
    await flush();
    expect(boot.getState()).toEqual({ status: "error" });
    const html = renderToString(<AuthGate.AuthBoot boot={boot}>{() => <p>APP-RENDERED</p>}</AuthGate.AuthBoot>);
    expect(text(html)).toContain("Can't reach the server's sign-in settings");
    expect(text(html)).not.toContain("APP-RENDERED");
    expect(logged).toEqual([]);
  });
});
