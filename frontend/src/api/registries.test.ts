// A registry password or token is typed once and never read back: the API doesn't return it, and
// the form drops it once submitted (lib/registries.test.ts). These tests check the other places
// it could stay: TanStack Query's query and mutation caches (including mutation variables),
// browser storage, the console and the query keys. Same rules as webhook URLs (webhooks.test.ts).
import { MutationObserver, QueryClient } from "@tanstack/react-query";
import { afterEach, beforeEach, describe, expect, it, vi } from "vitest";
import { createRegistryMutation, updateRegistryMutation } from "./hooks/registries";
import { qk } from "./keys";
import type { RegistryCredential } from "./types";

const ORG = "00000000-0000-4000-8000-000000000001";
const REG = "00000000-0000-4000-8000-0000000000c1";
// Built at test time, never committed as literals (CLAUDE.md).
const PASSWORD = ["ghp", Array.from({ length: 36 }, (_, i) => "abcdefghijklmnopqrstuvwxyz0123456789"[(i * 11 + 5) % 36]).join("")].join("_");
const NEW_PASSWORD = ["glpat", Array.from({ length: 20 }, (_, i) => "ABCDEFGHJKLMNPQRSTUVWXYZ"[(i * 7 + 3) % 24]).join("")].join("-");

const cred: RegistryCredential = {
  id: REG,
  host: "ghcr.io",
  username: "acme-bot",
  created_by: { id: "u1", email: "linh@acme.example", display_name: "Linh Tran" },
  created_at: "2026-11-01T10:00:00Z",
  updated_at: "2026-11-01T10:00:00Z",
  last_used_at: null,
  last_error: null,
};

function memoryStorage() {
  const data = new Map<string, string>();
  return {
    setItem: vi.fn((k: string, v: string) => void data.set(k, v)),
    getItem: vi.fn((k: string) => data.get(k) ?? null),
    removeItem: vi.fn((k: string) => void data.delete(k)),
    clear: vi.fn(() => data.clear()),
    key: vi.fn(() => null),
    get length() {
      return data.size;
    },
  };
}

function cacheDump(qc: QueryClient): string {
  const queries = qc.getQueryCache().getAll().map((q) => ({ key: q.queryKey, state: q.state }));
  const mutations = qc.getMutationCache().getAll().map((m) => ({ state: m.state, options: { ...m.options, mutationFn: undefined } }));
  return JSON.stringify({ queries, mutations });
}

describe("registry password", () => {
  let local: ReturnType<typeof memoryStorage>;
  let session: ReturnType<typeof memoryStorage>;
  const consoleCalls: unknown[][] = [];
  const sent: { url: string; method: string; body: string | undefined }[] = [];

  beforeEach(() => {
    local = memoryStorage();
    session = memoryStorage();
    vi.stubGlobal("localStorage", local);
    vi.stubGlobal("sessionStorage", session);
    for (const m of ["log", "info", "warn", "error", "debug"] as const) {
      vi.spyOn(console, m).mockImplementation((...a: unknown[]) => void consoleCalls.push(a));
    }
    vi.stubGlobal(
      "fetch",
      vi.fn(async (url: string, init: RequestInit) => {
        sent.push({ url, method: String(init.method), body: init.body as string | undefined });
        const reply = (data: unknown, status = 200) =>
          new Response(JSON.stringify(status >= 400 ? { data: null, error: data, meta: { request_id: "r1" } } : { data, error: null, meta: { request_id: "r1" } }), {
            status,
            headers: { "Content-Type": "application/json" },
          });
        if (url === `/api/v1/orgs/${ORG}/registries` && init.method === "POST") {
          const body = JSON.parse(String(init.body)) as { host: string };
          if (body.host === "fail.example") return reply({ code: "SECRETS_KEY_MISSING", message: "no key" }, 409);
          return reply(cred, 201);
        }
        if (url === `/api/v1/orgs/${ORG}/registries/${REG}` && init.method === "PATCH") return reply(cred);
        return reply({ code: "INTERNAL", message: "x" }, 500);
      }),
    );
  });

  afterEach(() => {
    vi.unstubAllGlobals();
    vi.restoreAllMocks();
    consoleCalls.length = 0;
    sent.length = 0;
  });

  it("create: sent once in the body; never in a cache, storage or the console", async () => {
    const qc = new QueryClient();
    qc.setQueryData(qk.registries(ORG), { items: [] });
    const observer = new MutationObserver(qc, createRegistryMutation(qc, ORG, () => ({ host: "ghcr.io", username: "acme-bot", password: PASSWORD })));
    const result = await observer.mutate();
    expect(result).toEqual(cred);
    expect(sent).toHaveLength(1);
    expect(sent[0]!.body).toContain(PASSWORD);
    expect(cacheDump(qc)).not.toContain(PASSWORD);
    expect(qc.getMutationCache().getAll()[0]!.state.variables).toBeUndefined();
    expect(local.setItem).not.toHaveBeenCalled();
    expect(session.setItem).not.toHaveBeenCalled();
    expect(JSON.stringify(consoleCalls)).not.toContain(PASSWORD);
  });

  it("create that fails (409 SECRETS_KEY_MISSING): the error and the caches hold no password", async () => {
    const qc = new QueryClient();
    const observer = new MutationObserver(qc, createRegistryMutation(qc, ORG, () => ({ host: "fail.example", username: "u", password: PASSWORD })));
    await expect(observer.mutate()).rejects.toMatchObject({ code: "SECRETS_KEY_MISSING" });
    expect(cacheDump(qc)).not.toContain(PASSWORD);
    expect(JSON.stringify(observer.getCurrentResult().error)).not.toContain(PASSWORD);
    expect(JSON.stringify(consoleCalls)).not.toContain(PASSWORD);
  });

  it("change: a new password is sent but not kept in the mutation cache", async () => {
    const qc = new QueryClient();
    const observer = new MutationObserver(qc, updateRegistryMutation(qc, ORG, REG, () => ({ password: NEW_PASSWORD })));
    await observer.mutate();
    expect(sent[0]).toMatchObject({ method: "PATCH", url: `/api/v1/orgs/${ORG}/registries/${REG}` });
    expect(sent[0]!.body).toBe(JSON.stringify({ password: NEW_PASSWORD }));
    expect(cacheDump(qc)).not.toContain(NEW_PASSWORD);
  });

  it("query keys never carry a password", () => {
    expect(qk.registries(ORG)).toEqual(["org", ORG, "registries"]);
  });
});
