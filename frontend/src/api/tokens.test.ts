// The full API token (`secret`) is shown once, in the create dialog, and kept only in that
// dialog's component state. These tests check the parts that could leak it: the TanStack
// Query caches (query and mutation), browser storage, the console, and the dialog's state
// after it closes.
import { MutationObserver, QueryClient } from "@tanstack/react-query";
import { afterEach, beforeEach, describe, expect, it, vi } from "vitest";
import { createTokenMutation } from "./hooks/tokens";
import { qk } from "./keys";
import type { ApiToken } from "./types";
import { INITIAL_TOKEN_DIALOG, maskedToken, tokenDialogReducer, validateTokenForm } from "../routes/settings/Tokens";

const ORG = "00000000-0000-4000-8000-000000000001";
const PROJECT = "00000000-0000-4000-8000-00000000000a";
// Built at test time, never committed as a literal (CLAUDE.md).
const PREFIX = "abcdefgh";
const SECRET = `wdn_${PREFIX}_${Array.from({ length: 52 }, (_, i) => "abcdefghijklmnopqrstuvwxyz234567"[(i * 7) % 32]).join("")}`;

const token: ApiToken = {
  id: "00000000-0000-4000-8000-0000000000f9",
  name: "CI",
  prefix: PREFIX,
  scopes: ["scan:write"],
  created_by: { id: "u1", email: "linh@acme.example", display_name: "Linh Tran" },
  created_at: "2026-10-26T10:00:00Z",
  expires_at: "2026-11-25T10:00:00Z",
  last_used_at: null,
  revoked_at: null,
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

describe("API token secret", () => {
  let local: ReturnType<typeof memoryStorage>;
  let session: ReturnType<typeof memoryStorage>;
  const consoleCalls: unknown[][] = [];

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
        expect(url).toBe(`/api/v1/orgs/${ORG}/projects/${PROJECT}/tokens`);
        expect(init.method).toBe("POST");
        return new Response(JSON.stringify({ data: { token, secret: SECRET }, error: null, meta: { request_id: "r1" } }), {
          status: 201,
          headers: { "Content-Type": "application/json" },
        });
      }),
    );
  });

  afterEach(() => {
    vi.unstubAllGlobals();
    vi.restoreAllMocks();
    consoleCalls.length = 0;
  });

  it("goes to the dialog only, never into the query or mutation cache, storage or the console", async () => {
    const qc = new QueryClient();
    qc.setQueryData(qk.tokens(ORG, PROJECT), { items: [] });
    let delivered: string | null = null;
    const observer = new MutationObserver(qc, createTokenMutation(qc, ORG, PROJECT, (s) => (delivered = s)));

    const result = await observer.mutate({ name: "CI", scopes: ["scan:write"], expires_in_days: 30 });

    expect(delivered).toBe(SECRET);
    expect(result).toEqual(token);
    expect(JSON.stringify(result)).not.toContain(SECRET);

    const queries = qc.getQueryCache().getAll().map((q) => ({ key: q.queryKey, state: q.state }));
    const mutations = qc.getMutationCache().getAll().map((m) => ({ state: m.state, options: { ...m.options, mutationFn: undefined } }));
    const dump = JSON.stringify({ queries, mutations });
    expect(mutations).toHaveLength(1);
    expect(dump).not.toContain(SECRET);
    // Not even the secret part without its prefix.
    expect(dump).not.toContain(SECRET.slice(`wdn_${PREFIX}_`.length));

    expect(local.setItem).not.toHaveBeenCalled();
    expect(session.setItem).not.toHaveBeenCalled();
    expect(JSON.stringify(consoleCalls)).not.toContain(SECRET);
  });

  it("is dropped from the dialog state when the dialog closes", () => {
    let s = tokenDialogReducer(INITIAL_TOKEN_DIALOG, { type: "secret", secret: SECRET });
    s = tokenDialogReducer(s, { type: "created", token });
    expect(s.secret).toBe(SECRET);
    s = tokenDialogReducer(s, { type: "close" });
    expect(s).toEqual({ secret: null, token: null });
    expect(JSON.stringify(s)).not.toContain(SECRET);
  });

  it("lists show only the prefix", () => {
    expect(maskedToken(PREFIX)).toBe("wdn_abcdefgh_…");
  });

  it("validates the create form before sending", () => {
    expect(validateTokenForm("", ["scan:write"]).name).toBeDefined();
    expect(validateTokenForm("x".repeat(81), ["scan:write"]).name).toMatch(/80/);
    expect(validateTokenForm("CI", []).scopes).toBeDefined();
    expect(validateTokenForm("  CI  ", ["issues:read"])).toEqual({});
  });
});
