// A snippet pasted into "Test on a snippet" may be real code, even a real secret. It is sent once
// and kept only in the test dialog's state. These tests check the places that could keep it:
// TanStack Query's query and mutation caches (including mutation variables), the query keys,
// browser storage and the console. They also check the result polling: backoff, stopping when
// the run ends, and giving up after 3 minutes.
import { environmentManager, MutationObserver, QueryClient, QueryObserver } from "@tanstack/react-query";
import { afterEach, beforeEach, describe, expect, it, vi } from "vitest";
import { ruleTestMutation, ruleTestQuery } from "./hooks/scanRules";
import { qk } from "./keys";
import type { RuleTest, RuleTestRequest } from "./types";

const ORG = "00000000-0000-4000-8000-000000000001";
const TEST = "00000000-0000-4000-8000-0000000000t1";
// Built at test time, never committed as a literal (CLAUDE.md): something shaped like a token.
const SECRETISH = `acme_tok_${Array.from({ length: 32 }, (_, i) => "abcdefghijklmnopqrstuvwxyz0123456789"[(i * 7 + 3) % 36]).join("")}`;
const SNIPPET = `const a = 1;\nconst key = "${SECRETISH}";\neval(req.body.x);\n`;

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

const reply = (data: unknown, status = 200) =>
  new Response(JSON.stringify({ data, error: null, meta: { request_id: "r1" } }), { status, headers: { "Content-Type": "application/json" } });

const queued: RuleTest = { id: TEST, state: "queued", findings: [], error: null, created_at: "2026-11-03T10:00:00Z", finished_at: null };

describe("rule test snippet", () => {
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
        if (url === `/api/v1/orgs/${ORG}/scan-rules/tests` && init.method === "POST") return reply(queued, 202);
        return reply(null, 500);
      }),
    );
  });

  afterEach(() => {
    vi.unstubAllGlobals();
    vi.restoreAllMocks();
    consoleCalls.length = 0;
    sent.length = 0;
  });

  it("is sent once and kept in no cache, query key, storage or log", async () => {
    const qc = new QueryClient();
    let request: RuleTestRequest | null = { tool: "gitleaks", body: '[[rules]]\nid = "acme"\n', filename: "settings.env", snippet: SNIPPET };
    const observer = new MutationObserver(qc, ruleTestMutation(qc, ORG, () => request!));
    const t = await observer.mutate();
    request = null;

    expect(t).toEqual(queued);
    expect(sent).toHaveLength(1);
    expect(sent[0]!.body).toContain(SECRETISH);
    // The result is cached under the test's id only, so the dialog's first poll has it.
    expect(qc.getQueryData(qk.ruleTest(ORG, TEST))).toEqual(queued);
    expect(qk.ruleTest(ORG, TEST)).toEqual(["org", ORG, "rule-tests", TEST]);

    const dump = cacheDump(qc);
    expect(qc.getMutationCache().getAll()).toHaveLength(1);
    expect(dump).not.toContain(SECRETISH);
    expect(dump).not.toContain("eval(req.body.x)");
    expect(local.setItem).not.toHaveBeenCalled();
    expect(session.setItem).not.toHaveBeenCalled();
    expect(JSON.stringify(consoleCalls)).not.toContain(SECRETISH);
  });

  it("errors are shown in the dialog, not as a toast", () => {
    const qc = new QueryClient();
    expect(ruleTestMutation(qc, ORG, () => ({}) as RuleTestRequest).meta).toEqual({ inlineErrors: true });
  });
});

describe("rule test polling", () => {
  // TanStack Query schedules no refetch timers on a server (no window); these tests are the browser.
  beforeEach(() => environmentManager.setIsServer(() => false));
  afterEach(() => {
    environmentManager.setIsServer(() => typeof window === "undefined");
    vi.useRealTimers();
    vi.unstubAllGlobals();
  });

  function stubStates(states: RuleTest["state"][]) {
    let n = 0;
    const calls = vi.fn(async () => {
      const state = states[Math.min(n, states.length - 1)]!;
      n += 1;
      const done = state === "done" || state === "failed";
      return reply({
        ...queued,
        state,
        findings: state === "done" ? [{ line: 3, end_line: null, message: "m" }, { line: 7, end_line: 8, message: "m" }] : [],
        error: state === "failed" ? "timeout" : null,
        finished_at: done ? "2026-11-03T10:00:05Z" : null,
      });
    });
    vi.stubGlobal("fetch", calls);
    return calls;
  }

  it("backs off (1, 2, 3 s) and stops when the test is done", async () => {
    vi.useFakeTimers();
    const calls = stubStates(["queued", "running", "running", "done", "done"]);
    const qc = new QueryClient();
    const observer = new QueryObserver(qc, ruleTestQuery(ORG, TEST, Date.now()));
    const seen: string[] = [];
    const unsub = observer.subscribe((r) => {
      if (r.data && seen[seen.length - 1] !== r.data.state) seen.push(r.data.state);
    });
    await vi.advanceTimersByTimeAsync(0);
    expect(calls).toHaveBeenCalledTimes(1);
    await vi.advanceTimersByTimeAsync(1000);
    expect(calls).toHaveBeenCalledTimes(2);
    await vi.advanceTimersByTimeAsync(1999);
    expect(calls).toHaveBeenCalledTimes(2);
    await vi.advanceTimersByTimeAsync(1);
    expect(calls).toHaveBeenCalledTimes(3);
    await vi.advanceTimersByTimeAsync(3000);
    expect(calls).toHaveBeenCalledTimes(4);
    expect(observer.getCurrentResult().data).toMatchObject({ state: "done", findings: [{ line: 3 }, { line: 7, end_line: 8 }] });
    // Done: no more requests.
    await vi.advanceTimersByTimeAsync(60_000);
    expect(calls).toHaveBeenCalledTimes(4);
    expect(seen).toEqual(["queued", "running", "done"]);
    unsub();
  });

  it("stops on failed", async () => {
    vi.useFakeTimers();
    const calls = stubStates(["running", "failed"]);
    const qc = new QueryClient();
    const observer = new QueryObserver(qc, ruleTestQuery(ORG, TEST, Date.now()));
    const unsub = observer.subscribe(() => {});
    await vi.advanceTimersByTimeAsync(30_000);
    expect(calls).toHaveBeenCalledTimes(2);
    expect(observer.getCurrentResult().data).toMatchObject({ state: "failed", error: "timeout" });
    unsub();
  });

  it("gives up after 3 minutes of queued or running", async () => {
    vi.useFakeTimers();
    const calls = stubStates(["queued", "running"]);
    const qc = new QueryClient();
    const observer = new QueryObserver(qc, ruleTestQuery(ORG, TEST, Date.now()));
    const unsub = observer.subscribe(() => {});
    await vi.advanceTimersByTimeAsync(3 * 60_000 + 1000);
    const atLimit = calls.mock.calls.length;
    // 1 + 1 + 2 + 3 s, then every 5 s: about 37 requests in 3 minutes, never more.
    expect(atLimit).toBeGreaterThan(30);
    expect(atLimit).toBeLessThan(40);
    await vi.advanceTimersByTimeAsync(10 * 60_000);
    expect(calls).toHaveBeenCalledTimes(atLimit);
    expect(observer.getCurrentResult().data?.state).toBe("running");
    unsub();
  });

  it("doesn't ask without a test id", async () => {
    const calls = stubStates(["queued"]);
    const qc = new QueryClient();
    const observer = new QueryObserver(qc, ruleTestQuery(ORG, null, Date.now()));
    const unsub = observer.subscribe(() => {});
    await new Promise((r) => setTimeout(r, 10));
    expect(calls).not.toHaveBeenCalled();
    unsub();
  });
});
