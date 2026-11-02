// A webhook's signing secret is shown once (after create or rotate) and kept only in the
// dialog's component state; its URL is typed once and never read back (for Slack the URL is the
// credential). These tests check the places that could leak either: TanStack Query's query and
// mutation caches (including mutation variables), browser storage, the console, the query keys
// and the dialog's state after it closes. Same rules as API tokens (tokens.test.ts).
import { MutationObserver, QueryClient } from "@tanstack/react-query";
import { afterEach, beforeEach, describe, expect, it, vi } from "vitest";
import { createWebhookMutation, rotateSecretMutation, updateWebhookMutation } from "./hooks/webhooks";
import { qk } from "./keys";
import type { CreateWebhookBody, Webhook } from "./types";
import { INITIAL_SECRET_DIALOG, secretDialogReducer } from "../lib/webhooks";

const ORG = "00000000-0000-4000-8000-000000000001";
const HOOK = "00000000-0000-4000-8000-0000000000aa";
// Built at test time, never committed as literals (CLAUDE.md).
const SECRET = `whsec_${btoa(Array.from({ length: 32 }, (_, i) => String.fromCharCode((i * 37 + 11) % 256)).join(""))}`;
const ROTATED = `whsec_${btoa(Array.from({ length: 32 }, (_, i) => String.fromCharCode((i * 53 + 7) % 256)).join(""))}`;
const SLACK_PATH = ["T0", "B0", Array.from({ length: 24 }, (_, i) => "abcdefghijklmnopqrstuvwx"[(i * 5) % 24]).join("")].join("/");
const SLACK_URL = `https://hooks.slack.com/services/${SLACK_PATH}`;
const RELAY_URL = `https://relay.acme.example/hooks/${Array.from({ length: 16 }, (_, i) => (i * 7) % 10).join("")}`;

const webhook: Webhook = {
  id: HOOK,
  kind: "generic",
  name: "Ticket relay",
  url_hint: "https://relay.acme.example",
  events: ["scan.finished"],
  project_ids: [],
  min_severity: null,
  enabled: true,
  disabled_reason: null,
  consecutive_failures: 0,
  last_delivery: null,
  created_by: { id: "u1", email: "linh@acme.example", display_name: "Linh Tran" },
  created_at: "2026-10-26T10:00:00Z",
  updated_at: "2026-10-26T10:00:00Z",
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

describe("webhook signing secret and URL", () => {
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
          new Response(JSON.stringify({ data, error: null, meta: { request_id: "r1" } }), { status, headers: { "Content-Type": "application/json" } });
        if (url === `/api/v1/orgs/${ORG}/webhooks` && init.method === "POST") {
          const body = JSON.parse(String(init.body)) as CreateWebhookBody;
          return body.kind === "slack"
            ? reply({ webhook: { ...webhook, kind: "slack", url_hint: "https://hooks.slack.com" }, secret: null }, 201)
            : reply({ webhook, secret: SECRET }, 201);
        }
        if (url === `/api/v1/orgs/${ORG}/webhooks/${HOOK}/rotate-secret`) return reply({ secret: ROTATED });
        if (url === `/api/v1/orgs/${ORG}/webhooks/${HOOK}` && init.method === "PATCH") return reply(webhook);
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

  it("create: the secret goes to the dialog only; neither it nor the URL reaches a cache, storage or the console", async () => {
    const qc = new QueryClient();
    qc.setQueryData(qk.webhooks(ORG), { items: [], available: true });
    let delivered: string | null = null;
    const body: CreateWebhookBody = { kind: "generic", name: "Ticket relay", url: RELAY_URL, events: ["scan.finished"] };
    const observer = new MutationObserver(qc, createWebhookMutation(qc, ORG, () => body, (s) => (delivered = s)));

    const result = await observer.mutate();

    expect(delivered).toBe(SECRET);
    expect(result).toEqual(webhook);
    // The URL was sent once, in the request body.
    expect(sent).toHaveLength(1);
    expect(sent[0]!.body).toContain(RELAY_URL);

    const dump = cacheDump(qc);
    expect(qc.getMutationCache().getAll()).toHaveLength(1);
    expect(dump).not.toContain(SECRET);
    expect(dump).not.toContain(SECRET.slice("whsec_".length));
    expect(dump).not.toContain(RELAY_URL);
    expect(local.setItem).not.toHaveBeenCalled();
    expect(session.setItem).not.toHaveBeenCalled();
    expect(JSON.stringify(consoleCalls)).not.toContain(SECRET);
    expect(JSON.stringify(consoleCalls)).not.toContain(RELAY_URL);
  });

  it("create (Slack): no secret, and the URL (the credential) stays out of the caches", async () => {
    const qc = new QueryClient();
    const onSecret = vi.fn();
    const body: CreateWebhookBody = { kind: "slack", name: "#security-alerts", url: SLACK_URL, events: ["scan.finished"] };
    const observer = new MutationObserver(qc, createWebhookMutation(qc, ORG, () => body, onSecret));
    const result = await observer.mutate();
    expect(onSecret).not.toHaveBeenCalled();
    expect(result.url_hint).toBe("https://hooks.slack.com");
    expect(cacheDump(qc)).not.toContain(SLACK_PATH);
  });

  it("edit: a replacement URL is sent but not kept in the mutation cache", async () => {
    const qc = new QueryClient();
    const observer = new MutationObserver(qc, updateWebhookMutation(qc, ORG, HOOK, () => ({ url: SLACK_URL })));
    await observer.mutate();
    expect(sent[0]).toMatchObject({ method: "PATCH" });
    expect(sent[0]!.body).toContain(SLACK_PATH);
    expect(cacheDump(qc)).not.toContain(SLACK_PATH);
  });

  it("rotate: the new secret goes to the dialog only and the mutation resolves with nothing", async () => {
    const qc = new QueryClient();
    let delivered: string | null = null;
    const observer = new MutationObserver(qc, rotateSecretMutation(qc, ORG, HOOK, (s) => (delivered = s)));
    const result = await observer.mutate();
    expect(result).toBeUndefined();
    expect(delivered).toBe(ROTATED);
    expect(cacheDump(qc)).not.toContain(ROTATED);
    expect(cacheDump(qc)).not.toContain(ROTATED.slice("whsec_".length));
    expect(local.setItem).not.toHaveBeenCalled();
    expect(session.setItem).not.toHaveBeenCalled();
    expect(JSON.stringify(consoleCalls)).not.toContain(ROTATED);
  });

  it("is dropped from the dialog state when the dialog closes", () => {
    let s = secretDialogReducer(INITIAL_SECRET_DIALOG, { type: "secret", secret: SECRET, webhook });
    expect(s.secret).toBe(SECRET);
    // Only the id and name of the webhook are kept beside it.
    expect(s.webhook).toEqual({ id: HOOK, name: "Ticket relay" });
    s = secretDialogReducer(s, { type: "close" });
    expect(s).toEqual({ secret: null, webhook: null });
    expect(JSON.stringify(s)).not.toContain(SECRET);
  });

  it("query keys never carry a URL or a secret", () => {
    expect(qk.webhooks(ORG)).toEqual(["org", ORG, "webhooks"]);
    expect(qk.webhookDeliveries(ORG, HOOK)).toEqual(["org", ORG, "webhooks", HOOK, "deliveries"]);
  });
});
