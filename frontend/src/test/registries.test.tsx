// v0.7 wave 2: Registries, scans of pulled images and secrets in image layers, with the mock API
// behind them. Rendered like screens.test.tsx (react-dom/server against the dev mock, no DOM):
// each pass fetches the queries the screen created, until nothing is pending.
import { QueryClient, QueryClientProvider } from "@tanstack/react-query";
import { renderToString } from "react-dom/server";
import { createMemoryRouter, RouterProvider } from "react-router";
import { beforeAll, describe, expect, it, vi } from "vitest";

type Fixtures = typeof import("../api/mock/fixtures");
let db: Fixtures;
let appRoutes: typeof import("../App").appRoutes;
let AuthGate: typeof import("../auth/AuthGate").AuthGate;
let qk: typeof import("../api/keys").qk;
let preloadRoutes: typeof import("../lib/lazyRoute").preloadRoutes;
let mockFetch: typeof import("../api/mock/server").mockFetch;

beforeAll(async () => {
  vi.stubEnv("VITE_MOCK", "1");
  vi.stubGlobal("window", { location: { origin: "http://localhost", search: "", pathname: "/" } });
  db = await import("../api/mock/fixtures");
  ({ appRoutes } = await import("../App"));
  ({ AuthGate } = await import("../auth/AuthGate"));
  ({ qk } = await import("../api/keys"));
  ({ preloadRoutes } = await import("../lib/lazyRoute"));
  ({ mockFetch } = await import("../api/mock/server"));
});

async function render(path: string, seed?: (qc: QueryClient) => void): Promise<{ html: string; qc: QueryClient }> {
  const qc = new QueryClient({ defaultOptions: { queries: { retry: false, retryOnMount: false, staleTime: Infinity } } });
  seed?.(qc);
  const errors: unknown[] = [];
  const spy = vi.spyOn(console, "error").mockImplementation((...a) => errors.push(a));
  let html = "";
  try {
    for (let pass = 0; pass < 8; pass++) {
      const router = createMemoryRouter(appRoutes, { initialEntries: [path] });
      html = renderToString(
        <QueryClientProvider client={qc}>
          <AuthGate authFailed={false}>
            <RouterProvider router={router} />
          </AuthGate>
        </QueryClientProvider>,
      );
      const pending = qc
        .getQueryCache()
        .getAll()
        .filter((q) => q.state.status === "pending" && q.state.fetchStatus === "idle" && q.options.queryFn && (q.options as { enabled?: unknown }).enabled !== false);
      const routeLoading = html.includes("data-route-loading");
      if (pending.length === 0 && !routeLoading) break;
      await Promise.all(pending.map((q) => q.fetch().catch(() => undefined)));
      if (routeLoading) {
        await preloadRoutes();
        await new Promise((r) => setTimeout(r, 0));
      }
    }
  } finally {
    spy.mockRestore();
  }
  expect(errors).toEqual([]);
  return { html, qc };
}

const text = (html: string) =>
  html
    .replace(/<[^>]+>/g, " ")
    .replace(/&#x27;/g, "'")
    .replace(/&quot;/g, '"')
    .replace(/&amp;/g, "&")
    .replace(/\s+/g, " ");

type Json = {
  data: ({ items?: Record<string, unknown>[] } & Record<string, unknown>) | null;
  error: { code: string; metadata?: { fields?: Record<string, string> } } | null;
};
async function call(method: string, path: string, body?: unknown): Promise<{ status: number; json: Json }> {
  const r = await mockFetch(`/api/v1${path}`, { method, body: body === undefined ? undefined : JSON.stringify(body) });
  return { status: r.status, json: (r.status === 204 ? { data: null, error: null } : await r.json()) as Json };
}

const org = () => `/orgs/${db.ORG_ID}`;
const registriesPage = () => `${org()}/settings/registries`;
const asRole = (role: "org_admin" | "security_lead" | "member") => ({
  ...db.me,
  orgs: db.me.orgs.map((o) => (o.id === db.ORG_ID ? { ...o, role } : o)),
});
/** A made-up password, built at test time (CLAUDE.md: never a committed secret-shaped literal). */
const fakePassword = () => ["pw", Math.random().toString(36).slice(2), Date.now().toString(36)].join("-");

describe("v0.7 wave 2: Registries", () => {
  it("list: hosts, usernames, last used, the refused one, Test / Change / Delete, n of 20; the Settings card links here", async () => {
    const { html } = await render(registriesPage());
    const t = text(html);
    expect(t).toContain("ghcr.io");
    expect(t).toContain("as acme-warden-bot");
    expect(t).toContain("registry.acme.example:5000");
    expect(t).toContain("harbor.acme.example");
    expect(t).toMatch(/Used 2 h ago/);
    expect(t).toContain("Not used yet");
    expect(t).toContain("Refused");
    expect(t).toContain("Last attempt: The registry refused these credentials.");
    expect(t).toContain("Test the credentials for ghcr.io");
    expect(t).toContain("Change the credentials for registry.acme.example:5000");
    expect(t).toContain("Delete the credentials for harbor.acme.example");
    expect(t).toContain("3 of 20");
    expect(t).toContain("Warden pulls only by digest, and only from the hosts listed here or anonymously.");
    // Hosts are text, never links; the page has no password anywhere.
    expect(html).not.toMatch(/href="https?:\/\/(ghcr\.io|registry\.acme|harbor\.acme)/);
    expect(html).not.toContain('type="password"');

    const settings = await render(`${org()}/settings`);
    expect(text(settings.html)).toContain("Manage registries");
    expect(settings.html).toContain(`href="/orgs/${db.ORG_ID}/settings/registries"`);
  });

  it("hidden from members, who never call the API; a 403 page if they open the URL; org admins see it", async () => {
    const member = await render(registriesPage(), (qc) => qc.setQueryData(qk.me, asRole("member")));
    expect(text(member.html)).toContain("You don't have access to this");
    expect(member.qc.getQueryCache().find({ queryKey: qk.registries(db.ORG_ID) })).toBeUndefined();
    const settings = await render(`${org()}/settings`, (qc) => qc.setQueryData(qk.me, asRole("member")));
    expect(text(settings.html)).not.toContain("Manage registries");
    expect(settings.html).not.toContain("/settings/registries");
    expect(settings.qc.getQueryCache().find({ queryKey: qk.registries(db.ORG_ID) })).toBeUndefined();
    // Acme Labs: the caller is a member there.
    const labs = await render(`/orgs/${db.ORG2_ID}/settings`);
    expect(labs.html).not.toContain("/settings/registries");
    const admin = await render(registriesPage(), (qc) => qc.setQueryData(qk.me, asRole("org_admin")));
    expect(text(admin.html)).toContain("acme-warden-bot");
  });

  it("empty state: Warden pulls only by digest, only from these hosts or anonymously", async () => {
    const list = db.registries[db.ORG_ID]!;
    const saved = [...list];
    list.splice(0);
    try {
      const t = text((await render(registriesPage())).html);
      expect(t).toContain("No registry credentials yet");
      expect(t).toContain("Warden pulls images only by digest (registry/repository@sha256:…), never by tag.");
      expect(t).toContain("It signs in only to the hosts listed here; any other image is pulled anonymously");
      expect(t).toContain("Add credentials");
    } finally {
      list.push(...saved);
    }
  });

  it("hostile hosts and usernames are text", async () => {
    const list = db.registries[db.ORG_ID]!;
    const hostile = { ...list[0]!, id: db.uuid(), host: "<img src=x onerror=alert(1)>", username: "javascript:alert(1)" };
    list.push(hostile);
    try {
      const { html } = await render(registriesPage());
      expect(html).not.toContain("<img");
      expect(html).not.toMatch(/href="javascript:/);
      expect(text(html)).toContain("&lt;img src=x onerror=alert(1)&gt;");
    } finally {
      list.splice(list.indexOf(hostile), 1);
    }
  });

  it("mock API follows the contract: roles, field checks, no password in any answer or log, 409s, test results and limit", async () => {
    const base = `/orgs/${db.ORG_ID}/registries`;
    expect((await call("GET", `/orgs/${db.ORG2_ID}/registries`)).status).toBe(403);
    const listed = await call("GET", base);
    expect(Object.keys(listed.json.data!.items![0]!).sort()).toEqual(
      ["created_at", "created_by", "host", "id", "last_error", "last_used_at", "updated_at", "username"].sort(),
    );

    const bad = await call("POST", base, { host: "https://10.0.0.5", username: "", password: "" });
    expect(bad.status).toBe(422);
    expect(Object.keys(bad.json.error!.metadata!.fields!).sort()).toEqual(["host", "password", "username"]);
    expect((await call("POST", base, { host: "10.0.0.5:5000", username: "u", password: "p" })).json.error?.metadata?.fields?.host).toMatch(/IP address/);
    expect((await call("POST", base, { host: "ghcr.io", username: "u", password: "p" })).json.error?.code).toBe("CONFLICT");

    const pw = fakePassword();
    const auditBefore = db.audit.length;
    const made = await call("POST", base, { host: "quay.io", username: "acme+warden", password: pw });
    expect(made.status).toBe(201);
    const id = (made.json.data as { id: string }).id;
    try {
      expect(JSON.stringify(made.json)).not.toContain(pw);
      expect(JSON.stringify(db.registries)).not.toContain(pw);
      expect(db.audit.length).toBe(auditBefore + 1);
      expect(db.audit[0]).toMatchObject({ action: "registry.created", data: { host: "quay.io", username: "acme+warden" } });
      expect(JSON.stringify(db.audit)).not.toContain(pw);

      const pw2 = fakePassword();
      const changed = await call("PATCH", `${base}/${id}`, { password: pw2 });
      expect(changed.status).toBe(200);
      expect(JSON.stringify(changed.json)).not.toContain(pw2);
      expect((await call("PATCH", `${base}/${id}`, {})).status).toBe(422);
      expect((await call("PATCH", `${base}/${id}`, { host: "x.io" })).status).toBe(422);

      // Ten tests an hour per credential, then 429.
      for (let i = 0; i < 10; i++) expect((await call("POST", `${base}/${id}/test`)).json.data).toEqual({ ok: true, error: null });
      expect((await call("POST", `${base}/${id}/test`)).status).toBe(429);
    } finally {
      expect((await call("DELETE", `${base}/${id}`)).status).toBe(204);
    }
    const refused = db.registries[db.ORG_ID]!.find((c) => c.last_error === "unauthorized")!;
    expect((await call("POST", `${base}/${refused.id}/test`)).json.data).toEqual({ ok: false, error: "unauthorized" });

    // Without secrets.key, saving answers SECRETS_KEY_MISSING; the list still loads.
    db.mockFlags.registries = "unavailable";
    try {
      expect((await call("POST", base, { host: "new.example", username: "u", password: fakePassword() })).json.error?.code).toBe("SECRETS_KEY_MISSING");
      expect((await call("PATCH", `${base}/${refused.id}`, { password: fakePassword() })).json.error?.code).toBe("SECRETS_KEY_MISSING");
      expect((await call("GET", base)).status).toBe(200);
    } finally {
      db.mockFlags.registries = null;
    }
  });
});

describe("v0.7 wave 2: scans of pulled images", () => {
  const web = () => db.projects[0]!;
  const pay = () => db.projects[1]!;
  const scansOf = (p: { id: string }) => `${org()}/projects/${p.id}/scans`;

  it("New scan › Image from a registry: the digest rule, Trivy and Gitleaks, the credentials note", async () => {
    const { html } = await render(`${scansOf(web())}?new=pull`);
    const t = text(html);
    expect(html).toMatch(/<button type="button" aria-pressed="true">Image from a registry<\/button>/);
    expect(html).toMatch(/<button type="button" aria-pressed="false">Container image<\/button>/);
    expect(t).toContain("Image reference");
    expect(html).toContain('placeholder="ghcr.io/acme/api@sha256:…"');
    expect(t).toContain("Pin by digest: registry/repo@sha256:…. Warden never pulls by tag");
    expect(t).toContain("docker inspect --format '{{index .RepoDigests 0}}' IMAGE");
    expect(t).toMatch(/Trivy packages/);
    expect(t).toMatch(/Gitleaks secrets in every layer/);
    expect(t).not.toContain("Opengrep");
    expect(t).toContain("Pull and scan");
    expect(t).toContain("otherwise it pulls anonymously");
    // A security lead may manage registries: the note links there. No file picker in this mode.
    expect(html).toContain(`href="/orgs/${db.ORG_ID}/settings/registries"`);
    expect(html).not.toContain('type="file"');

    // A project owner who isn't an org admin or security lead: no link, the same words.
    const owner = await render(`${scansOf(web())}?new=pull`, (qc) => qc.setQueryData(qk.me, asRole("member")));
    expect(text(owner.html)).toContain("Pull and scan");
    expect(owner.html).not.toContain("/settings/registries");
  });

  it("Container image uploads run Trivy and Gitleaks too, and point at the registry mode", async () => {
    const t = text((await render(`${scansOf(web())}?new=image`)).html);
    expect(t).toMatch(/Trivy packages/);
    expect(t).toMatch(/Gitleaks secrets in every layer/);
    expect(t).toContain("To scan an image without saving it, choose Image from a registry.");
    expect(t).not.toContain("secrets inside images aren't scanned");
  });

  it("history and panel: Pulled from <host> with the digest reference; no file name", async () => {
    const pulled = db.PULLED_SCAN;
    const t = text((await render(scansOf(web()))).html);
    expect(t).toContain(pulled.image_ref!);
    expect(t).toContain("Pulled from ghcr.io");
    const panel = text((await render(`${scansOf(web())}?scan=${pulled.id}`)).html);
    expect(panel).toMatch(/Pulled from ghcr\.io · 191 MB/);
    expect(panel).toContain("Issues tracked under ghcr.io/acme/api");
    expect(panel).not.toContain("api.tar");
    expect(panel).toContain("View issues");
  });

  it("each PULL_* failure: Failed in the history, Pull failed with what to do in the panel, Pull again", async () => {
    const history = text((await render(scansOf(pay()))).html);
    for (const short of ["registry refused access", "image not found", "image too large to pull", "registry address blocked", "no image for this platform", "pull failed"]) {
      expect(history).toContain(short);
    }
    const words: Record<string, RegExp> = {
      PULL_UNAUTHORIZED: /The registry refused to give Warden this image ?\..*Registries/,
      PULL_NOT_FOUND: /The registry has no image with this digest ?\./,
      PULL_TOO_LARGE: /The image is larger than this server pulls ?\./,
      PULL_BLOCKED: /private or internal address/,
      PULL_PLATFORM: /linux\/amd64 unless your operator changed it/,
      PULL_FAILED: /If it keeps happening, tell your operator\./,
    };
    for (const s of db.PULL_FAILURES) {
      const p = text((await render(`${scansOf(pay())}?scan=${s.id}`)).html);
      expect(p).toContain("Pull failed");
      expect(p).not.toContain("Rejected");
      expect(p).toMatch(words[s.error_code!]!);
      expect(p).toContain(s.error_code!);
      expect(p).toContain("Nothing was scanned and no issues changed.");
      expect(p).toContain("Pull again");
      expect(p).not.toContain("Upload a new .tar");
      expect(p).toContain("Pulled from ghcr.io");
    }
  });

  it("mock API: digest only, Trivy and Gitleaks only, queued at once; a failure per word in the reference", async () => {
    const path = `/orgs/${db.ORG_ID}/projects/${web().id}/scans/pull`;
    const digest = db.fakeDigest(9901);
    const tag = await call("POST", path, { image_ref: "ghcr.io/acme/api:1.4.2" });
    expect(tag.status).toBe(422);
    expect(tag.json.error?.metadata?.fields?.image_ref).toBeDefined();
    expect((await call("POST", path, { image_ref: `ghcr.io/acme/api@${digest}`, tools: ["opengrep"] })).json.error?.metadata?.fields?.tools).toBeDefined();
    expect((await call("POST", path, { image_ref: `ghcr.io/acme/api@${digest}`, tools: [] })).status).toBe(422);

    const ghcr = db.registries[db.ORG_ID]!.find((c) => c.host === "ghcr.io")!;
    const usedBefore = ghcr.last_used_at;
    const made: string[] = [];
    try {
      const ok = await call("POST", path, { image_ref: `ghcr.io/acme/api@${digest}` });
      expect(ok.status).toBe(201);
      const scan = ok.json.data as Record<string, unknown> & { id: string };
      made.push(scan.id);
      expect(scan).toMatchObject({ pulled: true, kind: "image", status: "queued", target: "ghcr.io/acme/api", tools: ["trivy", "gitleaks"] });
      expect(scan).not.toHaveProperty("_t");
      expect(ghcr.last_used_at).not.toBe(usedBefore);

      const missing = await call("POST", path, { image_ref: `ghcr.io/acme/missing@${digest}`, tools: ["gitleaks"] });
      const id = (missing.json.data as { id: string }).id;
      made.push(id);
      // The worker picks it up after a few seconds in the mock: move its clock back.
      Object.assign(db.scans.find((s) => s.id === id)!, { _t: Date.now() - 10_000 });
      expect((await call("GET", `/orgs/${db.ORG_ID}/scans/${id}`)).json.data).toMatchObject({ status: "failed", error_code: "PULL_NOT_FOUND", tool_runs: [] });
    } finally {
      for (const id of made) db.scans.splice(db.scans.findIndex((s) => s.id === id), 1);
      ghcr.last_used_at = usedBefore;
    }
  });

  it("CI setup has no pull snippet: the CLI's --image-ref only labels an uploaded .tar", async () => {
    const t = text((await render(`${org()}/projects/${web().id}/settings`)).html);
    expect(t).not.toContain("--image-ref");
    expect(t).not.toContain("scans/pull");
  });
});
