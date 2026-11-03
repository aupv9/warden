// v0.6 wave 1: the Scan rules screens and the mock API behind them. Rendered like
// screens.test.tsx (react-dom/server against the dev mock, no DOM): each pass fetches the
// queries the screen created, until nothing is pending.
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

async function render(path: string, seed?: (qc: QueryClient) => void): Promise<string> {
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
  return html;
}

const text = (html: string) =>
  html
    .replace(/<[^>]+>/g, " ")
    .replace(/&#x27;/g, "'")
    .replace(/&quot;/g, '"')
    .replace(/&amp;/g, "&")
    .replace(/\s+/g, " ");

type Json = {
  data: ({ items?: Record<string, unknown>[]; next_cursor?: string | null } & Record<string, unknown>) | null;
  error: { code: string; metadata?: { fields?: Record<string, string>; problems?: { line: number | null; column: number | null; message: string }[] } } | null;
};
async function call(method: string, path: string, body?: unknown): Promise<{ status: number; json: Json; headers: Headers }> {
  const r = await mockFetch(`/api/v1${path}`, { method, body: body === undefined ? undefined : JSON.stringify(body) });
  return { status: r.status, headers: r.headers, json: (r.status === 204 ? { data: null, error: null } : await r.json()) as Json };
}

const org = () => `/orgs/${db.ORG_ID}`;
const rules = () => `${org()}/settings/scan-rules`;
const asRole = (role: "org_admin" | "security_lead" | "member") => ({
  ...db.me,
  orgs: db.me.orgs.map((o) => (o.id === db.ORG_ID ? { ...o, role } : o)),
});
/** Runs `fn` with the caller in `role` in Acme Engineering (the mock API reads /me's role). */
async function withRole<T>(role: "org_admin" | "security_lead" | "member", fn: () => Promise<T>): Promise<T> {
  const eng = db.me.orgs.find((o) => o.id === db.ORG_ID)!;
  const before = eng.role;
  eng.role = role;
  try {
    return await fn();
  } finally {
    eng.role = before;
  }
}

describe("v0.6 screens: Scan rules", () => {
  it("list: navigation, tabs with counts, rows, the on/off switch, scope and who changed it last", async () => {
    const html = await render(rules());
    const t = text(html);
    expect(html).toContain(`href="/orgs/${db.ORG_ID}/settings/scan-rules"`);
    // Under Organization, after Integrations and before Settings; Settings isn't marked current.
    expect(html.indexOf("Scan rules</span>")).toBeGreaterThan(html.indexOf("Integrations</span>"));
    expect(html.indexOf("Scan rules</span>")).toBeLessThan(html.indexOf("Settings</span>"));
    expect(html).not.toMatch(/<a[^>]*aria-current="page"[^>]*href="\/orgs\/[^"]+\/settings"/);
    expect(t).toMatch(/Opengrep 3 Gitleaks 1/);
    expect(t).toContain("No eval of request data");
    expect(t).toContain("org.no-eval-of-request-data");
    expect(t).toContain("Unsafe YAML load");
    expect(t).toContain("MD5 in payment signatures");
    expect(t).not.toContain("Acme internal API token");
    expect(t).toContain("All projects");
    expect(t).toContain("2 projects");
    expect(t).toContain("1 project");
    expect(t).toMatch(/by Linh Tran/);
    expect(t).toContain("3 of 200 Opengrep rules");
    expect(t).toContain("They only add findings: they can't ignore, allowlist or exclude anything.");
    // A switch per rule for a security lead, named after the rule; the off rule is unchecked.
    expect(html.match(/role="switch"/g)).toHaveLength(3);
    expect(t).toContain("run MD5 in payment signatures in scans");
    expect(html).toContain(`href="/orgs/${db.ORG_ID}/settings/scan-rules/new?tool=opengrep"`);
    // Gitleaks tab.
    const g = text(await render(`${rules()}?tool=gitleaks`));
    expect(g).toContain("Acme internal API token");
    expect(g).toContain("org.acme-internal-token");
    expect(g).not.toContain("Unsafe YAML load");
  });

  it("list: read-only for members (no switch, no Add), who still see the rules", async () => {
    let seed: QueryClient | null = null;
    const html = await render(rules(), (qc) => {
      seed = qc;
      qc.setQueryData(qk.me, asRole("member"));
    });
    const t = text(html);
    expect(t).toContain("No eval of request data");
    expect(t).toContain("Only org admins and security leads can add or change scan rules.");
    expect(html).not.toContain('role="switch"');
    expect(html).not.toContain("/settings/scan-rules/new");
    expect(t).toMatch(/Off/);
    expect(seed!.getQueryCache().find({ queryKey: qk.scanRuleList(db.ORG_ID) })?.state.status).toBe("success");
    // The new-rule page is a 403 page for them.
    const n = text(await render(`${rules()}/new?tool=opengrep`, (qc) => qc.setQueryData(qk.me, asRole("member"))));
    expect(n).toContain("You don't have access to this");
    // An org admin manages them too.
    const admin = await render(rules(), (qc) => qc.setQueryData(qk.me, asRole("org_admin")));
    expect(admin.match(/role="switch"/g)).toHaveLength(3);
  });

  it("list: the empty state says what org rules can and can't do", async () => {
    const list = db.scanRules[db.ORG_ID]!;
    const saved = list.splice(0);
    try {
      const t = text(await render(rules()));
      expect(t).toContain("No Opengrep rules yet");
      expect(t).toContain("They only add findings.");
      expect(t).toContain("An org rule can't ignore, allowlist or exclude anything, and Warden's built-in rules still run.");
      expect(t).toContain("Turning a rule off or deleting it doesn't close the issues it found.");
      expect(t).toContain("Add an Opengrep rule");
      const g = text(await render(`${rules()}?tool=gitleaks`));
      expect(g).toContain("No Gitleaks rules yet");
      expect(g).toContain("your own secret formats");
      expect(g).toContain("Add a Gitleaks rule");
    } finally {
      list.push(...saved);
    }
    // Acme Labs: no rules and the caller is a member there: the explainer, no Add.
    const labs = text(await render(`/orgs/${db.ORG2_ID}/settings/scan-rules`));
    expect(labs).toContain("No Opengrep rules yet");
    expect(labs).not.toContain("Add an Opengrep rule");
  });

  it("editor: the body in a plain textarea with line numbers, the scope, the switch, test, delete", async () => {
    const r = db.RULE_NO_EVAL;
    const html = await render(`${rules()}/${r.id}`);
    const t = text(html);
    expect(t).toContain("No eval of request data");
    expect(t).toContain("org.no-eval-of-request-data");
    expect(t).toContain("version 4");
    expect(t).toContain("Rule (YAML)");
    expect(html).toMatch(/<textarea[^>]*class="rule-textarea"[^>]*>rules:\n {2}- id: no-eval-of-request-data/);
    expect(html).toMatch(/wrap="off"/);
    // One gutter number per line, hidden from screen readers (the textarea has the text).
    expect(html).toMatch(/<div class="rule-gutter" aria-hidden="true"><span>1<\/span><span>2<\/span><span>3<\/span><span>4<\/span><span>5<\/span><span>6<\/span><span>7<\/span><\/div>/);
    expect(t).toContain("No allowlists, ignores or path exclusions.");
    expect(t).toMatch(/of 64 KiB/);
    expect(t).toContain("Where it runs");
    expect(t).toContain("Run this rule in scans");
    expect(t).toContain("It never closes the issues the rule already found.");
    expect(t).toContain("Test on a snippet…");
    expect(t).toContain("Delete rule…");
    expect(t).toContain("Its issues stay open: deleting a rule never fixes or closes what it found.");
    // Nothing changed yet: Save is disabled.
    expect(html).toMatch(/<button type="submit" class="btn btn-primary"[^>]*disabled=""[^>]*>Save rule<\/button>/);
    expect(html).toContain(`href="/orgs/${db.ORG_ID}/settings/scan-rules/${r.id}?tab=history"`);
  });

  it("new rule: a template per scanner, Add rule; Gitleaks is TOML", async () => {
    const o = await render(`${rules()}/new?tool=opengrep`);
    expect(text(o)).toContain("New Opengrep rule");
    expect(o).toContain("rules:\n  - id: no-eval-of-request-data");
    expect(text(o)).toContain("Add rule");
    const g = await render(`${rules()}/new?tool=gitleaks`);
    expect(text(g)).toContain("New Gitleaks rule");
    expect(text(g)).toContain("Rule (TOML)");
    expect(g).toContain("[[rules]]");
    expect(text(g)).not.toContain("Delete rule…");
  });

  it("read-only rule page for members: the stored body as text, no textarea", async () => {
    const r = db.RULE_NO_EVAL;
    const html = await render(`${rules()}/${r.id}`, (qc) => qc.setQueryData(qk.me, asRole("member")));
    const t = text(html);
    expect(html).not.toContain("<textarea");
    expect(t).toContain("Only org admins and security leads can change scan rules.");
    expect(t).toContain("Findings carry org.no-eval-of-request-data");
    expect(t).toContain("All projects, including projects created later");
    expect(html).toContain('aria-label="No eval of request data, as Warden stores it"');
    expect(t).toContain("pattern: eval($REQ.body)");
    expect(t).not.toContain("Delete rule…");
  });

  it("history: who and when, what each version changed, and a line diff of two versions", async () => {
    const r = db.RULE_NO_EVAL;
    const html = await render(`${rules()}/${r.id}?tab=history`);
    const t = text(html);
    for (const v of [4, 3, 2, 1]) expect(t).toContain(`Version ${v}`);
    expect(t).toContain("Current");
    expect(t).toMatch(/Version 4 Current Linh Tran/);
    expect(t).toContain("Turned on · Rule changed");
    expect(t).toContain("Turned off");
    expect(t).toContain("Projects: 1 project → All projects · Renamed from “No eval” · Rule changed");
    expect(t).toContain("Created for 1 project");
    expect(t).toContain("Compare versions");
    // Version 3 → 4: the message and the languages changed.
    expect(t).toContain("2 lines added, 2 removed from version 3 to version 4.");
    expect(t).toContain("Also: Turned on.");
    expect(html).toContain('aria-label="Changes from version 3 to version 4"');
    expect(html).toMatch(/class="line diff-del".*Removed: .*languages: \[javascript\]/s);
    expect(html).toMatch(/class="line diff-add".*Added: .*languages: \[javascript, typescript\]/s);
    expect(html.match(/class="line diff-same"/g)!.length).toBeGreaterThanOrEqual(4);
  });

  it("hostile names, keys and bodies are text, never markup", async () => {
    const list = db.scanRules[db.ORG_ID]!;
    const hostile = { ...db.RULE_NO_EVAL, id: db.uuid(), name: "<img src=x onerror=alert(1)>", body: "rules:\n  - id: x\n    message: <script>alert(1)</script>\n" };
    list.push(hostile);
    db.scanRuleVersions[hostile.id] = [{ version: 1, body: hostile.body, sha256: hostile.sha256, name: hostile.name, enabled: true, project_ids: null, created_by: null, created_at: hostile.created_at }];
    try {
      for (const path of [rules(), `${rules()}/${hostile.id}`, `${rules()}/${hostile.id}?tab=history`]) {
        const html = await render(path);
        expect(html).not.toContain("<img");
        expect(html).not.toContain("<script>");
        expect(html).toContain("&lt;img src=x onerror=alert(1)&gt;");
      }
      const ro = await render(`${rules()}/${hostile.id}`, (qc) => qc.setQueryData(qk.me, asRole("member")));
      expect(ro).toContain("&lt;script&gt;alert(1)&lt;/script&gt;");
    } finally {
      list.splice(list.indexOf(hostile), 1);
      delete db.scanRuleVersions[hostile.id];
    }
  });

  it("issue page: the Org rule tag and card, linked while the rule exists, 'a deleted rule' after", async () => {
    const live = await render(`${org()}/issues/${db.ORG_RULE_ISSUE.id}`);
    const t = text(live);
    expect(live).toContain('class="tag org-rule-tag"');
    expect(t).toContain("Org rule");
    expect(t).toContain("Found by No eval of request data , one of your org's own Opengrep rules · org.no-eval-of-request-data");
    expect(live).toContain(`href="/orgs/${db.ORG_ID}/settings/scan-rules/${db.RULE_NO_EVAL.id}"`);
    expect(t).toContain("Turning the rule off or changing it doesn't close this issue");
    const gone = await render(`${org()}/issues/${db.DELETED_RULE_ISSUE.id}`);
    const g = text(gone);
    expect(g).toContain("Found by a deleted rule");
    expect(g).toContain("org.no-pickle-loads");
    expect(g).toContain("It stays open until someone closes it.");
    expect(gone).not.toMatch(/href="[^"]*\/settings\/scan-rules\//);
    // Issues from built-in rules have neither.
    const plain = await render(`${org()}/issues/${db.issues[1]!.id}`);
    expect(plain).not.toContain("org-rule-tag");
    expect(text(plain)).not.toContain("Found by");
  });

  it("scan panel: the org rules the scan ran, at their versions; a deleted one as text", async () => {
    const web = db.projects[0]!;
    const html = await render(`${org()}/projects/${web.id}/scans?scan=${db.scans[0]!.id}`);
    const t = text(html);
    expect(t).toContain("Org rules · 3");
    expect(t).toContain("No eval of request data org.no-eval-of-request-data · Opengrep · version 2 (now 4)");
    expect(t).toContain("Unsafe YAML load org.unsafe-yaml-load · Opengrep · version 1");
    expect(t).toContain("Acme internal API token org.acme-internal-token · Gitleaks · version 1");
    expect(t).toContain("Issues from an org rule are fixed only by scans that run it.");
    expect(html).toContain(`href="/orgs/${db.ORG_ID}/settings/scan-rules/${db.RULE_NO_EVAL.id}"`);
    const pay = db.PAY_RULES_SCAN!;
    expect(pay).toBeDefined();
    const p = text(await render(`${org()}/projects/${pay.project_id}/scans?scan=${pay.id}`));
    expect(p).toContain("Org rules · 1");
    expect(p).toContain("Deleted rule org.no-pickle-loads · Opengrep · version 2");
    // A scan that ran no org rule says nothing about them.
    expect(text(await render(`${org()}/projects/${web.id}/scans?scan=${db.scans[1]!.id}`))).not.toContain("Org rules");
  });

  it("editor: the server's problems are marked at their lines and listed, each one a button to its line", async () => {
    const { RuleBodyField } = await import("../routes/ScanRule");
    const body = db.sampleRuleBodies.opengrepInvalid;
    const problems = [
      { line: 6, column: 20, message: "lookaround and backreferences aren't supported (Warden uses RE2 regular expressions)" },
      { line: 7, column: 5, message: "“paths” isn't allowed: org rules only add findings" },
      { line: 9, column: null, message: "a body holds exactly one rule; this is a second one" },
      { line: null, column: null, message: "<b>the rule needs languages</b>" },
    ];
    const html = renderToString(<RuleBodyField tool="opengrep" value={body} onChange={() => {}} problems={problems} textareaRef={{ current: null }} />);
    const t = text(html);
    // The gutter marks lines 6, 7 and 9 only.
    const gutter = html.match(/<div class="rule-gutter"[^>]*>(.*?)<\/div>/s)![1]!;
    expect([...gutter.matchAll(/<span class="bad">(\d+)<\/span>/g)].map((m) => Number(m[1]))).toEqual([6, 7, 9]);
    expect(html).toContain('aria-invalid="true"');
    expect(html).toMatch(/aria-describedby="[^"]*-p"/);
    expect(html).toContain('aria-label="Problems in the rule"');
    expect(t).toContain("Line 6:20 lookaround and backreferences aren't supported");
    expect(t).toContain("Line 7:5 “paths” isn't allowed: org rules only add findings");
    expect(t).toContain("Line 9 a body holds exactly one rule; this is a second one");
    expect(html.match(/<button type="button" class="btn-link mono">/g)).toHaveLength(3);
    // A problem without a line is listed as text; the server's words are never markup.
    expect(html).toContain("&lt;b&gt;the rule needs languages&lt;/b&gt;");
    expect(html).not.toContain("<b>the rule");
    // No problems: nothing marked, no list.
    const clean = renderToString(<RuleBodyField tool="gitleaks" value={db.sampleRuleBodies.gitleaksValid} onChange={() => {}} problems={[]} textareaRef={{ current: null }} />);
    expect(clean).not.toContain('class="bad"');
    expect(clean).not.toContain("Problems in the rule");
    expect(text(clean)).toContain("Rule (TOML)");
  });

  it("editor: a VERSION_CONFLICT on save shows “Someone changed this rule” with Reload", async () => {
    const { RuleConflictBanner } = await import("../routes/ScanRule");
    const html = renderToString(<RuleConflictBanner onReload={() => {}} reloading={false} />);
    const t = text(html);
    expect(html).toContain('role="alert"');
    expect(t).toContain("Someone changed this rule while you had it open.");
    expect(t).toContain("Your change wasn't saved.");
    expect(t).toContain("Reload rule");
  });

  it("command palette: Scan rules for everyone, new rules for those who manage them", async () => {
    const { pageItems } = await import("../components/CommandPalette");
    const lead = pageItems("/orgs/x", "security_lead").map((i) => i.label);
    expect(lead).toContain("Scan rules (Opengrep and Gitleaks)");
    expect(lead).toContain("New Opengrep rule");
    expect(lead).toContain("New Gitleaks rule");
    const member = pageItems("/orgs/x", "member").map((i) => i.label);
    expect(member).toContain("Scan rules (Opengrep and Gitleaks)");
    expect(member).not.toContain("New Opengrep rule");
    expect(pageItems("/orgs/x", "member").find((i) => i.id === "p-scan-rules")!.to).toBe("/orgs/x/settings/scan-rules");
  });

  it("org settings link to the Scan rules page", async () => {
    const t = text(await render(`${org()}/settings`));
    expect(t).toContain("Manage scan rules");
    const m = text(await render(`${org()}/settings`, (qc) => qc.setQueryData(qk.me, asRole("member"))));
    expect(m).toContain("View scan rules");
  });
});

describe("mock API follows the scan-rule contract", () => {
  const base = () => `/orgs/${db.ORG_ID}/scan-rules`;

  it("reading needs view_results, writing manage_rules; non-members get 404", async () => {
    expect((await call("GET", `/orgs/${db.ORG2_ID}/scan-rules`)).status).toBe(200);
    expect((await call("POST", `/orgs/${db.ORG2_ID}/scan-rules/validate`, { tool: "opengrep", body: "x" })).status).toBe(403);
    expect((await call("POST", `/orgs/${db.ORG2_ID}/scan-rules`, { tool: "opengrep", name: "x", body: "x" })).status).toBe(403);
    expect((await call("GET", `/orgs/00000000-0000-4000-8000-ffffffffffff/scan-rules`)).status).toBe(404);
    const list = await call("GET", `${base()}?tool=gitleaks`);
    expect(list.json.data!.items!.map((r) => r.key)).toEqual(["acme-internal-token"]);
    expect(Object.keys(list.json.data!.items![0]!).sort()).toEqual(
      ["body", "created_at", "created_by", "enabled", "id", "key", "name", "project_ids", "rule_id", "severity", "sha256", "tool", "updated_at", "updated_by", "version"].sort(),
    );
    expect((await call("GET", `${base()}?tool=trivy`)).status).toBe(422);
  });

  it("validate: problems at their lines for invalid rules; the canonical body for valid ones", async () => {
    const bad = await call("POST", `${base()}/validate`, { tool: "opengrep", body: db.sampleRuleBodies.opengrepInvalid });
    expect(bad.status).toBe(200);
    expect(bad.json.data).toMatchObject({ ok: false, key: null, severity: null, body: null });
    const problems = bad.json.data!.problems as { line: number | null; message: string }[];
    expect(problems.find((p) => p.line === 6)!.message).toMatch(/lookaround/);
    expect(problems.find((p) => p.line === 7)!.message).toMatch(/“paths” isn't allowed: org rules only add findings/);
    expect(problems.find((p) => p.line === 9)!.message).toMatch(/exactly one rule/);

    const gl = await call("POST", `${base()}/validate`, { tool: "gitleaks", body: db.sampleRuleBodies.gitleaksInvalid });
    const glp = gl.json.data!.problems as { line: number | null; message: string }[];
    expect(glp.find((p) => p.line === 2)!.message).toMatch(/the id must be lowercase/);
    expect(glp.find((p) => p.line === 3)!.message).toMatch(/lookaround/);
    expect(glp.find((p) => p.line === 4)!.message).toMatch(/allowlists aren't allowed/);

    const good = await call("POST", `${base()}/validate`, { tool: "opengrep", body: `# a comment\n${db.sampleRuleBodies.opengrepValid}   \n\n` });
    expect(good.json.data).toMatchObject({ ok: true, key: "no-eval-of-request-data", severity: "high", problems: [] });
    expect(good.json.data!.body).toBe(`${db.sampleRuleBodies.opengrepValid}\n`);
    const g2 = await call("POST", `${base()}/validate`, { tool: "gitleaks", body: db.sampleRuleBodies.gitleaksValid });
    expect(g2.json.data).toMatchObject({ ok: true, key: "acme-internal-token", severity: "high" });
  });

  it("create, change with the version, conflict, delete; RULE_INVALID carries metadata.problems", async () => {
    const invalid = await call("POST", base(), { tool: "gitleaks", name: "Bad", body: db.sampleRuleBodies.gitleaksInvalid });
    expect(invalid.status).toBe(422);
    expect(invalid.json.error!.code).toBe("RULE_INVALID");
    expect(invalid.json.error!.metadata!.problems!.map((p) => p.line)).toEqual(expect.arrayContaining([2, 3, 4]));
    // A key that exists for the scanner.
    expect((await call("POST", base(), { tool: "opengrep", name: "Again", body: db.sampleRuleBodies.opengrepValid })).json.error!.code).toBe("CONFLICT");
    expect((await call("POST", base(), { tool: "opengrep", name: "", body: "x" })).json.error!.metadata!.fields).toMatchObject({ name: expect.any(String) });

    const body = db.sampleRuleBodies.gitleaksValid.replace("acme-internal-token", "acme-session-cookie");
    const made = await call("POST", base(), { tool: "gitleaks", name: "Acme session cookie", body, enabled: false, project_ids: [db.projects[0]!.id] });
    expect(made.status).toBe(201);
    const r = made.json.data as { id: string; version: number; rule_id: string; enabled: boolean };
    expect(r).toMatchObject({ version: 1, rule_id: "org.acme-session-cookie", enabled: false });
    try {
      expect((await call("PATCH", `${base()}/${r.id}`, { version: 1 })).status).toBe(422);
      const on = await call("PATCH", `${base()}/${r.id}`, { version: 1, enabled: true, project_ids: null });
      expect(on.json.data).toMatchObject({ version: 2, enabled: true, project_ids: null });
      // The version that was read is stale now.
      const stale = await call("PATCH", `${base()}/${r.id}`, { version: 1, name: "x" });
      expect(stale.status).toBe(409);
      expect(stale.json.error!.code).toBe("VERSION_CONFLICT");
      const versions = await call("GET", `${base()}/${r.id}/versions`);
      expect(versions.json.data!.items!.map((v) => v.version)).toEqual([2, 1]);
      expect(versions.json.data!.next_cursor).toBeNull();
      expect((await call("DELETE", `${base()}/${r.id}?version=1`)).status).toBe(409);
    } finally {
      expect((await call("DELETE", `${base()}/${r.id}?version=2`)).status).toBe(204);
    }
    expect((await call("GET", `${base()}/${r.id}`)).status).toBe(404);
  });

  it("“Unsafe YAML load” changes under the first reader once: VERSION_CONFLICT, then the reload saves", async () => {
    const r = db.RULE_YAML;
    const saved = { ...r };
    const versions = [...db.scanRuleVersions[r.id]!];
    try {
      const first = await call("GET", `${base()}/${r.id}`);
      expect(first.json.data).toMatchObject({ version: 1 });
      const save = await call("PATCH", `${base()}/${r.id}`, { version: 1, enabled: false });
      expect(save.json.error!.code).toBe("VERSION_CONFLICT");
      const reloaded = await call("GET", `${base()}/${r.id}`);
      expect(reloaded.json.data).toMatchObject({ version: 2, updated_by: { display_name: "Huy Do" }, project_ids: null });
      expect((await call("PATCH", `${base()}/${r.id}`, { version: 2, enabled: false })).json.data).toMatchObject({ version: 3, enabled: false });
    } finally {
      Object.assign(r, saved);
      db.scanRuleVersions[r.id] = versions;
    }
  });

  it("deleting a rule keeps its issues open; they lose the rule's name and id only", async () => {
    const r = db.RULE_NO_EVAL;
    const list = db.scanRules[db.ORG_ID]!;
    const at = list.indexOf(r);
    const issue = db.ORG_RULE_ISSUE;
    const before = { status: issue.status, org_rule: issue.org_rule };
    try {
      expect((await call("DELETE", `${base()}/${r.id}?version=${r.version}`)).status).toBe(204);
      const got = await call("GET", `/orgs/${db.ORG_ID}/issues/${issue.id}`);
      expect(got.json.data).toMatchObject({ status: before.status, org_rule: { rule_id: r.rule_id, name: null, scan_rule_id: null } });
      // Summaries never carry org_rule (only the issue does).
      const listed = await call("GET", `/orgs/${db.ORG_ID}/issues?q=${encodeURIComponent(issue.key)}`);
      expect(listed.json.data!.items![0]).not.toHaveProperty("org_rule");
    } finally {
      list.splice(at, 0, r);
      issue.org_rule = before.org_rule;
    }
  });

  it("snippet tests: queued, running, done with 2 lines; failures by file name; never the snippet back; 20 an hour", async () => {
    const snippet = "const a = 1;\n// eval is fine in a comment? no:\neval(req.body.a);\nconst b = 2;\n\n\nfoo(eval(req.body.b));\n";
    const made: string[] = [];
    try {
      const start = await call("POST", `${base()}/tests`, { tool: "opengrep", body: db.sampleRuleBodies.opengrepValid, filename: "app.js", snippet });
      expect(start.status).toBe(202);
      const id = (start.json.data as { id: string }).id;
      made.push(id);
      expect(start.json.data).toMatchObject({ state: "queued", findings: [], error: null, finished_at: null });
      expect(JSON.stringify(start.json)).not.toContain("req.body.a");
      expect(JSON.stringify(db.ruleTests[id])).not.toContain("req.body.a");
      db.ruleTests[id]!._t! -= 2000;
      expect((await call("GET", `${base()}/tests/${id}`)).json.data).toMatchObject({ state: "running" });
      db.ruleTests[id]!._t! -= 3000;
      const done = await call("GET", `${base()}/tests/${id}`);
      expect(done.json.data).toMatchObject({ state: "done", error: null, findings: [{ line: 3 }, { line: 7 }] });
      expect(JSON.stringify(done.json)).not.toContain("req.body");

      const failed = await call("POST", `${base()}/tests`, { tool: "opengrep", body: db.sampleRuleBodies.opengrepValid, filename: "timeout.js", snippet });
      const fid = (failed.json.data as { id: string }).id;
      made.push(fid);
      db.ruleTests[fid]!._t! -= 5000;
      expect((await call("GET", `${base()}/tests/${fid}`)).json.data).toMatchObject({ state: "failed", error: "timeout", findings: [] });

      // An invalid rule isn't run; a bad file name is a field error.
      const inv = await call("POST", `${base()}/tests`, { tool: "gitleaks", body: db.sampleRuleBodies.gitleaksInvalid, filename: "a.env", snippet });
      expect(inv.json.error!.code).toBe("RULE_INVALID");
      expect((await call("POST", `${base()}/tests`, { tool: "opengrep", body: db.sampleRuleBodies.opengrepValid, filename: "../x.js", snippet })).json.error!.metadata!.fields).toHaveProperty("filename");

      // The seeded results: 2 lines found, and a timeout.
      expect((await call("GET", `${base()}/tests/${db.TEST_TWO_LINES.id}`)).json.data).toMatchObject({ state: "done", findings: [{ line: 3 }, { line: 7, end_line: 8 }] });
      expect((await call("GET", `${base()}/tests/${db.TEST_FAILED.id}`)).json.data).toMatchObject({ state: "failed", error: "timeout" });

      // Only its creator can read a test.
      db.ruleTests[id]!._by = "someone-else";
      expect((await call("GET", `${base()}/tests/${id}`)).status).toBe(404);
      db.ruleTests[id]!._by = db.me.id;

      // 20 per user per hour, then 429 with Retry-After.
      let limited: Awaited<ReturnType<typeof call>> | null = null;
      for (let i = 0; i < 25 && !limited; i++) {
        const r = await call("POST", `${base()}/tests`, { tool: "opengrep", body: db.sampleRuleBodies.opengrepValid, filename: "app.js", snippet: "x" });
        if (r.status === 429) limited = r;
        else made.push((r.json.data as { id: string }).id);
      }
      expect(limited!.json.error!.code).toBe("RATE_LIMITED");
      expect(limited!.headers.get("Retry-After")).toBeTruthy();
      expect(made.length).toBe(20);
      // Members can't run tests.
      expect(await withRole("member", async () => (await call("POST", `${base()}/tests`, { tool: "opengrep", body: "x", filename: "a.js", snippet: "x" })).status)).toBe(403);
    } finally {
      for (const id of made) delete db.ruleTests[id];
    }
  });

  it("a new scan runs the enabled org rules in its project's scope", async () => {
    const web = db.projects[0]!;
    const r = await call("POST", `/orgs/${db.ORG_ID}/projects/${web.id}/scans`, { file_name: "web.zip", file_size: 10, sha256: "a".repeat(64) });
    const scan = (r.json.data as { scan: { id: string; org_rules: { rule_id: string; version: number }[] } }).scan;
    try {
      // MD5 is off and scoped to PAY; Unsafe YAML load includes WEB; the others are org-wide.
      expect(scan.org_rules.map((x) => x.rule_id).sort()).toEqual(["org.acme-internal-token", "org.no-eval-of-request-data", "org.unsafe-yaml-load"]);
    } finally {
      db.scans.splice(
        db.scans.findIndex((s) => s.id === scan.id),
        1,
      );
    }
  });
});
