// Smoke test for every screen without a browser or DOM library: render each route to HTML with
// react-dom/server against the dev mock API. Queries don't run during server rendering, so each
// pass collects the queries the screen created, fetches them through the mock, and renders
// again until nothing is pending. A render error fails the test; the final HTML must contain
// text from the loaded data.
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

beforeAll(async () => {
  vi.stubEnv("VITE_MOCK", "1");
  vi.stubGlobal("window", { location: { origin: "http://localhost", search: "", pathname: "/" } });
  db = await import("../api/mock/fixtures");
  ({ appRoutes } = await import("../App"));
  ({ AuthGate } = await import("../auth/AuthGate"));
  ({ qk } = await import("../api/keys"));
  ({ preloadRoutes } = await import("../lib/lazyRoute"));
  const { isMockMode } = await import("../api/client");
  expect(isMockMode).toBe(true);
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
      // A lazy route chunk that isn't loaded yet renders the Suspense fallback; React.lazy
      // settles a tick after its import resolves, then the next pass renders the page.
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

const text = (html: string) => html.replace(/<[^>]+>/g, " ").replace(/&#x27;/g, "'").replace(/&amp;/g, "&").replace(/\s+/g, " ");

describe("every screen renders with mock data", () => {
  const org = () => `/orgs/${db.ORG_ID}`;
  const web = () => db.projects[0]!;

  it("projects", async () => {
    const t = text(await render(`${org()}/projects`));
    expect(t).toContain("Web storefront");
    expect(t).toContain("No scan yet");
    // WEB: two code issues, (v0.3) Log4Shell from the image scan and (v0.4 wave 2) the AWS key
    // found in git history. (This used to match "23 Critical", the org total before it.)
    expect(t).toMatch(/Web storefront WEB Owner 4 Critical/);
    expect(t).toContain("Exceptions to review");
  });

  it("project issues, scans, members, settings", async () => {
    const base = `${org()}/projects/${web().id}`;
    expect(text(await render(`${base}/issues`))).toContain("AWS access key in deploy config");
    const scans = text(await render(`${base}/scans`));
    expect(scans).toContain("Scan history");
    expect(scans).toContain("Rejected");
    expect(scans).toContain("path outside the root");
    expect(scans).toContain("Partial · a scanner failed");
    const partial = db.scans.find((s) => s.status === "partial")!;
    expect(text(await render(`${base}/scans?scan=${partial.id}`))).toContain("Partial · Trivy timed out");
    const rejected = db.scans.find((s) => s.error_code === "ZIP_PATH_TRAVERSAL")!;
    const r = text(await render(`${base}/scans?scan=${rejected.id}`));
    expect(r).toContain("Archive rejected");
    expect(r).toContain("Nothing was scanned and no issues changed.");
    expect(text(await render(`${base}/members`))).toContain("Minh Pham");
    expect(text(await render(`${base}/settings`))).toContain("Default scanners");
  });

  it("issue list with filters from the URL", async () => {
    const all = text(await render(`${org()}/issues`));
    expect(all).toMatch(/\d+ issues match/);
    expect(all).toContain("WEB-41");
    const filtered = text(await render(`${org()}/issues?severity=critical&past_sla=true`));
    expect(filtered).toContain("2 issues match");
    const none = text(await render(`${org()}/issues?q=nothing-matches-this`));
    expect(none).toContain("No issues match these filters");
  });

  it("issue detail: masked snippet, actions from the payload, comment warning", async () => {
    const issue = db.issues[0]!;
    const html = await render(`${org()}/issues/${issue.id}`);
    const t = text(html);
    expect(t).toContain("AWS_ACCESS_KEY_ID=AKIA****");
    expect(t).toContain("Warden stores only its first 4 characters");
    expect(t).toContain("Reassign");
    expect(html).toContain("Write a comment. Never paste secrets here.");
    expect(t).toContain("Activity");
    const pkg = text(await render(`${org()}/issues/${db.issues[2]!.id}`));
    expect(pkg).toContain("upgrade to v0.23.0");
  });

  it("split view links: the list's filters travel to the issue and back", async () => {
    const issue = db.issues[0]!;
    const list = await render(`${org()}/issues?severity=critical&past_sla=true`);
    // Row links open the issue with the same filters in the query string.
    expect(list).toContain(`href="/orgs/${db.ORG_ID}/issues/${issue.id}?severity=critical&amp;past_sla=true"`);
    // Below 1200 px (and in server rendering) the issue is its own page; its back link
    // returns to the filtered list. Unknown query parameters are not carried over.
    const page = await render(`${org()}/issues/${issue.id}?severity=critical&past_sla=true&evil=1`);
    expect(page).toContain(`href="/orgs/${db.ORG_ID}/issues?severity=critical&amp;past_sla=true"`);
    expect(page).not.toContain("evil");
    // From a project's tab, the project becomes a filter on the org-wide list.
    const web = db.projects[0]!;
    const tab = await render(`${org()}/projects/${web.id}/issues`);
    expect(tab).toContain(`href="/orgs/${db.ORG_ID}/issues/${issue.id}?project=${web.id}"`);
  });

  it("saved views are presets of the URL filters", async () => {
    const t = await render(`${org()}/issues?assignee=me`);
    expect(t).toMatch(/<a[^>]*aria-current="true"[^>]*>Assigned to me</);
    expect(t).not.toMatch(/<a[^>]*aria-current="true"[^>]*>Active</);
    expect(t).toContain(`href="/orgs/${db.ORG_ID}/issues?tool=gitleaks"`);
    expect(t).toContain(`href="/orgs/${db.ORG_ID}/issues?past_sla=true"`);
  });

  it("issue that doesn't exist shows the generic 404", async () => {
    const t = text(await render(`${org()}/issues/00000000-0000-4000-8000-ffffffffffff`));
    expect(t).toContain("Not found");
    expect(t).toContain("doesn't exist, or you don't have access to it");
  });

  it("exceptions: queue, review panel, own request can't be decided", async () => {
    const t = text(await render(`${org()}/exceptions`));
    expect(t).toContain("Review");
    expect(t).toContain("Approve");
    const own = db.exceptions.find((e) => e.requested_by.id === db.me.id)!;
    expect(text(await render(`${org()}/exceptions?id=${own.id}`))).toContain("You can't decide on a request you made yourself. Another");
    expect(text(await render(`${org()}/exceptions?tab=rejected`))).toContain("No rejected requests");
  });

  it("members and permission matrix", async () => {
    const t = text(await render(`${org()}/members`));
    expect(t).toContain("What each role can do");
    expect(t).toContain("Own issues");
    expect(t).toContain("Deactivated");
  });

  it("audit log", async () => {
    const t = text(await render(`${org()}/audit-log`));
    expect(t).toContain("Append-only and hash-chained.");
    expect(t).toContain("WEB-41 open → assigned".replace("WEB-41", db.issues[0]!.key));
    expect(t).toContain("System");
  });

  it("an org the user isn't in looks like any missing page", async () => {
    const t = text(await render(`/orgs/00000000-0000-4000-8000-0000000000aa/projects`));
    expect(t).toContain("Not found");
  });

  // ---- v0.2 ----

  it("code-split routes render: overview with charts and table alternatives", async () => {
    const html = await render(`${org()}/overview?days=90`);
    const t = text(html);
    expect(html).not.toContain("data-route-loading");
    expect(t).toContain("Open issues by severity");
    expect(t).toContain("New vs fixed");
    expect(t).toContain("Time to fix");
    expect(t).toContain("SLA compliance");
    expect(t).toContain("Per week");
    expect(t.match(/Show the data as a table/g)).toHaveLength(4);
    expect(html).toMatch(/role="img" aria-label="New vs fixed, all projects: \d+ new and \d+ fixed in the last 90 days\."/);
    expect(html).toContain('aria-pressed="true"');
    // Overview is the first item in the navigation.
    expect(html.indexOf("Overview</span>")).toBeLessThan(html.indexOf("All projects</span>"));
  });

  it("org settings: editable for a security lead, read-only for a member", async () => {
    const lead = text(await render(`${org()}/settings`));
    expect(lead).toContain("SLA policy");
    expect(lead).toContain("Save policy");
    expect(lead).toContain("Also recalculate the due dates of open issues");
    const member = text(await render(`/orgs/${db.ORG2_ID}/settings`));
    expect(member).toContain("Only security leads can change the SLA policy");
    expect(member).not.toContain("Save policy");
  });

  it("org settings, sign-in: security leads read, members don't see it", async () => {
    const html = await render(`${org()}/settings`);
    const t = text(html);
    expect(t).toContain("Identity provider");
    expect(t).toContain("https://id.acme.example/realms/warden");
    expect(t).toContain("Discovered from the issuer");
    expect(t).toContain("2 signing keys loaded, last refreshed");
    expect(t).toContain("set up at the identity provider, not in Warden");
    expect(html).toMatch(/<a href="https:\/\/id\.acme\.example\/admin\/warden\/console\/" target="_blank" rel="noopener noreferrer">Open identity provider console/);
    expect(t).toMatch(/Org admin : required · Required by the server/);
    expect(t).toMatch(/Member : not required/);
    expect(t).toContain("All org admins and security leads have signed in with two-factor.");
    expect(t).toContain("acme.example");
    expect(t).toContain("Only org admins can change the sign-in policy");
    expect(t).not.toContain("Save sign-in policy");
    expect(html).not.toContain('id="mfa-role-member"');

    const member = text(await render(`/orgs/${db.ORG2_ID}/settings`));
    expect(member).not.toContain("Identity provider");
    expect(member).not.toContain("Sign-in policy");
  });

  it("mock API follows the sign-in contract: roles, 422 field errors, 409 MFA_NOT_ENABLED, the domain rule", async () => {
    const { mockFetch } = await import("../api/mock/server");
    const call = async (method: string, path: string, body?: unknown) => {
      const r = await mockFetch(`/api/v1${path}`, { method, body: body === undefined ? undefined : JSON.stringify(body) });
      return { status: r.status, json: (await r.json()) as { data: { policy?: unknown } | null; error: { code: string; metadata?: { fields?: Record<string, string> } } | null } };
    };
    const signIn = `/orgs/${db.ORG_ID}/sign-in`;
    const put = `/orgs/${db.ORG_ID}/sign-in-policy`;
    expect((await call("GET", signIn)).status).toBe(200);
    expect((await call("GET", `/orgs/${db.ORG2_ID}/sign-in`)).status).toBe(403);
    expect((await call("PUT", put, { mfa_roles: [], allowed_email_domains: [] })).status).toBe(403);

    const eng = db.me.orgs.find((o) => o.id === db.ORG_ID)!;
    const before = { role: eng.role, settings: db.signIn[db.ORG_ID]! };
    eng.role = "org_admin";
    try {
      const bad = await call("PUT", put, { mfa_roles: ["member", "member"], allowed_email_domains: ["ok.example", "*.example.com", "OK.example"] });
      expect(bad.status).toBe(422);
      expect(bad.json.error?.metadata?.fields).toEqual({
        mfa_roles: expect.any(String),
        "allowed_email_domains[1]": expect.any(String),
        "allowed_email_domains[2]": "duplicate domain",
      });
      // Requiring a role for the caller's own role, newly, without a second factor.
      db.signIn[db.ORG_ID] = { ...before.settings, mfa: { ...before.settings.mfa, instance_roles: [], effective_roles: [] } };
      const locked = await call("PUT", put, { mfa_roles: ["org_admin"], allowed_email_domains: [] });
      expect(locked.status).toBe(409);
      expect(locked.json.error?.code).toBe("MFA_NOT_ENABLED");
      db.signIn[db.ORG_ID] = before.settings;
      const ok = await call("PUT", put, { mfa_roles: ["member"], allowed_email_domains: ["acme.example", "corp.acme.example"] });
      expect(ok.status).toBe(200);
      expect(ok.json.data?.policy).toEqual({ mfa_roles: ["member"], allowed_email_domains: ["acme.example", "corp.acme.example"] });
      const add = await call("POST", `/orgs/${db.ORG_ID}/members`, { email: "someone@elsewhere.example", role: "member" });
      expect(add.status).toBe(422);
      expect(add.json.error?.metadata?.fields?.email).toBe("must be an address at one of: acme.example, corp.acme.example");
    } finally {
      eng.role = before.role;
      db.signIn[db.ORG_ID] = before.settings;
    }
  });

  it("org settings, sign-in: org admins edit; server-required roles are fixed", async () => {
    const asAdmin = { ...db.me, orgs: db.me.orgs.map((o) => (o.id === db.ORG_ID ? { ...o, role: "org_admin" as const } : o)) };
    const html = await render(`${org()}/settings`, (qc) => qc.setQueryData(qk.me, asAdmin));
    const t = text(html);
    expect(t).toContain("Save sign-in policy");
    expect(html).toMatch(/<button type="submit"[^>]*disabled=""[^>]*>Save sign-in policy/);
    expect(html).toMatch(/<legend[^>]*>Require two-factor sign-in for<\/legend>/);
    const checkbox = (role: string) => html.match(new RegExp(`<input id="mfa-role-${role}"[^>]*>`))?.[0] ?? "";
    for (const fixed of ["org_admin", "security_lead"]) {
      expect(checkbox(fixed)).toContain('checked=""');
      expect(checkbox(fixed)).toContain('disabled=""');
      expect(checkbox(fixed)).toContain(`aria-describedby="mfa-role-${fixed}-h"`);
    }
    expect(checkbox("member")).toContain('type="checkbox"');
    expect(checkbox("member")).not.toContain("checked");
    expect(checkbox("member")).not.toContain("disabled");
    expect(t).toContain("Required by the server");
    expect(html).toContain('value="acme.example"');
    expect(html).toContain('aria-label="Remove acme.example"');
    expect(t).toContain("1 of 20");
    expect(t).toContain("Existing members stay");
    expect(t).not.toContain("Only org admins can change the sign-in policy");
  });

  it("notification preferences and the bell", async () => {
    const html = await render(`${org()}/preferences`);
    const t = text(html);
    expect(t).toContain("Issue assigned to you");
    expect(t).toContain("Scan finished");
    expect(t).toContain("Save preferences");
    expect(html).toContain('aria-label="Notifications, 5 unread"');
    expect(html).toContain('role="switch"');
  });

  it("project settings: tokens (prefix only), CI snippets without a token, rules, archive", async () => {
    const web = db.projects[0]!;
    const html = await render(`${org()}/projects/${web.id}/settings`);
    const t = text(html);
    expect(t).toContain("API tokens");
    expect(t).toContain("wdn_k7m2q4xa_…");
    expect(t).toContain("Revoked");
    expect(t).toContain("Expired");
    expect(t).toContain("CI setup");
    expect(t).toContain(`--org ${db.ORG_ID}`);
    expect(t).toContain(`--project ${web.id}`);
    expect(t).toContain("secrets.WARDEN_TOKEN");
    expect(html).not.toMatch(/wdn_[a-z2-7]{8}_[a-z2-7]{20,}/);
    expect(t).toContain("Auto-assign rules");
    expect(html).toContain('value="internal/payments/**"');
    expect(t).toContain("Archive project");
  });

  it("creating a token needs run_scan too: an org admin can list and revoke but not create", async () => {
    const web = db.projects[0]!;
    const asAdmin = { ...db.me, orgs: db.me.orgs.map((o) => (o.id === db.ORG_ID ? { ...o, role: "org_admin" as const } : o)) };
    const projectAsNonMember = { ...web, my_role: null };
    const html = await render(`${org()}/projects/${web.id}/settings`, (qc) => {
      qc.setQueryData(qk.me, asAdmin);
      qc.setQueryData(qk.project(db.ORG_ID, web.id), projectAsNonMember);
    });
    expect(html).toMatch(/<button[^>]*disabled=""[^>]*aria-describedby="tokens-blocked"/);
    expect(text(html)).toContain("creating one needs a role that can run scans here");
    expect(text(html)).toContain("Revoke");
  });

  it("archived project: banner, no upload, hidden from the list unless asked", async () => {
    const leg = db.projects[4]!;
    const scans = text(await render(`${org()}/projects/${leg.id}/scans`));
    expect(scans).toContain("This project takes no new scans");
    expect(scans).toContain("Uploads are turned off");
    expect(scans).not.toContain("Upload .zip");
    expect(text(await render(`${org()}/projects`))).not.toContain("Legacy portal");
    expect(text(await render(`${org()}/projects?archived=1`))).toContain("Legacy portal");
  });

  it("saved views show counts from /issues/counts", async () => {
    const t = text(await render(`${org()}/issues`));
    const secrets = db.issues.filter((i) => i.tool === "gitleaks" && ["open", "assigned", "in_progress", "reopened"].includes(i.status)).length;
    expect(t).toMatch(new RegExp(`Secrets , ${secrets} issues`));
    expect(t).toMatch(/Past SLA , \d+ issues/);
  });

  it("MFA_REQUIRED from me.mfa_required_orgs: full page, no org data loaded", async () => {
    const { resetMfaBlocked } = await import("../lib/mfa");
    resetMfaBlocked();
    const html = await render(`/orgs/${db.ORG3_ID}/projects`);
    const t = text(html);
    expect(t).toContain("Two-factor sign-in required");
    expect(t).toContain("Sign out and sign in again");
    expect(t).toContain("Acme Security");
    expect(t).not.toContain("Search or jump to");
    expect(t).not.toContain("All projects");
  });

  it("MFA_REQUIRED from an error code shows the same page", async () => {
    const { resetMfaBlocked } = await import("../lib/mfa");
    resetMfaBlocked();
    const t = text(await render(`/orgs/${db.ORG3_ID}/projects`, (qc) => qc.setQueryData(qk.me, { ...db.me, mfa_required_orgs: [] })));
    expect(t).toContain("Two-factor sign-in required");
    resetMfaBlocked();
  });

  it("a user with no org gets the operator instructions", async () => {
    const t = text(await render("/", (qc) => qc.setQueryData(qk.me, { ...db.me, orgs: [] })));
    expect(t).toContain("You're not in an organization yet");
    expect(t).toContain("warden-admin org create");
    expect(t).toContain(db.me.email);
  });

  // ---- v0.3 ----

  it("scans: image scans in the history, the SBOM download, image rejections, the Source/Image switch", async () => {
    const base = `${org()}/projects/${web().id}/scans`;
    const html = await render(base);
    const t = text(html);
    expect(t).toContain("api-1.4.2.tar");
    expect(t).toMatch(/Image ghcr\.io\/acme\/api:1\.4\.2/);
    expect(t).toContain("more than one image");
    expect(html).toMatch(/<div class="segmented kind-switch" role="group" aria-label="What to scan">/);
    expect(html).toMatch(/<button type="button" aria-pressed="true">Source code<\/button>/);
    expect(html).toContain('accept=".zip,application/zip"');

    const image = db.scans.find((s) => s.file_name === "api-1.4.2.tar")!;
    const panel = text(await render(`${base}?scan=${image.id}`));
    expect(panel).toContain("Download SBOM (CycloneDX)");
    expect(panel).toContain("412 components · 1.2 MB");
    expect(panel).toContain("Issues tracked under ghcr.io/acme/api");
    // A source scan has its SBOM too; a partial scan whose Trivy timed out has none.
    const partial = db.scans.find((s) => s.status === "partial")!;
    expect(text(await render(`${base}?scan=${partial.id}`))).not.toContain("Download SBOM");
    const viewIssues = await render(`${base}?scan=${image.id}`);
    expect(viewIssues).toContain(`href="/orgs/${db.ORG_ID}/projects/${web().id}/issues?target=ghcr.io%2Facme%2Fapi"`);

    const rejected = db.scans.find((s) => s.error_code === "IMAGE_MULTIPLE")!;
    const r = text(await render(`${base}?scan=${rejected.id}`));
    expect(r).toContain("Image rejected");
    expect(r).toMatch(/The archive holds more than one image ?\. Save one image per file/);
    expect(r).toContain("IMAGE_MULTIPLE");
    expect(r).toContain("Upload a new .tar");
  });

  it("issue list: KEV and EPSS on rows, the KEV and Licenses views with counts, the EPSS sort", async () => {
    const html = await render(`${org()}/issues`);
    const t = text(html);
    const active = db.issues.filter((i) => ["open", "assigned", "in_progress", "reopened"].includes(i.status));
    expect(t).toMatch(new RegExp(`Exploited \\(KEV\\) , ${active.filter((i) => i.kev).length} issues`));
    expect(t).toMatch(new RegExp(`Licenses , ${active.filter((i) => i.rule_id.startsWith("license:")).length} issues`));
    expect(html).toContain(`href="/orgs/${db.ORG_ID}/issues?kev=true"`);
    expect(html).toContain(`href="/orgs/${db.ORG_ID}/issues?kind=license"`);
    // The KEV mark has an accessible name; EPSS reads as a percentage.
    expect(t).toContain("Known exploited (CISA KEV)");
    expect(t).toContain("EPSS 94%");
    expect(html).toContain('<option value="-epss">Exploit probability</option>');

    const kev = await render(`${org()}/issues?kev=true&sort=-epss`);
    expect(kev).toMatch(/<a[^>]*aria-current="true"[^>]*>Exploited \(KEV\)/);
    expect(text(kev)).toContain(`${active.filter((i) => i.kev).length} issues match`);
    expect(text(kev)).not.toContain("SQL built from request parameters");

    const lic = text(await render(`${org()}/issues?kind=license`));
    expect(lic).toContain("@acme/legacy-charts uses GPL-3.0-only (restricted)");
    expect(lic).not.toContain("log4j-core");

    const filtered = text(await render(`${org()}/issues?source=image&target=ghcr.io%2Facme%2Fapi&epss_min=0.5`));
    expect(filtered).toContain("Image is ghcr.io/acme/api");
    expect(filtered).toContain("EPSS ≥ 50%");
    expect(filtered).toContain("Source is Container images");
    expect(filtered).toContain("2 issues match");
  });

  it("issue detail: KEV block, EPSS, CVE linked to NVD, image location", async () => {
    const log4shell = db.issues.find((i) => i.rule_id === "CVE-2021-44228")!;
    const html = await render(`${org()}/issues/${log4shell.id}`);
    const t = text(html);
    expect(t).toContain("Known exploited (CISA KEV)");
    expect(t).toContain("added to the catalog on Dec 10, 2021");
    expect(t).toContain("Used in ransomware campaigns");
    expect(html).toContain('<a href="https://www.cisa.gov/known-exploited-vulnerabilities-catalog" target="_blank" rel="noopener noreferrer">CISA KEV catalog');
    expect(t).toContain("94% chance of exploitation in the next 30 days (FIRST EPSS) , higher than 99.9% of scored CVEs");
    expect(html).toContain('<a href="https://nvd.nist.gov/vuln/detail/CVE-2021-44228" target="_blank" rel="noopener noreferrer">CVE-2021-44228');
    expect(t).toContain("Image ghcr.io/acme/api · app/lib/log4j-core-2.14.1.jar · org.apache.logging.log4j:log4j-core 2.14.1 → upgrade to 2.17.1");
    expect(t).toContain("They don't change the severity or the SLA.");
  });

  it("issue detail: malformed CVE ids from scanner output are never links", async () => {
    const base = db.issues.find((i) => i.rule_id === "CVE-2023-4911")!;
    const hostile = { ...base, cve: ["CVE-2023-4911", 'CVE-2023-1"><img src=x onerror=alert(1)>', "javascript:alert(1)", "CVE-2023-4911/../../x"] };
    const html = await render(`${org()}/issues/${base.id}`, (qc) => qc.setQueryData(qk.issue(db.ORG_ID, base.id), hostile));
    expect(html.match(/href="https:\/\/nvd\.nist\.gov\/vuln\/detail\/[^"]*"/g)).toEqual(['href="https://nvd.nist.gov/vuln/detail/CVE-2023-4911"']);
    expect(html).not.toContain("<img");
    expect(html).not.toMatch(/href="javascript:/);
    expect(text(html)).toContain("javascript:alert(1)");
  });

  it("issue detail: a license issue shows the license, not an upgrade", async () => {
    const gpl = db.issues.find((i) => i.rule_id === "license:GPL-3.0-only")!;
    const t = text(await render(`${org()}/issues/${gpl.id}`));
    expect(t).toMatch(/License GPL-3\.0-only \( ?restricted ?\) in @acme\/legacy-charts 2\.1\.0/);
    expect(t).not.toContain("no fixed version yet");
    expect(t).not.toContain("Exploitation");
  });

  it("org settings: the license policy form for a security lead, vulnerability data for everyone", async () => {
    const html = await render(`${org()}/settings`);
    const t = text(html);
    expect(t).toContain("License policy");
    expect(t).toContain("Apply recommended preset");
    expect(t).toContain("License data depends on the lockfile.");
    expect(html.match(/<select id="license-cat-[a-z]+"/g)).toHaveLength(7);
    expect(html).toMatch(/<select id="license-cat-forbidden"[^>]*>.*<option value="block" selected="">Block · High issue/s);
    expect(t).toContain("SSPL-1.0");
    expect(html).toContain('aria-label="Remove SSPL-1.0 from Deny"');
    expect(t).toContain("2 of 100");
    expect(html).toMatch(/<button type="submit"[^>]*disabled=""[^>]*>Save license policy/);
    expect(t).toContain("Vulnerability data");
    expect(t).toContain("CISA KEV catalog");
    expect(t).toContain("1,484 CVEs");
    expect(t).toContain("Out of date");
    expect(t).toMatch(/Out of date or missing: FIRST EPSS scores ?\./);
    expect(t).toContain("make mirror");
  });

  it("org settings: members read the license policy; it says Off until it is set", async () => {
    const t = text(await render(`/orgs/${db.ORG2_ID}/settings`));
    expect(t).toContain("License policy");
    expect(t).toMatch(/Off\. No license issues are created/);
    expect(t).toContain("Only security leads can change the license policy");
    expect(t).not.toContain("Save license policy");
    expect(t).toContain("Vulnerability data");
  });

  it("overview: a Known exploited tile linking to the KEV view", async () => {
    const html = await render(`${org()}/overview`);
    expect(html).toMatch(new RegExp(`<a class="stat-label" href="/orgs/${db.ORG_ID}/issues\\?kev=true"[^>]*>Known exploited</a>`));
    expect(text(html)).toContain("Open, in CISA KEV");
  });

  it("mock API follows the v0.3 contract: license policy rules, SBOM 404, image scan creation", async () => {
    const { mockFetch } = await import("../api/mock/server");
    const call = async (method: string, path: string, body?: unknown) => {
      const r = await mockFetch(`/api/v1${path}`, { method, body: body === undefined ? undefined : JSON.stringify(body) });
      return { status: r.status, json: (await r.json()) as { data: Record<string, unknown> | null; error: { code: string; metadata?: { fields?: Record<string, string> } } | null } };
    };
    const lp = `/orgs/${db.ORG_ID}/license-policy`;
    const before = db.licensePolicies[db.ORG_ID]!;
    try {
      expect((await call("GET", `/orgs/${db.ORG2_ID}/license-policy`)).json.data?.enabled).toBe(false);
      expect((await call("PUT", `/orgs/${db.ORG2_ID}/license-policy`, { categories: before.categories, deny: [], allow: [] })).status).toBe(403);
      const bad = await call("PUT", lp, { categories: { ...before.categories, unknown: "maybe" }, deny: ["MIT", "not an id"], allow: ["mit"] });
      expect(bad.status).toBe(422);
      expect(bad.json.error?.metadata?.fields).toEqual({ "categories.unknown": expect.any(String), "deny[1]": expect.any(String), "allow[0]": "also in deny" });
      const ok = await call("PUT", lp, { categories: before.categories, deny: [], allow: ["MIT"] });
      expect(ok.json.data).toMatchObject({ enabled: true, deny: [], allow: ["MIT"] });
    } finally {
      db.licensePolicies[db.ORG_ID] = before;
    }

    const noSbom = db.scans.find((s) => s.status === "partial")!;
    expect((await call("GET", `/orgs/${db.ORG_ID}/scans/${noSbom.id}/sbom`)).status).toBe(404);
    const image = db.scans.find((s) => s.file_name === "api-1.4.2.tar")!;
    const link = await call("GET", `/orgs/${db.ORG_ID}/scans/${image.id}/sbom`);
    expect(link.json.data).toMatchObject({ format: "cyclonedx-json", components: 412, url: expect.stringMatching(/^https:\/\//) });

    const scans = `/orgs/${db.ORG_ID}/projects/${web().id}/scans`;
    const sha = "a".repeat(64);
    const badImage = await call("POST", scans, { file_name: "a.tar", file_size: 4, sha256: sha, kind: "image", target: "ghcr.io/acme/api:1", tools: ["opengrep"] });
    expect(badImage.json.error?.metadata?.fields).toEqual({ target: expect.any(String), tools: expect.any(String) });
    const created = await call("POST", scans, { file_name: "a.tar", file_size: 4, sha256: sha, kind: "image", target: "ghcr.io/acme/api", image_ref: "ghcr.io/acme/api:2" });
    expect(created.status).toBe(201);
    const made = (created.json.data as { scan: { id: string; kind: string; tools: string[]; target: string } }).scan;
    // v0.7 wave 2: image scans run Trivy and Gitleaks (secrets in the layers).
    expect(made).toMatchObject({ kind: "image", tools: ["trivy", "gitleaks"], target: "ghcr.io/acme/api", pulled: false });
    db.scans.splice(db.scans.findIndex((s) => s.id === made.id), 1);
  });
});

describe("v0.4 screens: component inventory, malicious packages, SPDX", () => {
  const org = () => `/orgs/${db.ORG_ID}`;
  const labs = () => `/orgs/${db.ORG2_ID}`;
  const web = () => db.projects[0]!;
  const call = async (method: string, path: string) => {
    const { mockFetch } = await import("../api/mock/server");
    const r = await mockFetch(`/api/v1${path}`, { method });
    return { status: r.status, json: (await r.json()) as { data: { items?: Record<string, unknown>[]; next_cursor?: string | null } & Record<string, unknown>; error: { code: string } | null } };
  };

  it("components page: the sidebar entry, the table, the malicious tag, the filters", async () => {
    const html = await render(`${org()}/components`);
    const t = text(html);
    expect(html).toContain(`href="/orgs/${db.ORG_ID}/components"`);
    expect(t).toContain("Components");
    expect(t).toContain("acme-ui-icons");
    expect(t).toContain("Malicious package (OSV advisory)");
    expect(html).toContain('aria-label="Ecosystem"');
    expect(html).toContain('aria-label="Project"');
    expect(html).toMatch(/<button type="button" class="toggle-chip" aria-pressed="false">/);
    // Archived projects (LEG's jquery) and another org's components (LAB's PyPI) are left out.
    expect(t).not.toContain("jquery");
    expect(t).not.toContain("acme-dataloader");
    // A row is a button that opens "Used in" (a disclosure, not a link).
    expect(html).toMatch(/<button type="button" class="row-button mono comp-name"[^>]*aria-expanded="false"[^>]*>axios/);
    expect(t).toMatch(/Showing 50 components/);

    const mal = text(await render(`${org()}/components?malicious=true`));
    expect(mal).toContain("acme-ui-icons");
    expect(mal).not.toContain("axios");
    const version = text(await render(`${org()}/components?q=${encodeURIComponent("zod 3.25.76")}`));
    expect(version).toContain("zod");
    expect(version).not.toContain("axios");
    const none = text(await render(`${org()}/components?q=nothing-is-called-this&ecosystem=PyPI`));
    expect(none).toContain("No components match these filters");
    expect(none).toContain("Name starts with “nothing-is-called-this”");
  });

  it("component names, paths and purls are text, never markup or links", async () => {
    const hostile = {
      ...db.inventory[0]!,
      name: '<img src=x onerror=alert(1)>',
      version: '1.0.0"><script>alert(1)</script>',
      purl: "javascript:alert(1)",
      path: "<a href=//evil.example>lockfile</a>",
      licenses: ["<b>MIT</b>"],
    };
    db.inventory.push(hostile);
    try {
      const html = await render(`${org()}/components?q=${encodeURIComponent("<img")}`);
      expect(html).not.toContain("<img");
      expect(html).not.toContain("<script>");
      expect(html).not.toContain("<b>MIT");
      expect(html).not.toMatch(/href="javascript:/);
      expect(text(html)).toContain("&lt;img src=x onerror=alert(1)&gt;");
      const tab = await render(`${org()}/projects/${web().id}/components?q=${encodeURIComponent("<img")}`);
      expect(tab).not.toContain("<img");
      expect(tab).not.toContain('<a href=//evil.example');
      expect(tab).not.toMatch(/href="\/\/evil/);
    } finally {
      db.inventory.splice(db.inventory.indexOf(hostile), 1);
    }
  });

  it("a project's Components tab: per target, with the target filter from GET …/targets", async () => {
    const base = `${org()}/projects/${web().id}`;
    const html = await render(`${base}/components`);
    const t = text(html);
    expect(html).toContain(`href="${base}/components"`);
    expect(t).toContain("org.apache.logging.log4j:log4j-core");
    expect(t).toContain("Source code");
    expect(html).toMatch(/<select[^>]*aria-label="Target"/);
    expect(html).toContain('<option value="(source)">Source code</option>');
    expect(html).toContain('<option value="ghcr.io/acme/api">ghcr.io/acme/api</option>');
    const image = text(await render(`${base}/components?target=ghcr.io%2Facme%2Fapi`));
    expect(image).toContain("libssl3");
    expect(image).not.toContain("react-dom");
    const source = text(await render(`${base}/components?target=%28source%29`));
    expect(source).toContain("react-dom");
    expect(source).not.toContain("libssl3");
  });

  it("issue list: the Image filter lists the project's image targets; the Malicious view and tag", async () => {
    const base = `${org()}/projects/${web().id}`;
    // The phone sheet isn't rendered on the server; the chip for a target in the URL is.
    const chip = text(await render(`${base}/issues?target=ghcr.io%2Facme%2Fapi`));
    expect(chip).toContain("Image is ghcr.io/acme/api");

    const html = await render(`${org()}/issues`);
    const t = text(html);
    expect(t).toMatch(/Malicious , 1 issues/);
    expect(html).toContain(`href="/orgs/${db.ORG_ID}/issues?kind=malicious"`);
    const mal = await render(`${org()}/issues?kind=malicious`);
    expect(mal).toMatch(/<a[^>]*aria-current="true"[^>]*>Malicious/);
    expect(text(mal)).toContain("acme-ui-icons 3.1.4 is a malicious package (MAL-2026-1873)");
    expect(text(mal)).toContain("Malicious package (OSV advisory)");
    expect(text(mal)).toContain("1 issue match");
    // Vulnerabilities exclude malicious packages and license issues.
    const vulns = text(await render(`${org()}/issues?kind=vulnerability`));
    expect(vulns).not.toContain("is a malicious package");
    expect(vulns).toContain("log4j-core");
  });

  it("issue page: the Malicious package card, the OSV link only for a MAL id, the remediation", async () => {
    const issue = db.issues.find((i) => i.rule_id === "malicious:MAL-2026-1873")!;
    const html = await render(`${org()}/issues/${issue.id}`);
    const t = text(html);
    expect(t).toContain("Malicious package");
    expect(t).toContain("Remove this version and rotate any credentials the build had access to.");
    expect(html).toContain('<a href="https://osv.dev/vulnerability/MAL-2026-1873" target="_blank" rel="noopener noreferrer"');
    expect(t).toContain("remove this version");
    expect(t).not.toContain("no fixed version yet");
    expect(t).not.toContain("Exploitation");

    const hostile = { ...issue, rule_id: 'malicious:MAL-2026-1"><img src=x>/../../x' };
    const bad = await render(`${org()}/issues/${issue.id}`, (qc) => qc.setQueryData(qk.issue(db.ORG_ID, issue.id), hostile));
    expect(bad).not.toContain("osv.dev");
    expect(bad).not.toContain("<img");
    expect(text(bad)).toContain("Remove this version and rotate any credentials");
  });

  it("issue page: an issue opened by an advisory without a scan says so", async () => {
    const lab = db.issues.find((i) => i.rule_id === "malicious:MAL-2026-2290")!;
    const t = text(await render(`${labs()}/issues/${lab.id}`));
    expect(t).toContain("Found by malicious-package advisory MAL-2026-2290 (no scan)");
    expect(t).not.toContain("from a scan");
  });

  it("license issues read the category from license_category, not the title", async () => {
    const gpl = db.issues.find((i) => i.rule_id === "license:GPL-3.0-only")!;
    const retitled = { ...gpl, title: "@acme/legacy-charts uses GPL-3.0-only", license_category: "reciprocal" as const };
    const t = text(await render(`${org()}/issues/${gpl.id}`, (qc) => qc.setQueryData(qk.issue(db.ORG_ID, gpl.id), retitled)));
    expect(t).toMatch(/License GPL-3\.0-only \( ?reciprocal ?\)/);
  });

  it("overview: a banner when malicious-package issues are open, none otherwise", async () => {
    const html = await render(`${labs()}/overview`);
    const t = text(html);
    expect(t).toContain("1 malicious-package issue is open.");
    expect(html).toContain(`href="/orgs/${db.ORG2_ID}/issues?kind=malicious"`);
    // In Acme Engineering, scoped to WEB (no malicious package there): no banner.
    expect(text(await render(`${org()}/overview?project=${web().id}`))).not.toContain("malicious-package issue");
  });

  it("scans: CycloneDX and SPDX downloads; a scan from before v0.4 offers CycloneDX only", async () => {
    const base = `${org()}/projects/${web().id}/scans`;
    const image = db.scans.find((s) => s.file_name === "api-1.4.2.tar")!;
    const panel = text(await render(`${base}?scan=${image.id}`));
    expect(panel).toContain("Download SBOM (CycloneDX)");
    expect(panel).toContain("Download SBOM (SPDX)");
    expect(panel).toContain("CycloneDX and SPDX JSON · 412 components · 1.2 MB (CycloneDX)");
    const old = db.scans.find((s) => s.file_name === "storefront-2.2.zip")!;
    const oldPanel = text(await render(`${base}?scan=${old.id}`));
    expect(oldPanel).toContain("Download SBOM (CycloneDX)");
    expect(oldPanel).not.toContain("SPDX");
  });

  it("vulnerability data lists the OSV feeds with their unsupported counts; preferences list the new type", async () => {
    const t = text(await render(`${org()}/settings`));
    expect(t).toContain("OSV malicious packages · npm");
    expect(t).toContain("OSV malicious packages · crates.io");
    expect(t).toContain("214,802 advisories");
    expect(t).toContain("37 advisories skipped: version ranges not supported");
    expect(t).toContain("never closes or hides one");
    const prefs = text(await render(`${org()}/preferences`));
    expect(prefs).toContain("Malicious package found");
    // v0.4 wave 2 adds "Webhook turned off" (on by default).
    expect(prefs).toMatch(/7 ?of ?9 ?emailed/);
  });

  it("mock API follows the v0.4 contract: components, usage, targets, visibility, SBOM formats", async () => {
    const list = await call("GET", `/orgs/${db.ORG_ID}/components?limit=200`);
    expect(list.status).toBe(200);
    const items = list.json.data.items!;
    expect(Object.keys(items[0]!).sort()).toEqual(["ecosystem", "licenses", "malicious", "name", "open_issues", "projects", "purl", "targets", "version"]);
    const axios = items.find((c) => c.name === "axios")!;
    expect(axios).toMatchObject({ projects: 2, targets: 2, malicious: false });
    expect(items.find((c) => c.name === "lodash" && c.version === "4.17.15")).toMatchObject({ open_issues: 1 });
    expect((await call("GET", `/orgs/${db.ORG_ID}/components?ecosystem=${encodeURIComponent("a/b")}`)).status).toBe(422);
    expect((await call("GET", `/orgs/${db.ORG_ID}/components?q=${"a".repeat(129)}`)).status).toBe(422);
    // PyPI names are normalised for the prefix search.
    const py = await call("GET", `/orgs/${db.ORG2_ID}/components?q=pyyaml`);
    expect(py.json.data.items!.map((c) => c.name)).toEqual(["PyYAML"]);

    const usage = await call("GET", `/orgs/${db.ORG_ID}/components/usage?ecosystem=npm&name=zod&version=3.25.76`);
    expect(usage.json.data.items!.map((u) => u.project_key)).toEqual(["PAY", "WEB"]);
    expect((await call("GET", `/orgs/${db.ORG_ID}/components/usage?ecosystem=npm&name=zod`)).status).toBe(422);

    const targets = await call("GET", `/orgs/${db.ORG_ID}/projects/${web().id}/targets`);
    expect(targets.json.data.items).toEqual([
      expect.objectContaining({ target: "", kind: "source" }),
      // v0.4 wave 2: the history scans' target.
      expect.objectContaining({ target: "(history)", kind: "history" }),
      // v0.8: one per imported tool and category.
      expect.objectContaining({ target: "(import) codeql /language:python/", kind: "import" }),
      expect.objectContaining({ target: "(import) gitlab-sast", kind: "import" }),
      expect.objectContaining({ target: "(import) semgrep", kind: "import" }),
      expect.objectContaining({ target: "ghcr.io/acme/api", kind: "image" }),
    ]);
    // Another org's project looks missing.
    expect((await call("GET", `/orgs/${db.ORG2_ID}/projects/${web().id}/targets`)).status).toBe(404);
    const src = await call("GET", `/orgs/${db.ORG_ID}/projects/${web().id}/components?target=&limit=200`);
    expect(src.json.data.items!.every((c) => c.target === "")).toBe(true);

    // A member sees only their projects (INFRA has no role for the caller).
    const eng = db.me.orgs.find((o) => o.id === db.ORG_ID)!;
    const role = eng.role;
    eng.role = "member";
    try {
      const pay = db.projects[1]!;
      const before = pay.my_role;
      pay.my_role = null;
      try {
        const m = await call("GET", `/orgs/${db.ORG_ID}/components?malicious=true`);
        expect(m.json.data.items).toEqual([]);
      } finally {
        pay.my_role = before;
      }
    } finally {
      eng.role = role;
    }

    const image = db.scans.find((s) => s.file_name === "api-1.4.2.tar")!;
    const spdx = await call("GET", `/orgs/${db.ORG_ID}/scans/${image.id}/sbom?format=spdx`);
    expect(spdx.json.data).toMatchObject({ format: "spdx-json", url: expect.stringMatching(/\.spdx\.json\?/) });
    expect((await call("GET", `/orgs/${db.ORG_ID}/scans/${image.id}/sbom?format=xml`)).status).toBe(422);
    const old = db.scans.find((s) => s.file_name === "storefront-2.2.zip")!;
    expect((await call("GET", `/orgs/${db.ORG_ID}/scans/${old.id}/sbom?format=spdx`)).status).toBe(404);
    expect((await call("GET", `/orgs/${db.ORG_ID}/scans/${old.id}/sbom`)).status).toBe(200);

    const counts = await call("GET", `/orgs/${db.ORG2_ID}/issues/counts`);
    expect(counts.json.data).toMatchObject({ malicious: 1, active: 1 });
  });
});

describe("v0.4 wave 2 screens: secrets in git history, integrations, CI setup", () => {
  const org = () => `/orgs/${db.ORG_ID}`;
  const web = () => db.projects[0]!;
  const historyScan = () => db.scans.find((s) => s.kind === "history" && s.status === "completed")!;
  const awsHistory = () => db.issues.find((i) => i.target === "(history)" && i.rule_id === "aws-access-token")!;
  const asRole = (role: "org_admin" | "security_lead" | "member") => ({
    ...db.me,
    orgs: db.me.orgs.map((o) => (o.id === db.ORG_ID ? { ...o, role } : o)),
  });
  const call = async (method: string, path: string, body?: unknown) => {
    const { mockFetch } = await import("../api/mock/server");
    const r = await mockFetch(`/api/v1${path}`, { method, body: body === undefined ? undefined : JSON.stringify(body) });
    return {
      status: r.status,
      json: (r.status === 204 ? { data: null, error: null } : await r.json()) as {
        data: ({ items?: Record<string, unknown>[]; next_cursor?: string | null } & Record<string, unknown>) | null;
        error: { code: string; metadata?: { fields?: Record<string, string> } } | null;
      },
    };
  };

  it("scans tab: the Git history tag and commits, the history panel, BUNDLE_* rejections, the note under New scan", async () => {
    const base = `${org()}/projects/${web().id}/scans`;
    const html = await render(base);
    const t = text(html);
    expect(t).toContain("storefront.bundle");
    expect(t).toContain("Git history");
    expect(t).toContain("2,481 commits");
    expect(t).toContain("shallow clone");
    // The New scan card stays Source code / Container image; history scans come from CI.
    expect(html).not.toMatch(/<button type="button" aria-pressed="false">Git history<\/button>/);
    expect(t).toContain("warden scan --history");
    expect(html).toContain(`href="/orgs/${db.ORG_ID}/projects/${web().id}/settings#ci-setup"`);

    const panelHtml = await render(`${base}?scan=${historyScan().id}`);
    const panel = text(panelHtml);
    expect(panel).toContain("2,481 commits scanned");
    expect(panel).toContain("Issues tracked under Git history");
    expect(panel).not.toContain("Only the newest");
    expect(panelHtml).toContain(`href="/orgs/${db.ORG_ID}/projects/${web().id}/issues?source=history"`);

    const truncated = { ...historyScan(), history: { commits: 100000, truncated: true } };
    const cut = text(await render(`${base}?scan=${truncated.id}`, (qc) => qc.setQueryData(qk.scan(db.ORG_ID, truncated.id), truncated)));
    expect(cut).toContain("Only the newest 100,000 commits were scanned (the server's limit).");

    const rejected = db.scans.find((s) => s.error_code === "BUNDLE_INCOMPLETE")!;
    const r = text(await render(`${base}?scan=${rejected.id}`));
    expect(r).toContain("Bundle rejected");
    expect(r).toContain("The bundle doesn't hold the full history");
    expect(r).toContain("BUNDLE_INCOMPLETE");
    // A browser can't build a bundle: no "Upload a new …" for a history scan.
    expect(r).not.toContain("Upload a new");
  });

  it("issue list: Source is Git history, the History tag, the Secrets view lists both", async () => {
    const html = await render(`${org()}/issues?source=history`);
    const t = text(html);
    expect(t).toContain("Source is Git history");
    expect(t).toContain("2 issues match");
    expect(t).toContain("AWS access key in git history");
    expect(t).toContain("Slack bot token in git history");
    expect(t).not.toContain("AWS access key in deploy config");
    expect(t).toContain("Found in git history");
    expect(t).not.toContain("(history) ·");
    const secrets = text(await render(`${org()}/issues?tool=gitleaks`));
    expect(secrets).toContain("AWS access key in git history");
    expect(secrets).toContain("AWS access key in deploy config");
    // Source code excludes history issues; images too.
    expect(text(await render(`${org()}/issues?source=code&tool=gitleaks`))).not.toContain("in git history");
    expect(text(await render(`${org()}/issues?source=image`))).not.toContain("in git history");
  });

  it("issue page: Found in git history with the short sha as text, the rotate sentence, Where and How to fix", async () => {
    const issue = awsHistory();
    const sha = issue.commit!.sha;
    const html = await render(`${org()}/issues/${issue.id}`);
    const t = text(html);
    expect(t).toContain("Found in git history");
    expect(t).toContain(`Added in commit ${sha.slice(0, 7)}`);
    expect(t).toContain("and in 2 more commits");
    // The full sha is in the accessible name and copyable, never a link.
    expect(html).toContain(`<span class="visually-hidden">${sha}</span>`);
    expect(html).toContain("Copy sha");
    expect(html).not.toMatch(new RegExp(`href="[^"]*${sha.slice(0, 7)}`));
    expect(html).toContain(
      "<strong>Rotate this secret. Deleting the file or the line doesn&#x27;t remove it from history; anyone with a clone still has it.</strong>",
    );
    expect(t).toContain(`scripts/deploy.sh:7 in commit ${sha.slice(0, 7)}`);
    // How to fix falls back to the same sentence; the snippet is the masked one.
    expect(t.match(/Rotate this secret\./g)!.length).toBeGreaterThanOrEqual(2);
    expect(t).toContain("export AWS_ACCESS_KEY_ID=AKIA****");
    expect(t).toContain("Git history");
    expect(t).not.toMatch(/Image \(history\)/);
  });

  it("issue page: hostile shas and titles are text, never markup or links", async () => {
    const issue = awsHistory();
    const hostile = {
      ...issue,
      title: '<img src=x onerror=alert(1)> in history',
      file_path: '"><script>alert(1)</script>',
      commit: { sha: 'javascript:alert(1)"><img src=x>', committed_at: null, count: 1 },
    };
    const html = await render(`${org()}/issues/${issue.id}`, (qc) => qc.setQueryData(qk.issue(db.ORG_ID, issue.id), hostile));
    expect(html).not.toContain("<img");
    expect(html).not.toContain("<script>");
    expect(html).not.toMatch(/href="javascript:/);
    expect(text(html)).toContain("javascript:alert(1)&quot;&gt;&lt;img src=x&gt;");
    expect(text(html)).not.toContain("more commit");
  });

  it("targets: (history) is not offered as an image or a component target", async () => {
    const tab = await render(`${org()}/projects/${web().id}/components`);
    expect(tab).not.toContain('value="(history)"');
    expect(tab).toContain('<option value="ghcr.io/acme/api">ghcr.io/acme/api</option>');
    // An Image filter of (history) in the URL is dropped (it isn't an image repository).
    const list = text(await render(`${org()}/projects/${web().id}/issues?target=%28history%29`));
    expect(list).not.toContain("Image is (history)");
  });

  it("integrations: navigation, list, tags, url_hint as text, states, the 20 limit, the palette entry", async () => {
    const html = await render(`${org()}/integrations`);
    const t = text(html);
    expect(html).toContain(`href="/orgs/${db.ORG_ID}/integrations"`);
    expect(html.indexOf("Integrations</span>")).toBeGreaterThan(html.indexOf("Members</span>"));
    expect(t).toContain("#security-alerts");
    expect(t).toContain("Ticket relay");
    expect(t).toMatch(/Slack/);
    expect(t).toMatch(/Webhook/);
    // The hint is text, never a link.
    expect(t).toContain("https://hooks.slack.com");
    expect(t).toContain("https://relay.acme.example");
    expect(html).not.toMatch(/href="https:\/\/(hooks\.slack\.com|relay\.acme\.example)/);
    expect(t).toContain("Active");
    expect(t).toContain("Turned off after failed deliveries");
    expect(t).toContain("Turn on again");
    expect(t).toContain("Critical only");
    expect(t).toContain("2 projects");
    expect(t).toContain("All projects");
    expect(t).toMatch(/Delivered \d+ min ago/);
    expect(t).toMatch(/Failed 2 h ago · HTTP 500/);
    expect(t).toContain("2 of 20");
    expect(t).toContain("never code, descriptions, comments, email addresses or secrets");
    // Icon-only and repeated buttons have names.
    expect(html).toContain('aria-label="More actions for Ticket relay"');
    expect(t).toContain("Delivery log of Ticket relay");
    expect(t).toContain("Send test to #security-alerts");
    expect(html).toMatch(/<button type="button" class="btn btn-primary btn-sm"[^>]*>.*Add<\/button>/s);
  });

  it("integrations: hidden from members, who never call the API; a 403 page if they open the URL", async () => {
    const before = db.me.orgs.find((o) => o.id === db.ORG_ID)!.role;
    let seed: QueryClient | null = null;
    const html = await render(`${org()}/integrations`, (qc) => {
      seed = qc;
      qc.setQueryData(qk.me, asRole("member"));
    });
    expect(before).toBe("security_lead");
    const t = text(html);
    expect(t).toContain("You don't have access to this");
    expect(html).not.toContain(`href="/orgs/${db.ORG_ID}/integrations"`);
    expect(seed!.getQueryCache().find({ queryKey: qk.webhooks(db.ORG_ID) })).toBeUndefined();
    // Acme Labs: the caller is a member there.
    const labs = await render(`/orgs/${db.ORG2_ID}/projects`);
    expect(labs).not.toContain(`href="/orgs/${db.ORG2_ID}/integrations"`);
    // An org admin sees it too.
    const admin = await render(`${org()}/integrations`, (qc) => qc.setQueryData(qk.me, asRole("org_admin")));
    expect(text(admin)).toContain("#security-alerts");
  });

  it("integrations: without secrets.key the page shows only the operator note", async () => {
    db.mockFlags.integrationsUnavailable = true;
    try {
      const html = await render(`${org()}/integrations`);
      const t = text(html);
      expect(t).toContain("Webhooks are turned off on this server.");
      expect(t).toContain("WARDEN_SECRETS__KEY");
      expect(t).not.toContain("#security-alerts");
      expect(html).not.toMatch(/>\s*Add<\/button>/);
      expect(html).toContain('rel="noopener noreferrer"');
    } finally {
      db.mockFlags.integrationsUnavailable = false;
    }
  });

  it("integrations: hostile names and hints are text", async () => {
    const list = db.webhooks[db.ORG_ID]!;
    const hostile = { ...list[0]!, id: db.uuid(), name: '<img src=x onerror=alert(1)>', url_hint: "javascript:alert(1)" };
    list.push(hostile);
    try {
      const html = await render(`${org()}/integrations`);
      expect(html).not.toContain("<img");
      expect(html).not.toMatch(/href="javascript:/);
      expect(text(html)).toContain("&lt;img src=x onerror=alert(1)&gt;");
      expect(text(html)).toContain("javascript:alert(1)");
    } finally {
      list.splice(list.indexOf(hostile), 1);
    }
  });

  it("CI setup: the switches, off by default; snippets never contain a token", async () => {
    const html = await render(`${org()}/projects/${web().id}/settings`);
    const t = text(html);
    expect(html).toContain('id="ci-setup"');
    expect(t).toContain("Comment on pull requests / merge requests");
    expect(t).toContain("Scan git history");
    // v0.8 adds a third: Import CodeQL / GitLab SAST results.
    expect(html.match(/role="switch"/g)).toHaveLength(3);
    expect(t).not.toContain("--comment auto\n");
    expect(html).not.toMatch(/wdn_[a-z2-7]{8}_[a-z2-7]{20,}|whsec_/);
    expect(t).toContain("Warden itself keeps no GitHub or GitLab credentials.");
  });

  it("notifications: the Webhook turned off preference and its link to Integrations", async () => {
    const prefs = text(await render(`${org()}/preferences`));
    expect(prefs).toContain("Webhook turned off");
    expect(prefs).toContain("Sent to org admins and security leads.");
    const { safeAppPath } = await import("../lib/notifications");
    const n = db.notifications.find((x) => x.type === "webhook.disabled")!;
    expect(safeAppPath(n.link)).toBe(`/orgs/${db.ORG_ID}/integrations`);
  });

  it("mock API follows the webhook contract: roles, URL checks, 409 at 20, Slack has no secret, the test limit, the log", async () => {
    const hooks = `/orgs/${db.ORG_ID}/webhooks`;
    expect((await call("GET", `/orgs/${db.ORG2_ID}/webhooks`)).status).toBe(403);
    const listed = await call("GET", hooks);
    expect(listed.json.data).toMatchObject({ available: true });
    expect(Object.keys(listed.json.data!.items![0]!).sort()).toEqual(
      ["consecutive_failures", "created_at", "created_by", "disabled_reason", "enabled", "events", "id", "kind", "last_delivery", "min_severity", "name", "project_ids", "updated_at", "url_hint"].sort(),
    );

    const bad = await call("POST", hooks, { kind: "slack", name: "", url: "http://10.0.0.5/x", events: [] });
    expect(bad.status).toBe(422);
    expect(bad.json.error?.metadata?.fields).toMatchObject({ name: expect.any(String), url: "must use https", events: expect.any(String) });
    expect((await call("POST", hooks, { kind: "generic", name: "x", url: "https://10.0.0.5/x", events: ["scan.finished"] })).json.error?.metadata?.fields?.url).toBe(
      "resolves to a private address",
    );
    expect((await call("POST", hooks, { kind: "slack", name: "x", url: "https://relay.acme.example/x", events: ["scan.finished"] })).json.error?.metadata?.fields?.url).toBe(
      "Slack URLs start with https://hooks.slack.com/services/",
    );

    const before = db.webhooks[db.ORG_ID]!.length;
    const made: string[] = [];
    try {
      const slack = await call("POST", hooks, { kind: "slack", name: "#ops", url: "https://hooks.slack.com/services/T0/B0/mock", events: ["scan.finished"] });
      expect(slack.status).toBe(201);
      expect(slack.json.data).toMatchObject({ secret: null, webhook: { url_hint: "https://hooks.slack.com" } });
      const sw = (slack.json.data as { webhook: { id: string } }).webhook;
      made.push(sw.id);
      expect(JSON.stringify(slack.json)).not.toContain("/services/T0");
      expect((await call("POST", `${hooks}/${sw.id}/rotate-secret`)).status).toBe(422);
      const gen = await call("POST", hooks, { kind: "generic", name: "relay 2", url: "https://relay2.acme.example/hook", events: ["issue.assigned"] });
      const gw = (gen.json.data as { webhook: { id: string }; secret: string }).webhook;
      made.push(gw.id);
      expect((gen.json.data as { secret: string }).secret).toMatch(/^whsec_/);
      expect((await call("POST", `${hooks}/${gw.id}/rotate-secret`)).json.data).toMatchObject({ secret: expect.stringMatching(/^whsec_/) });
      // Ten tests an hour, then 429.
      for (let i = 0; i < 10; i++) expect((await call("POST", `${hooks}/${gw.id}/test`)).status).toBe(202);
      expect((await call("POST", `${hooks}/${gw.id}/test`)).status).toBe(429);
      // At most 20 per org.
      while (db.webhooks[db.ORG_ID]!.length < 20) {
        const r = await call("POST", hooks, { kind: "slack", name: "filler", url: "https://hooks.slack.com/services/T0/B0/fill", events: ["scan.finished"] });
        made.push((r.json.data as { webhook: { id: string } }).webhook.id);
      }
      expect((await call("POST", hooks, { kind: "slack", name: "one too many", url: "https://hooks.slack.com/services/T0/B0/x", events: ["scan.finished"] })).status).toBe(409);
    } finally {
      for (const id of made) expect((await call("DELETE", `${hooks}/${id}`)).status).toBe(204);
    }
    expect(db.webhooks[db.ORG_ID]!.length).toBe(before);

    // Turning the relay on again resets its failures.
    const relay = db.webhooks[db.ORG_ID]!.find((w) => w.name === "Ticket relay")!;
    const saved = { ...relay };
    try {
      const on = await call("PATCH", `${hooks}/${relay.id}`, { enabled: true });
      expect(on.json.data).toMatchObject({ enabled: true, disabled_reason: null, consecutive_failures: 0 });
      expect((await call("PATCH", `${hooks}/${relay.id}`, {})).status).toBe(422);
    } finally {
      Object.assign(relay, saved);
    }

    // The log pages 50 at a time, newest first.
    const slackHook = db.webhooks[db.ORG_ID]!.find((w) => w.kind === "slack")!;
    const page1 = await call("GET", `${hooks}/${slackHook.id}/deliveries`);
    expect(page1.json.data!.items).toHaveLength(50);
    expect(page1.json.data!.next_cursor).not.toBeNull();
    const relayLog = await call("GET", `${hooks}/${relay.id}/deliveries`);
    const errors = new Set(relayLog.json.data!.items!.map((d) => d.error));
    for (const e of ["timeout", "dns", "connect", "tls", "blocked_address", "redirect", "http_status", "disabled", "key_unavailable"]) expect(errors).toContain(e);
    expect(new Set(relayLog.json.data!.items!.map((d) => d.state))).toEqual(new Set(["pending", "delivered", "failed"]));

    // History issues: source=history, and summaries carry no commit (only the issue does).
    const hist = await call("GET", `/orgs/${db.ORG_ID}/issues?source=history`);
    expect(hist.json.data!.items!.map((i) => i.target)).toEqual(["(history)", "(history)"]);
    expect(hist.json.data!.items![0]).not.toHaveProperty("commit");
  });
});

describe("v0.5: sign-in settings from the server", () => {
  it("mock mode answers GET /web-config through the mock API, and the UI accepts it", async () => {
    const { loadWebConfig, WebConfigError } = await import("../auth/webConfig");
    // Mock mode loads the settings as from a real server (no IdP is contacted: mock mode never
    // signs in).
    await expect(loadWebConfig()).resolves.toEqual(db.webConfig);
    // ?mock_web_config=unavailable|invalid shows the error page.
    for (const mode of ["unavailable", "invalid"]) {
      db.mockFlags.webConfig = mode;
      try {
        await expect(loadWebConfig()).rejects.toBeInstanceOf(WebConfigError);
      } finally {
        db.mockFlags.webConfig = null;
      }
    }
  });

  it("the splash, then the error page", async () => {
    const { AuthBoot } = await import("../auth/AuthGate");
    const { createBoot } = await import("../auth/boot");
    const boot = createBoot(() => Promise.reject(new Error("unreachable")));
    const app = () => <p>APP-RENDERED</p>;
    expect(text(renderToString(<AuthBoot boot={boot}>{app}</AuthBoot>))).toContain("Loading Warden");
    boot.start();
    await new Promise((r) => setTimeout(r, 0));
    const t = text(renderToString(<AuthBoot boot={boot}>{app}</AuthBoot>));
    expect(t).toContain("Can't reach the server's sign-in settings");
    expect(t).toContain("Try again");
    expect(t).not.toContain("APP-RENDERED");
    expect(t).not.toContain("unreachable");
  });
});

describe("v0.5 wave 2: export, verify, filters", () => {
  const org = () => `/orgs/${db.ORG_ID}`;
  const call = async (method: string, path: string, body?: unknown) => {
    const { mockFetch } = await import("../api/mock/server");
    return mockFetch(`/api/v1${path}`, { method, body: body === undefined ? undefined : JSON.stringify(body) });
  };
  type J = { data: ({ items?: Record<string, unknown>[] } & Record<string, unknown>) | null; error: { code: string } | null };
  const json = async (r: Response) => (await r.json()) as J;

  it("audit log: Verify chain replaces the bare guarantee; the mock verifies, breaks, limits and records it", async () => {
    const t = text(await render(`${org()}/audit-log`));
    expect(t).toContain("Append-only and hash-chained.");
    expect(t).toContain("Verify chain");
    expect(t).toContain("Verify the chain to recompute every hash now.");

    const before = db.audit.length;
    try {
      const ok = await json(await call("POST", `/orgs/${db.ORG_ID}/audit-log/verify`));
      expect(ok.data).toMatchObject({ ok: true, entries: before, first_bad_id: null, verified_at: expect.any(String) });
      // Recorded as audit.verified, with a numeric id like every entry.
      expect(db.audit[0]).toMatchObject({ action: "audit.verified", data: { ok: true } });
      expect(db.audit.every((e) => /^\d+$/.test(e.id))).toBe(true);
      expect(text(await render(`${org()}/audit-log`))).toContain(`Chain intact · ${before} entries`);

      db.mockFlags.auditBroken = true;
      const broken = await json(await call("POST", `/orgs/${db.ORG_ID}/audit-log/verify`));
      expect(broken.data).toMatchObject({ ok: false, first_bad_id: expect.stringMatching(/^\d+$/) });
      // The bad entry is one the first page of the log shows (the UI links to it).
      const page1 = await json(await call("GET", `/orgs/${db.ORG_ID}/audit-log`));
      expect(page1.data!.items!.map((e) => e.id)).toContain(broken.data!.first_bad_id);

      // Members can't verify; ten checks an hour per org, then 429 with Retry-After.
      const eng = db.me.orgs.find((o) => o.id === db.ORG_ID)!;
      const role = eng.role;
      eng.role = "member";
      try {
        expect((await call("POST", `/orgs/${db.ORG_ID}/audit-log/verify`)).status).toBe(403);
      } finally {
        eng.role = role;
      }
      for (let i = 2; i < 10; i++) expect((await call("POST", `/orgs/${db.ORG_ID}/audit-log/verify`)).status).toBe(200);
      const limited = await call("POST", `/orgs/${db.ORG_ID}/audit-log/verify`);
      expect(limited.status).toBe(429);
      expect(limited.headers.get("Retry-After")).toMatch(/^\d+$/);
    } finally {
      db.mockFlags.auditBroken = false;
      db.audit.splice(0, db.audit.length - before);
    }
  });

  it("issue list: Export CSV for everyone who sees the list; the mock exports with the list's filters", async () => {
    const { checkComplete } = await import("../lib/issueExport");
    const asMember = { ...db.me, orgs: db.me.orgs.map((o) => (o.id === db.ORG_ID ? { ...o, role: "member" as const } : o)) };
    expect(text(await render(`${org()}/issues`))).toContain("Export CSV");
    expect(text(await render(`${org()}/issues`, (qc) => qc.setQueryData(qk.me, asMember)))).toContain("Export CSV");
    expect(text(await render(`${org()}/projects/${db.projects[0]!.id}/issues`))).toContain("Export CSV");

    const issue = db.issues[0]!;
    const title = issue.title;
    issue.title = '=HYPERLINK("https://evil.example","x")';
    try {
      const r = await call("GET", `/orgs/${db.ORG_ID}/issues/export.csv?severity=critical&past_sla=true`);
      expect(r.status).toBe(200);
      expect(r.headers.get("Content-Type")).toBe("text/csv; charset=utf-8");
      expect(r.headers.get("Content-Disposition")).toMatch(/^attachment; filename="warden-issues-acme-engineering-\d{4}-\d{2}-\d{2}\.csv"$/);
      expect(r.headers.get("X-Warden-Truncated")).toBeNull();
      const lines = (await r.text()).trim().split("\r\n");
      expect(lines[0]).toBe("key,project,title,severity,status,tool,rule_id,file_path,line,target,cve,kev,epss,assignee,due_at,created_at,updated_at");
      // The same filters as the list: two issues match (see "issue list with filters from the URL"),
      // then (v0.7) the end line with their count.
      expect(lines).toHaveLength(4);
      expect(lines[3]).toBe("#warden:end rows=2");
      // A cell a spreadsheet would run as a formula starts with an apostrophe.
      expect(lines.join("\n")).toContain(`"'=HYPERLINK(""https://evil.example"",""x"")"`);
    } finally {
      issue.title = title;
    }
    // A cell with line breaks stays on one line (the server makes them spaces), so the file is complete.
    issue.title = "first line\r\nsecond line\nthird";
    try {
      const r = await call("GET", `/orgs/${db.ORG_ID}/issues/export.csv`);
      const body = await r.blob();
      expect(await body.text()).toContain("first line  second line third");
      expect(await checkComplete(body)).toBe(true);
    } finally {
      issue.title = title;
    }
    for (const [flag, status] of [["truncated", 200], ["rate_limited", 429], ["invalid", 422], ["cut", 200], ["miscount", 200]] as const) {
      db.mockFlags.export = flag;
      try {
        const r = await call("GET", `/orgs/${db.ORG_ID}/issues/export.csv`);
        expect(r.status).toBe(status);
        if (flag === "truncated") expect(r.headers.get("X-Warden-Truncated")).toBe("true");
        if (flag === "rate_limited") expect(r.headers.get("Retry-After")).toBe("120");
        // v0.7: a truncated export is still complete; cut and miscount aren't.
        if (status === 200) expect(await checkComplete(await r.blob())).toBe(flag === "truncated");
      } finally {
        db.mockFlags.export = null;
      }
    }
  });

  it("issue list without a project in scope: the Image filter comes from GET /orgs/{org}/targets, grouped by project", async () => {
    let qc: QueryClient | undefined;
    await render(`${org()}/issues`, (c) => (qc = c));
    const rows = qc!.getQueryData<{ items: { project_key: string; target: string; kind: string }[] }>(qk.orgTargets(db.ORG_ID, "image"));
    expect(rows!.items.map((t) => `${t.project_key} ${t.target}`)).toEqual(["PAY ghcr.io/acme/payments", "WEB ghcr.io/acme/api"]);
    // With a project in scope the project's own list is used, and the org-wide one isn't asked for.
    let qc2: QueryClient | undefined;
    const web = db.projects[0]!;
    await render(`${org()}/projects/${web.id}/issues`, (c) => (qc2 = c));
    expect(qc2!.getQueryData(qk.projectTargets(db.ORG_ID, web.id))).toBeDefined();
    expect(qc2!.getQueryState(qk.orgTargets(db.ORG_ID, "image"))?.data).toBeUndefined();
    // A target from the URL keeps its chip on the org-wide list.
    expect(text(await render(`${org()}/issues?target=ghcr.io%2Facme%2Fpayments`))).toContain("Image is ghcr.io/acme/payments");

    // The mock follows the contract: issue-list visibility, archived projects left out, ?kind=.
    const all = await json(await call("GET", `/orgs/${db.ORG_ID}/targets`));
    const items = all.data!.items! as { project_id: string; project_key: string; target: string; kind: string }[];
    expect(new Set(items.map((t) => t.kind))).toEqual(new Set(["source", "image", "history", "import"]));
    expect(items.map((t) => t.project_key)).toEqual([...items.map((t) => t.project_key)].sort());
    const archived = db.projects.filter((p) => p.archived_at).map((p) => p.id);
    expect(items.some((t) => archived.includes(t.project_id))).toBe(false);
    expect((await call("GET", `/orgs/${db.ORG_ID}/targets?kind=nope`)).status).toBe(422);
  });

  it("components: the ecosystem filter lists the inventory's ecosystems with counts, and keeps the URL's value", async () => {
    const eco = await json(await call("GET", `/orgs/${db.ORG_ID}/components/ecosystems`));
    const items = eco.data!.items! as { ecosystem: string; components: number }[];
    expect(items.length).toBeGreaterThan(1);
    // Most first.
    expect(items.map((i) => i.components)).toEqual([...items.map((i) => i.components)].sort((a, b) => b - a));
    const top = items[0]!;

    const html = await render(`${org()}/components`);
    expect(html).toContain(`>${top.ecosystem === "deb" ? "Debian packages (deb)" : top.ecosystem} (${top.components})</option>`);
    // The fixed list is gone once the inventory's is loaded: RubyGems isn't in the mock inventory.
    expect(items.some((i) => i.ecosystem === "RubyGems")).toBe(false);
    expect(html).not.toContain(">RubyGems</option>");
    // A valid ecosystem from the URL that the inventory doesn't hold stays selectable.
    const hex = await render(`${org()}/components?ecosystem=hex`);
    expect(hex).toMatch(/<option value="hex" selected="">hex<\/option>/);

    // Members count only their projects' components.
    const eng = db.me.orgs.find((o) => o.id === db.ORG_ID)!;
    const role = eng.role;
    eng.role = "member";
    try {
      const mine = await json(await call("GET", `/orgs/${db.ORG_ID}/components/ecosystems`));
      const total = (r: J) => (r.data!.items! as { components: number }[]).reduce((n, i) => n + i.components, 0);
      expect(total(mine)).toBeLessThanOrEqual(total(eco));
    } finally {
      eng.role = role;
    }
  });

  it("webhook delivery log: ?state= filters the mock's log", async () => {
    const relay = db.webhooks[db.ORG_ID]!.find((w) => w.name === "Ticket relay")!;
    const path = `/orgs/${db.ORG_ID}/webhooks/${relay.id}/deliveries`;
    for (const state of ["pending", "delivered", "failed"]) {
      const r = await json(await call("GET", `${path}?state=${state}`));
      expect(r.data!.items!.length).toBeGreaterThan(0);
      expect(new Set(r.data!.items!.map((d) => d.state))).toEqual(new Set([state]));
    }
    expect((await call("GET", `${path}?state=bogus`)).status).toBe(422);
  });

  it("add webhook: the mock answers WEBHOOK_LIMIT at 20 and SECRETS_KEY_MISSING without a key", async () => {
    const hooks = `/orgs/${db.ORG_ID}/webhooks`;
    const body = { kind: "slack", name: "x", url: "https://hooks.slack.com/services/T0/B0/x", events: ["scan.finished"] };
    db.mockFlags.integrationsUnavailable = true;
    try {
      const r = await call("POST", hooks, body);
      expect(r.status).toBe(409);
      expect((await json(r)).error?.code).toBe("SECRETS_KEY_MISSING");
    } finally {
      db.mockFlags.integrationsUnavailable = false;
    }
    const list = db.webhooks[db.ORG_ID]!;
    const saved = [...list];
    try {
      while (list.length < 20) list.push({ ...list[0]!, id: `filler-${list.length}` });
      const r = await call("POST", hooks, body);
      expect(r.status).toBe(409);
      expect((await json(r)).error?.code).toBe("WEBHOOK_LIMIT");
    } finally {
      list.splice(0, list.length, ...saved);
    }
  });

  it("bulk assign: the mock skips issues the assignee can't take and says how many", async () => {
    const { users } = db;
    // Bao is a member of INFRA only; one WEB issue and one fixed issue are skipped.
    const web = db.issues.find((i) => i.project_id === db.projects[0]!.id && ["open", "reopened", "assigned", "in_progress"].includes(i.status))!;
    const infra = db.issues.find((i) => db.projectMembers[i.project_id]?.some((m) => m.user.id === users.bao.id) && ["open", "reopened", "assigned", "in_progress"].includes(i.status));
    const saved = db.issues.map((i) => ({ ...i }));
    try {
      const ids = [web.id, ...(infra ? [infra.id] : [])];
      const r = await json(await call("POST", `/orgs/${db.ORG_ID}/issues/assign`, { issue_ids: ids, assignee_id: users.bao.id }));
      expect(r.data).toEqual({ updated: infra ? 1 : 0, skipped: 1 });
    } finally {
      db.issues.forEach((i, n) => Object.assign(i, saved[n]));
    }
  });
});
