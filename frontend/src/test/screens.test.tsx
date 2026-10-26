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
    expect(t).toMatch(/2 Critical/);
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

  it("notification preferences and the bell", async () => {
    const html = await render(`${org()}/preferences`);
    const t = text(html);
    expect(t).toContain("Issue assigned to you");
    expect(t).toContain("Scan finished");
    expect(t).toContain("Save preferences");
    expect(html).toContain('aria-label="Notifications, 3 unread"');
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
});
