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

beforeAll(async () => {
  vi.stubEnv("VITE_MOCK", "1");
  vi.stubGlobal("window", { location: { origin: "http://localhost", search: "", pathname: "/" } });
  db = await import("../api/mock/fixtures");
  ({ appRoutes } = await import("../App"));
  ({ AuthGate } = await import("../auth/AuthGate"));
  ({ qk } = await import("../api/keys"));
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
      if (pending.length === 0) break;
      await Promise.all(pending.map((q) => q.fetch().catch(() => undefined)));
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

  it("a user with no org gets the operator instructions", async () => {
    const t = text(await render("/", (qc) => qc.setQueryData(qk.me, { ...db.me, orgs: [] })));
    expect(t).toContain("You're not in an organization yet");
    expect(t).toContain("warden-admin org create");
    expect(t).toContain(db.me.email);
  });
});
