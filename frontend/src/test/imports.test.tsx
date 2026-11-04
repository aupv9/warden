// v0.8 wave 1: results imported from another tool (SARIF, GitLab SAST), with the mock API behind
// them. Rendered like screens.test.tsx (react-dom/server against the dev mock, no DOM): each pass
// fetches the queries the screen created, until nothing is pending.
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
    .replace(/&lt;/g, "<")
    .replace(/&gt;/g, ">")
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
const web = () => db.projects[0]!;
const scansTab = () => `${org()}/projects/${web().id}/scans`;
const SHA = "ab".repeat(32);
const HOSTILE = '<img src=x onerror="alert(1)">';

describe("v0.8 wave 1: import scans on the Scans tab", () => {
  it("history: an Imported tag with the tool and category, Rejected with the reason; no import button in New scan", async () => {
    const html = await render(scansTab());
    const t = text(html);
    expect(t).toContain("python.sarif");
    expect(t).toMatch(/Imported CodeQL · \/language:python\//);
    expect(t).toMatch(/gl-sast-report\.json Imported GitLab SAST/);
    expect(t).toContain("not a SARIF or GitLab SAST report");
    // The New scan switch stays Source code / Container image / Image from a registry: imports
    // come from CI, and the note under it says so.
    expect(html.match(/<button type="button" aria-pressed="(true|false)"[^>]*>[^<]*<\/button>/g)?.map((b) => b.replace(/<[^>]+>/g, ""))).toEqual([
      "Source code",
      "Container image",
      "Image from a registry",
    ]);
    expect(t).toContain("are imported from CI with warden import");
    expect(html).toContain(`href="/orgs/${db.ORG_ID}/projects/${web().id}/settings#ci-setup"`);
  });

  it("panel: tool, category, format and version; results read, dropped and screened, explained; the run named after the tool", async () => {
    const s = db.CODEQL_IMPORT;
    const html = await render(`${scansTab()}?scan=${s.id}`);
    const t = text(html);
    expect(t).toContain("Scan finished");
    expect(t).toMatch(/Imported CodeQL · \/language:python\/ SARIF · version 2\.23\.1/);
    expect(t).toContain("14 results read");
    expect(t).toContain("1 dropped");
    expect(t).toContain("2 screened by Gitleaks");
    expect(t).toContain("strings left out because they looked like secrets");
    expect(t).toContain("An import fixes only issues of its own tool and category");
    // The scanner table names CodeQL, not "external" (or the generic "Imported").
    expect(html).toContain("<th>Tool</th>");
    expect(html).toMatch(/<strong>CodeQL<\/strong>/);
    expect(t).not.toMatch(/\bexternal\b/);
    expect(html).toContain(`href="/orgs/${db.ORG_ID}/projects/${web().id}/issues?source=import&amp;external_tool=codeql"`);

    const gl = text(await render(`${scansTab()}?scan=${db.GITLAB_SAST_IMPORT.id}`));
    expect(gl).toMatch(/Imported GitLab SAST GitLab SAST report · version 6\.6\.0/);
    expect(gl).toContain("0 screened by Gitleaks");
  });

  it("a rejected report: Report rejected, what to do, run the CI job again; no Upload a new …", async () => {
    const t = text(await render(`${scansTab()}?scan=${db.INVALID_IMPORT.id}`));
    expect(t).toContain("Report rejected");
    expect(t).toContain("isn't a SARIF 2.1.0 file or a GitLab SAST report");
    expect(t).toContain("IMPORT_INVALID");
    expect(t).toContain("Imports run from CI with warden import");
    expect(t).not.toContain("Upload a new");
  });

  it("before the worker read the report: no counts yet; a failed screening is Import failed, not Rejected", async () => {
    const queued = { ...db.CODEQL_IMPORT, status: "queued" as const, finished_at: null, import: { ...db.CODEQL_IMPORT.import!, tool_version: null, results: null, dropped: null, screened: null } };
    const q = text(await render(`${scansTab()}?scan=${queued.id}`, (qc) => qc.setQueryData(qk.scan(db.ORG_ID, queued.id), queued)));
    expect(q).toContain("Imported CodeQL");
    expect(q).not.toContain("results read");
    const failed = { ...db.CODEQL_IMPORT, status: "failed" as const, error_code: "IMPORT_SCREEN_FAILED", tool_runs: [] };
    const f = text(await render(`${scansTab()}?scan=${failed.id}`, (qc) => qc.setQueryData(qk.scan(db.ORG_ID, failed.id), failed)));
    expect(f).toContain("Import failed");
    expect(f).not.toContain("Report rejected");
    expect(f).toContain("Gitleaks couldn't check the report's texts for secrets");
  });

  it("text from the report is text: a hostile tool version and category never become markup", async () => {
    const evil = { ...db.CODEQL_IMPORT, import: { ...db.CODEQL_IMPORT.import!, tool_version: HOSTILE, category: HOSTILE } };
    const html = await render(`${scansTab()}?scan=${evil.id}`, (qc) => qc.setQueryData(qk.scan(db.ORG_ID, evil.id), evil));
    expect(html).not.toContain("<img");
    expect(html).toContain("&lt;img");
  });
});

describe("v0.8 wave 1: imported issues", () => {
  const codeql = () => db.IMPORTED_ISSUES.find((i) => i.rule_id === "py/path-injection")!;

  it("list: Source › Imported shows them with an Imported · <tool> tag; Warden's issues don't have it", async () => {
    const html = await render(`${org()}/issues?source=import`);
    const t = text(html);
    expect(t).toContain("Uncontrolled data used in path expression");
    expect(t).toContain("Improper neutralization of special elements used in an SQL command");
    expect(t).toContain("Imported · CodeQL");
    expect(t).toContain("Imported · GitLab SAST");
    expect(t).toContain("Source is Imported");
    expect(t).toContain("api/files.py:42");
    // The target isn't shown as if it were an image.
    expect(t).not.toContain("(import) codeql");
    expect(t).not.toContain("AWS access key in deploy config");
  });

  it("Imported from: a chip of its own, apart from Scanner; the CSV export takes it", async () => {
    const html = await render(`${org()}/issues?external_tool=codeql`);
    const t = text(html);
    expect(t).toContain("Imported from CodeQL");
    expect(t).not.toContain("Scanner is");
    expect(t).toContain("Uncontrolled data used in path expression");
    expect(t).not.toContain("Improper neutralization");
    expect(html).toContain('title="Download these issues as a CSV file"');
    // The choices come from the import targets (org-wide here).
    let qc: QueryClient | undefined;
    await render(`${org()}/issues`, (c) => (qc = c));
    const rows = qc!.getQueryData<{ items: { target: string }[] }>(qk.orgTargets(db.ORG_ID, "import"));
    expect(rows!.items.map((r) => r.target).sort()).toEqual(["(import) codeql /language:python/", "(import) gitlab-sast", "(import) semgrep"]);
  });

  it("issue page: the tag, an Imported from card with the category, no snippet section, Imported from in Details", async () => {
    const html = await render(`${org()}/issues/${codeql().id}`);
    const t = text(html);
    expect(t).toContain("Imported · CodeQL");
    expect(t).toContain("Imported from CodeQL");
    expect(t).toMatch(/Found by CodeQL \(category \/language:python\/ ?\) and imported from its report with warden import ?\. Warden didn't run this tool\./);
    expect(t).toContain("Warden's own scans never fix it");
    expect(html).not.toContain('aria-label="Code snippet"');
    expect(t).not.toContain("No code snippet for this finding");
    expect(t).toContain("Imported results carry no code");
    expect(t).toMatch(/Imported from CodeQL · \/language:python\//);
    expect(t).not.toMatch(/Scanner (Imported|external)/);
    expect(t).not.toContain("Image (import)");
    expect(t).toContain("Validate user input before using it to construct a file path");

    // The screened issue: its rule text was dropped, so its title is the rule id and there is no fix text.
    const screened = db.IMPORTED_ISSUES.find((i) => i.rule_id === "py/clear-text-logging-sensitive-data")!;
    expect(text(await render(`${org()}/issues/${screened.id}`))).toContain("The report gave no fix advice for this rule.");
  });

  it("an imported issue's tool from the server is text: hostile values never become markup", async () => {
    const i = { ...codeql(), external_tool: HOSTILE, target: `(import) ${HOSTILE}` };
    // On the list too: the row's external_tool is the server's text.
    const stored = codeql();
    stored.external_tool = HOSTILE;
    try {
      const listHtml = await render(`${org()}/issues?source=import`);
      expect(listHtml).not.toContain("<img");
      expect(listHtml).toContain("&lt;img");
    } finally {
      stored.external_tool = "codeql";
    }
    const html = await render(`${org()}/issues/${i.id}`, (qc) => qc.setQueryData(qk.issue(db.ORG_ID, i.id), i));
    expect(html).not.toContain("<img");
  });
});

describe("v0.8 wave 1: CI setup", () => {
  it("a third switch: Import CodeQL results (GitHub), off by default", async () => {
    const t = text(await render(`${org()}/projects/${web().id}/settings`));
    expect(t).toContain("Import CodeQL results");
    expect(t).toContain('warden import --tool codeql --category "/language:<lang>/"');
    expect(t).toContain("github/codeql-action/analyze");
    // Off: the snippet has no import job yet.
    expect(t).not.toContain("Import the CodeQL results into Warden");
  });
});

describe("v0.8 wave 1: the mock follows the contract", () => {
  const importPath = () => `${org()}/projects/${web().id}/scans/import`;

  it("POST …/scans/import: the tool, format, category and file checks; never a Warden scanner", async () => {
    const ok = { tool: "codeql", category: "/language:python/", file_name: "python.sarif", file_size: 1024, sha256: SHA };
    for (const [patch, field] of [
      [{ tool: "gitleaks" }, "tool"],
      [{ tool: "external" }, "tool"],
      [{ tool: "external.UPPER" }, "tool"],
      [{ format: "csv" }, "format"],
      [{ category: "has space" }, "category"],
      [{ file_name: "report.txt" }, "file_name"],
      [{ file_name: "../x.sarif" }, "file_name"],
      [{ file_size: 51 * 1024 * 1024 }, "file_size"],
      [{ sha256: "abc" }, "sha256"],
      [{ extra: 1 }, "extra"],
    ] as const) {
      const r = await call("POST", importPath(), { ...ok, ...patch });
      expect(r.status, JSON.stringify(patch)).toBe(422);
      expect(r.json.error?.metadata?.fields?.[field]).toBeDefined();
    }

    const made: string[] = [];
    try {
      const r = await call("POST", importPath(), ok);
      expect(r.status).toBe(201);
      const scan = (r.json.data as { scan: Record<string, unknown> & { id: string } }).scan;
      made.push(scan.id);
      expect(scan).toMatchObject({
        kind: "import",
        status: "pending_upload",
        tools: ["external"],
        target: "(import) codeql /language:python/",
        import: { tool: "codeql", category: "/language:python/", format: "sarif", tool_version: null, results: null, dropped: null, screened: null },
      });
      expect((await call("POST", `${org()}/scans/${scan.id}/start`)).json.data).toMatchObject({ status: "queued" });
      // The worker reads it a few seconds later in the mock: move its clock back.
      Object.assign(db.scans.find((s) => s.id === scan.id)!, { _t: Date.now() - 60_000 });
      const done = (await call("GET", `${org()}/scans/${scan.id}`)).json.data!;
      expect(done).toMatchObject({ status: "completed", import: { results: 9, dropped: 1, screened: 1 } });

      const gl = await call("POST", importPath(), { tool: "gitlab-sast", format: "gitlab-sast", file_name: "gl-sast-report.json", file_size: 10, sha256: SHA });
      const glScan = (gl.json.data as { scan: { id: string; target: string } }).scan;
      made.push(glScan.id);
      expect(glScan.target).toBe("(import) gitlab-sast");
    } finally {
      for (const id of made) db.scans.splice(db.scans.findIndex((s) => s.id === id), 1);
    }
  });

  it("external is a 422 wherever a scan's tools are chosen, and kind import only comes from …/scans/import", async () => {
    const base = { file_name: "a.zip", file_size: 10, sha256: SHA };
    const scans = `${org()}/projects/${web().id}/scans`;
    expect((await call("POST", scans, { ...base, tools: ["external"] })).json.error?.metadata?.fields?.tools).toBeDefined();
    expect((await call("POST", scans, { ...base, kind: "import" })).json.error?.metadata?.fields?.kind).toBeDefined();
    const pull = await call("POST", `${scans}/pull`, { image_ref: `ghcr.io/acme/api@${db.fakeDigest(9902)}`, tools: ["external"] });
    expect(pull.status).toBe(422);
  });

  it("issue filters: source=import, external_tool, on the list and the CSV export; rows and the issue carry external_tool", async () => {
    const list = await call("GET", `${org()}/issues?source=import&limit=200`);
    const rows = list.json.data!.items!;
    expect(rows).toHaveLength(3);
    expect(rows.every((r) => r.tool === "external")).toBe(true);
    expect(rows.map((r) => r.external_tool).sort()).toEqual(["codeql", "codeql", "gitlab-sast"]);
    const csv = await mockFetch(`/api/v1${org()}/issues/export.csv?external_tool=gitlab-sast`, { method: "GET" });
    expect(csv.status).toBe(200);
    const lines = (await csv.text()).trim().split("\n");
    expect(lines).toHaveLength(3);
    expect(lines[1]).toContain("external:gitlab-sast");
    expect(lines[2]).toBe("#warden:end rows=1");
    const gl = await call("GET", `${org()}/issues?external_tool=gitlab-sast`);
    expect(gl.json.data!.items!.map((r) => r.rule_id)).toEqual(["bandit.B608"]);
    expect((await call("GET", `${org()}/issues?external_tool=gitleaks`)).status).toBe(422);
    expect((await call("GET", `${org()}/issues?source=nope`)).status).toBe(422);
    // Image issues aren't imported ones, and imported ones aren't images.
    const images = await call("GET", `${org()}/issues?source=image&limit=200`);
    expect(images.json.data!.items!.some((r) => r.tool === "external")).toBe(false);
    const one = await call("GET", `${org()}/issues/${db.IMPORTED_ISSUES[0]!.id}`);
    expect(one.json.data).toMatchObject({ tool: "external", external_tool: "codeql", snippet: null });
    // Warden's own issues: external_tool is null.
    const own = await call("GET", `${org()}/issues/${db.issues[0]!.id}`);
    expect(own.json.data).toMatchObject({ external_tool: null });
  });

  it("targets: imports have kind import, and ?kind=import lists them", async () => {
    const r = await call("GET", `${org()}/targets?kind=import`);
    expect(r.json.data!.items!.map((t) => t.kind)).toEqual(["import", "import", "import"]);
  });
});
