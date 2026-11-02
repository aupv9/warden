// v0.5 wave 2: "Export CSV" on the issue list. The export needs the bearer token, so it is a
// fetch with the token in the Authorization header (never in the URL), and the body is saved
// as a file from a Blob under a sanitised name; the page never reads or renders it.
import { afterEach, beforeEach, describe, expect, it, vi } from "vitest";
import type { ApiDeps } from "../api/client";
import { DEFAULT_FILTERS, issueFilterQuery } from "./issueFilters";
import {
  dispositionFilename,
  EXPORT_INVALID,
  EXPORT_TRUNCATED,
  exportIssuesCsv,
  fallbackFileName,
  runIssueExport,
  safeFileName,
  saveBlob,
} from "./issueExport";
import type { SaveEnv } from "./issueExport";
import { clearToasts, currentToasts } from "./toast";

const ORG = "00000000-0000-4000-8000-000000000001";
const PROJECT = "00000000-0000-4000-8000-0000000000b1";
// Built at test time (CLAUDE.md: no secret-shaped literals in fixtures).
const TOKEN = ["eyJ", "hbGciOiJSUzI1NiJ9", Array.from({ length: 24 }, (_, i) => "abcdefghij"[i % 10]).join("")].join(".");
const FRESH = `${TOKEN}-refreshed`;
const CSV = "key,project,title\r\nWEB-41,WEB,'=HYPERLINK(\"x\")\r\n";

type Sent = { url: string; init: RequestInit };

function stubFetch(reply: (n: number) => Response) {
  const sent: Sent[] = [];
  vi.stubGlobal(
    "fetch",
    vi.fn(async (url: string, init: RequestInit) => {
      sent.push({ url, init });
      return reply(sent.length);
    }),
  );
  return sent;
}

const csvResponse = (headers: Record<string, string> = {}) =>
  new Response(CSV, {
    status: 200,
    headers: { "Content-Type": "text/csv; charset=utf-8", "Content-Disposition": 'attachment; filename="warden-issues-acme-engineering-2026-11-02.csv"', ...headers },
  });

const errorResponse = (status: number, code: string, headers: Record<string, string> = {}) =>
  new Response(JSON.stringify({ data: null, error: { code, message: "server words, never shown" }, meta: { request_id: "req-1" } }), {
    status,
    headers: { "Content-Type": "application/json", ...headers },
  });

const deps: ApiDeps = { getToken: async () => TOKEN, refreshToken: async () => FRESH };
const filters = { ...DEFAULT_FILTERS, severity: ["critical" as const, "high" as const], kev: true, q: "log4j", target: "ghcr.io/acme/api" };

describe("issue CSV export", () => {
  let saved: { blob: Blob; name: string }[];
  const save = (blob: Blob, name: string) => void saved.push({ blob, name });

  beforeEach(() => {
    saved = [];
    clearToasts();
  });
  afterEach(() => {
    vi.unstubAllGlobals();
    clearToasts();
  });

  it("sends the list's filters with the token in the Authorization header, never in the URL", async () => {
    const sent = stubFetch(() => csvResponse());
    const res = await exportIssuesCsv(ORG, issueFilterQuery(filters, PROJECT), { api: deps, save });
    expect(sent).toHaveLength(1);
    const { url, init } = sent[0]!;
    const u = new URL(url, "http://localhost");
    expect(u.pathname).toBe(`/api/v1/orgs/${ORG}/issues/export.csv`);
    expect(Object.fromEntries([...new Set(u.searchParams.keys())].map((k) => [k, u.searchParams.getAll(k)]))).toEqual({
      project_id: [PROJECT],
      severity: ["critical", "high"],
      kev: ["true"],
      target: ["ghcr.io/acme/api"],
      q: ["log4j"],
    });
    // No paging on an export, and the token is nowhere in the URL.
    expect(u.searchParams.has("limit")).toBe(false);
    expect(url).not.toContain(TOKEN);
    expect(url).not.toMatch(/token|access|bearer|auth/i);
    expect(init.method).toBe("GET");
    expect(init.credentials).toBe("omit");
    expect(init.headers).toEqual({ Accept: "text/csv", Authorization: `Bearer ${TOKEN}` });
    expect(res).toEqual({ fileName: "warden-issues-acme-engineering-2026-11-02.csv", truncated: false });
    // Saved as a file with the server's name; the bytes are handed over untouched.
    expect(saved).toHaveLength(1);
    expect(saved[0]!.name).toBe("warden-issues-acme-engineering-2026-11-02.csv");
    expect(saved[0]!.blob).toBeInstanceOf(Blob);
    expect(await saved[0]!.blob.text()).toBe(CSV);
  });

  it("refreshes the token once on 401; the new one also goes only in the header", async () => {
    const sent = stubFetch((n) => (n === 1 ? errorResponse(401, "UNAUTHORIZED") : csvResponse()));
    await exportIssuesCsv(ORG, issueFilterQuery(DEFAULT_FILTERS), { api: deps, save });
    expect(sent.map((s) => (s.init.headers as Record<string, string>).Authorization)).toEqual([`Bearer ${TOKEN}`, `Bearer ${FRESH}`]);
    for (const s of sent) expect(s.url).not.toContain(TOKEN);
    expect(saved).toHaveLength(1);
  });

  it("a success toast names the file; a truncated export warns that only 50,000 rows were exported", async () => {
    stubFetch(() => csvResponse());
    expect(await runIssueExport(ORG, issueFilterQuery(DEFAULT_FILTERS), { api: deps, save })).toBe(true);
    expect(currentToasts()).toMatchObject([{ tone: "success", message: "Issues exported as warden-issues-acme-engineering-2026-11-02.csv." }]);

    clearToasts();
    stubFetch(() => csvResponse({ "X-Warden-Truncated": "true" }));
    expect(await runIssueExport(ORG, issueFilterQuery(DEFAULT_FILTERS), { api: deps, save })).toBe(true);
    expect(EXPORT_TRUNCATED).toBe("Only the first 50,000 rows were exported. Narrow the filters to export the rest.");
    expect(currentToasts()).toMatchObject([{ tone: "warning", message: EXPORT_TRUNCATED }]);
    // Saved anyway: the file holds the first 50,000 rows.
    expect(saved).toHaveLength(2);
  });

  it("429 says when to try again (Retry-After); 422 asks to clear the filters; nothing is saved", async () => {
    stubFetch(() => errorResponse(429, "RATE_LIMITED", { "Retry-After": "120" }));
    expect(await runIssueExport(ORG, issueFilterQuery(DEFAULT_FILTERS), { api: deps, save })).toBe(false);
    expect(currentToasts()).toMatchObject([{ tone: "warning", title: "Slow down.", message: "Too many requests in a short time. Try again in 2 minutes." }]);

    clearToasts();
    stubFetch(() => errorResponse(429, "RATE_LIMITED"));
    await runIssueExport(ORG, issueFilterQuery(DEFAULT_FILTERS), { api: deps, save });
    expect(currentToasts()[0]!.message).toBe("Too many requests in a short time. Wait a minute, then try again.");

    clearToasts();
    stubFetch(() => errorResponse(422, "VALIDATION_FAILED"));
    await runIssueExport(ORG, issueFilterQuery(DEFAULT_FILTERS), { api: deps, save });
    expect(currentToasts()).toMatchObject([{ tone: "error", message: EXPORT_INVALID }]);

    clearToasts();
    stubFetch(() => errorResponse(503, "INTERNAL"));
    await runIssueExport(ORG, issueFilterQuery(DEFAULT_FILTERS), { api: deps, save });
    expect(currentToasts()).toMatchObject([{ tone: "error", message: expect.stringMatching(/^Warden didn't answer/), reference: "req-1" }]);
    // The server's message is never shown.
    expect(JSON.stringify(currentToasts())).not.toContain("server words");
    expect(saved).toEqual([]);
  });

  it("a proxy's HTML error page is neither saved nor shown", async () => {
    stubFetch(() => new Response("<html><script>alert(1)</script></html>", { status: 502, headers: { "Content-Type": "text/html" } }));
    expect(await runIssueExport(ORG, issueFilterQuery(DEFAULT_FILTERS), { api: deps, save })).toBe(false);
    expect(saved).toEqual([]);
    expect(JSON.stringify(currentToasts())).not.toContain("script");
  });
});

describe("export file name", () => {
  const fallback = "warden-issues-2026-11-02.csv";

  it("reads filename= from Content-Disposition", () => {
    expect(dispositionFilename('attachment; filename="warden-issues-acme-2026-11-02.csv"')).toBe("warden-issues-acme-2026-11-02.csv");
    expect(dispositionFilename("attachment; filename=plain.csv")).toBe("plain.csv");
    expect(dispositionFilename('attachment; filename="a\\"b.csv"')).toBe('a"b.csv');
    // filename* is not filename.
    expect(dispositionFilename("attachment; filename*=UTF-8''x.csv")).toBeNull();
    expect(dispositionFilename("attachment")).toBeNull();
    expect(dispositionFilename(null)).toBeNull();
  });

  it("keeps the server's name and makes anything hostile safe", () => {
    expect(safeFileName("warden-issues-acme-engineering-2026-11-02.csv", fallback)).toBe("warden-issues-acme-engineering-2026-11-02.csv");
    const cases: [string | null, string][] = [
      ["../../etc/passwd", "passwd.csv"],
      ["..\\..\\Windows\\System32\\evil.bat", "evil.bat.csv"],
      ["/tmp/x.csv", "x.csv"],
      [".bashrc", "bashrc.csv"],
      ["....csv", "csv.csv"],
      ["report.html", "report.html.csv"],
      ["evil.csv.exe", "evil.csv.exe.csv"],
      ["a b\r\nSet-Cookie: x=1.csv", "a-b-Set-Cookie-x-1.csv"],
      // The "/" in "</script>" counts as a path separator.
      ["<script>alert(1)</script>.csv", "script-.csv"],
      ["\u202Evsc.exe", "vsc.exe.csv"],
      ["", fallback],
      [null, fallback],
      ["../", fallback],
      ["x".repeat(500) + ".csv", "x".repeat(120) + ".csv"],
    ];
    for (const [raw, want] of cases) {
      const got = safeFileName(raw, fallback);
      expect(got, String(raw)).toBe(want);
      expect(got).toMatch(/^[A-Za-z0-9][A-Za-z0-9._-]*\.csv$/);
      expect(got.length).toBeLessThanOrEqual(124);
    }
  });

  it("falls back to a dated name", () => {
    expect(fallbackFileName(new Date(2026, 10, 2, 9))).toBe("warden-issues-2026-11-02.csv");
  });
});

describe("saving the Blob", () => {
  it("clicks a hidden <a download> on a blob: URL typed as octet-stream, then revokes the URL", async () => {
    const made: Blob[] = [];
    const revoked: string[] = [];
    const later: (() => void)[] = [];
    const clicked: { href: string; download: string; rel: string; hidden: boolean }[] = [];
    let removed = 0;
    const env: SaveEnv = {
      createObjectURL: (b) => {
        made.push(b);
        return "blob:http://localhost/1234";
      },
      revokeObjectURL: (u) => void revoked.push(u),
      createElement: () => {
        const a = {
          href: "",
          download: "",
          rel: "",
          hidden: false,
          click: () => void clicked.push({ href: a.href, download: a.download, rel: a.rel, hidden: a.hidden }),
          remove: () => void (removed += 1),
        };
        return a;
      },
      append: () => undefined,
      later: (fn) => void later.push(fn),
    };
    saveBlob(new Blob(["<html>not rendered</html>"], { type: "text/html" }), "x.csv", env);
    expect(clicked).toEqual([{ href: "blob:http://localhost/1234", download: "x.csv", rel: "noopener", hidden: true }]);
    expect(removed).toBe(1);
    // Whatever type the response claimed, the saved Blob can't be rendered in place.
    expect(made[0]!.type).toBe("application/octet-stream");
    expect(await made[0]!.text()).toBe("<html>not rendered</html>");
    expect(revoked).toEqual([]);
    later.forEach((fn) => fn());
    expect(revoked).toEqual(["blob:http://localhost/1234"]);
  });
});
