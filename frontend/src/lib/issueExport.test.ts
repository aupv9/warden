// v0.5 wave 2: "Export CSV" on the issue list. The export needs the bearer token, so it is a
// fetch with the token in the Authorization header (never in the URL), and the body is saved
// as a file from a Blob under a sanitised name; the page never parses or renders it. v0.7: it is
// saved only when complete (the end line `#warden:end rows=<N>` with the right N).
import { afterEach, beforeEach, describe, expect, it, vi } from "vitest";
import type { ApiDeps } from "../api/client";
import { DEFAULT_FILTERS, issueFilterQuery } from "./issueFilters";
import {
  checkComplete,
  countNewlines,
  dispositionFilename,
  EXPORT_INCOMPLETE,
  EXPORT_INVALID,
  EXPORT_TRUNCATED,
  exportIssuesCsv,
  fallbackFileName,
  runIssueExport,
  safeFileName,
  saveBlob,
  TAIL_BYTES,
} from "./issueExport";
import type { SaveEnv } from "./issueExport";
import { clearToasts, currentToasts } from "./toast";

const ORG = "00000000-0000-4000-8000-000000000001";
const PROJECT = "00000000-0000-4000-8000-0000000000b1";
// Built at test time (CLAUDE.md: no secret-shaped literals in fixtures).
const TOKEN = ["eyJ", "hbGciOiJSUzI1NiJ9", Array.from({ length: 24 }, (_, i) => "abcdefghij"[i % 10]).join("")].join(".");
const FRESH = `${TOKEN}-refreshed`;
const CSV = "key,project,title\r\nWEB-41,WEB,'=HYPERLINK(\"x\")\r\n#warden:end rows=1\r\n";

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

const csvResponse = (headers: Record<string, string> = {}, body: string = CSV) =>
  new Response(body, {
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

// v0.7: an export is complete when its last non-empty line is exactly `#warden:end rows=<N>`
// and N is the number of data rows. Rows are built here; cells never hold a raw line break
// (the server turns them into spaces).
const HEADER = "key,project,title,severity";
const row = (i: number) => `WEB-${i},WEB,"Request data passed to eval, case ${i}",high`;
function csv(rows: number, { end = `#warden:end rows=${rows}`, eol = "\r\n", trailer = eol }: { end?: string | null; eol?: string; trailer?: string } = {}): string {
  const lines = [HEADER, ...Array.from({ length: rows }, (_, i) => row(i + 1))];
  if (end !== null) lines.push(end);
  return lines.join(eol) + trailer;
}
const blob = (s: string) => new Blob([s], { type: "text/csv" });

describe("export completeness (v0.7)", () => {
  let saved: { blob: Blob; name: string }[];
  const save = (b: Blob, name: string) => void saved.push({ blob: b, name });

  beforeEach(() => {
    saved = [];
    clearToasts();
  });
  afterEach(() => {
    vi.restoreAllMocks();
    vi.unstubAllGlobals();
    clearToasts();
  });

  it("complete: the end line counts the data rows, with CRLF, LF, no final line break or blank lines after it", async () => {
    for (const n of [0, 1, 2, 7, 600]) {
      expect(await checkComplete(blob(csv(n))), `${n} CRLF`).toBe(true);
      expect(await checkComplete(blob(csv(n, { eol: "\n" }))), `${n} LF`).toBe(true);
      expect(await checkComplete(blob(csv(n, { trailer: "" }))), `${n} no final break`).toBe(true);
      expect(await checkComplete(blob(csv(n, { trailer: "\r\n\r\n\r\n" }))), `${n} blank lines`).toBe(true);
    }
    // A file far larger than the tail: the tail starts inside a row.
    const big = csv(5_000);
    expect(big.length).toBeGreaterThan(100 * TAIL_BYTES);
    expect(await checkComplete(blob(big))).toBe(true);
    // Newlines are counted over the whole file, CRLF or LF alike.
    expect(await countNewlines(blob(csv(3)))).toBe(5);
    expect(await countNewlines(blob(csv(3, { eol: "\n" })))).toBe(5);
  });

  it("cut: a file without the end line, or one that ends inside it, is incomplete", async () => {
    expect(await checkComplete(blob(csv(3, { end: null })))).toBe(false);
    expect(await checkComplete(blob(csv(3, { end: null, trailer: "" })))).toBe(false);
    // The stream broke in the middle of a row.
    expect(await checkComplete(blob(csv(3, { end: null }).slice(0, -9)))).toBe(false);
    // ... or in the middle of the end line.
    const full = csv(12, { trailer: "" });
    for (let cut = 1; cut < "#warden:end rows=12".length; cut++) expect(await checkComplete(blob(full.slice(0, -cut))), `cut ${cut}`).toBe(false);
    expect(await checkComplete(blob(""))).toBe(false);
    expect(await checkComplete(blob(HEADER))).toBe(false);
    // Only the end line, with no header before it.
    expect(await checkComplete(blob("#warden:end rows=0\r\n"))).toBe(false);
  });

  it("miscount: an end line whose N isn't the number of data rows is incomplete", async () => {
    expect(await checkComplete(blob(csv(3, { end: "#warden:end rows=4" })))).toBe(false);
    expect(await checkComplete(blob(csv(3, { end: "#warden:end rows=2" })))).toBe(false);
    expect(await checkComplete(blob(csv(0, { end: "#warden:end rows=1" })))).toBe(false);
    // Rows lost before the end line was written (the count is the server's, the rows are ours).
    const lines = csv(5).split("\r\n");
    lines.splice(2, 1);
    expect(await checkComplete(blob(lines.join("\r\n")))).toBe(false);
  });

  it("the end line must be exactly that, alone and last", async () => {
    const bad = [
      "#warden:end rows=3 ",
      " #warden:end rows=3",
      "#warden:end rows=03",
      "#warden:end rows=+3",
      "#warden:end rows=3.0",
      "#warden:end rows=-1",
      "#warden:end rows=",
      "#Warden:end rows=3",
      "#warden:end  rows=3",
      '"#warden:end rows=3"',
      "#warden:end rows=3,",
      "WEB-9,#warden:end rows=3",
      "#warden:end rows=99999999999999999999",
    ];
    for (const end of bad) expect(await checkComplete(blob(csv(3, { end }))), end).toBe(false);
    // An end line followed by more rows is not the last line.
    expect(await checkComplete(blob(`${csv(3)}${row(4)}\r\n`))).toBe(false);
    // A row that ends in the end line's text, padded with blank lines so the tail starts right at
    // "#warden:end": with no line break before it in the tail, it isn't a line of its own.
    const end = "#warden:end rows=0";
    const trailer = "\r\n".repeat((TAIL_BYTES - end.length) / 2);
    const forged = `${HEADER}\r\nWEB-1,${end}${trailer}`;
    expect(new TextDecoder().decode(await blob(forged).slice(-TAIL_BYTES).arrayBuffer()).startsWith(end)).toBe(true);
    expect(await checkComplete(blob(forged))).toBe(false);
  });

  it("truncated at 50,000 rows with its end line: saved, with the warning; cut or miscounted: nothing saved", async () => {
    stubFetch(() => csvResponse({ "X-Warden-Truncated": "true" }, csv(4)));
    expect(await runIssueExport(ORG, issueFilterQuery(DEFAULT_FILTERS), { api: deps, save })).toBe(true);
    expect(currentToasts()).toMatchObject([{ tone: "warning", title: "Export cut off.", message: EXPORT_TRUNCATED }]);
    expect(saved).toHaveLength(1);

    for (const body of [csv(4, { end: null }), csv(4, { end: "#warden:end rows=5" }), csv(4, { end: null }).slice(0, -20)]) {
      for (const headers of [{}, { "X-Warden-Truncated": "true" }] as Record<string, string>[]) {
        clearToasts();
        stubFetch(() => csvResponse(headers, body));
        expect(await runIssueExport(ORG, issueFilterQuery(DEFAULT_FILTERS), { api: deps, save })).toBe(false);
        expect(EXPORT_INCOMPLETE).toBe("The export was cut off. Nothing was saved; try again.");
        expect(currentToasts()).toMatchObject([{ tone: "error", message: EXPORT_INCOMPLETE }]);
      }
    }
    expect(saved).toHaveLength(1);
  });

  it("reads only the last 256 bytes as text; the rest is counted as bytes", async () => {
    const reads: number[] = [];
    for (const m of ["arrayBuffer", "text", "bytes"] as const) {
      const orig = Blob.prototype[m] as (this: Blob) => Promise<unknown>;
      vi.spyOn(Blob.prototype, m).mockImplementation(function (this: Blob) {
        reads.push(this.size);
        return orig.call(this) as never;
      });
    }
    const body = csv(2_000);
    stubFetch(() => csvResponse({}, body));
    expect(await runIssueExport(ORG, issueFilterQuery(DEFAULT_FILTERS), { api: deps, save })).toBe(true);
    expect(saved).toHaveLength(1);
    expect(saved[0]!.blob.size).toBe(body.length);
    expect(reads.length).toBeGreaterThan(0);
    for (const n of reads) expect(n).toBeLessThanOrEqual(TAIL_BYTES);
  });

  it("no CSV text reaches the DOM or a toast, complete or not", async () => {
    // A cell an attacker controls (an issue title from scanned code).
    const marker = `<img src=x onerror=alert(1)>-${Math.random().toString(36).slice(2)}`;
    const body = `${HEADER}\r\nWEB-1,WEB,${marker},high\r\n#warden:end rows=1\r\n`;
    const writes: unknown[] = [];
    const recorded = <T extends object>(o: T): T =>
      new Proxy(o, {
        set(t, k, v) {
          writes.push([String(k), v]);
          return Reflect.set(t, k, v);
        },
      });
    const created: string[] = [];
    vi.stubGlobal("document", {
      createElement: (tag: string) => {
        created.push(tag);
        return recorded({ click: () => undefined, remove: () => undefined });
      },
      body: recorded({ append: (...nodes: unknown[]) => void writes.push(["append", ...nodes]) }),
    });
    const urls: Blob[] = [];
    vi.spyOn(URL, "createObjectURL").mockImplementation((b) => {
      urls.push(b as Blob);
      return "blob:http://localhost/1";
    });
    vi.spyOn(URL, "revokeObjectURL").mockImplementation(() => undefined);
    vi.spyOn(globalThis, "setTimeout").mockImplementation((() => 0) as unknown as typeof setTimeout);

    for (const b of [body, body.replace("rows=1", "rows=2")]) {
      stubFetch(() => csvResponse({}, b));
      await runIssueExport(ORG, issueFilterQuery(DEFAULT_FILTERS), { api: deps });
    }
    // The complete one was handed to the browser as a download, the other wasn't.
    expect(created).toEqual(["a"]);
    expect(urls).toHaveLength(1);
    expect(urls[0]!.type).toBe("application/octet-stream");
    expect(writes).toContainEqual(["download", "warden-issues-acme-engineering-2026-11-02.csv"]);
    // Only the anchor's own fields were set; nothing of the file.
    expect(writes.map((w) => (w as unknown[])[0])).toEqual(expect.arrayContaining(["href", "download", "rel", "hidden", "append"]));
    expect(writes.map((w) => (w as unknown[])[0])).not.toEqual(expect.arrayContaining(["innerHTML", "textContent", "innerText", "outerHTML"]));
    const seen = JSON.stringify(writes, (_k, v: unknown) => (v instanceof Blob ? "[blob]" : v)) + JSON.stringify(currentToasts());
    expect(seen).not.toContain(marker);
    expect(seen).not.toContain("WEB-1");
    expect(currentToasts().map((t) => t.message)).toEqual(["Issues exported as warden-issues-acme-engineering-2026-11-02.csv.", EXPORT_INCOMPLETE]);
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
