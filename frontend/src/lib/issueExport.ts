import { ApiError, apiFile } from "../api/client";
import type { ApiDeps } from "../api/client";
import { errorMessage, supportReference } from "../api/errors";
import type { IssueFilterQuery } from "./issueFilters";
import { showToast } from "./toast";

// v0.5 wave 2: "Export CSV" on the issue list (DESIGN.md "Issue triage").
//
// GET /orgs/{org}/issues/export.csv takes the list's filters and answers a CSV attachment. It
// needs the bearer token, so it can't be a plain link: the page fetches it with the token in the
// Authorization header (never in the URL, where it would end up in history, logs and Referer),
// and saves the body as a file through a temporary `<a download>` on a blob: URL. The CSV is
// never parsed or rendered by the page: its cells come from scanned code and other users.
//
// v0.7: before saving, the page checks that the file is complete (checkComplete): if the server
// fails mid-stream the response just ends (over HTTP/2 with no error at all), and a short file
// must not be saved as if it were the export. It reads only the last 256 bytes as text and counts
// newline bytes over the rest; no cell is decoded, kept or shown.

export const EXPORT_MAX_ROWS = 50_000;
export const EXPORT_TRUNCATED = `Only the first ${EXPORT_MAX_ROWS.toLocaleString("en-US")} rows were exported. Narrow the filters to export the rest.`;
export const EXPORT_INVALID = "Warden couldn't export with these filters. Clear them and try again.";
export const EXPORT_INCOMPLETE = "The export was cut off. Nothing was saved; try again.";

/** The tail read as text: the end line is at most ~30 bytes, so 256 leaves room for the line
 *  break before it and a few trailing blank lines. */
export const TAIL_BYTES = 256;
const END_LINE = /^#warden:end rows=(0|[1-9][0-9]{0,8})$/;

/** The export ended before the server wrote its end line, or with a different row count. */
export class ExportIncompleteError extends Error {
  constructor() {
    super("incomplete export");
    this.name = "ExportIncompleteError";
  }
}

/** Newline bytes in the whole Blob, read as a stream chunk by chunk without decoding it or
 *  building strings: the page counts lines, it never reads cells. */
export async function countNewlines(blob: Blob): Promise<number> {
  const reader = blob.stream().getReader();
  let n = 0;
  for (;;) {
    const { done, value } = await reader.read();
    if (done) return n;
    for (let i = value.indexOf(10); i !== -1; i = value.indexOf(10, i + 1)) n++;
  }
}

/** Whether the file is a complete export (contract, GET /issues/export.csv): its last non-empty
 *  line is exactly `#warden:end rows=<N>` and N is the number of data rows above it, header
 *  excluded. Only the last TAIL_BYTES of the Blob are read as text (blob.slice), and only to find
 *  that line; the rows are counted as newline bytes (countNewlines).
 *
 *  Counting newlines counts rows because a CSV cell never holds a raw line break: the server
 *  turns every control character in a cell, CR and LF included, into a space, so each record
 *  is one line. Lines end in CRLF (RFC 4180); a bare LF is accepted too. A data row can't forge
 *  the end line: every row starts with the server's issue key, never `#`. */
export async function checkComplete(blob: Blob): Promise<boolean> {
  const start = Math.max(0, blob.size - TAIL_BYTES);
  const tail = new TextDecoder().decode(await blob.slice(start).arrayBuffer());
  const lines = tail.split("\n");
  // Trailing empty lines (the end line's own CRLF, or a blank line after it) are skipped.
  let last = lines.length - 1;
  while (last >= 0 && lines[last]!.replace(/\r$/, "") === "") last--;
  // The end line must be whole: a line break before it inside the tail (the header always
  // precedes it), so a tail that starts in the middle of a longer line doesn't count.
  if (last < 1) return false;
  const m = END_LINE.exec(lines[last]!.replace(/\r$/, ""));
  if (!m) return false;
  // Newlines from the end line's start to the end of the file: one per line after it.
  const after = lines.length - 1 - last;
  const rows = (await countNewlines(blob)) - after - 1; // minus the header's line break
  return rows >= 0 && rows === Number(m[1]);
}

const NAME_MAX = 120;

/** The `filename` from a Content-Disposition header (`filename*` is ignored: the server sends
 *  an ASCII name), or null. */
export function dispositionFilename(header: string | null): string | null {
  if (!header) return null;
  const m = /(?:^|;)\s*filename\s*=\s*(?:"((?:[^"\\]|\\.)*)"|([^;\s]*))/i.exec(header);
  if (!m) return null;
  return (m[1] !== undefined ? m[1].replace(/\\(.)/g, "$1") : m[2]) || null;
}

/** A file name that is safe to hand to the browser: the last path segment only, letters,
 *  digits, dot, dash and underscore, no leading dot, at most 120 characters, ending in `ext`.
 *  Anything left empty falls back. The server's name (warden-issues-<org>-<date>.csv) passes
 *  unchanged. */
export function safeFileName(raw: string | null | undefined, fallback: string, ext = ".csv"): string {
  let name = (raw ?? "").normalize("NFKC");
  name = name.split(/[\\/]/).pop() ?? "";
  name = name
    .replace(/[^A-Za-z0-9._-]+/g, "-")
    .replace(/-{2,}/g, "-")
    .replace(/^[.-]+/, "")
    .replace(/[.-]+$/, "")
    .slice(0, NAME_MAX);
  if (!name.toLowerCase().endsWith(ext)) name = name ? `${name.replace(/[.-]+$/, "")}${ext}` : "";
  return name && name.toLowerCase() !== ext ? name : fallback;
}

export function fallbackFileName(now: Date = new Date()): string {
  const d = `${now.getFullYear()}-${String(now.getMonth() + 1).padStart(2, "0")}-${String(now.getDate()).padStart(2, "0")}`;
  return `warden-issues-${d}.csv`;
}

/** Minimal browser surface for saving a Blob, so tests can see what would be clicked. */
export interface SaveEnv {
  createObjectURL(blob: Blob): string;
  revokeObjectURL(url: string): void;
  createElement(tag: "a"): Pick<HTMLAnchorElement, "href" | "download" | "rel" | "hidden" | "click" | "remove">;
  append(el: unknown): void;
  later(fn: () => void, ms: number): void;
}

const browserEnv = (): SaveEnv => ({
  createObjectURL: (b) => URL.createObjectURL(b),
  revokeObjectURL: (u) => URL.revokeObjectURL(u),
  createElement: (tag) => document.createElement(tag),
  append: (el) => document.body.append(el as Node),
  later: (fn, ms) => void setTimeout(fn, ms),
});

/** Saves the bytes as a file. The Blob is re-typed as application/octet-stream, so no browser
 *  ever renders it in place whatever type the response claimed; the URL is revoked once the
 *  download has had time to start. */
export function saveBlob(blob: Blob, name: string, env: SaveEnv = browserEnv()): void {
  const url = env.createObjectURL(new Blob([blob], { type: "application/octet-stream" }));
  const a = env.createElement("a");
  a.href = url;
  a.download = name;
  a.rel = "noopener";
  a.hidden = true;
  env.append(a);
  a.click();
  a.remove();
  env.later(() => env.revokeObjectURL(url), 60_000);
}

export interface ExportDeps {
  api?: ApiDeps;
  save?: (blob: Blob, name: string) => void;
  now?: () => Date;
}

export interface ExportResult {
  fileName: string;
  truncated: boolean;
}

/** Fetches the CSV for these filters and saves it. Throws ApiError on failure. */
export async function exportIssuesCsv(orgId: string, query: IssueFilterQuery, deps: ExportDeps = {}): Promise<ExportResult> {
  const { blob, headers } = await apiFile(`/orgs/${encodeURIComponent(orgId)}/issues/export.csv`, { query, accept: "text/csv" }, deps.api);
  const fileName = safeFileName(dispositionFilename(headers.get("Content-Disposition")), fallbackFileName(deps.now?.() ?? new Date()));
  // A cut-off file is never saved: the user would take it for the whole export.
  if (!(await checkComplete(blob))) throw new ExportIncompleteError();
  (deps.save ?? saveBlob)(blob, fileName);
  return { fileName, truncated: headers.get("X-Warden-Truncated") === "true" };
}

/** What the toast says when the export failed (DESIGN.md "Error messages": 429 says when to
 *  retry from Retry-After; a 422 has no field to show it under). */
export function exportErrorMessage(err: unknown): string {
  if (err instanceof ExportIncompleteError) return EXPORT_INCOMPLETE;
  if (err instanceof ApiError && err.code === "VALIDATION_FAILED") return EXPORT_INVALID;
  return errorMessage(err);
}

/** The button's action: export, then a toast. An export the server cut at 50,000 rows is a
 *  warning that stays until dismissed, since the file is missing rows; one that ended early
 *  (no end line, or a different count) is an error and nothing is saved. Resolves true when a
 *  file was saved. */
export async function runIssueExport(orgId: string, query: IssueFilterQuery, deps: ExportDeps = {}): Promise<boolean> {
  try {
    const { fileName, truncated } = await exportIssuesCsv(orgId, query, deps);
    if (truncated) showToast({ tone: "warning", title: "Export cut off.", message: EXPORT_TRUNCATED });
    else showToast({ tone: "success", message: `Issues exported as ${fileName}.` });
    return true;
  } catch (err) {
    const rateLimited = err instanceof ApiError && err.code === "RATE_LIMITED";
    showToast({
      tone: rateLimited ? "warning" : "error",
      title: rateLimited ? "Slow down." : undefined,
      message: exportErrorMessage(err),
      reference: supportReference(err),
    });
    return false;
  }
}
