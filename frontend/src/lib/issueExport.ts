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
// never read, parsed or rendered by the page: its cells come from scanned code and other users.

export const EXPORT_MAX_ROWS = 50_000;
export const EXPORT_TRUNCATED = `Only the first ${EXPORT_MAX_ROWS.toLocaleString("en-US")} rows were exported. Narrow the filters to export the rest.`;
export const EXPORT_INVALID = "Warden couldn't export with these filters. Clear them and try again.";

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
  (deps.save ?? saveBlob)(blob, fileName);
  return { fileName, truncated: headers.get("X-Warden-Truncated") === "true" };
}

/** What the toast says when the export failed (DESIGN.md "Error messages": 429 says when to
 *  retry from Retry-After; a 422 has no field to show it under). */
export function exportErrorMessage(err: unknown): string {
  if (err instanceof ApiError && err.code === "VALIDATION_FAILED") return EXPORT_INVALID;
  return errorMessage(err);
}

/** The button's action: export, then a toast. A cut-off export is a warning that stays until
 *  dismissed, since the file is missing rows. Resolves true when a file was saved. */
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
