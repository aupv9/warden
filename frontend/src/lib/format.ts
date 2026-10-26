import type { ExceptionType, IssueStatus, Limits, ScanStatus, Severity, Tool, ToolStatus } from "../api/types";

export const SEVERITY_LABELS: Record<Severity, string> = {
  critical: "Critical",
  high: "High",
  medium: "Medium",
  low: "Low",
  info: "Info",
};

export const STATUS_LABELS: Record<IssueStatus, string> = {
  open: "Open",
  assigned: "Assigned",
  in_progress: "In progress",
  fixed: "Fixed",
  verified: "Verified",
  reopened: "Reopened",
  false_positive: "False positive",
  risk_accepted: "Risk accepted",
};

export const TOOL_LABELS: Record<Tool, string> = {
  gitleaks: "Gitleaks",
  opengrep: "Opengrep",
  trivy: "Trivy",
  checkov: "Checkov",
};

export const TOOL_KIND: Record<Tool, string> = {
  gitleaks: "secrets",
  opengrep: "code",
  trivy: "dependencies",
  checkov: "IaC",
};

export const SCAN_STATUS_LABELS: Record<ScanStatus, string> = {
  pending_upload: "Uploading",
  queued: "Queued",
  running: "Running",
  completed: "Completed",
  partial: "Partial",
  failed: "Failed",
  cancelled: "Cancelled",
};

export const TOOL_STATUS_LABELS: Record<ToolStatus, string> = {
  queued: "Queued",
  running: "Running",
  succeeded: "Succeeded",
  failed: "Failed",
  timeout: "Timed out",
  skipped: "Skipped",
};

export const EXCEPTION_TYPE_LABELS: Record<ExceptionType, string> = {
  false_positive: "False positive",
  risk_accepted: "Risk accepted",
};

/** Server defaults, used when /me has no limits (older server). */
export const DEFAULT_LIMITS: Limits = {
  upload_max_mb: 200,
  unzip_max_mb: 1024,
  unzip_max_files: 100_000,
  scan_timeout_minutes: 30,
  scans_per_hour: 20,
};

export function formatMb(mb: number): string {
  return mb >= 1024 && mb % 1024 === 0 ? `${mb / 1024} GB` : `${mb.toLocaleString("en-US")} MB`;
}

/** Scan.error_code → [short text for history rows, full text for the scan card]
 *  (DESIGN.md "Scan error_code"). Unknown codes use the fallback. */
export function scanErrorMessages(code: string, limits: Limits = DEFAULT_LIMITS): { short: string; full: string } {
  const files = limits.unzip_max_files.toLocaleString("en-US");
  switch (code) {
    case "ZIP_PATH_TRAVERSAL":
      return {
        short: "path outside the root",
        full: "The archive has a path outside its root. An entry such as ../config.yml or /etc/hosts would land outside the folder. Re-create the .zip from inside the project folder.",
      };
    case "ZIP_BOMB":
      return {
        short: "suspected zip bomb",
        full: `The archive unpacks to more than ${formatMb(limits.unzip_max_mb)}, or a file in it is compressed more than 100 to 1. Remove large generated or binary files and try again.`,
      };
    case "ZIP_TOO_LARGE":
      return {
        short: `archive over ${formatMb(limits.upload_max_mb)}`,
        full: `The archive is larger than ${formatMb(limits.upload_max_mb)}. Leave out dependencies and build output (node_modules, vendor, dist).`,
      };
    case "ZIP_TOO_MANY_FILES":
      return {
        short: `over ${files} files`,
        full: `The archive has more than ${files} files. Leave out dependencies and build output.`,
      };
    case "ZIP_ENCRYPTED":
      return { short: "password-protected", full: "The archive is password-protected. Upload a .zip without a password." };
    case "ZIP_INVALID":
      return { short: "not a readable .zip", full: "This isn't a readable .zip file. Create the archive again with a standard zip tool." };
    case "ZIP_EMPTY":
      return {
        short: "no source files",
        full: "No files were left to scan. Warden skips node_modules, vendor, dist, build, .git and .venv.",
      };
    case "CHECKSUM_MISMATCH":
      return {
        short: "file changed in upload",
        full: "The stored file doesn't match the one you picked, so it was not scanned. Upload it again.",
      };
    case "ALL_SCANNERS_FAILED":
      return {
        short: "every scanner failed",
        full: "Every scanner failed, so there are no results. Each scanner's error is listed below. If it happens again, tell your operator.",
      };
    case "TIMEOUT":
      return {
        short: `took over ${limits.scan_timeout_minutes} min`,
        full: `The scan took longer than the ${limits.scan_timeout_minutes}-minute limit and was stopped.`,
      };
    default:
      return { short: "failed", full: `The scan failed (${code}). Tell your operator; the worker log has the details.` };
  }
}

/** A failed scan whose archive was refused before any scanner ran is shown as "Rejected";
 *  any other failed scan is "Failed". The API has no "rejected" status. */
export function isRejected(scan: { status: ScanStatus; error_code: string | null }): boolean {
  const code = scan.error_code;
  return scan.status === "failed" && !!code && (code.startsWith("ZIP_") || code === "CHECKSUM_MISMATCH");
}

const DAY = 86_400_000;

function toDate(ts: string | Date): Date {
  return ts instanceof Date ? ts : new Date(ts);
}

function sameDay(a: Date, b: Date): boolean {
  return a.getFullYear() === b.getFullYear() && a.getMonth() === b.getMonth() && a.getDate() === b.getDate();
}

/** "Oct 22, 2026" */
export function formatDate(ts: string | null | undefined): string {
  if (!ts) return "–";
  return toDate(ts).toLocaleDateString("en-US", { month: "short", day: "numeric", year: "numeric" });
}

/** "Today 09:12", "Yesterday 16:05", "Oct 22 11:30", or with a year when not this year. */
export function formatDateTime(ts: string | null | undefined, now: Date = new Date()): string {
  if (!ts) return "–";
  const d = toDate(ts);
  const time = d.toLocaleTimeString("en-GB", { hour: "2-digit", minute: "2-digit" });
  if (sameDay(d, now)) return `Today ${time}`;
  if (sameDay(d, new Date(now.getTime() - DAY))) return `Yesterday ${time}`;
  const opts: Intl.DateTimeFormatOptions = { month: "short", day: "numeric" };
  if (d.getFullYear() !== now.getFullYear()) opts.year = "numeric";
  return `${d.toLocaleDateString("en-US", opts)} ${time}`;
}

/** "just now", "5 min ago", "2 h ago", "yesterday", "3 days ago", else a date. */
export function relativeTime(ts: string | null | undefined, now: Date = new Date()): string {
  if (!ts) return "–";
  const diff = now.getTime() - toDate(ts).getTime();
  if (diff < 60_000) return "just now";
  if (diff < 3_600_000) return `${Math.floor(diff / 60_000)} min ago`;
  if (diff < DAY) return `${Math.floor(diff / 3_600_000)} h ago`;
  if (diff < 2 * DAY) return "yesterday";
  if (diff < 30 * DAY) return `${Math.floor(diff / DAY)} days ago`;
  return formatDate(ts);
}

/** Waiting time: "5 hours", "2 days". */
export function age(ts: string, now: Date = new Date()): string {
  const diff = Math.max(0, now.getTime() - toDate(ts).getTime());
  if (diff < 3_600_000) return `${Math.max(1, Math.floor(diff / 60_000))} min`;
  if (diff < DAY) {
    const h = Math.floor(diff / 3_600_000);
    return `${h} hour${h === 1 ? "" : "s"}`;
  }
  const d = Math.floor(diff / DAY);
  return `${d} day${d === 1 ? "" : "s"}`;
}

/** SLA text: "2 days overdue", "Due today", "Due in 3 days", "No due date". */
export function dueText(dueAt: string | null, now: Date = new Date()): { text: string; overdue: boolean } {
  if (!dueAt) return { text: "No due date", overdue: false };
  const due = toDate(dueAt);
  const startOf = (d: Date) => new Date(d.getFullYear(), d.getMonth(), d.getDate()).getTime();
  const days = Math.round((startOf(due) - startOf(now)) / DAY);
  if (due.getTime() < now.getTime() && days < 0) {
    const n = -days;
    return { text: `${n} day${n === 1 ? "" : "s"} overdue`, overdue: true };
  }
  if (days <= 0) return { text: "Due today", overdue: due.getTime() < now.getTime() };
  if (days === 1) return { text: "Due tomorrow", overdue: false };
  return { text: `Due in ${days} days`, overdue: false };
}

/** Compact SLA text for list rows: "2d overdue", "Today", "Tomorrow", "in 4d", "–". The full
 *  sentence (dueText) goes in the row's accessible text via `long`. */
export function dueShort(dueAt: string | null, now: Date = new Date()): { text: string; long: string; overdue: boolean } {
  const full = dueText(dueAt, now);
  if (!dueAt) return { text: "–", long: full.text, overdue: false };
  const m = /^(\d+) days? overdue$/.exec(full.text);
  if (m) return { text: `${m[1]}d overdue`, long: full.text, overdue: true };
  if (full.text === "Due today") return { text: "Today", long: full.text, overdue: full.overdue };
  if (full.text === "Due tomorrow") return { text: "Tomorrow", long: full.text, overdue: false };
  const n = /^Due in (\d+) days$/.exec(full.text);
  return { text: n ? `in ${n[1]}d` : full.text, long: full.text, overdue: false };
}

/** Days from now until ts, rounded up (for "accepted until … (97 days)"). */
export function daysUntil(ts: string, now: Date = new Date()): number {
  return Math.ceil((toDate(ts).getTime() - now.getTime()) / DAY);
}

export function formatBytes(n: number): string {
  if (n < 1024) return `${n} B`;
  if (n < 1024 * 1024) return `${Math.round(n / 1024)} KB`;
  if (n < 1024 * 1024 * 1024) return `${(n / (1024 * 1024)).toFixed(n < 10 * 1024 * 1024 ? 1 : 0)} MB`;
  return `${(n / (1024 * 1024 * 1024)).toFixed(1)} GB`;
}

/** "12 s", "6 m 40 s", "1 h 05 m" */
export function formatDuration(ms: number | null | undefined): string {
  if (ms === null || ms === undefined) return "–";
  const s = Math.round(ms / 1000);
  if (s < 60) return `${s} s`;
  const m = Math.floor(s / 60);
  if (m < 60) return `${m} m ${String(s % 60).padStart(2, "0")} s`;
  return `${Math.floor(m / 60)} h ${String(m % 60).padStart(2, "0")} m`;
}

export function durationBetween(start: string | null, end: string | null): number | null {
  if (!start || !end) return null;
  return Math.max(0, toDate(end).getTime() - toDate(start).getTime());
}

export function initials(name: string): string {
  const parts = name.trim().split(/[\s@._-]+/).filter(Boolean);
  const letters = parts.length >= 2 ? `${parts[0]![0]}${parts[1]![0]}` : (parts[0] ?? "?").slice(0, 2);
  return letters.toUpperCase();
}

export function userName(u: { display_name?: string | null; email: string } | null | undefined): string {
  if (!u) return "System";
  return u.display_name?.trim() || u.email;
}

/** "deploy/prod.env:12" */
export function location(path: string | null, line: number | null): string {
  if (!path) return "";
  return line ? `${path}:${line}` : path;
}

/** <input type="date"> value (local date) for a timestamp. */
export function toDateInput(d: Date): string {
  const p = (n: number) => String(n).padStart(2, "0");
  return `${d.getFullYear()}-${p(d.getMonth() + 1)}-${p(d.getDate())}`;
}

/** A date input's value as local midnight in RFC 3339 (UTC). Local midnight of the last allowed
 *  day is always within "now + N days", so the server's upper bound holds. */
export function fromDateInput(value: string): string | null {
  if (!/^\d{4}-\d{2}-\d{2}$/.test(value)) return null;
  const d = new Date(`${value}T00:00:00`);
  return Number.isNaN(d.getTime()) ? null : d.toISOString();
}

export function addDays(d: Date, n: number): Date {
  return new Date(d.getTime() + n * DAY);
}
