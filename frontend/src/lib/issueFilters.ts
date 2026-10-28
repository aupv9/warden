import type { QueryParams } from "../api/client";
import { ISSUE_STATUSES, SEVERITIES, TOOLS } from "../api/types";
import type { IssueSort, IssueStatus, Severity, Tool } from "../api/types";
import { formatEpss, isImageTarget } from "./intel";

// Issue list filters live in the URL (shareable, back button works). The URL is untrusted
// input: every value is checked against the contract's enums before it reaches the API.

export type StatusFilter = "active" | "all" | IssueStatus;
/** v0.3: Trivy issues only: dependency vulnerabilities or license-policy issues; v0.4 adds
 *  malicious packages (OSV MAL- advisories). */
export type IssueKindFilter = "vulnerability" | "license" | "malicious";
/** v0.3: issues from source scans or from image scans. */
export type IssueSourceFilter = "code" | "image";

export interface IssueFilters {
  q: string;
  /** "" = all projects the caller can see. */
  project: string;
  status: StatusFilter;
  severity: Severity[];
  /** "" = anyone; "me"; "none"; or a user id. */
  assignee: string;
  tool: Tool | "";
  pastSla: boolean;
  sort: IssueSort;
  /** v0.3 */
  kind: IssueKindFilter | "";
  /** v0.3: only issues with a CVE in CISA KEV. */
  kev: boolean;
  /** v0.3: EPSS at least this (0..1); null = any. */
  epssMin: number | null;
  /** v0.3 */
  source: IssueSourceFilter | "";
  /** v0.3: one image repository ("" = any). */
  target: string;
}

export const DEFAULT_FILTERS: IssueFilters = {
  q: "",
  project: "",
  status: "active",
  severity: [],
  assignee: "",
  tool: "",
  pastSla: false,
  sort: "due_at",
  kind: "",
  kev: false,
  epssMin: null,
  source: "",
  target: "",
};

export const SORTS: IssueSort[] = ["due_at", "-severity", "-updated_at", "-epss"];
export const ISSUE_KINDS: IssueKindFilter[] = ["vulnerability", "malicious", "license"];
export const ISSUE_SOURCES: IssueSourceFilter[] = ["code", "image"];
/** The EPSS presets offered in the UI; the URL may carry any value from 0 to 1. */
export const EPSS_PRESETS = [0.01, 0.1, 0.5] as const;
const UUID_RE = /^[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}$/i;
const MAX_Q = 200;

function oneOf<T extends string>(value: string | null, allowed: readonly T[]): T | undefined {
  return value !== null && (allowed as readonly string[]).includes(value) ? (value as T) : undefined;
}

/** A plain decimal from 0 to 1 ("0.1", "1", ".5"); no exponents, signs, NaN or junk. */
export function parseEpssMin(raw: string | null): number | null {
  if (raw === null || !/^(?:0|1|0?\.\d{1,6}|1\.0{1,6})$/.test(raw)) return null;
  const n = Number(raw);
  return n > 0 && n <= 1 ? n : null;
}

export function parseIssueFilters(sp: URLSearchParams): IssueFilters {
  const status = sp.get("status");
  const assignee = sp.get("assignee") ?? "";
  const project = sp.get("project") ?? "";
  const severities = new Set(sp.getAll("severity"));
  const target = sp.get("target") ?? "";
  return {
    q: (sp.get("q") ?? "").trim().slice(0, MAX_Q),
    project: UUID_RE.test(project) ? project : "",
    status:
      status === "all" || status === "active" ? status : (oneOf(status, ISSUE_STATUSES) ?? DEFAULT_FILTERS.status),
    // Canonical order, no duplicates, unknown values dropped.
    severity: SEVERITIES.filter((s) => severities.has(s)),
    assignee: assignee === "me" || assignee === "none" || UUID_RE.test(assignee) ? assignee : "",
    tool: oneOf(sp.get("tool"), TOOLS) ?? "",
    pastSla: sp.get("past_sla") === "true",
    sort: oneOf(sp.get("sort"), SORTS) ?? DEFAULT_FILTERS.sort,
    kind: oneOf(sp.get("kind"), ISSUE_KINDS) ?? "",
    kev: sp.get("kev") === "true",
    epssMin: parseEpssMin(sp.get("epss_min")),
    source: oneOf(sp.get("source"), ISSUE_SOURCES) ?? "",
    target: isImageTarget(target) ? target : "",
  };
}

/** URL form: defaults are left out so a plain /issues link means "the default view". */
export function issueFiltersToSearch(f: IssueFilters): URLSearchParams {
  const sp = new URLSearchParams();
  if (f.q) sp.set("q", f.q);
  if (f.project) sp.set("project", f.project);
  if (f.status !== DEFAULT_FILTERS.status) sp.set("status", f.status);
  for (const s of f.severity) sp.append("severity", s);
  if (f.assignee) sp.set("assignee", f.assignee);
  if (f.tool) sp.set("tool", f.tool);
  if (f.pastSla) sp.set("past_sla", "true");
  if (f.kind) sp.set("kind", f.kind);
  if (f.kev) sp.set("kev", "true");
  if (f.epssMin !== null) sp.set("epss_min", String(f.epssMin));
  if (f.source) sp.set("source", f.source);
  if (f.target) sp.set("target", f.target);
  if (f.sort !== DEFAULT_FILTERS.sort) sp.set("sort", f.sort);
  return sp;
}

/** Query for GET /orgs/{org}/issues. `fixedProject` comes from the route on a project's Issues tab. */
export function issueFiltersToApiQuery(f: IssueFilters, fixedProject?: string): QueryParams {
  const project = fixedProject ?? f.project;
  return {
    project_id: project || undefined,
    status: f.status === "all" ? ISSUE_STATUSES : f.status === "active" ? undefined : [f.status],
    severity: f.severity.length ? f.severity : undefined,
    assignee: f.assignee || undefined,
    tool: f.tool || undefined,
    past_sla: f.pastSla ? "true" : undefined,
    kind: f.kind || undefined,
    kev: f.kev ? "true" : undefined,
    epss_min: f.epssMin !== null ? String(f.epssMin) : undefined,
    source: f.source || undefined,
    target: f.target || undefined,
    q: f.q || undefined,
    sort: f.sort === DEFAULT_FILTERS.sort ? undefined : f.sort,
    limit: 50,
  };
}

export function toggleSeverity(f: IssueFilters, s: Severity): IssueFilters {
  const has = f.severity.includes(s);
  const next = new Set(has ? f.severity.filter((x) => x !== s) : [...f.severity, s]);
  return { ...f, severity: SEVERITIES.filter((x) => next.has(x)) };
}

const STATUS_WORDS: Record<string, string> = {
  active: "Active",
  all: "All statuses",
  open: "Open",
  assigned: "Assigned",
  in_progress: "In progress",
  fixed: "Fixed",
  verified: "Verified",
  reopened: "Reopened",
  false_positive: "False positive",
  risk_accepted: "Risk accepted",
};
const SEVERITY_WORDS: Record<Severity, string> = { critical: "Critical", high: "High", medium: "Medium", low: "Low", info: "Info" };
const TOOL_WORDS: Record<Tool, string> = { gitleaks: "Gitleaks", opengrep: "Opengrep", trivy: "Trivy", checkov: "Checkov" };
export const KIND_LABELS: Record<IssueKindFilter, string> = { vulnerability: "Vulnerabilities", malicious: "Malicious packages", license: "Licenses" };
export const SOURCE_LABELS: Record<IssueSourceFilter, string> = { code: "Source code", image: "Container images" };

/** "EPSS ≥ 10%" */
export function epssMinText(n: number): string {
  return `EPSS ≥ ${formatEpss(n) ?? String(n)}`;
}

/** The active filters in words, e.g. ["Active", "Critical", "Past SLA only", "Web storefront"]. */
export function describeFilters(f: IssueFilters, names: { project?: string; assignee?: string } = {}): string[] {
  const words = [STATUS_WORDS[f.status] ?? f.status];
  for (const s of f.severity) words.push(SEVERITY_WORDS[s]);
  if (f.pastSla) words.push("Past SLA only");
  if (f.kev) words.push("Known exploited");
  if (f.epssMin !== null) words.push(epssMinText(f.epssMin));
  if (f.kind) words.push(KIND_LABELS[f.kind]);
  if (f.tool) words.push(TOOL_WORDS[f.tool]);
  if (f.source) words.push(SOURCE_LABELS[f.source]);
  if (f.target) words.push(`Image ${f.target}`);
  if (f.assignee) words.push(names.assignee ?? "One assignee");
  if (names.project) words.push(names.project);
  if (f.q) words.push(`“${f.q}”`);
  return words;
}

export function hasActiveFilters(f: IssueFilters): boolean {
  return issueFiltersToSearch({ ...f, sort: DEFAULT_FILTERS.sort }).toString() !== "";
}

// ---- Saved views: presets of the URL filters above (no state of their own) ----

export type SavedView = "active" | "mine" | "past_sla" | "kev" | "malicious" | "secrets" | "licenses";

export const SAVED_VIEWS: { id: SavedView; label: string }[] = [
  { id: "active", label: "Active" },
  { id: "mine", label: "Assigned to me" },
  { id: "past_sla", label: "Past SLA" },
  { id: "kev", label: "Exploited (KEV)" },
  { id: "malicious", label: "Malicious" },
  { id: "secrets", label: "Secrets" },
  { id: "licenses", label: "Licenses" },
];

const VIEW_PRESETS: Record<SavedView, Partial<IssueFilters>> = {
  active: {},
  mine: { assignee: "me" },
  past_sla: { pastSla: true },
  kev: { kev: true },
  malicious: { kind: "malicious" },
  secrets: { tool: "gitleaks" },
  licenses: { kind: "license" },
};

/** The filters for a saved view. The search text, sort and project scope are kept. */
export function applyView(f: IssueFilters, view: SavedView): IssueFilters {
  return { ...DEFAULT_FILTERS, q: f.q, sort: f.sort, project: f.project, ...VIEW_PRESETS[view] };
}

/** The saved view these filters are exactly, or null for a custom set of filters. */
export function currentView(f: IssueFilters): SavedView | null {
  const key = (x: IssueFilters) => issueFiltersToSearch(x).toString();
  return SAVED_VIEWS.find((v) => key(applyView(f, v.id)) === key(f))?.id ?? null;
}

// ---- Split view links: the list's filters travel with the selected issue ----

function withSearch(path: string, search: URLSearchParams): string {
  const s = search.toString();
  return s ? `${path}?${s}` : path;
}

/** `/orgs/:org/issues/:issue?<filters>`: the issue, opened from a list with these filters.
 *  Only the parsed, validated filters are carried over, never other query parameters. */
export function issueHref(orgId: string, issueId: string, f: IssueFilters): string {
  return withSearch(`/orgs/${orgId}/issues/${encodeURIComponent(issueId)}`, issueFiltersToSearch(f));
}

/** `/orgs/:org/issues?<filters>`: back to the list (closing the pane, or the phone back link). */
export function issueListHref(orgId: string, f: IssueFilters): string {
  return withSearch(`/orgs/${orgId}/issues`, issueFiltersToSearch(f));
}
