import type { QueryParams } from "../api/client";
import { ISSUE_STATUSES, SEVERITIES, TOOLS } from "../api/types";
import type { IssueSort, IssueStatus, Severity, Tool } from "../api/types";

// Issue list filters live in the URL (shareable, back button works). The URL is untrusted
// input: every value is checked against the contract's enums before it reaches the API.

export type StatusFilter = "active" | "all" | IssueStatus;

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
};

const SORTS: IssueSort[] = ["due_at", "-severity", "-updated_at"];
const UUID_RE = /^[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}$/i;
const MAX_Q = 200;

function oneOf<T extends string>(value: string | null, allowed: readonly T[]): T | undefined {
  return value !== null && (allowed as readonly string[]).includes(value) ? (value as T) : undefined;
}

export function parseIssueFilters(sp: URLSearchParams): IssueFilters {
  const status = sp.get("status");
  const assignee = sp.get("assignee") ?? "";
  const project = sp.get("project") ?? "";
  const severities = new Set(sp.getAll("severity"));
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

/** The active filters in words, e.g. ["Active", "Critical", "Past SLA only", "Web storefront"]. */
export function describeFilters(f: IssueFilters, names: { project?: string; assignee?: string } = {}): string[] {
  const words = [STATUS_WORDS[f.status] ?? f.status];
  for (const s of f.severity) words.push(SEVERITY_WORDS[s]);
  if (f.pastSla) words.push("Past SLA only");
  if (f.tool) words.push(TOOL_WORDS[f.tool]);
  if (f.assignee) words.push(names.assignee ?? "One assignee");
  if (names.project) words.push(names.project);
  if (f.q) words.push(`“${f.q}”`);
  return words;
}

export function hasActiveFilters(f: IssueFilters): boolean {
  return issueFiltersToSearch({ ...f, sort: DEFAULT_FILTERS.sort }).toString() !== "";
}
