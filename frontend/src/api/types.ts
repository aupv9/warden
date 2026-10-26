// API types, mirroring the v0.1 and v0.2 API contracts field for field (snake_case, as on the wire).
// Every screen imports from this one module so it can later be replaced by types generated
// from the backend's openapi.json (`npm run gen:api` writes src/api/schema.d.ts).

export type UUID = string;
/** RFC 3339 timestamp, UTC. */
export type Timestamp = string;

export interface UserRef {
  id: UUID;
  email: string;
  display_name: string;
}

export type Severity = "critical" | "high" | "medium" | "low" | "info";
export type OrgRole = "org_admin" | "security_lead" | "member";
export type ProjectRole = "owner" | "developer" | "viewer";
export type IssueStatus =
  | "open"
  | "assigned"
  | "in_progress"
  | "fixed"
  | "verified"
  | "reopened"
  | "false_positive"
  | "risk_accepted";
export type ScanStatus = "pending_upload" | "queued" | "running" | "completed" | "partial" | "failed" | "cancelled";
export type ToolStatus = "queued" | "running" | "succeeded" | "failed" | "timeout" | "skipped";
export type Tool = "gitleaks" | "opengrep" | "trivy" | "checkov";

export interface SeverityCounts {
  critical: number;
  high: number;
  medium: number;
  low: number;
  info: number;
}

export interface Page<T> {
  items: T[];
  next_cursor: string | null;
}

export interface ItemList<T> {
  items: T[];
}

// ---- Me ----

export interface MeOrg {
  id: UUID;
  name: string;
  role: OrgRole;
}

/** Server configuration limits (scan.* settings). */
export interface Limits {
  upload_max_mb: number;
  unzip_max_mb: number;
  unzip_max_files: number;
  scan_timeout_minutes: number;
  scans_per_hour: number;
}

export interface Me {
  id: UUID;
  sub: string;
  email: string;
  name: string | null;
  mfa: boolean;
  orgs: MeOrg[];
  limits: Limits;
  /** v0.2: orgs where the caller's role requires two-factor sign-in and this session has none. */
  mfa_required_orgs: UUID[];
}

// ---- Orgs ----

export interface Org {
  id: UUID;
  name: string;
  sla_days: SlaDays;
  my_role: OrgRole;
}

export interface OrgSummary {
  open_issues: number;
  critical_high_open: number;
  past_sla: number;
  exceptions_pending: number;
}

export interface OrgMember {
  user: UserRef & { is_active: boolean };
  role: OrgRole;
  mfa: boolean | null;
  projects: { id: UUID; key: string; role: ProjectRole }[];
}

export interface AddOrgMemberBody {
  email: string;
  role: OrgRole;
}

// ---- Projects ----

export interface Project {
  id: UUID;
  key: string;
  name: string;
  description: string | null;
  default_tools: Tool[];
  my_role: ProjectRole | null;
  open_by_severity: SeverityCounts;
  past_sla: number;
  last_scan: { id: UUID; status: ScanStatus; created_at: Timestamp; finished_at: Timestamp | null } | null;
  created_at: Timestamp;
  /** v0.2: archived projects take no new scans; their issues stay readable. */
  archived_at: Timestamp | null;
}

export interface CreateProjectBody {
  key: string;
  name: string;
  description?: string;
  default_tools?: Tool[];
}

export interface ProjectMember {
  user: UserRef;
  role: ProjectRole;
}

// ---- Scans ----

export interface ToolRun {
  tool: Tool;
  tool_version: string;
  status: ToolStatus;
  findings_count: number | null;
  duration_ms: number | null;
  error: string | null;
}

export interface Scan {
  id: UUID;
  project_id: UUID;
  status: ScanStatus;
  file_name: string;
  file_size: number;
  tools: Tool[];
  error_code: string | null;
  stats: { new: number; fixed: number; reopened: number; total: number };
  created_by: UserRef;
  created_at: Timestamp;
  queued_at: Timestamp | null;
  started_at: Timestamp | null;
  finished_at: Timestamp | null;
  tool_runs?: ToolRun[];
  /** v0.2: the API token that created the scan (CI), or null for a scan from the UI. */
  via_token: TokenRef | null;
}

export interface CreateScanBody {
  file_name: string;
  file_size: number;
  sha256: string;
  tools?: Tool[];
}

export interface PresignedUpload {
  method: "PUT";
  url: string;
  headers: Record<string, string>;
  expires_at: Timestamp;
}

export interface CreateScanResponse {
  scan: Scan;
  upload: PresignedUpload;
}

// ---- Issues ----

export interface IssueSummary {
  id: UUID;
  key: string;
  project_id: UUID;
  title: string;
  severity: Severity;
  status: IssueStatus;
  tool: Tool;
  rule_id: string;
  file_path: string | null;
  start_line: number | null;
  package_name: string | null;
  package_version: string | null;
  fixed_version: string | null;
  assignee: UserRef | null;
  due_at: Timestamp | null;
  past_sla: boolean;
  updated_at: Timestamp;
}

export interface IssuePage extends Page<IssueSummary> {
  counts_by_severity: SeverityCounts;
}

export interface Issue extends IssueSummary {
  description: string | null;
  remediation: string | null;
  /** Already masked by the server (`AKIA****`). Never a raw secret. */
  snippet: string | null;
  end_line: number | null;
  cwe: string[];
  cve: string[];
  first_seen_scan: { id: UUID; created_at: Timestamp };
  last_seen_scan: { id: UUID; created_at: Timestamp };
  occurrences: number;
  version: number;
  allowed_transitions: IssueStatus[];
  can_assign: boolean;
  can_request_exception: boolean;
  pending_exception_id: UUID | null;
}

export type IssueSort = "due_at" | "-severity" | "-updated_at";

export interface TransitionBody {
  to: IssueStatus;
  version: number;
  assignee_id?: UUID;
  reason?: string;
}

export interface BulkAssignBody {
  issue_ids: UUID[];
  assignee_id: UUID;
}

export type IssueEventType =
  | "created"
  | "status_changed"
  | "assigned"
  | "seen_again"
  | "severity_changed"
  | "commented"
  | "exception_requested"
  | "exception_decided";

export interface IssueEvent {
  id: UUID;
  type: IssueEventType;
  /** null = system */
  actor: UserRef | null;
  from_value: string | null;
  to_value: string | null;
  note: string | null;
  created_at: Timestamp;
}

export interface Comment {
  id: UUID;
  author: UserRef;
  body: string;
  created_at: Timestamp;
  edited_at: Timestamp | null;
}

// ---- Exceptions ----

export type ExceptionType = "false_positive" | "risk_accepted";
export type ExceptionStatus = "pending" | "approved" | "rejected" | "expired";
/** The list filter: `expiring` = approved risk_accepted expiring within 14 days. */
export type ExceptionTab = "pending" | "approved" | "rejected" | "expiring";

export interface ExceptionRequest {
  id: UUID;
  issue: { id: UUID; key: string; title: string; severity: Severity; status: IssueStatus };
  type: ExceptionType;
  reason: string;
  status: ExceptionStatus;
  requested_by: UserRef;
  decided_by: UserRef | null;
  decision_note: string | null;
  expires_at: Timestamp | null;
  decided_at: Timestamp | null;
  created_at: Timestamp;
}

export interface CreateExceptionBody {
  type: ExceptionType;
  reason: string;
  expires_at?: Timestamp;
}

export interface DecisionBody {
  decision: "approve" | "reject";
  note?: string;
  expires_at?: Timestamp;
}

// ---- Audit log ----

export interface AuditEntry {
  id: UUID;
  actor: UserRef | null;
  action: string;
  target_type: string | null;
  target_id: string | null;
  ip: string | null;
  data: unknown;
  created_at: Timestamp;
}

export const AUDIT_ACTIONS = [
  "token.created",
  "token.revoked",
  "org.policy_changed",
  "project.archived",
  "project.unarchived",
  "member.added",
  "member.role_changed",
  "member.removed",
  "project.created",
  "project_member.set",
  "project_member.removed",
  "scan.created",
  "scan.started",
  "scan.cancelled",
  "issue.transitioned",
  "issue.assigned",
  "exception.requested",
  "exception.decided",
] as const;

// ---- v0.2: API tokens and the scan gate ----

export type TokenScope = "scan:write" | "issues:read";

/** A token named on a scan (`Scan.via_token`); openapi schema TokenRef. */
export interface TokenRef {
  id: UUID;
  name: string;
  prefix: string;
}
export const TOKEN_SCOPES: TokenScope[] = ["scan:write", "issues:read"];

export interface ApiToken {
  id: UUID;
  name: string;
  /** 8 lowercase base32 characters; the token reads `wdn_<prefix>_<secret>`. */
  prefix: string;
  scopes: string[];
  created_by: UserRef;
  created_at: Timestamp;
  expires_at: Timestamp;
  last_used_at: Timestamp | null;
  revoked_at: Timestamp | null;
}

/** openapi schema CreateTokenRequest. */
export interface CreateTokenBody {
  name: string;
  scopes: TokenScope[];
  expires_in_days: number;
}

/** The only response that carries `secret`. The UI keeps it in the dialog's state only. */
export interface CreatedToken {
  token: ApiToken;
  secret: string;
}

export interface Gate {
  scan_id: UUID;
  status: ScanStatus;
  finished: boolean;
  fail_on: Severity;
  pass: boolean;
  counts: SeverityCounts;
  blocking: IssueSummary[];
}

// ---- v0.2: notifications ----

export type NotificationType =
  | "issue.assigned"
  | "issue.reopened"
  | "exception.requested"
  | "exception.decided"
  | "scan.finished"
  | "sla.due_soon"
  | "sla.overdue";

export const NOTIFICATION_TYPES: NotificationType[] = [
  "issue.assigned",
  "issue.reopened",
  "exception.requested",
  "exception.decided",
  "scan.finished",
  "sla.due_soon",
  "sla.overdue",
];

export interface Notification {
  id: UUID;
  org_id: UUID;
  type: NotificationType;
  /** Server-built text such as "WEB-41 assigned to you". Rendered as text. */
  title: string;
  /** An app path, e.g. /orgs/…/issues/…. */
  link: string;
  actor: UserRef | null;
  read_at: Timestamp | null;
  created_at: Timestamp;
}

export interface UnreadCount {
  count: number;
}

export type MarkReadBody = { ids: UUID[] } | { all: true };

export interface NotificationPref {
  type: NotificationType;
  email: boolean;
}

// ---- v0.2: policy and automation ----

export interface SlaDays {
  critical: number;
  high: number;
  medium: number;
  low: number;
}

export interface UpdatePolicyBody {
  sla_days: SlaDays;
  recompute_open?: boolean;
}

export interface AssignRule {
  match: { path_glob?: string; tool?: Tool; severity_at_least?: Severity };
  assignee_id: UUID;
}

// ---- v0.2: metrics ----

export type MetricsDays = 30 | 90 | 180;
export const METRICS_DAYS: MetricsDays[] = [30, 90, 180];

export interface OpenByDay {
  date: string;
  critical: number;
  high: number;
  medium: number;
  low: number;
}

export interface DayCount {
  date: string;
  count: number;
}

export interface Metrics {
  days: number;
  open_by_day: OpenByDay[];
  mttr_hours: { critical: number | null; high: number | null; medium: number | null; low: number | null };
  sla: { fixed_in_time: number; fixed_late: number; open_overdue: number };
  new_by_day: DayCount[];
  fixed_by_day: DayCount[];
}

export interface IssueCounts {
  active: number;
  mine: number;
  past_sla: number;
  secrets: number;
}

// ---- Enumerations used by the UI ----

export const SEVERITIES: Severity[] = ["critical", "high", "medium", "low", "info"];
export const TOOLS: Tool[] = ["gitleaks", "opengrep", "trivy", "checkov"];
export const ISSUE_STATUSES: IssueStatus[] = [
  "open",
  "assigned",
  "in_progress",
  "fixed",
  "verified",
  "reopened",
  "false_positive",
  "risk_accepted",
];
export const ACTIVE_STATUSES: IssueStatus[] = ["open", "assigned", "in_progress", "reopened"];
export const ORG_ROLES: OrgRole[] = ["org_admin", "security_lead", "member"];
export const PROJECT_ROLES: ProjectRole[] = ["owner", "developer", "viewer"];
