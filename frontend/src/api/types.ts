// API types, mirroring the v0.1 API contract field for field (snake_case, as on the wire).
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
}

// ---- Orgs ----

export interface Org {
  id: UUID;
  name: string;
  sla_days: { critical: number; high: number; medium: number; low: number };
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
  description: string;
  remediation: string;
  /** Already masked by the server (`AKIA****`). Never a raw secret. */
  snippet: string;
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
  target_type: string;
  target_id: string;
  ip: string | null;
  data: unknown;
  created_at: Timestamp;
}

export const AUDIT_ACTIONS = [
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
