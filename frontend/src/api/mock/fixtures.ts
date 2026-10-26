// Dev-only fixtures for VITE_MOCK=1 (never in a production build: see api/client.ts).
// Shaped exactly like the API contract. Names, numbers and files are examples. Snippets are
// already masked, as the API sends them; nothing here is a real or real-looking secret.
import type {
  AuditEntry,
  Comment,
  ExceptionRequest,
  Issue,
  IssueEvent,
  Me,
  Org,
  OrgMember,
  Project,
  ProjectMember,
  Scan,
  Severity,
  UserRef,
} from "../types";

const DAY = 86_400_000;
const H = 3_600_000;
export const now = () => Date.now();
const ago = (ms: number) => new Date(now() - ms).toISOString();
const ahead = (ms: number) => new Date(now() + ms).toISOString();

let seq = 0;
export function uuid(): string {
  seq += 1;
  const hex = seq.toString(16).padStart(12, "0");
  return `00000000-0000-4000-8000-${hex}`;
}

export const ORG_ID = uuid();
export const ORG2_ID = uuid();

const u = (display_name: string, email: string): UserRef => ({ id: uuid(), display_name, email });
export const users = {
  linh: u("Linh Tran", "linh@acme.example"),
  huy: u("Huy Do", "huy@acme.example"),
  minh: u("Minh Pham", "minh@acme.example"),
  an: u("An Nguyen", "an@acme.example"),
  bao: u("Bao Le", "bao@acme.example"),
  quynh: u("Quynh Vo", "quynh@acme.example"),
};

export const me: Me = {
  id: users.linh.id,
  sub: "mock-sub-linh",
  email: users.linh.email,
  name: users.linh.display_name,
  mfa: true,
  orgs: [
    { id: ORG_ID, name: "Acme Engineering", role: "security_lead" },
    { id: ORG2_ID, name: "Acme Labs", role: "member" },
  ],
  limits: { upload_max_mb: 200, unzip_max_mb: 1024, unzip_max_files: 100000, scan_timeout_minutes: 30, scans_per_hour: 20 },
};

export const org: Org = {
  id: ORG_ID,
  name: "Acme Engineering",
  sla_days: { critical: 7, high: 30, medium: 90, low: 180 },
  my_role: "security_lead",
};

const zero = { critical: 0, high: 0, medium: 0, low: 0, info: 0 };

function project(key: string, name: string, my_role: Project["my_role"], description: string | null): Project {
  return {
    id: uuid(),
    key,
    name,
    description,
    default_tools: ["gitleaks", "opengrep", "trivy", "checkov"],
    my_role,
    open_by_severity: { ...zero },
    past_sla: 0,
    last_scan: null,
    created_at: ago(40 * DAY),
  };
}

export const projects: Project[] = [
  project("WEB", "Web storefront", "owner", "Customer-facing shop: Go API and React front end."),
  project("PAY", "Payments API", "developer", null),
  project("INFRA", "Terraform modules", null, "Shared infrastructure as code."),
  project("MOB", "Mobile app", "viewer", null),
];
const [WEB, PAY, INFRA] = projects as [Project, Project, Project, Project];

export const projectMembers: Record<string, ProjectMember[]> = {
  [WEB.id]: [
    { user: users.minh, role: "owner" },
    { user: users.an, role: "developer" },
    { user: users.quynh, role: "viewer" },
    { user: users.linh, role: "owner" },
  ],
  [PAY.id]: [
    { user: users.an, role: "owner" },
    { user: users.minh, role: "developer" },
    { user: users.linh, role: "developer" },
  ],
  [INFRA.id]: [{ user: users.bao, role: "developer" }],
  [projects[3]!.id]: [{ user: users.linh, role: "viewer" }],
};

export const orgMembers: OrgMember[] = [
  { user: { ...users.linh, is_active: true }, role: "security_lead", mfa: true, projects: [] },
  { user: { ...users.huy, is_active: true }, role: "org_admin", mfa: true, projects: [] },
  { user: { ...users.minh, is_active: true }, role: "member", mfa: true, projects: [] },
  { user: { ...users.an, is_active: true }, role: "member", mfa: false, projects: [] },
  { user: { ...users.bao, is_active: false }, role: "member", mfa: null, projects: [] },
  { user: { ...users.quynh, is_active: true }, role: "member", mfa: true, projects: [] },
];

function scan(p: Project, partial: Partial<Scan>, createdAgo: number): Scan {
  const created = ago(createdAgo);
  return {
    id: uuid(),
    project_id: p.id,
    status: "completed",
    file_name: `${p.key.toLowerCase()}-main.zip`,
    file_size: 48 * 1024 * 1024,
    tools: p.default_tools,
    error_code: null,
    stats: { new: 0, fixed: 0, reopened: 0, total: 0 },
    created_by: users.minh,
    created_at: created,
    queued_at: created,
    started_at: created,
    finished_at: new Date(Date.parse(created) + 400_000).toISOString(),
    tool_runs: p.default_tools.map((tool) => ({
      tool,
      tool_version: tool === "gitleaks" ? "8.28.0" : tool === "trivy" ? "0.67.2" : tool === "opengrep" ? "1.10.0" : "3.2.480",
      status: "succeeded" as const,
      findings_count: 3,
      duration_ms: 12_000 + tool.length * 4000,
      error: null,
    })),
    ...partial,
  };
}

export const scans: Scan[] = [
  scan(WEB, { file_name: "storefront-release-2.3.zip", stats: { new: 4, fixed: 7, reopened: 1, total: 31 } }, 2 * H),
  scan(
    WEB,
    {
      file_name: "storefront-main.zip",
      status: "partial",
      created_by: users.linh,
      stats: { new: 2, fixed: 0, reopened: 0, total: 26 },
      finished_at: ago(DAY + 30 * 60_000 - 1_800_000),
      tool_runs: [
        { tool: "gitleaks", tool_version: "8.28.0", status: "succeeded", findings_count: 3, duration_ms: 12_000, error: null },
        { tool: "opengrep", tool_version: "1.10.0", status: "succeeded", findings_count: 9, duration_ms: 48_000, error: null },
        { tool: "trivy", tool_version: "0.67.2", status: "timeout", findings_count: null, duration_ms: 1_800_000, error: "stopped after the scanner time limit" },
        { tool: "checkov", tool_version: "3.2.480", status: "succeeded", findings_count: 14, duration_ms: 31_000, error: null },
      ],
    },
    DAY + 30 * 60_000,
  ),
  scan(WEB, { file_name: "storefront.zip", status: "failed", error_code: "ZIP_PATH_TRAVERSAL", file_size: 3 * 1024 * 1024, tool_runs: [], finished_at: ago(4 * DAY - 1000) }, 4 * DAY),
  scan(WEB, { file_name: "storefront-assets.zip", status: "failed", error_code: "ZIP_BOMB", tool_runs: [], finished_at: ago(5 * DAY - 4000) }, 5 * DAY),
  scan(WEB, { file_name: "storefront-old.zip", status: "cancelled", created_by: users.linh, finished_at: ago(6 * DAY - 72_000), tool_runs: [
    { tool: "gitleaks", tool_version: "8.28.0", status: "succeeded", findings_count: 3, duration_ms: 12_000, error: null },
    { tool: "opengrep", tool_version: "1.10.0", status: "skipped", findings_count: null, duration_ms: null, error: null },
    { tool: "trivy", tool_version: "0.67.2", status: "skipped", findings_count: null, duration_ms: null, error: null },
    { tool: "checkov", tool_version: "3.2.480", status: "skipped", findings_count: null, duration_ms: null, error: null },
  ] }, 6 * DAY),
  scan(WEB, { file_name: "storefront-2.2.zip", stats: { new: 26, fixed: 0, reopened: 0, total: 26 } }, 7 * DAY),
  scan(PAY, { file_name: "payments-api.zip" }, DAY),
  scan(INFRA, { file_name: "terraform.zip" }, 5 * DAY),
];

const issueN: Record<string, number> = { WEB: 40, PAY: 6, INFRA: 3 };

interface IssueSeed {
  p: Project;
  title: string;
  severity: Severity;
  status: Issue["status"];
  tool: Issue["tool"];
  rule_id: string;
  file_path?: string;
  start_line?: number;
  snippet?: string;
  pkg?: [string, string, string | null];
  assignee?: UserRef | null;
  dueIn: number;
  cwe?: string[];
  cve?: string[];
  remediation: string;
  description: string;
}

function issue(s: IssueSeed): Issue {
  issueN[s.p.key] = (issueN[s.p.key] ?? 0) + 1;
  const due = s.dueIn === Infinity ? null : new Date(now() + s.dueIn).toISOString();
  return {
    id: uuid(),
    key: `${s.p.key}-${issueN[s.p.key]}`,
    project_id: s.p.id,
    title: s.title,
    severity: s.severity,
    status: s.status,
    tool: s.tool,
    rule_id: s.rule_id,
    file_path: s.file_path ?? (s.pkg ? "go.mod" : null),
    start_line: s.start_line ?? null,
    package_name: s.pkg?.[0] ?? null,
    package_version: s.pkg?.[1] ?? null,
    fixed_version: s.pkg?.[2] ?? null,
    assignee: s.assignee ?? null,
    due_at: due,
    past_sla: due !== null && Date.parse(due) < now(),
    updated_at: ago(3 * H),
    description: s.description,
    remediation: s.remediation,
    snippet: s.snippet ?? "",
    end_line: s.start_line ?? null,
    cwe: s.cwe ?? [],
    cve: s.cve ?? [],
    first_seen_scan: { id: scans[5]!.id, created_at: scans[5]!.created_at },
    last_seen_scan: { id: scans[0]!.id, created_at: scans[0]!.created_at },
    occurrences: 4,
    version: 1,
    allowed_transitions: [],
    can_assign: false,
    can_request_exception: false,
    pending_exception_id: null,
  };
}

// The masked value is built at runtime from a fixed prefix plus asterisks, like redact.Mask.
const masked = ["AK", "IA"].join("") + "****";

export const issues: Issue[] = [
  issue({
    p: WEB,
    title: "AWS access key in deploy config",
    severity: "critical",
    status: "assigned",
    tool: "gitleaks",
    rule_id: "aws-access-token",
    file_path: "deploy/prod.env",
    start_line: 12,
    snippet: `AWS_ACCESS_KEY_ID=${masked}`,
    assignee: users.minh,
    dueIn: -2 * DAY,
    cwe: ["CWE-798"],
    description: "An AWS access key ID was found in a committed file.",
    remediation:
      "1. Revoke the key in AWS IAM now: removing it from the code does not make it safe.\n2. Move the value to your secret store and read it at runtime.\n3. Upload a new scan. The issue moves to Fixed when the finding is gone.",
  }),
  issue({
    p: WEB,
    title: "SQL built from request parameters",
    severity: "critical",
    status: "reopened",
    tool: "opengrep",
    rule_id: "go.lang.security.sqli",
    file_path: "internal/order/repo.go",
    start_line: 88,
    snippet: 'q := "SELECT * FROM orders WHERE id = " + r.URL.Query().Get("id")',
    dueIn: -1 * DAY,
    cwe: ["CWE-89"],
    description: "User input is concatenated into a SQL statement.",
    remediation: "Use a parameterised query (db.Query(\"... WHERE id = $1\", id)).",
  }),
  issue({
    p: PAY,
    title: "golang.org/x/net: HTTP/2 rapid reset",
    severity: "high",
    status: "in_progress",
    tool: "trivy",
    rule_id: "CVE-2023-44487",
    pkg: ["golang.org/x/net", "v0.17.0", "v0.23.0"],
    assignee: users.an,
    dueIn: 4 * H,
    cve: ["CVE-2023-44487"],
    description: "The HTTP/2 implementation allows a denial of service through rapid stream resets.",
    remediation: "Upgrade golang.org/x/net to v0.23.0 or later and rebuild.",
  }),
  issue({
    p: INFRA,
    title: "Security group allows SSH from anywhere",
    severity: "high",
    status: "open",
    tool: "checkov",
    rule_id: "CKV_AWS_24",
    file_path: "terraform/network.tf",
    start_line: 31,
    snippet: 'cidr_blocks = ["0.0.0.0/0"]',
    dueIn: 4 * DAY,
    description: "Port 22 is open to 0.0.0.0/0.",
    remediation: "Restrict ingress to your VPN or bastion CIDR.",
  }),
  issue({
    p: WEB,
    title: "JWT signature not verified in admin middleware",
    severity: "high",
    status: "open",
    tool: "opengrep",
    rule_id: "go.jwt.unverified",
    file_path: "internal/http/admin.go",
    start_line: 57,
    snippet: "token, _, _ := new(jwt.Parser).ParseUnverified(raw, claims)",
    dueIn: 7 * DAY,
    cwe: ["CWE-347"],
    description: "The token is parsed without checking its signature.",
    remediation: "Use jwt.Parse with a key function that pins the algorithm and key.",
  }),
  issue({
    p: PAY,
    title: "lodash: prototype pollution in zipObjectDeep",
    severity: "high",
    status: "assigned",
    tool: "trivy",
    rule_id: "CVE-2020-8203",
    pkg: ["lodash", "4.17.15", "4.17.21"],
    assignee: users.bao,
    dueIn: 10 * DAY,
    cve: ["CVE-2020-8203"],
    description: "Prototype pollution in lodash before 4.17.20.",
    remediation: "Upgrade lodash to 4.17.21.",
  }),
  ...Array.from({ length: 9 }, (_, i) =>
    issue({
      p: i % 2 ? INFRA : WEB,
      title: i % 2 ? `S3 bucket without access logging (${i})` : `Missing CSRF protection on form handler ${i}`,
      severity: i % 3 === 0 ? "low" : "medium",
      status: i === 4 ? "fixed" : "open",
      tool: i % 2 ? "checkov" : "opengrep",
      rule_id: i % 2 ? "CKV_AWS_18" : "go.http.csrf",
      file_path: i % 2 ? `terraform/s3_${i}.tf` : `internal/http/form_${i}.go`,
      start_line: 10 + i,
      snippet: i % 2 ? 'resource "aws_s3_bucket" "logs" {' : "mux.HandleFunc(\"/form\", submit)",
      dueIn: (20 + i * 9) * DAY,
      description: "Example finding for the mock mode.",
      remediation: "Example remediation for the mock mode.",
    }),
  ),
];

export const events: Record<string, IssueEvent[]> = {};
export const comments: Record<string, Comment[]> = {};
for (const i of issues) {
  events[i.id] = [
    { id: uuid(), type: "seen_again", actor: null, from_value: null, to_value: null, note: null, created_at: ago(2 * H) },
    ...(i.assignee
      ? [{ id: uuid(), type: "assigned" as const, actor: users.linh, from_value: null, to_value: i.assignee.display_name, note: null, created_at: ago(6 * DAY) }]
      : []),
    { id: uuid(), type: "created", actor: null, from_value: null, to_value: "open", note: null, created_at: ago(7 * DAY) },
  ];
  comments[i.id] = [];
}
comments[issues[0]!.id] = [
  { id: uuid(), author: users.minh, body: "Key is rotated in IAM. Removing the file from the repo in the next release.", created_at: ago(DAY), edited_at: null },
];
events[issues[0]!.id]!.unshift({ id: uuid(), type: "commented", actor: users.minh, from_value: null, to_value: null, note: null, created_at: ago(DAY) });

export const exceptions: ExceptionRequest[] = [
  {
    id: uuid(),
    issue: { id: issues[5]!.id, key: issues[5]!.key, title: "Outdated TLS config in test harness", severity: "high", status: "assigned" },
    type: "risk_accepted",
    reason:
      "The harness only talks to a local mock server and never ships. We will remove it when the integration suite moves to testcontainers next quarter.",
    status: "pending",
    requested_by: users.an,
    decided_by: null,
    decision_note: null,
    expires_at: ahead(97 * DAY),
    decided_at: null,
    created_at: ago(2 * DAY),
  },
  {
    id: uuid(),
    issue: { id: issues[4]!.id, key: issues[4]!.key, title: issues[4]!.title, severity: "high", status: "open" },
    type: "false_positive",
    reason: "The parser output is only used for logging the key ID; verification happens in the gateway before this runs.",
    status: "pending",
    requested_by: users.linh,
    decided_by: null,
    decision_note: null,
    expires_at: null,
    decided_at: null,
    created_at: ago(DAY),
  },
  {
    id: uuid(),
    issue: { id: issues[7]!.id, key: issues[7]!.key, title: issues[7]!.title, severity: "medium", status: "risk_accepted" },
    type: "risk_accepted",
    reason: "Bucket only holds public marketing assets; logging is enabled at the CDN instead.",
    status: "approved",
    requested_by: users.bao,
    decided_by: users.linh,
    decision_note: "OK until the CDN migration.",
    expires_at: ahead(10 * DAY),
    decided_at: ago(3 * DAY),
    created_at: ago(5 * DAY),
  },
];
issues[5]!.pending_exception_id = exceptions[0]!.id;
issues[4]!.pending_exception_id = exceptions[1]!.id;

export const audit: AuditEntry[] = [
  { id: uuid(), actor: users.minh, action: "issue.transitioned", target_type: "issue", target_id: issues[0]!.id, ip: "10.20.4.17", data: { issue_key: issues[0]!.key, from: "open", to: "assigned", version: 2 }, created_at: ago(40 * 60_000) },
  { id: uuid(), actor: users.linh, action: "exception.decided", target_type: "exception", target_id: exceptions[2]!.id, ip: "10.20.4.9", data: { issue_key: issues[7]!.key, decision: "approve", type: "risk_accepted", expires_at: exceptions[2]!.expires_at }, created_at: ago(3 * DAY) },
  { id: uuid(), actor: users.minh, action: "scan.started", target_type: "scan", target_id: scans[0]!.id, ip: "10.20.4.17", data: { project_key: "WEB", file_name: scans[0]!.file_name }, created_at: ago(2 * H) },
  { id: uuid(), actor: users.minh, action: "scan.created", target_type: "scan", target_id: scans[0]!.id, ip: "10.20.4.17", data: { project_key: "WEB", file_name: scans[0]!.file_name, file_size: scans[0]!.file_size }, created_at: ago(2 * H + 60_000) },
  { id: uuid(), actor: users.linh, action: "issue.assigned", target_type: "issue", target_id: issues[2]!.id, ip: "10.20.4.9", data: { count: 3, assignee_name: "An Nguyen" }, created_at: ago(DAY + 2 * H) },
  { id: uuid(), actor: users.bao, action: "exception.requested", target_type: "issue", target_id: issues[7]!.id, ip: "2001:db8::4f", data: { issue_key: issues[7]!.key, type: "risk_accepted" }, created_at: ago(5 * DAY) },
  { id: uuid(), actor: users.huy, action: "member.role_changed", target_type: "user", target_id: users.bao.id, ip: "10.20.4.2", data: { member_name: "Bao Le", from: "member", to: "security_lead" }, created_at: ago(6 * DAY) },
  { id: uuid(), actor: null, action: "issue.transitioned", target_type: "issue", target_id: issues[10]!.id, ip: null, data: { issue_key: issues[10]!.key, from: "open", to: "fixed" }, created_at: ago(7 * DAY) },
  { id: uuid(), actor: users.huy, action: "project.created", target_type: "project", target_id: PAY.id, ip: "10.20.4.2", data: { project_key: "PAY", name: "Payments API" }, created_at: ago(40 * DAY) },
];
