// Dev-only fixtures for VITE_MOCK=1 (never in a production build: see api/client.ts).
// Shaped exactly like the API contract. Names, numbers and files are examples. Snippets are
// already masked, as the API sends them; nothing here is a real or real-looking secret.
import { NOTIFICATION_TYPES } from "../types";
import type {
  ApiToken,
  AssignRule,
  AuditEntry,
  Comment,
  ExceptionRequest,
  Issue,
  IssueEvent,
  Me,
  Metrics,
  MetricsDays,
  Notification,
  NotificationType,
  Org,
  OrgMember,
  OrgRole,
  Project,
  ProjectMember,
  Scan,
  Severity,
  SignInSettings,
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
/** An org where the caller is an org admin and two-factor sign-in is required (v0.2 MFA rule). */
export const ORG3_ID = uuid();

const PARAMS = new URLSearchParams(typeof window !== "undefined" ? window.location.search : "");
/** `?mock_bulk=1` adds hundreds of tokens and notifications, to check long lists. */
const BULK = PARAMS.get("mock_bulk") === "1";
/** `?mock_role=org_admin` (or member) changes the caller's role in Acme Engineering, e.g. to edit
 *  the sign-in policy, which only org admins may. Default: security lead. */
const ROLE_PARAM = PARAMS.get("mock_role");
const ENG_ROLE: OrgRole = ROLE_PARAM === "org_admin" || ROLE_PARAM === "member" ? ROLE_PARAM : "security_lead";
/** `?mock_keys=error` or `?mock_keys=not_loaded` shows the other identity-provider key states. */
const KEYS_PARAM = PARAMS.get("mock_keys");

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
  // The mock server behaves like `oidc.require_mfa_roles=["org_admin"]` with a session signed
  // in without a second factor: blocked in Acme Security (org admin), fine elsewhere.
  mfa: false,
  orgs: [
    { id: ORG_ID, name: "Acme Engineering", role: ENG_ROLE },
    { id: ORG2_ID, name: "Acme Labs", role: "member" },
    { id: ORG3_ID, name: "Acme Security", role: "org_admin" },
  ],
  limits: { upload_max_mb: 200, unzip_max_mb: 1024, unzip_max_files: 100000, scan_timeout_minutes: 30, scans_per_hour: 20 },
  mfa_required_orgs: [ORG3_ID],
};

export const org: Org = {
  id: ORG_ID,
  name: "Acme Engineering",
  sla_days: { critical: 7, high: 30, medium: 90, low: 180 },
  my_role: ENG_ROLE,
};

/** Acme Labs: the caller is a plain member there, so policy is read-only. */
export const org2: Org = {
  id: ORG2_ID,
  name: "Acme Labs",
  sla_days: { critical: 3, high: 14, medium: 60, low: 120 },
  my_role: "member",
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
    archived_at: null,
  };
}

export const projects: Project[] = [
  project("WEB", "Web storefront", "owner", "Customer-facing shop: Go API and React front end."),
  project("PAY", "Payments API", "developer", null),
  project("INFRA", "Terraform modules", null, "Shared infrastructure as code."),
  project("MOB", "Mobile app", "viewer", null),
  { ...project("LEG", "Legacy portal", "owner", "The old customer portal, replaced by WEB."), archived_at: ago(20 * DAY) },
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
  [projects[4]!.id]: [{ user: users.linh, role: "owner" }],
};

export const orgMembers: OrgMember[] = [
  { user: { ...users.linh, is_active: true }, role: ENG_ROLE, mfa: true, projects: [] },
  { user: { ...users.huy, is_active: true }, role: "org_admin", mfa: true, projects: [] },
  { user: { ...users.minh, is_active: true }, role: "member", mfa: true, projects: [] },
  { user: { ...users.an, is_active: true }, role: "member", mfa: false, projects: [] },
  { user: { ...users.bao, is_active: false }, role: "member", mfa: null, projects: [] },
  { user: { ...users.quynh, is_active: true }, role: "member", mfa: true, projects: [] },
];

function signInSettings(policy: SignInSettings["policy"]): SignInSettings {
  const instance: OrgRole[] = ["org_admin", "security_lead"];
  const keys: SignInSettings["keys"] =
    KEYS_PARAM === "error"
      ? { status: "error", count: 2, fetched_at: ago(3 * H), error: "unreachable" }
      : KEYS_PARAM === "not_loaded"
        ? { status: "not_loaded", count: 0, fetched_at: null, error: null }
        : { status: "ok", count: 2, fetched_at: ago(7 * 60_000), error: null };
  return {
    provider: {
      issuer: "https://id.acme.example/realms/warden",
      audience: "warden-api",
      algorithms: ["RS256"],
      keys_url: null,
      console_url: "https://id.acme.example/admin/warden/console/",
    },
    keys,
    mfa: {
      amr: ["otp", "mfa", "hwk", "webauthn"],
      acr: [],
      // Like `oidc.require_mfa_roles=["org_admin","security_lead"]`. The mock doesn't apply it to
      // the caller (me.mfa_required_orgs decides who is blocked), so the screens stay usable.
      instance_roles: instance,
      org_roles: policy.mfa_roles,
      effective_roles: (["org_admin", "security_lead", "member"] as OrgRole[]).filter((r) => instance.includes(r) || policy.mfa_roles.includes(r)),
    },
    policy,
  };
}

/** GET/PUT …/sign-in(-policy) state per org; the server mock rebuilds it on every save. */
export const signIn: Record<string, SignInSettings> = {
  [ORG_ID]: signInSettings({ mfa_roles: [], allowed_email_domains: ["acme.example"] }),
  [ORG2_ID]: signInSettings({ mfa_roles: [], allowed_email_domains: [] }),
};

export function rebuildSignIn(orgId: string, policy: SignInSettings["policy"]): SignInSettings {
  const next = signInSettings(policy);
  signIn[orgId] = next;
  return next;
}

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
    via_token: null,
    ...partial,
  };
}

export const scans: Scan[] = [
  scan(
    WEB,
    {
      file_name: "storefront-release-2.3.zip",
      stats: { new: 4, fixed: 7, reopened: 1, total: 31 },
      created_by: users.linh,
      via_token: { id: "00000000-0000-4000-8000-00000000f001", name: "GitHub Actions (main)", prefix: "k7m2q4xa" },
    },
    2 * H,
  ),
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
  scan(projects[4]!, { file_name: "legacy-portal-final.zip", stats: { new: 0, fixed: 3, reopened: 0, total: 9 } }, 24 * DAY),
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

// ---- v0.2 fixtures ----

/** Deterministic pseudo-random numbers (mulberry32), so mock data is the same on every load. */
export function seeded(seed: number): () => number {
  let a = seed >>> 0;
  return () => {
    a = (a + 0x6d2b79f5) >>> 0;
    let t = a;
    t = Math.imul(t ^ (t >>> 15), t | 1);
    t ^= t + Math.imul(t ^ (t >>> 7), t | 61);
    return ((t ^ (t >>> 14)) >>> 0) / 4294967296;
  };
}

const B32 = "abcdefghijklmnopqrstuvwxyz234567";
const tokenRand = seeded(2026);
/** Lowercase base32 from the seeded generator. Mock token secrets are built with this at
 *  runtime; no token-shaped string is committed (CLAUDE.md). */
export function base32(n: number, rand: () => number = tokenRand): string {
  let out = "";
  for (let i = 0; i < n; i++) out += B32[Math.floor(rand() * 32)];
  return out;
}

function token(t: Partial<ApiToken> & Pick<ApiToken, "name" | "prefix">): ApiToken {
  return {
    id: uuid(),
    scopes: ["scan:write"],
    created_by: users.linh,
    created_at: ago(30 * DAY),
    expires_at: ahead(60 * DAY),
    last_used_at: null,
    revoked_at: null,
    ...t,
  };
}

export const tokens: Record<string, ApiToken[]> = {
  [WEB.id]: [
    token({ id: "00000000-0000-4000-8000-00000000f001", name: "GitHub Actions (main)", prefix: "k7m2q4xa", last_used_at: ago(2 * H), created_at: ago(12 * DAY), expires_at: ahead(78 * DAY) }),
    token({ name: "Release pipeline", prefix: "p3rt6vbn", scopes: ["scan:write", "issues:read"], created_by: users.minh, created_at: ago(3 * DAY), expires_at: ahead(362 * DAY) }),
    token({ name: "Nightly scan", prefix: "f6ny3sle", created_at: ago(95 * DAY), expires_at: ago(5 * DAY), last_used_at: ago(6 * DAY) }),
    token({ name: "Jenkins (old)", prefix: "j2hd5wcz", last_used_at: ago(16 * DAY), created_at: ago(120 * DAY), expires_at: ahead(5 * DAY), revoked_at: ago(14 * DAY) }),
  ],
  [PAY.id]: [token({ name: "GitLab CI", prefix: "m4qz7tdk", created_by: users.an, last_used_at: ago(DAY) })],
};
if (BULK) {
  const list = tokens[WEB.id]!;
  for (let i = 0; i < 240; i++) {
    list.push(
      token({
        name: `Service pipeline ${i + 1} for the monorepo build matrix`,
        prefix: base32(8),
        created_at: ago((i + 1) * H),
        last_used_at: i % 3 ? ago(i * 60_000) : null,
        revoked_at: i % 7 === 0 ? ago(i * 60_000) : null,
      }),
    );
  }
}

export const assignRules: Record<string, AssignRule[]> = {
  [WEB.id]: [
    { match: { path_glob: "internal/payments/**" }, assignee_id: users.an.id },
    { match: { tool: "gitleaks" }, assignee_id: users.minh.id },
    { match: { path_glob: "deploy/**", severity_at_least: "high" }, assignee_id: users.linh.id },
  ],
};

const notifRand = seeded(41);
function notification(
  type: NotificationType,
  title: string,
  link: string,
  actor: UserRef | null,
  createdAgo: number,
  read: boolean,
  orgId = ORG_ID,
): Notification {
  return { id: uuid(), org_id: orgId, type, title, link, actor, read_at: read ? ago(createdAgo - 60_000) : null, created_at: ago(createdAgo) };
}
const issueLink = (i: Issue) => `/orgs/${ORG_ID}/issues/${i.id}`;

export const notifications: Notification[] = [
  notification("issue.assigned", `${issues[1]!.key} assigned to you`, issueLink(issues[1]!), users.minh, 12 * 60_000, false),
  notification("exception.requested", `${issues[5]!.key}: exception requested (risk accepted)`, `/orgs/${ORG_ID}/exceptions?id=${exceptions[0]!.id}`, users.an, 2 * H, false),
  notification("scan.finished", "Scan of storefront-release-2.3.zip finished: 4 new, 7 fixed", `/orgs/${ORG_ID}/projects/${WEB.id}/scans?scan=${scans[0]!.id}`, null, 2 * H + 5 * 60_000, false),
  notification("sla.overdue", "3 of your issues are past their SLA", `/orgs/${ORG_ID}/issues?assignee=me&past_sla=true`, null, 9 * H, true),
  notification("issue.reopened", `${issues[1]!.key} reopened by a scan`, issueLink(issues[1]!), null, DAY + H, true),
  notification("exception.decided", `${issues[7]!.key}: your exception request was approved`, `/orgs/${ORG_ID}/exceptions?tab=approved&id=${exceptions[2]!.id}`, users.huy, 3 * DAY, true),
  notification("sla.due_soon", "2 of your issues are due within 3 days", `/orgs/${ORG_ID}/issues?assignee=me`, null, 3 * DAY + 2 * H, true),
  notification("issue.assigned", "LAB-7 assigned to you", `/orgs/${ORG2_ID}/issues`, users.huy, 5 * DAY, true, ORG2_ID),
];
if (BULK) {
  for (let i = 0; i < 300; i++) {
    const t = NOTIFICATION_TYPES[Math.floor(notifRand() * NOTIFICATION_TYPES.length)]!;
    notifications.push(notification(t, `WEB-${100 + i} assigned to you`, issueLink(issues[i % issues.length]!), users.minh, (6 + i) * DAY, i % 4 !== 0));
  }
}

/** Email preference per type; missing = the default (on, except scan.finished). */
export const notificationPrefs: Partial<Record<NotificationType, boolean>> = { "sla.due_soon": false };

const isoDate = (d: Date) => d.toISOString().slice(0, 10);

/** Metrics shaped like GET /orgs/{org}/metrics: a slow downward trend with weekly noise,
 *  scaled per project. Deterministic for a given (days, project, day of generation). */
export function metrics(days: MetricsDays, projectId: string | null): Metrics {
  const idx = projectId ? projects.findIndex((p) => p.id === projectId) : -1;
  const scale = idx < 0 ? 1 : ([0.55, 0.25, 0.15, 0.05, 0.02][idx] ?? 0.1);
  const rand = seeded(idx + 7);
  const today = new Date(now());
  today.setUTCHours(0, 0, 0, 0);
  const open_by_day: Metrics["open_by_day"] = [];
  const new_by_day: Metrics["new_by_day"] = [];
  const fixed_by_day: Metrics["fixed_by_day"] = [];
  const total = 180;
  // Open issues follow from what was found and fixed: open(t) = open(t-1) + new − fixed, split
  // by severity shares that drift towards fewer Critical and High issues.
  let open = 210 * scale;
  for (let i = total - 1; i >= 0; i--) {
    const d = new Date(today.getTime() - i * DAY);
    const t = (total - i) / total;
    const monday = d.getUTCDay() === 1 ? 1 : 0;
    const add = Math.round((rand() * 5 + monday * 8) * scale);
    const fix = Math.round((rand() * 5 + 1.6 + t * 0.8) * scale);
    open = Math.max(0, open + add - fix);
    const share = { critical: 0.06 - 0.03 * t, high: 0.22 - 0.06 * t, medium: 0.42, low: 0 };
    share.low = 1 - share.critical - share.high - share.medium;
    if (i < days) {
      const date = isoDate(d);
      open_by_day.push({
        date,
        critical: Math.round(open * share.critical),
        high: Math.round(open * share.high),
        medium: Math.round(open * share.medium),
        low: Math.round(open * share.low),
      });
      new_by_day.push({ date, count: add });
      fixed_by_day.push({ date, count: fix });
    }
  }
  const fixedTotal = fixed_by_day.reduce((n, d) => n + d.count, 0);
  const late = Math.round(fixedTotal * 0.14);
  return {
    days,
    open_by_day,
    mttr_hours: idx === 3 ? { critical: null, high: null, medium: 410, low: null } : { critical: 52, high: 190, medium: 610, low: 1340 },
    sla: { fixed_in_time: fixedTotal - late, fixed_late: late, open_overdue: Math.round(11 * scale) },
    new_by_day,
    fixed_by_day,
  };
}
