// Dev-only mock API for VITE_MOCK=1 (`npm run dev:mock`). It answers like the contract, with
// in-memory state, so the UI can be clicked through without the backend. Loaded by a dynamic
// import behind `import.meta.env.DEV`, so production builds never include it.
//
// Try: append ?mock_error=CODE to any page URL (e.g. VERSION_CONFLICT, RATE_LIMITED, NOT_FOUND)
// to make the next write fail with that code.
import { ACTIVE_STATUSES, SEVERITIES } from "../types";
import type { ExceptionRequest, Issue, IssueStatus, Project, Scan, SeverityCounts } from "../types";
import * as db from "./fixtures";

const LATENCY = import.meta.env.MODE === "test" ? 0 : 250;
const PAGE = 50;

type Handler = (m: RegExpMatchArray, url: URL, body: unknown) => unknown;
class Fail {
  constructor(
    readonly status: number,
    readonly code: string,
    readonly fields?: Record<string, string>,
  ) {}
}

const NOT_FOUND = () => new Fail(404, "NOT_FOUND");

function envelope(status: number, data: unknown, error: unknown, extra: Record<string, string> = {}): Response {
  if (status === 204) return new Response(null, { status });
  return new Response(JSON.stringify({ data, error, meta: { request_id: `mock-${Math.random().toString(36).slice(2, 10)}` } }), {
    status,
    headers: { "Content-Type": "application/json", ...extra },
  });
}

function page<T extends { id: string }>(all: T[], url: URL) {
  const limit = Math.min(Number(url.searchParams.get("limit")) || PAGE, 200);
  const cursor = url.searchParams.get("cursor");
  const start = cursor ? Number(cursor) : 0;
  const items = all.slice(start, start + limit);
  return { items, next_cursor: start + limit < all.length ? String(start + limit) : null };
}

const ACTIVE: IssueStatus[] = ACTIVE_STATUSES;

function counts(list: Issue[]): SeverityCounts {
  const c: SeverityCounts = { critical: 0, high: 0, medium: 0, low: 0, info: 0 };
  for (const i of list) c[i.severity] += 1;
  return c;
}

function projectView(p: Project): Project {
  const open = db.issues.filter((i) => i.project_id === p.id && ACTIVE.includes(i.status));
  const last = db.scans.filter((s) => s.project_id === p.id).sort((a, b) => b.created_at.localeCompare(a.created_at))[0];
  return {
    ...p,
    open_by_severity: counts(open),
    past_sla: open.filter((i) => i.past_sla).length,
    last_scan: last ? { id: last.id, status: last.status, created_at: last.created_at, finished_at: last.finished_at } : null,
  };
}

// The caller is a security lead: mirror issuestate + rbac for what they may do.
function issueView(i: Issue): Issue {
  const mine = i.assignee?.id === db.me.id;
  const t: IssueStatus[] = [];
  if (i.status === "open") t.push("assigned");
  if (i.status === "assigned") t.push("open", ...(mine ? (["in_progress"] as IssueStatus[]) : []));
  if (i.status === "reopened") t.push("assigned", ...(mine ? (["in_progress"] as IssueStatus[]) : []));
  if (i.status === "in_progress" && mine) t.push("fixed");
  if (i.status === "fixed") t.push("verified");
  if (i.status === "false_positive") t.push("open");
  return {
    ...i,
    allowed_transitions: t,
    can_assign: true,
    can_request_exception: ACTIVE.includes(i.status) && !i.pending_exception_id,
  };
}

/** Moves a started scan along: queued → running → each scanner finishes a few seconds apart. */
function advance(s: Scan): Scan {
  const startedAt = (s as Scan & { _t?: number })._t;
  if (startedAt === undefined || !["queued", "running"].includes(s.status)) return s;
  const elapsed = db.now() - startedAt;
  if (elapsed < 3000) return s;
  s.status = "running";
  s.started_at ??= new Date(startedAt + 3000).toISOString();
  const runs = s.tool_runs ?? [];
  runs.forEach((r, idx) => {
    const doneAt = 3000 + (idx + 1) * 3500;
    if (elapsed >= doneAt) {
      r.status = r.tool === "trivy" && s.file_name.includes("timeout") ? "timeout" : "succeeded";
      r.findings_count = r.status === "succeeded" ? (idx * 3 + 1) % 7 : null;
      r.duration_ms = 3500;
    } else if (elapsed >= doneAt - 3500) r.status = "running";
  });
  if (runs.every((r) => r.status !== "queued" && r.status !== "running")) {
    s.status = runs.some((r) => r.status !== "succeeded") ? "partial" : "completed";
    s.finished_at = new Date().toISOString();
    s.stats = { new: 2, fixed: 1, reopened: 0, total: 12 };
    if (s.file_name.includes("traversal")) {
      s.status = "failed";
      s.error_code = "ZIP_PATH_TRAVERSAL";
      s.tool_runs = [];
    }
  }
  return s;
}

function findIssue(id: string): Issue {
  const i = db.issues.find((x) => x.id === id);
  if (!i) throw NOT_FOUND();
  return i;
}

function findProject(id: string): Project {
  const p = db.projects.find((x) => x.id === id);
  if (!p) throw NOT_FOUND();
  return p;
}

function memberUser(userId: string) {
  const m = db.orgMembers.find((x) => x.user.id === userId);
  if (!m) throw new Fail(422, "VALIDATION_FAILED", { user_id: "not an org member" });
  return m;
}

function audit(action: string, target_type: string, target_id: string, data: unknown) {
  db.audit.unshift({ id: db.uuid(), actor: { id: db.me.id, email: db.me.email, display_name: db.me.name ?? db.me.email }, action, target_type, target_id, ip: "127.0.0.1", data, created_at: new Date().toISOString() });
}

const O = "/orgs/([^/]+)";
const routes: [string, RegExp, Handler][] = [
  ["GET", /^\/me$/, () => db.me],
  ["GET", new RegExp(`^${O}$`), (m) => (m[1] === db.ORG_ID ? db.org : (() => { throw NOT_FOUND(); })())],
  [
    "GET",
    new RegExp(`^${O}/summary$`),
    () => {
      const open = db.issues.filter((i) => ACTIVE.includes(i.status));
      return {
        open_issues: open.length,
        critical_high_open: open.filter((i) => i.severity === "critical" || i.severity === "high").length,
        past_sla: open.filter((i) => i.past_sla).length,
        exceptions_pending: db.exceptions.filter((e) => e.status === "pending").length,
      };
    },
  ],
  [
    "GET",
    new RegExp(`^${O}/members$`),
    () => ({
      items: db.orgMembers.map((m) => ({
        ...m,
        projects: Object.entries(db.projectMembers).flatMap(([pid, list]) =>
          list.filter((x) => x.user.id === m.user.id).map((x) => ({ id: pid, key: findProject(pid).key, role: x.role })),
        ),
      })),
    }),
  ],
  [
    "POST",
    new RegExp(`^${O}/members$`),
    (_m, _u, body) => {
      const b = body as { email: string; role: "member" };
      if (!b.email.endsWith("@acme.example")) throw new Fail(404, "USER_NOT_FOUND");
      if (db.orgMembers.some((x) => x.user.email === b.email)) throw new Fail(409, "CONFLICT");
      const user = { id: db.uuid(), email: b.email, display_name: b.email.split("@")[0]!, is_active: true };
      const m = { user, role: b.role, mfa: null, projects: [] };
      db.orgMembers.push(m);
      audit("member.added", "user", user.id, { email: b.email, role: b.role });
      return [201, m];
    },
  ],
  [
    "PATCH",
    new RegExp(`^${O}/members/([^/]+)$`),
    (m, _u, body) => {
      const mem = memberUser(m[2]!);
      const role = (body as { role: typeof mem.role }).role;
      if (mem.role === "org_admin" && role !== "org_admin" && db.orgMembers.filter((x) => x.role === "org_admin").length === 1) throw new Fail(409, "CONFLICT");
      audit("member.role_changed", "user", mem.user.id, { member_name: mem.user.display_name, from: mem.role, to: role });
      mem.role = role;
      return mem;
    },
  ],
  [
    "DELETE",
    new RegExp(`^${O}/members/([^/]+)$`),
    (m) => {
      const mem = memberUser(m[2]!);
      if (mem.role === "org_admin" && db.orgMembers.filter((x) => x.role === "org_admin").length === 1) throw new Fail(409, "CONFLICT");
      db.orgMembers.splice(db.orgMembers.indexOf(mem), 1);
      for (const list of Object.values(db.projectMembers)) {
        const idx = list.findIndex((x) => x.user.id === mem.user.id);
        if (idx >= 0) list.splice(idx, 1);
      }
      return [204, null];
    },
  ],
  ["GET", new RegExp(`^${O}/projects$`), () => ({ items: db.projects.map(projectView) })],
  [
    "POST",
    new RegExp(`^${O}/projects$`),
    (_m, _u, body) => {
      const b = body as { key: string; name: string; description?: string; default_tools?: Project["default_tools"] };
      if (!/^[A-Z][A-Z0-9]{1,9}$/.test(b.key)) throw new Fail(422, "VALIDATION_FAILED", { key: "must match ^[A-Z][A-Z0-9]{1,9}$" });
      if (db.projects.some((p) => p.key === b.key)) throw new Fail(409, "CONFLICT");
      const p: Project = {
        id: db.uuid(),
        key: b.key,
        name: b.name,
        description: b.description ?? null,
        default_tools: b.default_tools ?? ["gitleaks", "opengrep", "trivy", "checkov"],
        my_role: null,
        open_by_severity: { critical: 0, high: 0, medium: 0, low: 0, info: 0 },
        past_sla: 0,
        last_scan: null,
        created_at: new Date().toISOString(),
      };
      db.projects.push(p);
      db.projectMembers[p.id] = [];
      audit("project.created", "project", p.id, { project_key: p.key, name: p.name });
      return [201, projectView(p)];
    },
  ],
  ["GET", new RegExp(`^${O}/projects/([^/]+)$`), (m) => projectView(findProject(m[2]!))],
  ["GET", new RegExp(`^${O}/projects/([^/]+)/members$`), (m) => ({ items: db.projectMembers[findProject(m[2]!).id] ?? [] })],
  [
    "PUT",
    new RegExp(`^${O}/projects/([^/]+)/members/([^/]+)$`),
    (m, _u, body) => {
      const p = findProject(m[2]!);
      const mem = memberUser(m[3]!);
      const role = (body as { role: "owner" | "developer" | "viewer" }).role;
      const list = (db.projectMembers[p.id] ??= []);
      const existing = list.find((x) => x.user.id === mem.user.id);
      const { is_active: _ignored, ...user } = mem.user;
      if (existing) existing.role = role;
      else list.push({ user, role });
      audit("project_member.set", "project", p.id, { project_key: p.key, member_name: user.display_name, role });
      return { user, role };
    },
  ],
  [
    "DELETE",
    new RegExp(`^${O}/projects/([^/]+)/members/([^/]+)$`),
    (m) => {
      const list = db.projectMembers[findProject(m[2]!).id] ?? [];
      const idx = list.findIndex((x) => x.user.id === m[3]);
      if (idx >= 0) list.splice(idx, 1);
      return [204, null];
    },
  ],
  [
    "GET",
    new RegExp(`^${O}/projects/([^/]+)/scans$`),
    (m, url) => {
      const list = db.scans
        .filter((s) => s.project_id === findProject(m[2]!).id)
        .map(advance)
        .sort((a, b) => b.created_at.localeCompare(a.created_at))
        .map(({ tool_runs: _omit, ...s }) => ({ ...s, id: s.id }));
      return page(list, url);
    },
  ],
  [
    "POST",
    new RegExp(`^${O}/projects/([^/]+)/scans$`),
    (m, _u, body) => {
      const p = findProject(m[2]!);
      const b = body as { file_name: string; file_size: number; sha256: string; tools?: Scan["tools"] };
      if (b.file_name.includes("ratelimit")) throw new Fail(429, "RATE_LIMITED");
      if (!/^[0-9a-f]{64}$/.test(b.sha256)) throw new Fail(422, "VALIDATION_FAILED", { sha256: "must be 64 hex characters" });
      const tools = b.tools ?? p.default_tools;
      const scan: Scan = {
        id: db.uuid(),
        project_id: p.id,
        status: "pending_upload",
        file_name: b.file_name,
        file_size: b.file_size,
        tools,
        error_code: null,
        stats: { new: 0, fixed: 0, reopened: 0, total: 0 },
        created_by: { id: db.me.id, email: db.me.email, display_name: db.me.name ?? db.me.email },
        created_at: new Date().toISOString(),
        queued_at: null,
        started_at: null,
        finished_at: null,
        tool_runs: tools.map((tool) => ({ tool, tool_version: "mock", status: "queued", findings_count: null, duration_ms: null, error: null })),
      };
      db.scans.unshift(scan);
      audit("scan.created", "scan", scan.id, { project_key: p.key, file_name: scan.file_name, file_size: scan.file_size });
      return [201, { scan, upload: { method: "PUT", url: "https://storage.mock.invalid/upload", headers: { "Content-Type": "application/zip" }, expires_at: new Date(db.now() + 15 * 60_000).toISOString() } }];
    },
  ],
  [
    "POST",
    new RegExp(`^${O}/scans/([^/]+)/start$`),
    (m) => {
      const s = db.scans.find((x) => x.id === m[2]);
      if (!s) throw NOT_FOUND();
      if (s.status === "pending_upload") {
        s.status = "queued";
        s.queued_at = new Date().toISOString();
        (s as Scan & { _t?: number })._t = db.now();
        audit("scan.started", "scan", s.id, { project_key: findProject(s.project_id).key, file_name: s.file_name });
      }
      return s;
    },
  ],
  [
    "POST",
    new RegExp(`^${O}/scans/([^/]+)/cancel$`),
    (m) => {
      const s = db.scans.find((x) => x.id === m[2]);
      if (!s) throw NOT_FOUND();
      advance(s);
      if (!["pending_upload", "queued", "running"].includes(s.status)) throw new Fail(409, "CONFLICT");
      s.status = "cancelled";
      s.finished_at = new Date().toISOString();
      for (const r of s.tool_runs ?? []) if (r.status === "queued" || r.status === "running") r.status = "skipped";
      audit("scan.cancelled", "scan", s.id, { file_name: s.file_name });
      return s;
    },
  ],
  [
    "GET",
    new RegExp(`^${O}/scans/([^/]+)$`),
    (m) => {
      const s = db.scans.find((x) => x.id === m[2]);
      if (!s) throw NOT_FOUND();
      return advance(s);
    },
  ],
  [
    "GET",
    new RegExp(`^${O}/issues$`),
    (_m, url) => {
      const sp = url.searchParams;
      const statuses = sp.getAll("status");
      const want = statuses.length === 0 || statuses.includes("active") ? ACTIVE : (statuses as IssueStatus[]);
      const q = (sp.get("q") ?? "").toLowerCase();
      const base = db.issues.filter(
        (i) =>
          want.includes(i.status) &&
          (!sp.get("project_id") || i.project_id === sp.get("project_id")) &&
          (!sp.get("tool") || i.tool === sp.get("tool")) &&
          (sp.get("past_sla") !== "true" || i.past_sla) &&
          (!sp.get("assignee") ||
            (sp.get("assignee") === "me" ? i.assignee?.id === db.me.id : sp.get("assignee") === "none" ? !i.assignee : i.assignee?.id === sp.get("assignee"))) &&
          (!q || [i.title, i.rule_id, i.file_path ?? "", i.key].some((s) => s.toLowerCase().includes(q))),
      );
      const sev = sp.getAll("severity");
      const filtered = sev.length ? base.filter((i) => sev.includes(i.severity)) : base;
      const sort = sp.get("sort") ?? "due_at";
      const sorted = [...filtered].sort((a, b) =>
        sort === "-severity"
          ? SEVERITIES.indexOf(a.severity) - SEVERITIES.indexOf(b.severity)
          : sort === "-updated_at"
            ? b.updated_at.localeCompare(a.updated_at)
            : (a.due_at ?? "9").localeCompare(b.due_at ?? "9"),
      );
      const { items, next_cursor } = page(sorted, url);
      return { items: items.map(({ id }) => summary(findIssue(id))), next_cursor, counts_by_severity: counts(base) };
    },
  ],
  [
    "POST",
    new RegExp(`^${O}/issues/assign$`),
    (_m, _u, body) => {
      const b = body as { issue_ids: string[]; assignee_id: string };
      const user = memberUser(b.assignee_id).user;
      let updated = 0;
      for (const id of b.issue_ids) {
        const i = findIssue(id);
        if (!["open", "reopened", "assigned", "in_progress"].includes(i.status)) continue;
        if (i.status === "open" || i.status === "reopened") i.status = "assigned";
        i.assignee = { id: user.id, email: user.email, display_name: user.display_name };
        i.version += 1;
        updated += 1;
      }
      audit("issue.assigned", "issue", b.issue_ids[0]!, { count: updated, assignee_name: user.display_name });
      return { updated };
    },
  ],
  ["GET", new RegExp(`^${O}/issues/([^/]+)$`), (m) => issueView(findIssue(m[2]!))],
  [
    "POST",
    new RegExp(`^${O}/issues/([^/]+)/transitions$`),
    (m, _u, body) => {
      const i = findIssue(m[2]!);
      const b = body as { to: IssueStatus; version: number; assignee_id?: string; reason?: string };
      if (b.version !== i.version) throw new Fail(409, "VERSION_CONFLICT");
      if (!issueView(i).allowed_transitions.includes(b.to)) throw new Fail(422, "INVALID_TRANSITION");
      const from = i.status;
      if (b.to === "assigned") {
        if (!b.assignee_id) throw new Fail(422, "VALIDATION_FAILED", { assignee_id: "required" });
        const u = memberUser(b.assignee_id).user;
        i.assignee = { id: u.id, email: u.email, display_name: u.display_name };
      }
      if (b.to === "open" && from === "assigned") i.assignee = null;
      i.status = b.to;
      i.version += 1;
      i.updated_at = new Date().toISOString();
      db.events[i.id]!.unshift({ id: db.uuid(), type: "status_changed", actor: { id: db.me.id, email: db.me.email, display_name: db.me.name ?? "" }, from_value: from, to_value: b.to, note: b.reason ?? null, created_at: i.updated_at });
      audit("issue.transitioned", "issue", i.id, { issue_key: i.key, from, to: b.to, version: i.version });
      return issueView(i);
    },
  ],
  ["GET", new RegExp(`^${O}/issues/([^/]+)/events$`), (m) => ({ items: db.events[findIssue(m[2]!).id] ?? [] })],
  ["GET", new RegExp(`^${O}/issues/([^/]+)/comments$`), (m) => ({ items: db.comments[findIssue(m[2]!).id] ?? [] })],
  [
    "POST",
    new RegExp(`^${O}/issues/([^/]+)/comments$`),
    (m, _u, body) => {
      const i = findIssue(m[2]!);
      const text = (body as { body: string }).body;
      if (!text || text.length > 10000) throw new Fail(422, "VALIDATION_FAILED", { body: "1 to 10,000 characters" });
      const c = { id: db.uuid(), author: { id: db.me.id, email: db.me.email, display_name: db.me.name ?? "" }, body: text, created_at: new Date().toISOString(), edited_at: null };
      db.comments[i.id]!.push(c);
      db.events[i.id]!.unshift({ id: db.uuid(), type: "commented", actor: c.author, from_value: null, to_value: null, note: null, created_at: c.created_at });
      return [201, c];
    },
  ],
  [
    "POST",
    new RegExp(`^${O}/issues/([^/]+)/exceptions$`),
    (m, _u, body) => {
      const i = findIssue(m[2]!);
      const b = body as { type: ExceptionRequest["type"]; reason: string; expires_at?: string };
      if (b.reason.length < 20) throw new Fail(422, "VALIDATION_FAILED", { reason: "at least 20 characters" });
      if (i.pending_exception_id) throw new Fail(409, "CONFLICT");
      if (!ACTIVE.includes(i.status)) throw new Fail(422, "INVALID_TRANSITION");
      const e: ExceptionRequest = {
        id: db.uuid(),
        issue: { id: i.id, key: i.key, title: i.title, severity: i.severity, status: i.status },
        type: b.type,
        reason: b.reason,
        status: "pending",
        requested_by: { id: db.me.id, email: db.me.email, display_name: db.me.name ?? "" },
        decided_by: null,
        decision_note: null,
        expires_at: b.expires_at ?? null,
        decided_at: null,
        created_at: new Date().toISOString(),
      };
      db.exceptions.unshift(e);
      i.pending_exception_id = e.id;
      db.events[i.id]!.unshift({ id: db.uuid(), type: "exception_requested", actor: e.requested_by, from_value: null, to_value: b.type, note: null, created_at: e.created_at });
      audit("exception.requested", "issue", i.id, { issue_key: i.key, type: b.type });
      return [201, e];
    },
  ],
  [
    "GET",
    new RegExp(`^${O}/exceptions$`),
    (_m, url) => {
      const tab = url.searchParams.get("status") ?? "pending";
      const soon = db.now() + 14 * 86_400_000;
      const list =
        tab === "expiring"
          ? db.exceptions.filter((e) => e.status === "approved" && e.type === "risk_accepted" && e.expires_at && Date.parse(e.expires_at) <= soon)
          : db.exceptions.filter((e) => e.status === tab);
      return page(list, url);
    },
  ],
  [
    "POST",
    new RegExp(`^${O}/exceptions/([^/]+)/decision$`),
    (m, _u, body) => {
      const e = db.exceptions.find((x) => x.id === m[2]);
      if (!e) throw NOT_FOUND();
      const b = body as { decision: "approve" | "reject"; note?: string; expires_at?: string };
      if (e.requested_by.id === db.me.id) throw new Fail(403, "FORBIDDEN");
      if (e.status !== "pending") throw new Fail(409, "CONFLICT");
      if (b.decision === "reject" && !b.note) throw new Fail(422, "VALIDATION_FAILED", { note: "required to reject" });
      const i = findIssue(e.issue.id);
      e.status = b.decision === "approve" ? "approved" : "rejected";
      e.decided_by = { id: db.me.id, email: db.me.email, display_name: db.me.name ?? "" };
      e.decided_at = new Date().toISOString();
      e.decision_note = b.note ?? null;
      if (b.expires_at) e.expires_at = b.expires_at;
      i.pending_exception_id = null;
      if (e.status === "approved") {
        i.status = e.type;
        i.version += 1;
      }
      e.issue.status = i.status;
      audit("exception.decided", "exception", e.id, { issue_key: i.key, decision: b.decision, type: e.type, expires_at: e.expires_at });
      return e;
    },
  ],
  [
    "GET",
    new RegExp(`^${O}/audit-log$`),
    (_m, url) => {
      const sp = url.searchParams;
      const actor = sp.get("actor_id");
      const list = db.audit.filter(
        (a) =>
          (!sp.get("action") || a.action === sp.get("action")) &&
          (!actor || (actor === "system" ? a.actor === null : a.actor?.id === actor)) &&
          (!sp.get("from") || a.created_at >= sp.get("from")!) &&
          (!sp.get("to") || a.created_at < sp.get("to")!),
      );
      return page(list, url);
    },
  ],
];

function summary(i: Issue) {
  const { description: _d, remediation: _r, snippet: _s, end_line: _e, cwe: _c, cve: _v, first_seen_scan: _f, last_seen_scan: _l, occurrences: _o, version: _ver, allowed_transitions: _a, can_assign: _ca, can_request_exception: _cr, pending_exception_id: _p, ...rest } = i;
  return rest;
}

function nextForcedError(method: string): string | null {
  if (method === "GET") return null;
  const code = new URLSearchParams(window.location.search).get("mock_error");
  return code && /^[A-Z_]+$/.test(code) ? code : null;
}

const STATUS: Record<string, number> = { VERSION_CONFLICT: 409, CONFLICT: 409, FORBIDDEN: 403, NOT_FOUND: 404, RATE_LIMITED: 429, INVALID_TRANSITION: 422, VALIDATION_FAILED: 422, UNAUTHORIZED: 401 };

export const mockFetch: typeof fetch = async (input, init) => {
  await new Promise((r) => setTimeout(r, LATENCY));
  const url = new URL(String(input), window.location.origin);
  const path = url.pathname.replace(/^\/api\/v1/, "");
  const method = (init?.method ?? "GET").toUpperCase();
  const body = typeof init?.body === "string" ? (JSON.parse(init.body) as unknown) : undefined;

  const forced = nextForcedError(method);
  if (forced) return envelope(STATUS[forced] ?? 500, null, { code: forced, message: "forced by ?mock_error" }, forced === "RATE_LIMITED" ? { "Retry-After": "120" } : {});

  for (const [m, re, handler] of routes) {
    if (m !== method) continue;
    const match = path.match(re);
    if (!match) continue;
    if (match[1] && match[1] !== db.ORG_ID && match[1] !== db.ORG2_ID) return envelope(404, null, { code: "NOT_FOUND", message: "not found" });
    try {
      const out = handler(match, url, body);
      if (Array.isArray(out) && out.length === 2 && typeof out[0] === "number") return envelope(out[0], out[1], null);
      return envelope(200, out, null);
    } catch (e) {
      if (e instanceof Fail) {
        return envelope(e.status, null, { code: e.code, message: e.code.toLowerCase(), ...(e.fields ? { metadata: { fields: e.fields } } : {}) }, e.status === 429 ? { "Retry-After": "300" } : {});
      }
      return envelope(500, null, { code: "INTERNAL", message: "mock error" });
    }
  }
  return envelope(404, null, { code: "NOT_FOUND", message: "no mock route" });
};
