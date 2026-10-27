// Dev-only mock API for VITE_MOCK=1 (`npm run dev:mock`). It answers like the contract, with
// in-memory state, so the UI can be clicked through without the backend. Loaded by a dynamic
// import behind `import.meta.env.DEV`, so production builds never include it.
//
// Try: append ?mock_error=CODE to any page URL (e.g. VERSION_CONFLICT, RATE_LIMITED, NOT_FOUND)
// to make the next write fail with that code.
import { ACTIVE_STATUSES, LICENSE_ACTIONS, LICENSE_CATEGORIES, METRICS_DAYS, NOTIFICATION_TYPES, ORG_ROLES, SEVERITIES, TOOLS } from "../types";
import type {
  ApiToken,
  AssignRule,
  CreateScanBody,
  CreateTokenBody,
  ExceptionRequest,
  Issue,
  IssueStatus,
  LicensePolicy,
  MetricsDays,
  NotificationPref,
  OrgRole,
  Project,
  Scan,
  SeverityCounts,
  UpdatePolicyBody,
} from "../types";
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
    // An SBOM when Trivy finished (the server stores it from the same Trivy run).
    if (runs.some((r) => r.tool === "trivy" && r.status === "succeeded")) {
      s.sbom = { components: s.kind === "image" ? 388 : 176, size: s.kind === "image" ? 1_190_442 : 342_118 };
    }
    // Name a file …traversal….zip, …multiple….tar or …invalid….tar to see a rejection.
    const reject = s.file_name.includes("traversal")
      ? "ZIP_PATH_TRAVERSAL"
      : s.kind === "image" && s.file_name.includes("multiple")
        ? "IMAGE_MULTIPLE"
        : s.kind === "image" && s.file_name.includes("invalid")
          ? "IMAGE_INVALID"
          : null;
    if (reject) {
      s.status = "failed";
      s.error_code = reject;
      s.tool_runs = [];
      s.sbom = null;
    }
  }
  return s;
}

/** The contract's patterns for v0.3 inputs. */
const IMAGE_TARGET = /^[a-z0-9]+(?:[._-][a-z0-9]+)*(?::[0-9]{1,5})?(?:\/[a-z0-9]+(?:(?:[._]|__|-+)[a-z0-9]+)*)*$/;
const SPDX_ID = /^(LicenseRef-)?[A-Za-z0-9][A-Za-z0-9.+-]{0,63}$/;

function validateLicensePolicy(body: unknown): LicensePolicy {
  const b = (body ?? {}) as Record<string, unknown>;
  const fields: Record<string, string> = {};
  for (const k of Object.keys(b)) if (!["categories", "deny", "allow"].includes(k)) fields[k] = "unknown field";
  const cats = b.categories as Record<string, unknown> | undefined;
  if (!cats || typeof cats !== "object") fields.categories = "required";
  else {
    for (const c of LICENSE_CATEGORIES) {
      if (!LICENSE_ACTIONS.includes(cats[c] as never)) fields[`categories.${c}`] = "must be allow, review or block";
    }
    for (const k of Object.keys(cats)) if (!LICENSE_CATEGORIES.includes(k as never)) fields[`categories.${k}`] = "unknown category";
  }
  const lists: Record<"deny" | "allow", string[]> = { deny: [], allow: [] };
  for (const list of ["deny", "allow"] as const) {
    const v = b[list];
    if (!Array.isArray(v)) {
      fields[list] = "required";
      continue;
    }
    if (v.length > 100) fields[list] = "at most 100 licenses";
    const seen = new Set<string>();
    v.forEach((id, i) => {
      if (typeof id !== "string" || !SPDX_ID.test(id)) fields[`${list}[${i}]`] = "must be an SPDX license id";
      else if (seen.has(id.toLowerCase())) fields[`${list}[${i}]`] = "duplicate license";
      else seen.add(id.toLowerCase());
    });
    lists[list] = v.filter((x): x is string => typeof x === "string");
  }
  const overlap = lists.allow.findIndex((a) => lists.deny.some((d) => d.toLowerCase() === a.toLowerCase()));
  if (overlap >= 0 && !fields[`allow[${overlap}]`]) fields[`allow[${overlap}]`] = "also in deny";
  if (Object.keys(fields).length) throw new Fail(422, "VALIDATION_FAILED", fields);
  const categories = Object.fromEntries(LICENSE_CATEGORIES.map((c) => [c, cats![c]])) as LicensePolicy["categories"];
  const enabled = lists.deny.length > 0 || LICENSE_CATEGORIES.some((c) => categories[c] !== "allow");
  return { enabled, categories, deny: lists.deny, allow: lists.allow };
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

function orgOf(id: string | undefined) {
  if (id === db.ORG_ID) return db.org;
  if (id === db.ORG2_ID) return db.org2;
  throw NOT_FOUND();
}

/** The caller's org role from /me (so `?mock_role=` applies to the API too). */
function callerRole(orgId: string): OrgRole | "none" {
  return db.me.orgs.find((o) => o.id === orgId)?.role ?? "none";
}

/** Lowercase DNS name with at least one dot; labels don't start or end with a hyphen. */
const DNS_NAME = /^(?=[a-z0-9.-]{1,253}$)[a-z0-9](?:[a-z0-9-]{0,61}[a-z0-9])?(?:\.[a-z0-9](?:[a-z0-9-]{0,61}[a-z0-9])?)+$/;

const meRef = () => ({ id: db.me.id, email: db.me.email, display_name: db.me.name ?? db.me.email });

/** `manage_project_members` for the caller: security lead in Acme Engineering, else project owner. */
function canManageProject(orgId: string, p: Project): boolean {
  return orgOf(orgId).my_role !== "member" || p.my_role === "owner";
}

function prefsView(): { items: NotificationPref[] } {
  return { items: NOTIFICATION_TYPES.map((type) => ({ type, email: db.notificationPrefs[type] ?? type !== "scan.finished" })) };
}

const GLOB_MAX = 200;

function validateRules(p: Project, items: AssignRule[]): void {
  if (!Array.isArray(items) || items.length > 50) throw new Fail(422, "VALIDATION_FAILED", { items: "at most 50 rules" });
  const members = db.projectMembers[p.id] ?? [];
  items.forEach((r, i) => {
    const m = r.match ?? {};
    if (!m.path_glob && !m.tool && !m.severity_at_least) throw new Fail(422, "VALIDATION_FAILED", { [`items[${i}].match`]: "needs at least one matcher" });
    if (m.path_glob && m.path_glob.length > GLOB_MAX) throw new Fail(422, "VALIDATION_FAILED", { [`items[${i}].match.path_glob`]: "at most 200 characters" });
    if (m.tool && !TOOLS.includes(m.tool)) throw new Fail(422, "VALIDATION_FAILED", { [`items[${i}].match.tool`]: "unknown tool" });
    if (!members.some((x) => x.user.id === r.assignee_id)) throw new Fail(422, "VALIDATION_FAILED", { [`items[${i}].assignee_id`]: "not a project member" });
  });
}

const O = "/orgs/([^/]+)";
const routes: [string, RegExp, Handler][] = [
  ["GET", /^\/me$/, () => db.me],
  // ---- v0.2 notifications (own data only) ----
  [
    "GET",
    /^\/me\/notifications$/,
    (_m, url) => {
      const unread = url.searchParams.get("unread") === "true";
      const list = [...db.notifications].filter((n) => !unread || !n.read_at).sort((a, b) => b.created_at.localeCompare(a.created_at));
      return page(list, url);
    },
  ],
  ["GET", /^\/me\/notifications\/unread-count$/, () => ({ count: db.notifications.filter((n) => !n.read_at).length })],
  [
    "POST",
    /^\/me\/notifications\/read$/,
    (_m, _u, body) => {
      const b = body as { ids?: string[]; all?: boolean };
      const at = new Date().toISOString();
      if (b.all === true) {
        for (const n of db.notifications) n.read_at ??= at;
      } else {
        if (!Array.isArray(b.ids) || b.ids.length < 1 || b.ids.length > 200) throw new Fail(422, "VALIDATION_FAILED", { ids: "1 to 200 ids" });
        for (const n of db.notifications) if (b.ids.includes(n.id)) n.read_at ??= at;
      }
      return [204, null];
    },
  ],
  ["GET", /^\/me\/notification-prefs$/, () => prefsView()],
  [
    "PUT",
    /^\/me\/notification-prefs$/,
    (_m, _u, body) => {
      const items = (body as { items: NotificationPref[] }).items;
      for (const it of items) {
        if (!NOTIFICATION_TYPES.includes(it.type)) throw new Fail(422, "VALIDATION_FAILED", { type: "unknown notification type" });
        db.notificationPrefs[it.type] = it.email;
      }
      return prefsView();
    },
  ],
  ["GET", new RegExp(`^${O}$`), (m) => orgOf(m[1])],
  [
    "PATCH",
    new RegExp(`^${O}$`),
    (m, _u, body) => {
      const o = orgOf(m[1]);
      if (o.my_role !== "security_lead") throw new Fail(403, "FORBIDDEN");
      const b = body as UpdatePolicyBody;
      const fields: Record<string, string> = {};
      for (const k of ["critical", "high", "medium", "low"] as const) {
        const v = b.sla_days?.[k];
        if (!Number.isInteger(v) || v < 1 || v > 365) fields[`sla_days.${k}`] = "1 to 365 days";
      }
      if (Object.keys(fields).length) throw new Fail(422, "VALIDATION_FAILED", fields);
      const from = o.sla_days;
      o.sla_days = { ...b.sla_days };
      audit("org.policy_changed", "org", o.id, { from, to: o.sla_days, recompute_open: !!b.recompute_open });
      return o;
    },
  ],
  [
    "GET",
    new RegExp(`^${O}/metrics$`),
    (_m, url) => {
      const days = Number(url.searchParams.get("days") ?? 30);
      if (!METRICS_DAYS.includes(days as MetricsDays)) throw new Fail(422, "VALIDATION_FAILED", { days: "30, 90 or 180" });
      const pid = url.searchParams.get("project_id");
      if (pid) findProject(pid);
      return db.metrics(days as MetricsDays, pid);
    },
  ],
  [
    "GET",
    new RegExp(`^${O}/issues/counts$`),
    (_m, url) => {
      const pid = url.searchParams.get("project_id");
      const active = db.issues.filter((i) => ACTIVE.includes(i.status) && (!pid || i.project_id === pid));
      return {
        active: active.length,
        mine: active.filter((i) => i.assignee?.id === db.me.id).length,
        past_sla: active.filter((i) => i.past_sla).length,
        secrets: active.filter((i) => i.tool === "gitleaks").length,
        kev: active.filter((i) => i.kev).length,
        licenses: active.filter((i) => i.tool === "trivy" && i.rule_id.startsWith("license:")).length,
      };
    },
  ],
  // ---- v0.3 license policy (any member reads, security lead writes) and vulnerability data ----
  [
    "GET",
    new RegExp(`^${O}/license-policy$`),
    (m) => {
      const p = db.licensePolicies[m[1]!];
      if (!p) throw NOT_FOUND();
      return p;
    },
  ],
  [
    "PUT",
    new RegExp(`^${O}/license-policy$`),
    (m, _u, body) => {
      const orgId = m[1]!;
      if (callerRole(orgId) !== "security_lead") throw new Fail(403, "FORBIDDEN");
      const next = validateLicensePolicy(body);
      const from = db.licensePolicies[orgId];
      db.licensePolicies[orgId] = next;
      if (JSON.stringify(from) !== JSON.stringify(next)) audit("org.license_policy_changed", "org", orgId, { from, to: next });
      return next;
    },
  ],
  ["GET", new RegExp(`^${O}/vuln-data$`), () => db.vulnData()],
  [
    "GET",
    new RegExp(`^${O}/scans/([^/]+)/sbom$`),
    (m) => {
      const s = db.scans.find((x) => x.id === m[2]);
      if (!s || !s.sbom) throw NOT_FOUND();
      return {
        // Never followed in mock mode (there is no object store); shaped like a presigned GET.
        url: `https://storage.mock.invalid/warden/sboms/${m[1]}/${s.id}.cdx.json?X-Amz-Expires=300&X-Amz-Signature=mock`,
        expires_at: new Date(db.now() + 5 * 60_000).toISOString(),
        format: "cyclonedx-json",
        size: s.sbom.size,
        sha256: db.fakeSha256(s.sbom.size),
        components: s.sbom.components,
      };
    },
  ],
  // ---- v0.2 API tokens ----
  [
    "GET",
    new RegExp(`^${O}/projects/([^/]+)/tokens$`),
    (m) => {
      const p = findProject(m[2]!);
      if (!canManageProject(m[1]!, p)) throw NOT_FOUND();
      return { items: [...(db.tokens[p.id] ?? [])].sort((a, b) => b.created_at.localeCompare(a.created_at)) };
    },
  ],
  [
    "POST",
    new RegExp(`^${O}/projects/([^/]+)/tokens$`),
    (m, _u, body) => {
      const p = findProject(m[2]!);
      if (!canManageProject(m[1]!, p)) throw NOT_FOUND();
      // Creating also needs run_scan: the token scans as its creator.
      const role = orgOf(m[1]).my_role;
      if (role !== "security_lead" && p.my_role !== "owner" && p.my_role !== "developer") throw new Fail(403, "FORBIDDEN");
      const b = body as CreateTokenBody;
      const fields: Record<string, string> = {};
      const name = (b.name ?? "").trim();
      if (name.length < 1 || name.length > 80) fields.name = "1 to 80 characters";
      if (!Array.isArray(b.scopes) || b.scopes.length < 1 || b.scopes.some((x) => x !== "scan:write" && x !== "issues:read")) fields.scopes = "at least one of scan:write, issues:read";
      if (!Number.isInteger(b.expires_in_days) || b.expires_in_days < 1 || b.expires_in_days > 365) fields.expires_in_days = "1 to 365 days";
      if (Object.keys(fields).length) throw new Fail(422, "VALIDATION_FAILED", fields);
      const prefix = db.base32(8);
      const t: ApiToken = {
        id: db.uuid(),
        name,
        prefix,
        scopes: b.scopes,
        created_by: meRef(),
        created_at: new Date().toISOString(),
        expires_at: new Date(db.now() + b.expires_in_days * 86_400_000).toISOString(),
        last_used_at: null,
        revoked_at: null,
      };
      (db.tokens[p.id] ??= []).unshift(t);
      audit("token.created", "project", p.id, { project_key: p.key, name, prefix, scopes: b.scopes });
      // Like the server: the secret goes back once and is not kept (the mock keeps nothing).
      // Valid base32 of the right length, but plainly fake, so screenshots never show a
      // real-looking token.
      return [201, { token: t, secret: `wdn_${prefix}_${"mocksecret".repeat(6).slice(0, 52)}` }];
    },
  ],
  [
    "DELETE",
    new RegExp(`^${O}/projects/([^/]+)/tokens/([^/]+)$`),
    (m) => {
      const p = findProject(m[2]!);
      if (!canManageProject(m[1]!, p)) throw NOT_FOUND();
      const t = (db.tokens[p.id] ?? []).find((x) => x.id === m[3]);
      if (!t) throw NOT_FOUND();
      if (!t.revoked_at) {
        t.revoked_at = new Date().toISOString();
        audit("token.revoked", "project", p.id, { project_key: p.key, name: t.name, prefix: t.prefix, scopes: t.scopes });
      }
      return [204, null];
    },
  ],
  // ---- v0.2 auto-assign rules and archiving ----
  ["GET", new RegExp(`^${O}/projects/([^/]+)/assign-rules$`), (m) => ({ items: db.assignRules[findProject(m[2]!).id] ?? [] })],
  [
    "PUT",
    new RegExp(`^${O}/projects/([^/]+)/assign-rules$`),
    (m, _u, body) => {
      const p = findProject(m[2]!);
      if (!canManageProject(m[1]!, p)) throw new Fail(403, "FORBIDDEN");
      const items = (body as { items: AssignRule[] }).items;
      validateRules(p, items);
      db.assignRules[p.id] = items;
      return { items };
    },
  ],
  [
    "POST",
    new RegExp(`^${O}/projects/([^/]+)/(archive|unarchive)$`),
    (m) => {
      const p = findProject(m[2]!);
      if (orgOf(m[1]).my_role === "member") throw new Fail(403, "FORBIDDEN");
      const archive = m[3] === "archive";
      if (archive && !p.archived_at) p.archived_at = new Date().toISOString();
      if (!archive) p.archived_at = null;
      audit(archive ? "project.archived" : "project.unarchived", "project", p.id, { project_key: p.key, name: p.name });
      return projectView(p);
    },
  ],
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
  // ---- Sign-in settings and policy (org admin, security lead read; org admin writes) ----
  [
    "GET",
    new RegExp(`^${O}/sign-in$`),
    (m) => {
      if (!["org_admin", "security_lead"].includes(callerRole(m[1]!))) throw new Fail(403, "FORBIDDEN");
      const s = db.signIn[m[1]!];
      if (!s) throw NOT_FOUND();
      return s;
    },
  ],
  [
    "PUT",
    new RegExp(`^${O}/sign-in-policy$`),
    (m, _u, body) => {
      const orgId = m[1]!;
      const role = callerRole(orgId);
      if (role !== "org_admin") throw new Fail(403, "FORBIDDEN");
      const current = db.signIn[orgId];
      if (!current) throw NOT_FOUND();
      const b = (body ?? {}) as { mfa_roles?: unknown; allowed_email_domains?: unknown };
      const fields: Record<string, string> = {};
      const extra = Object.keys(b).filter((k) => k !== "mfa_roles" && k !== "allowed_email_domains");
      for (const k of extra) fields[k] = "unknown field";
      const roles = b.mfa_roles;
      if (!Array.isArray(roles)) fields.mfa_roles = "required";
      else if (roles.some((r) => !ORG_ROLES.includes(r as OrgRole)) || new Set(roles).size !== roles.length) {
        fields.mfa_roles = "must be distinct values of org_admin, security_lead, member";
      }
      const domains = b.allowed_email_domains;
      if (!Array.isArray(domains)) fields.allowed_email_domains = "required";
      else if (domains.length > 20) fields.allowed_email_domains = "at most 20 domains";
      else {
        const seen = new Set<string>();
        domains.forEach((raw, i) => {
          const d = typeof raw === "string" ? raw.toLowerCase() : "";
          if (!DNS_NAME.test(d) || d.length > 253) fields[`allowed_email_domains[${i}]`] = "must be a DNS name such as example.com (no wildcard)";
          else if (seen.has(d)) fields[`allowed_email_domains[${i}]`] = "duplicate domain";
          seen.add(d);
        });
      }
      if (Object.keys(fields).length) throw new Fail(422, "VALIDATION_FAILED", fields);
      const policy = {
        mfa_roles: ORG_ROLES.filter((r) => (roles as OrgRole[]).includes(r)),
        allowed_email_domains: (domains as string[]).map((d) => d.toLowerCase()),
      };
      // Self-lockout guard. The server checks the caller's current sign-in; in the mock, a caller
      // whose role is already required got here with a second factor (else MFA_REQUIRED), so
      // only a role newly required, with me.mfa false, is refused. Or try ?mock_error=MFA_NOT_ENABLED.
      const next = new Set([...current.mfa.instance_roles, ...policy.mfa_roles]);
      if (next.has(role) && !current.mfa.effective_roles.includes(role) && !db.me.mfa) throw new Fail(409, "MFA_NOT_ENABLED");
      const from = current.policy;
      const updated = db.rebuildSignIn(orgId, policy);
      if (JSON.stringify(from) !== JSON.stringify(policy)) audit("org.sign_in_policy_changed", "org", orgId, { from, to: policy });
      return updated;
    },
  ],
  [
    "POST",
    new RegExp(`^${O}/members$`),
    (match, _u, body) => {
      const b = body as { email: string; role: "member" };
      const allowed = db.signIn[match[1]!]?.policy.allowed_email_domains ?? [];
      const domain = b.email.slice(b.email.lastIndexOf("@") + 1).toLowerCase();
      if (allowed.length > 0 && !allowed.includes(domain)) {
        throw new Fail(422, "VALIDATION_FAILED", { email: `must be an address at one of: ${allowed.join(", ")}` });
      }
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
  [
    "GET",
    new RegExp(`^${O}/projects$`),
    (_m, url) => ({
      items: db.projects.filter((p) => !p.archived_at || url.searchParams.get("include_archived") === "true").map(projectView),
    }),
  ],
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
        archived_at: null,
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
      const b = body as CreateScanBody;
      if (p.archived_at) throw new Fail(409, "PROJECT_ARCHIVED");
      if (b.file_name.includes("ratelimit")) throw new Fail(429, "RATE_LIMITED");
      if (!/^[0-9a-f]{64}$/.test(b.sha256)) throw new Fail(422, "VALIDATION_FAILED", { sha256: "must be 64 hex characters" });
      const kind = b.kind ?? "source";
      const fields: Record<string, string> = {};
      if (kind === "image") {
        if (!/\.tar$/i.test(b.file_name)) fields.file_name = "must be a .tar for an image scan";
        if (!b.target || b.target.length > 255 || !IMAGE_TARGET.test(b.target)) fields.target = "must be an image repository without tag, e.g. ghcr.io/acme/api";
        if (b.tools && b.tools.some((t) => t !== "trivy")) fields.tools = "image scans run trivy only";
        if (b.image_ref && b.image_ref.length > 512) fields.image_ref = "at most 512 characters";
        if (b.file_size > db.me.limits.image_upload_max_mb * 1024 * 1024) fields.file_size = "larger than image_upload_max_mb";
      } else {
        if (!/\.zip$/i.test(b.file_name)) fields.file_name = "must be a .zip for a source scan";
        if (b.target || b.image_ref) fields[b.target ? "target" : "image_ref"] = "only for image scans";
      }
      if (Object.keys(fields).length) throw new Fail(422, "VALIDATION_FAILED", fields);
      const tools = kind === "image" ? (["trivy"] as Scan["tools"]) : (b.tools ?? p.default_tools);
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
        via_token: null,
        kind,
        target: kind === "image" ? b.target! : "",
        image_ref: kind === "image" ? (b.image_ref ?? null) : null,
        sbom: null,
        tool_runs: tools.map((tool) => ({ tool, tool_version: "mock", status: "queued", findings_count: null, duration_ms: null, error: null })),
      };
      db.scans.unshift(scan);
      audit("scan.created", "scan", scan.id, { project_key: p.key, file_name: scan.file_name, file_size: scan.file_size });
      const type = kind === "image" ? "application/x-tar" : "application/zip";
      return [201, { scan, upload: { method: "PUT", url: "https://storage.mock.invalid/upload", headers: { "Content-Type": type }, expires_at: new Date(db.now() + 15 * 60_000).toISOString() } }];
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
          // v0.3
          (sp.get("kev") !== "true" || i.kev) &&
          (!sp.get("epss_min") || (i.epss ?? -1) >= Number(sp.get("epss_min"))) &&
          (!sp.get("kind") ||
            (i.tool === "trivy" && (sp.get("kind") === "license") === i.rule_id.startsWith("license:"))) &&
          (!sp.get("source") || (sp.get("source") === "image") === (i.target !== "")) &&
          (!sp.get("target") || i.target === sp.get("target")) &&
          (!sp.get("assignee") ||
            (sp.get("assignee") === "me" ? i.assignee?.id === db.me.id : sp.get("assignee") === "none" ? !i.assignee : i.assignee?.id === sp.get("assignee"))) &&
          (!q || [i.title, i.rule_id, i.file_path ?? "", i.key].some((s) => s.toLowerCase().includes(q))),
      );
      const sev = sp.getAll("severity");
      const filtered = sev.length ? base.filter((i) => sev.includes(i.severity)) : base;
      const sort = sp.get("sort") ?? "due_at";
      const sorted = [...filtered].sort((a, b) =>
        sort === "-epss"
          ? (b.epss ?? -1) - (a.epss ?? -1) || (a.due_at ?? "9").localeCompare(b.due_at ?? "9")
          : sort === "-severity"
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
  const { description: _d, remediation: _r, snippet: _s, end_line: _e, cwe: _c, cve: _v, first_seen_scan: _f, last_seen_scan: _l, occurrences: _o, version: _ver, allowed_transitions: _a, can_assign: _ca, can_request_exception: _cr, pending_exception_id: _p, epss_percentile: _ep, kev_added: _ka, kev_ransomware: _kr, ...rest } = i;
  return rest;
}

function nextForcedError(method: string): string | null {
  if (method === "GET") return null;
  const code = new URLSearchParams(window.location.search).get("mock_error");
  return code && /^[A-Z_]+$/.test(code) ? code : null;
}

const STATUS: Record<string, number> = { MFA_NOT_ENABLED: 409, MFA_REQUIRED: 403, TOKEN_SCOPE: 403, PROJECT_ARCHIVED: 409, VERSION_CONFLICT: 409, CONFLICT: 409, FORBIDDEN: 403, NOT_FOUND: 404, RATE_LIMITED: 429, INVALID_TRANSITION: 422, VALIDATION_FAILED: 422, UNAUTHORIZED: 401 };

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
    if (match[1] && match[1] !== db.ORG_ID && match[1] !== db.ORG2_ID && match[1] !== db.ORG3_ID) return envelope(404, null, { code: "NOT_FOUND", message: "not found" });
    // v0.2 MFA rule: the caller is an org admin in Acme Security and signed in without MFA.
    if (match[1] === db.ORG3_ID) return envelope(403, null, { code: "MFA_REQUIRED", message: "Your role requires two-factor sign-in." });
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
