import type { AuditEntry } from "../api/types";
import { EXCEPTION_TYPE_LABELS, formatBytes, formatDate, STATUS_LABELS } from "./format";
import { ORG_ROLE_LABELS, PROJECT_ROLE_LABELS } from "./permissions";

// A one-line summary of an audit entry's target, built from target_type, target_id and data
// (DESIGN.md "Audit log"). `data` is written by the server but its shape per action isn't in the
// contract, so every field is read defensively; when the expected fields aren't there the
// summary falls back to "<target_type> <short id>". The result is plain text.

type Data = Record<string, unknown>;

function str(d: Data, ...keys: string[]): string | undefined {
  for (const k of keys) {
    const v = d[k];
    if (typeof v === "string" && v) return v;
    if (typeof v === "number") return String(v);
  }
  return undefined;
}

function label(map: Record<string, string>, v: string | undefined): string | undefined {
  if (!v) return undefined;
  return (map[v] ?? v).toLowerCase();
}

export function shortId(id: string): string {
  return id.length > 12 ? `${id.slice(0, 4)}…${id.slice(-4)}` : id;
}

export function auditTargetSummary(e: Pick<AuditEntry, "action" | "target_type" | "target_id" | "data">): string {
  const d: Data = e.data && typeof e.data === "object" && !Array.isArray(e.data) ? (e.data as Data) : {};
  const fallback = [e.target_type, e.target_id ? shortId(e.target_id) : null].filter(Boolean).join(" ") || "—";
  const issueKey = str(d, "issue_key", "key");
  const projectKey = str(d, "project_key");
  const who = str(d, "member_name", "user_name", "display_name", "email", "member_email", "user_email");

  switch (e.action) {
    case "issue.transitioned": {
      const from = label(STATUS_LABELS, str(d, "from"));
      const to = label(STATUS_LABELS, str(d, "to"));
      if (!issueKey) return fallback;
      return from && to ? `${issueKey} ${from} → ${to}` : to ? `${issueKey} → ${to}` : issueKey;
    }
    case "issue.assigned": {
      const count = typeof d.count === "number" ? d.count : Array.isArray(d.issue_ids) ? d.issue_ids.length : undefined;
      const to = str(d, "assignee_name", "assignee_email");
      if (count !== undefined && to) return `${count} issue${count === 1 ? "" : "s"} to ${to}`;
      if (issueKey && to) return `${issueKey} to ${to}`;
      return fallback;
    }
    case "exception.requested": {
      const type = label(EXCEPTION_TYPE_LABELS, str(d, "type"));
      return issueKey ? `${issueKey}${type ? ` ${type}` : ""}` : fallback;
    }
    case "exception.decided": {
      const decision = str(d, "decision");
      const verb = decision === "approve" ? "approved" : decision === "reject" ? "rejected" : decision;
      const type = label(EXCEPTION_TYPE_LABELS, str(d, "type"));
      const until = str(d, "expires_at");
      if (!issueKey) return fallback;
      if (verb === "approved" && type) return `${issueKey} approved, ${type}${until ? ` until ${formatDate(until)}` : ""}`;
      return verb ? `${issueKey} ${verb}` : issueKey;
    }
    case "scan.created":
    case "scan.started":
    case "scan.cancelled": {
      const file = str(d, "file_name");
      if (!file) return fallback;
      const size = e.action === "scan.created" && typeof d.file_size === "number" ? ` · ${formatBytes(d.file_size)}` : "";
      return `${projectKey ? `${projectKey} ` : ""}${file}${size}`;
    }
    case "project.created": {
      const name = str(d, "name", "project_name");
      return projectKey || name ? [projectKey, name].filter(Boolean).join(" ") : fallback;
    }
    case "member.added": {
      const role = label(ORG_ROLE_LABELS, str(d, "role"));
      return who ? `${who}${role ? ` as ${role}` : ""}` : fallback;
    }
    case "member.role_changed": {
      const from = label(ORG_ROLE_LABELS, str(d, "from"));
      const to = label(ORG_ROLE_LABELS, str(d, "to", "role"));
      if (!who) return fallback;
      return from && to ? `${who} ${from} → ${to}` : to ? `${who} → ${to}` : who;
    }
    case "member.removed":
      return who ?? fallback;
    case "project_member.set": {
      const role = label(PROJECT_ROLE_LABELS, str(d, "role", "to"));
      if (!who) return fallback;
      return `${projectKey ? `${projectKey} ` : ""}${who}${role ? ` as ${role}` : ""}`;
    }
    case "project_member.removed":
      return who ? `${projectKey ? `${projectKey} ` : ""}${who}` : fallback;
    case "token.created":
    case "token.revoked": {
      // name, prefix and scopes only: the audit data never holds the secret.
      const name = str(d, "name");
      const prefix = str(d, "prefix");
      if (!name && !prefix) return fallback;
      return [projectKey, name ? `“${name}”` : null, prefix ? `wdn_${prefix}_…` : null].filter(Boolean).join(" ");
    }
    case "project.archived":
    case "project.unarchived": {
      const name = str(d, "name", "project_name");
      return projectKey || name ? [projectKey, name].filter(Boolean).join(" ") : fallback;
    }
    case "org.policy_changed": {
      const to = d.to && typeof d.to === "object" ? (d.to as Data) : (d.sla_days as Data | undefined);
      if (!to || typeof to !== "object") return fallback;
      const days = (["critical", "high", "medium", "low"] as const).map((k) => str(to, k) ?? "?");
      return `SLA days ${days.join(" / ")}${d.recompute_open === true ? ", open issues recomputed" : ""}`;
    }
    case "org.sign_in_policy_changed": {
      const to = d.to && typeof d.to === "object" ? (d.to as Data) : undefined;
      if (!to) return fallback;
      const strings = (v: unknown) => (Array.isArray(v) ? v.filter((x): x is string => typeof x === "string") : null);
      const roles = strings(to.mfa_roles);
      const domains = strings(to.allowed_email_domains);
      if (!roles || !domains) return fallback;
      const roleText = roles.length ? roles.map((r) => label(ORG_ROLE_LABELS, r)).join(", ") : "no extra roles";
      return `Two-factor for ${roleText}; domains ${domains.length ? domains.join(", ") : "any"}`;
    }
    case "user.relinked": {
      const how = str(d, "via") === "sign-in" ? "at sign-in" : "by the operator";
      return `${fallback} moved to a new sign-in identity ${how}`;
    }
    case "user.relink_allowed": {
      const until = str(d, "until");
      return until ? `${fallback} may move to a new sign-in identity until ${until}` : fallback;
    }
    default:
      return fallback;
  }
}

/** `data` for the expanded row: pretty JSON, shown as text (never HTML). */
export function auditDataText(data: unknown): string {
  if (data === null || data === undefined) return "—";
  try {
    return JSON.stringify(data, null, 2);
  } catch {
    return String(data);
  }
}
