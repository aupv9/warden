import { api } from "../client";
import { qk } from "../keys";
import { useCursorList } from "../paging";
import type { AuditEntry, AuditVerification, Page } from "../types";

export interface AuditFilters {
  action: string;
  /** "" = anyone, "system" = system entries, or a user id. */
  actorId: string;
  /** RFC 3339 bounds, or "". */
  from: string;
  to: string;
}

export function auditQuery(f: AuditFilters) {
  return {
    action: f.action || undefined,
    actor_id: f.actorId || undefined,
    from: f.from || undefined,
    to: f.to || undefined,
    limit: 50,
  };
}

/** v0.5 wave 2: POST …/audit-log/verify. Not a TanStack mutation: the audit page shows the
 *  result and any error (429 with its own words) in place, not in a toast. Afterwards the log is
 *  refreshed, since the check is itself recorded as audit.verified. */
export function verifyAuditLog(orgId: string): Promise<AuditVerification> {
  return api<AuditVerification>(`/orgs/${encodeURIComponent(orgId)}/audit-log/verify`, { method: "POST" });
}

export function useAuditLog(orgId: string, filters: AuditFilters, enabled = true) {
  const query = auditQuery(filters);
  return useCursorList<Page<AuditEntry>>(qk.auditLog(orgId, query), `/orgs/${encodeURIComponent(orgId)}/audit-log`, query, { enabled });
}
