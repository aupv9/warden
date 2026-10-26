import { qk } from "../keys";
import { useCursorList } from "../paging";
import type { AuditEntry, Page } from "../types";

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

export function useAuditLog(orgId: string, filters: AuditFilters, enabled = true) {
  const query = auditQuery(filters);
  return useCursorList<Page<AuditEntry>>(qk.auditLog(orgId, query), `/orgs/${encodeURIComponent(orgId)}/audit-log`, query, { enabled });
}
