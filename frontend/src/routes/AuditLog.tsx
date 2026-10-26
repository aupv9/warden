import { Fragment, useMemo, useState } from "react";
import { useSearchParams } from "react-router";
import { useAuditLog } from "../api/hooks/audit";
import type { AuditFilters } from "../api/hooks/audit";
import { useOrgMembers } from "../api/hooks/orgs";
import { flattenPages } from "../api/paging";
import { AUDIT_ACTIONS } from "../api/types";
import type { AuditEntry } from "../api/types";
import { Button } from "../components/Button";
import { Card } from "../components/Card";
import { Select, TextField } from "../components/Field";
import { ChevronIcon, LockIcon } from "../components/Icons";
import { LoadMore, Table } from "../components/Table";
import { EmptyState, ErrorState, ForbiddenState, SkeletonRows } from "../components/States";
import { useOrgCtx } from "../layout/OrgLayout";
import { auditDataText, auditTargetSummary } from "../lib/auditSummary";
import { addDays, formatDate, formatDateTime, fromDateInput, userName } from "../lib/format";
import { can } from "../lib/permissions";
import { usePageTitle } from "../lib/usePageTitle";

const DATE_RE = /^\d{4}-\d{2}-\d{2}$/;
const ACTOR_RE = /^(system|[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12})$/i;

/** Filters live in the URL; values are checked before they reach the API. */
export function parseAuditParams(sp: URLSearchParams): { action: string; actor: string; from: string; to: string } {
  const action = sp.get("action") ?? "";
  const actor = sp.get("actor") ?? "";
  const from = sp.get("from") ?? "";
  const to = sp.get("to") ?? "";
  return {
    action: (AUDIT_ACTIONS as readonly string[]).includes(action) ? action : "",
    actor: ACTOR_RE.test(actor) ? actor : "",
    from: DATE_RE.test(from) ? from : "",
    to: DATE_RE.test(to) ? to : "",
  };
}

/** Dates are local days; `to` is inclusive, so it becomes the start of the next day. */
export function auditApiFilters(p: ReturnType<typeof parseAuditParams>): AuditFilters {
  const toNext = p.to ? fromDateInput(p.to) : null;
  return {
    action: p.action,
    actorId: p.actor,
    from: (p.from && fromDateInput(p.from)) || "",
    to: toNext ? addDays(new Date(toNext), 1).toISOString() : "",
  };
}

function timeZoneLabel(): string {
  const mins = -new Date().getTimezoneOffset();
  const sign = mins >= 0 ? "+" : "-";
  const h = Math.floor(Math.abs(mins) / 60);
  const m = Math.abs(mins) % 60;
  return `UTC${sign}${h}${m ? `:${String(m).padStart(2, "0")}` : ""}`;
}

export function AuditLogPage() {
  usePageTitle("Audit log");
  const { orgId, org } = useOrgCtx();
  const [params, setParams] = useSearchParams();
  const p = useMemo(() => parseAuditParams(params), [params]);
  const filters = useMemo(() => auditApiFilters(p), [p]);
  const allowed = can("view_audit_log", org.role);
  const log = useAuditLog(orgId, filters, allowed);
  const members = useOrgMembers(orgId, allowed);
  const items = flattenPages(log.data?.pages);
  const [open, setOpen] = useState<string | null>(null);

  if (!allowed) return <ForbiddenState orgName={org.name} backTo={`/orgs/${orgId}/projects`} />;

  const set = (key: string, value: string) =>
    setParams((prev) => {
      const sp = new URLSearchParams(prev);
      if (value) sp.set(key, value);
      else sp.delete(key);
      return sp;
    });

  const range =
    p.from || p.to
      ? `${p.from ? formatDate(fromDateInput(p.from)) : "Start"} – ${p.to ? formatDate(fromDateInput(p.to)) : "now"}`
      : "All entries";

  return (
    <>
      <header className="page-head">
        <div className="titles">
          <h1>Audit log</h1>
          <p className="muted">Every change made in {org.name}: who did it, to what, from where. Visible to org admins and security leads.</p>
        </div>
      </header>
      <div className="banner banner-info">
        <LockIcon />
        <span>
          <strong>Append-only and hash-chained.</strong> Entries can't be edited or deleted, not even by an org admin or the
          database role Warden runs as. Each entry's hash covers the one before it, so a changed or missing entry breaks the
          chain.
        </span>
      </div>

      <section className="card" aria-label="Filters">
        <div className="grid" style={{ gridTemplateColumns: "repeat(auto-fit, minmax(170px, 1fr))", alignItems: "end", gap: 12 }}>
          <Select
            label="Action"
            value={p.action}
            onChange={(e) => set("action", e.target.value)}
            options={[{ value: "", label: "All actions" }, ...AUDIT_ACTIONS.map((a) => ({ value: a, label: a }))]}
            className="mono"
          />
          <Select
            label="Actor"
            value={p.actor}
            onChange={(e) => set("actor", e.target.value)}
            options={[
              { value: "", label: "Anyone" },
              { value: "system", label: "System" },
              ...(members.data ?? []).map((m) => ({ value: m.user.id, label: userName(m.user) })),
            ]}
          />
          <TextField label="From" type="date" value={p.from} max={p.to || undefined} onChange={(e) => set("from", e.target.value)} />
          <TextField label="To" type="date" value={p.to} min={p.from || undefined} onChange={(e) => set("to", e.target.value)} />
          <div>
            <Button onClick={() => setParams(new URLSearchParams())} disabled={!p.action && !p.actor && !p.from && !p.to}>
              Clear
            </Button>
          </div>
        </div>
      </section>

      <Card flush aria-label="Entries">
        <div className="card-head">
          <p>
            <strong>{range}</strong> <span className="muted">· newest first · times in your time zone ({timeZoneLabel()})</span>
          </p>
        </div>
        {log.isPending ? (
          <SkeletonRows label="audit log" />
        ) : log.isError ? (
          <ErrorState error={log.error} onRetry={() => void log.refetch()} what="the audit log" />
        ) : items.length === 0 ? (
          <EmptyState title="No entries">{p.action || p.actor || p.from || p.to ? "Nothing matches these filters." : "Changes appear here as people use Warden."}</EmptyState>
        ) : (
          <>
            <Table
              caption="Audit log entries"
              head={
                <tr>
                  <th>Time</th>
                  <th>Actor</th>
                  <th>Action</th>
                  <th>Target</th>
                  <th>IP</th>
                  <th>
                    <span className="visually-hidden">Details</span>
                  </th>
                </tr>
              }
            >
              {items.map((e) => (
                <AuditRow key={e.id} entry={e} open={open === e.id} onToggle={() => setOpen(open === e.id ? null : e.id)} />
              ))}
            </Table>
            <LoadMore
              hasNext={!!log.hasNextPage}
              loading={log.isFetchingNextPage}
              onLoad={() => void log.fetchNextPage()}
              shown={items.length}
              label="Load older entries"
            />
          </>
        )}
      </Card>
    </>
  );
}

function AuditRow({ entry: e, open, onToggle }: { entry: AuditEntry; open: boolean; onToggle: () => void }) {
  const detailsId = `audit-${e.id}`;
  return (
    <Fragment>
      <tr className={open ? "selected" : undefined}>
        <td className="nowrap">{formatDateTime(e.created_at)}</td>
        <td data-label="Actor" className="nowrap">
          {e.actor ? userName(e.actor) : <span className="muted">System</span>}
        </td>
        <td data-label="Action" className="mono" style={{ fontSize: 13 }}>
          {e.action}
        </td>
        <td data-label="Target" style={{ overflowWrap: "anywhere" }}>
          {auditTargetSummary(e)}
        </td>
        <td data-label="IP" className="mono muted" style={{ fontSize: 13 }}>
          {e.ip ?? "–"}
        </td>
        <td className="no-label" style={{ textAlign: "right" }}>
          <button
            type="button"
            className="icon-btn"
            style={{ border: "1px solid var(--control-line)" }}
            aria-expanded={open}
            aria-controls={detailsId}
            aria-label={open ? "Hide details" : "Show details"}
            onClick={onToggle}
          >
            <ChevronIcon up={open} />
          </button>
        </td>
      </tr>
      {open && (
        <tr id={detailsId} className="expand-row">
          <td colSpan={6} className="no-label">
            <div className="grid grid-2" style={{ gap: 16 }}>
              <dl className="kv" style={{ fontSize: 13 }}>
                <dt>Entry</dt>
                <dd className="mono">{e.id}</dd>
                <dt>Actor</dt>
                <dd>{e.actor ? `${userName(e.actor)} · ${e.actor.email}` : "System"}</dd>
                <dt>Target</dt>
                <dd className="mono">
                  {e.target_type} {e.target_id}
                </dd>
                <dt>Time (UTC)</dt>
                <dd className="mono">{e.created_at}</dd>
              </dl>
              {/* Pretty-printed JSON as text, never HTML. */}
              <pre className="code-json" aria-label="Entry data" tabIndex={0}>
                {auditDataText(e.data)}
              </pre>
            </div>
          </td>
        </tr>
      )}
    </Fragment>
  );
}
