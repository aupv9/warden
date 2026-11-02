import { Fragment, useMemo, useRef, useState } from "react";
import type { ReactNode } from "react";
import { useQueryClient } from "@tanstack/react-query";
import { useSearchParams } from "react-router";
import { supportReference } from "../api/errors";
import { useAuditLog, verifyAuditLog } from "../api/hooks/audit";
import type { AuditFilters } from "../api/hooks/audit";
import { useOrgMembers } from "../api/hooks/orgs";
import { qk } from "../api/keys";
import { flattenPages } from "../api/paging";
import { AUDIT_ACTIONS } from "../api/types";
import type { AuditEntry, AuditVerification } from "../api/types";
import { Button } from "../components/Button";
import { Card } from "../components/Card";
import { Select, TextField } from "../components/Field";
import { AlertIcon, CheckIcon, ChevronIcon, LockIcon } from "../components/Icons";
import { badEntryHint, verificationSummary, verifyErrorText } from "../lib/auditVerify";
import { LoadMore, Table } from "../components/Table";
import { PageHeader } from "../components/PageHeader";
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
  const qc = useQueryClient();
  // v0.5 wave 2: the last "Verify chain" result (or its error), shown under the note.
  const [verify, setVerify] = useState<{ busy: boolean; result?: AuditVerification; error?: unknown }>({ busy: false });
  const tableRef = useRef<HTMLDivElement>(null);

  if (!allowed)
    return (
      <div className="page">
        <PageHeader title="Audit log" />
        <div className="page-body">
          <ForbiddenState orgName={org.name} backTo={`/orgs/${orgId}/projects`} />
        </div>
      </div>
    );

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
  const filtered = !!(p.action || p.actor || p.from || p.to);

  const runVerify = async () => {
    setVerify((v) => ({ ...v, busy: true }));
    try {
      const result = await verifyAuditLog(orgId);
      setVerify({ busy: false, result });
    } catch (error) {
      setVerify({ busy: false, error });
    }
    // The check is recorded as audit.verified.
    void qc.invalidateQueries({ queryKey: qk.auditLogs(orgId) });
  };

  /** Scroll to the first bad entry and open its details (when it is loaded). */
  const showEntry = (id: string) => {
    setOpen(id);
    const row = tableRef.current?.querySelector<HTMLElement>(`[data-entry="${CSS.escape(id)}"]`);
    row?.scrollIntoView({ block: "center" });
    row?.querySelector<HTMLElement>("button[aria-expanded]")?.focus({ preventScroll: true });
  };

  return (
    <div className="page">
      <PageHeader title="Audit log" />
      <div className="page-body">
      <p className="faint small">Every change made in {org.name}: who did it, to what, from where. Visible to org admins and security leads.</p>
      {/* A block, not a flex column: the empty live region below takes no space or gap. */}
      <div className="verify-block">
        <div className="banner banner-info">
          <LockIcon />
          <div className="stack" style={{ gap: 10 }}>
            <span>
              <strong>Append-only and hash-chained.</strong> Entries can't be edited or deleted, not even by an org admin or the
              database role Warden runs as. Each entry's hash covers the one before it, so a changed or missing entry breaks the
              chain. Verify the chain to recompute every hash now.
            </span>
            <span>
              <Button size="sm" busy={verify.busy} onClick={() => void runVerify()}>
                {verify.busy ? "Verifying…" : "Verify chain"}
              </Button>
            </span>
          </div>
        </div>
        <VerifyResult
          result={verify.result}
          error={verify.error}
          loadedIds={items.map((e) => e.id)}
          filtered={filtered}
          onShow={showEntry}
        />
      </div>

      <section className="card" aria-label="Filters">
        <div className="grid filters-grid">
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
            <strong>{range}</strong> <span className="faint">· newest first · times in your time zone ({timeZoneLabel()})</span>
          </p>
        </div>
        {log.isPending ? (
          <SkeletonRows label="audit log" />
        ) : log.isError ? (
          <ErrorState error={log.error} onRetry={() => void log.refetch()} what="the audit log" />
        ) : items.length === 0 ? (
          <EmptyState title="No entries">{p.action || p.actor || p.from || p.to ? "Nothing matches these filters." : "Changes appear here as people use Warden."}</EmptyState>
        ) : (
          <div ref={tableRef}>
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
                <AuditRow
                  key={e.id}
                  entry={e}
                  open={open === e.id}
                  bad={!!verify.result && !verify.result.ok && verify.result.first_bad_id === e.id}
                  onToggle={() => setOpen(open === e.id ? null : e.id)}
                />
              ))}
            </Table>
            <LoadMore
              hasNext={!!log.hasNextPage}
              loading={log.isFetchingNextPage}
              onLoad={() => void log.fetchNextPage()}
              shown={items.length}
              label="Load older entries"
            />
          </div>
        )}
      </Card>
      </div>
    </div>
  );
}

/** v0.5 wave 2: the result of "Verify chain", in a live region so it is announced. */
function VerifyResult({
  result,
  error,
  loadedIds,
  filtered,
  onShow,
}: {
  result?: AuditVerification;
  error?: unknown;
  loadedIds: string[];
  filtered: boolean;
  onShow: (id: string) => void;
}) {
  let body: ReactNode = null;
  if (error) {
    const ref = supportReference(error);
    body = (
      <div className="banner banner-error">
        <AlertIcon />
        <span>
          {verifyErrorText(error)}
          {ref && <span className="mono faint small"> Request {ref}</span>}
        </span>
      </div>
    );
  } else if (result) {
    const s = verificationSummary(result);
    const hint = badEntryHint(s.badId, loadedIds, filtered);
    body = (
      <div className={s.ok ? "banner banner-success" : "banner banner-error"}>
        {s.ok ? <CheckIcon /> : <AlertIcon />}
        <div className="stack" style={{ gap: 8 }}>
          <span>
            <strong>{s.title}</strong> {s.text}
          </span>
          {s.badId && !hint && (
            <span>
              <Button size="sm" onClick={() => onShow(s.badId!)}>
                Show entry {s.badId}
              </Button>
            </span>
          )}
          {hint && <span className="small">{hint}</span>}
        </div>
      </div>
    );
  }
  return (
    <div role="status" aria-live="polite">
      {body}
    </div>
  );
}

function AuditRow({ entry: e, open, bad, onToggle }: { entry: AuditEntry; open: boolean; bad: boolean; onToggle: () => void }) {
  const detailsId = `audit-${e.id}`;
  return (
    <Fragment>
      <tr className={open || bad ? "selected" : undefined} data-entry={e.id}>
        <td className="nowrap">
          {formatDateTime(e.created_at)}
          {bad && (
            <>
              {" "}
              <span className="tag tag-danger">Hash mismatch</span>
            </>
          )}
        </td>
        <td data-label="Actor" className="nowrap">
          {e.actor ? userName(e.actor) : <span className="muted">System</span>}
        </td>
        <td data-label="Action" className="mono small">
          {e.action}
        </td>
        <td data-label="Target" style={{ overflowWrap: "anywhere" }}>
          {auditTargetSummary(e)}
        </td>
        <td data-label="IP" className="mono faint small">
          {e.ip ?? "–"}
        </td>
        <td className="no-label" style={{ textAlign: "right" }}>
          <button
            type="button"
            className="icon-btn bordered"
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
              <dl className="kv">
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
