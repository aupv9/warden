import { useState } from "react";
import type { FormEvent } from "react";
import { Link, useSearchParams } from "react-router";
import { useDecideException, useExceptions } from "../api/hooks/exceptions";
import { useOrgSummary } from "../api/hooks/orgs";
import { flattenPages } from "../api/paging";
import type { ExceptionRequest, ExceptionTab } from "../api/types";
import { Pill, SeverityBadge } from "../components/Badges";
import { Button } from "../components/Button";
import { Card } from "../components/Card";
import { focusFirstInvalid, TextArea, TextField } from "../components/Field";
import { CheckIcon } from "../components/Icons";
import { LoadMore, Table } from "../components/Table";
import { ActionError, EmptyState, ErrorState, SkeletonRows } from "../components/States";
import { useOrgCtx } from "../layout/OrgLayout";
import {
  addDays,
  age,
  daysUntil,
  EXCEPTION_TYPE_LABELS,
  formatDate,
  fromDateInput,
  relativeTime,
  toDateInput,
  userName,
} from "../lib/format";
import { can } from "../lib/permissions";
import { showToast } from "../lib/toast";
import { usePageTitle } from "../lib/usePageTitle";
import { MAX_RISK_DAYS } from "./IssueDetail";

const TABS: { id: ExceptionTab; label: string }[] = [
  { id: "pending", label: "Pending" },
  { id: "approved", label: "Approved" },
  { id: "rejected", label: "Rejected" },
  { id: "expiring", label: "Expiring soon" },
];

export function parseTab(v: string | null): ExceptionTab {
  return TABS.some((t) => t.id === v) ? (v as ExceptionTab) : "pending";
}

export function ExceptionsPage() {
  usePageTitle("Exceptions");
  const { orgId, org } = useOrgCtx();
  const [params, setParams] = useSearchParams();
  const tab = parseTab(params.get("tab"));
  const list = useExceptions(orgId, tab);
  const summary = useOrgSummary(orgId);
  const items = flattenPages(list.data?.pages);
  const selectedId = params.get("id") ?? items[0]?.id;
  const selected = items.find((e) => e.id === selectedId);
  const isLead = can("decide_exception", org.role);

  const go = (next: { tab?: ExceptionTab; id?: string | null }) =>
    setParams(
      (prev) => {
        const sp = new URLSearchParams(prev);
        if (next.tab) {
          sp.set("tab", next.tab);
          sp.delete("id");
        }
        if (next.id) sp.set("id", next.id);
        else if (next.id === null) sp.delete("id");
        return sp;
      },
      { replace: !next.tab },
    );

  return (
    <>
      <header className="page-head">
        <div className="titles">
          <h1>Exceptions</h1>
          <p className="muted">
            Requests to close an issue as a false positive or an accepted risk. Only a security lead can decide.
            {!isLead && " You see the requests you made."}
          </p>
        </div>
      </header>

      <div className="tabs" role="tablist" aria-label="Exception status">
        {TABS.map((t) => (
          <button key={t.id} type="button" role="tab" aria-selected={tab === t.id} onClick={() => go({ tab: t.id })}>
            {t.label}
            {t.id === "pending" && isLead && (summary.data?.exceptions_pending ?? 0) > 0 && (
              <span className="pill">{summary.data?.exceptions_pending}</span>
            )}
          </button>
        ))}
      </div>

      <div className="layout-review" role="tabpanel">
        <Card flush aria-label="Requests">
          {list.isPending ? (
            <SkeletonRows label="exception requests" />
          ) : list.isError ? (
            <ErrorState error={list.error} onRetry={() => void list.refetch()} what="exception requests" />
          ) : items.length === 0 ? (
            <EmptyTab tab={tab} isLead={isLead} />
          ) : (
            <>
              <Table
                caption="Exception requests"
                head={
                  <tr>
                    <th>Issue</th>
                    <th>Type</th>
                    <th>Requested by</th>
                    <th>Until</th>
                    <th>{tab === "pending" ? "Waiting" : "Decided"}</th>
                  </tr>
                }
              >
                {items.map((e) => (
                  <tr key={e.id} className={e.id === selected?.id ? "selected" : undefined}>
                    <td style={{ minWidth: 200 }}>
                      <button type="button" className="row-button" onClick={() => go({ id: e.id })} aria-pressed={e.id === selected?.id}>
                        <span className="mono muted" style={{ fontWeight: 500 }}>
                          {e.issue.key}
                        </span>{" "}
                        {e.issue.title}
                      </button>
                      <div style={{ marginTop: 4 }}>
                        <SeverityBadge severity={e.issue.severity} />
                      </div>
                    </td>
                    <td data-label="Type">
                      <Pill>{EXCEPTION_TYPE_LABELS[e.type]}</Pill>
                    </td>
                    <td data-label="Requested by" className="nowrap">
                      {userName(e.requested_by)}
                    </td>
                    <td data-label="Until">
                      {e.expires_at ? (
                        <>
                          {formatDate(e.expires_at)} <span className="muted">({daysUntil(e.expires_at)} days)</span>
                        </>
                      ) : (
                        <span className="muted">–</span>
                      )}
                    </td>
                    <td data-label={tab === "pending" ? "Waiting" : "Decided"} className="nowrap">
                      {tab === "pending" ? age(e.created_at) : relativeTime(e.decided_at)}
                    </td>
                  </tr>
                ))}
              </Table>
              {list.hasNextPage && (
                <LoadMore hasNext loading={list.isFetchingNextPage} onLoad={() => void list.fetchNextPage()} shown={items.length} noun="requests" />
              )}
            </>
          )}
        </Card>
        {selected && <ReviewPanel key={selected.id} exc={selected} onDecided={() => go({ id: null })} />}
      </div>
    </>
  );
}

function EmptyTab({ tab, isLead }: { tab: ExceptionTab; isLead: boolean }) {
  if (tab === "pending") {
    return (
      <EmptyState icon={<CheckIcon size={20} />} title="Nothing to review">
        {isLead ? "New requests for a false positive or an accepted risk show up here." : "You have no pending requests."}
      </EmptyState>
    );
  }
  const text: Record<Exclude<ExceptionTab, "pending">, [string, string]> = {
    approved: ["No approved requests", "Approved false positives and accepted risks are listed here."],
    rejected: ["No rejected requests", "Rejected requests are listed here with the decision note."],
    expiring: ["Nothing expiring soon", "Accepted risks that end within 14 days show up here. When one ends, its issue reopens by itself."],
  };
  const [title, body] = text[tab];
  return <EmptyState title={title}>{body}</EmptyState>;
}

function ReviewPanel({ exc, onDecided }: { exc: ExceptionRequest; onDecided: () => void }) {
  const { orgId, org, me } = useOrgCtx();
  const decide = useDecideException(orgId);
  const now = new Date();
  const maxDate = toDateInput(addDays(now, MAX_RISK_DAYS));
  const minDate = toDateInput(addDays(now, 1));
  const [until, setUntil] = useState(exc.expires_at ? toDateInput(new Date(exc.expires_at)) : maxDate);
  const [note, setNote] = useState("");
  const [noteError, setNoteError] = useState<string | undefined>();
  const [untilError, setUntilError] = useState<string | undefined>();
  const isLead = can("decide_exception", org.role);
  const own = exc.requested_by.id === me.id;
  const canDecide = exc.status === "pending" && isLead && !own;

  async function submit(decision: "approve" | "reject", form: HTMLFormElement | null) {
    setNoteError(undefined);
    setUntilError(undefined);
    if (decision === "reject" && !note.trim()) {
      setNoteError("A note is required to reject, so the requester knows why.");
      return focusFirstInvalid(form);
    }
    let expires: string | undefined;
    if (decision === "approve" && exc.type === "risk_accepted") {
      const iso = fromDateInput(until);
      if (!iso || until < minDate || until > maxDate) {
        setUntilError(`Pick a date from tomorrow to ${formatDate(addDays(now, MAX_RISK_DAYS).toISOString())}.`);
        return focusFirstInvalid(form);
      }
      expires = iso;
    }
    const res = await decide
      .mutateAsync({ id: exc.id, body: { decision, ...(note.trim() ? { note: note.trim() } : {}), ...(expires ? { expires_at: expires } : {}) } })
      .catch(() => undefined);
    if (res) {
      showToast({
        tone: "success",
        message:
          decision === "approve"
            ? `${exc.issue.key} approved: ${EXCEPTION_TYPE_LABELS[exc.type].toLowerCase()}${res.expires_at ? ` until ${formatDate(res.expires_at)}` : ""}.`
            : `${exc.issue.key} rejected. The issue stays open.`,
      });
      onDecided();
    }
  }

  return (
    <Card as="aside" title={`Review ${exc.issue.key}`} titleId="review-h">
      <form
        className="form-grid"
        noValidate
        onSubmit={(e: FormEvent<HTMLFormElement>) => {
          e.preventDefault();
          void submit("approve", e.currentTarget);
        }}
      >
        <p className="muted" style={{ fontSize: 13 }}>
          {EXCEPTION_TYPE_LABELS[exc.type]} · requested by {userName(exc.requested_by)}, {relativeTime(exc.created_at)} ·{" "}
          <Link to={`/orgs/${orgId}/issues/${exc.issue.id}`}>Open issue</Link>
        </p>
        <div className="field">
          <span>Reason</span>
          {/* Written by the requester: plain text. */}
          <div className="quote" style={{ fontWeight: 400 }}>
            {exc.reason}
          </div>
        </div>

        {canDecide ? (
          <>
            {exc.type === "risk_accepted" && (
              <TextField
                label="Accepted until"
                type="date"
                min={minDate}
                max={maxDate}
                value={until}
                onChange={(e) => setUntil(e.target.value)}
                hint={`At most ${MAX_RISK_DAYS} days. When it ends, the issue reopens by itself.`}
                error={untilError}
              />
            )}
            <TextArea
              label="Decision note"
              placeholder="Required when rejecting"
              value={note}
              onChange={(e) => setNote(e.target.value)}
              maxLength={2000}
              error={noteError}
            />
            <ActionError error={decide.error} overrides={{ CONFLICT: "This request was already decided. Reload the list." }} />
            <div className="dialog-actions">
              <Button busy={decide.isPending && decide.variables?.body.decision === "reject"} onClick={(e) => void submit("reject", e.currentTarget.form)}>
                Reject
              </Button>
              <Button type="submit" variant="primary" busy={decide.isPending && decide.variables?.body.decision === "approve"}>
                Approve
              </Button>
            </div>
          </>
        ) : exc.status === "pending" ? (
          <p className="notice">
            {own && isLead
              ? "You can't decide on a request you made yourself. Another security lead has to."
              : "Waiting for a security lead to decide."}
          </p>
        ) : (
          <dl className="kv">
            <dt>Decision</dt>
            <dd>{exc.status === "approved" ? "Approved" : exc.status === "rejected" ? "Rejected" : "Expired"}</dd>
            <dt>By</dt>
            <dd>{exc.decided_by ? userName(exc.decided_by) : "–"}</dd>
            <dt>When</dt>
            <dd>{formatDate(exc.decided_at)}</dd>
            {exc.expires_at && (
              <>
                <dt>Until</dt>
                <dd>{formatDate(exc.expires_at)}</dd>
              </>
            )}
            {exc.decision_note && (
              <>
                <dt>Note</dt>
                <dd className="prose">{exc.decision_note}</dd>
              </>
            )}
          </dl>
        )}
        <p className="muted" style={{ fontSize: 12, borderTop: "1px solid var(--line)", paddingTop: 12 }}>
          You can't decide on a request you made yourself. Every decision is written to the audit log.
        </p>
      </form>
    </Card>
  );
}
