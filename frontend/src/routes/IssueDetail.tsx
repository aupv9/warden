import { useState } from "react";
import type { FormEvent } from "react";
import { Link, useParams } from "react-router";
import { fieldErrors, isNotFound } from "../api/errors";
import { useRequestException } from "../api/hooks/exceptions";
import { useAddComment, useIssue, useIssueComments, useIssueEvents, useTransitionIssue } from "../api/hooks/issues";
import { useOrg } from "../api/hooks/orgs";
import { useProject } from "../api/hooks/projects";
import type { ExceptionType, Issue, IssueEvent, IssueStatus, ProjectRole } from "../api/types";
import { SeverityBadge, StatusPill } from "../components/Badges";
import { Button, ButtonLink } from "../components/Button";
import { Card } from "../components/Card";
import { Dialog } from "../components/Dialog";
import { focusFirstInvalid, TextArea, TextField } from "../components/Field";
import { BackIcon, RefreshIcon } from "../components/Icons";
import { ActionError, ErrorState, Loading, NotFoundState, Skeleton, SkeletonBlock } from "../components/States";
import { useOrgCtx } from "../layout/OrgLayout";
import {
  addDays,
  dueText,
  EXCEPTION_TYPE_LABELS,
  formatDate,
  formatDateTime,
  fromDateInput,
  initials,
  relativeTime,
  SEVERITY_LABELS,
  STATUS_LABELS,
  toDateInput,
  TOOL_LABELS,
  userName,
} from "../lib/format";
import { issueActions, workflowSteps } from "../lib/issueActions";
import type { IssueAction } from "../lib/issueActions";
import { canComment } from "../lib/permissions";
import { showToast } from "../lib/toast";
import { usePageTitle } from "../lib/usePageTitle";
import { AssignForm, isConflict } from "./AssignForm";

export function IssueDetailPage() {
  const { orgId } = useOrgCtx();
  const { issueId = "" } = useParams();
  const issue = useIssue(orgId, issueId);
  usePageTitle(issue.data ? `${issue.data.key} ${issue.data.title}` : "Issue");
  const issuesUrl = `/orgs/${orgId}/issues`;

  if (issue.isError && isNotFound(issue.error)) {
    return <NotFoundState backTo={issuesUrl} backLabel="Back to issues" />;
  }
  return (
    <>
      <nav className="breadcrumb desktop-only" aria-label="Breadcrumb">
        <Link to={issuesUrl}>Issues</Link> / <span className="mono">{issue.data?.key ?? "…"}</span>
      </nav>
      <Link to={issuesUrl} className="mobile-only back-link">
        <BackIcon /> Issues
      </Link>
      {issue.isPending ? (
        <Loading label="issue">
          <div className="stack">
            <Skeleton width="50%" height={30} />
            <div className="row">
              <Skeleton width={64} height={22} />
              <Skeleton width={76} height={22} />
              <Skeleton width={140} height={22} />
            </div>
            <div className="layout-side">
              <div className="card stack">
                <Skeleton width="30%" />
                <Skeleton height={96} style={{ background: "#1e293b" }} />
              </div>
              <div className="card stack">
                {Array.from({ length: 6 }, (_, i) => (
                  <Skeleton key={i} width={`${50 + i * 7}%`} />
                ))}
              </div>
            </div>
          </div>
        </Loading>
      ) : issue.isError ? (
        <ErrorState error={issue.error} onRetry={() => void issue.refetch()} what="this issue" />
      ) : (
        <IssueView issue={issue.data} reload={() => issue.refetch()} />
      )}
    </>
  );
}

function IssueView({ issue, reload }: { issue: Issue; reload: () => Promise<unknown> }) {
  const { orgId } = useOrgCtx();
  const project = useProject(orgId, issue.project_id);
  const due = dueText(issue.due_at);
  // A stale-version or no-longer-valid change: actions stay disabled until "Reload issue".
  const [conflict, setConflict] = useState<{ code: string; to?: IssueStatus } | null>(null);
  const [reloading, setReloading] = useState(false);

  async function doReload() {
    setReloading(true);
    await reload();
    setReloading(false);
    setConflict(null);
  }

  const onConflict = (err: unknown, to?: IssueStatus) => {
    const code = (err as { code?: string }).code ?? "VERSION_CONFLICT";
    setConflict({ code, to });
  };

  return (
    <>
      {conflict && (
        <div className="banner banner-warning" role="alert">
          <RefreshIcon />
          <div className="stack" style={{ gap: 10 }}>
            {conflict.code === "INVALID_TRANSITION" ? (
              <span>
                <strong>This issue can't move to {conflict.to ? STATUS_LABELS[conflict.to] : "that status"} any more.</strong>{" "}
                Reload to see what changed.
              </span>
            ) : (
              <span>
                <strong>Someone changed this issue while you had it open.</strong> Your change wasn't saved. Reload to see
                the latest version, then try again.
              </span>
            )}
            <div>
              <Button variant="primary" onClick={() => void doReload()} busy={reloading}>
                Reload issue
              </Button>
            </div>
          </div>
        </div>
      )}
      <header className="page-head" style={{ alignItems: "flex-start" }}>
        <div className="titles" style={{ gap: 10 }}>
          <h1>
            <span className="mono muted" style={{ fontWeight: 500 }}>
              {issue.key}
            </span>{" "}
            {issue.title}
          </h1>
          <div className="row" style={{ fontSize: 13 }}>
            <SeverityBadge severity={issue.severity} />
            <StatusPill status={issue.status} />
            {issue.due_at && (
              <span className={due.overdue || issue.past_sla ? "danger-text" : undefined}>SLA: {due.text}</span>
            )}
            <span className="muted">
              {project.data && (
                <>
                  · <Link to={`/orgs/${orgId}/projects/${project.data.id}/issues`}>{project.data.name}</Link>{" "}
                </>
              )}
              · first seen {formatDate(issue.first_seen_scan.created_at)}
            </span>
          </div>
        </div>
        <IssueActions issue={issue} disabled={!!conflict} onConflict={onConflict} />
      </header>

      <div className="layout-side">
        <div className="stack">
          <LocationCard issue={issue} />
          {issue.description && (
            <Card title="What was found" titleId="desc-h">
              <p className="prose">{issue.description}</p>
            </Card>
          )}
          <Card title="How to fix" titleId="fix-h">
            {issue.remediation ? (
              <p className="prose">{issue.remediation}</p>
            ) : (
              <p className="muted">The scanner gave no fix advice for this rule.</p>
            )}
          </Card>
          <Comments issue={issue} projectRole={project.data?.my_role} />
        </div>
        <div className="stack">
          <DetailsCard issue={issue} />
          <WorkflowCard status={issue.status} />
          <HistoryCard issue={issue} />
        </div>
      </div>
    </>
  );
}

function LocationCard({ issue }: { issue: Issue }) {
  const lines = issue.snippet ? issue.snippet.replace(/\n$/, "").split("\n") : [];
  const first = issue.start_line ?? 1;
  const last = issue.end_line ?? issue.start_line ?? 0;
  const where = issue.file_path ?? issue.package_name ?? "";
  return (
    <Card
      title="Location"
      titleId="loc-h"
      actions={
        where ? (
          <span className="mono muted" style={{ fontSize: 13, wordBreak: "break-all" }}>
            {where}
            {issue.start_line ? ` · line ${issue.start_line}` : ""}
          </span>
        ) : undefined
      }
    >
      {lines.length > 0 ? (
        // The snippet arrives already masked (AKIA****) and is rendered as text, never as HTML.
        // tabIndex lets keyboard users scroll it sideways.
        <pre className="code" aria-label="Code snippet" tabIndex={0}>
          {lines.map((text, i) => {
            const n = first + i;
            const hl = issue.start_line !== null && n >= first && n <= last;
            return (
              <span key={i} className={hl ? "line hl" : "line"}>
                <span className="ln">{n}</span>
                <span className="txt">{text}</span>
                {hl && <span className="visually-hidden"> (finding)</span>}
              </span>
            );
          })}
        </pre>
      ) : (
        <p className="muted">No code snippet for this finding.</p>
      )}
      {issue.package_name && (
        <p style={{ marginTop: 12 }}>
          <span className="mono">
            {issue.package_name} {issue.package_version}
          </span>
          {issue.fixed_version ? (
            <>
              {" "}
              → upgrade to <span className="mono">{issue.fixed_version}</span>
            </>
          ) : (
            <span className="muted"> · no fixed version yet</span>
          )}
        </p>
      )}
      {issue.tool === "gitleaks" && (
        <p className="muted" style={{ fontSize: 13, marginTop: 12 }}>
          The secret was masked inside the scanner sandbox. Warden stores only its first 4 characters and a keyed
          fingerprint, so this issue is tracked without keeping the secret.
        </p>
      )}
    </Card>
  );
}

function DetailsCard({ issue }: { issue: Issue }) {
  const { orgId } = useOrgCtx();
  const org = useOrg(orgId);
  const sla = issue.severity !== "info" ? org.data?.sla_days[issue.severity] : undefined;
  const scanLink = (scan: { id: string; created_at: string }) => (
    <Link to={`/orgs/${orgId}/projects/${issue.project_id}/scans?scan=${encodeURIComponent(scan.id)}`}>
      Scan of {formatDateTime(scan.created_at)}
    </Link>
  );
  return (
    <Card title="Details" titleId="details-h">
      <dl className="kv">
        <dt>Assignee</dt>
        <dd>{issue.assignee ? userName(issue.assignee) : <span className="muted">Unassigned</span>}</dd>
        <dt>Due</dt>
        <dd>
          {issue.due_at ? (
            <>
              <span className={issue.past_sla ? "danger-text" : undefined}>{formatDate(issue.due_at)}</span>
              {sla !== undefined && (
                <span className="muted">
                  {" "}
                  ({SEVERITY_LABELS[issue.severity]}: {sla} days)
                </span>
              )}
            </>
          ) : (
            <span className="muted">No SLA</span>
          )}
        </dd>
        <dt>Scanner</dt>
        <dd>{TOOL_LABELS[issue.tool]}</dd>
        <dt>Rule</dt>
        <dd className="mono" style={{ fontSize: 13 }}>
          {issue.rule_id}
        </dd>
        {issue.cwe.length > 0 && (
          <>
            <dt>CWE</dt>
            <dd>{issue.cwe.join(", ")}</dd>
          </>
        )}
        {issue.cve.length > 0 && (
          <>
            <dt>CVE</dt>
            <dd className="mono" style={{ fontSize: 13 }}>
              {issue.cve.join(", ")}
            </dd>
          </>
        )}
        {issue.package_name && (
          <>
            <dt>Package</dt>
            <dd className="mono" style={{ fontSize: 13 }}>
              {issue.package_name} {issue.package_version}
              {issue.fixed_version && ` → ${issue.fixed_version}`}
            </dd>
          </>
        )}
        <dt>First seen</dt>
        <dd>{scanLink(issue.first_seen_scan)}</dd>
        <dt>Last seen</dt>
        <dd>{scanLink(issue.last_seen_scan)}</dd>
        <dt>Occurrences</dt>
        <dd>
          {issue.occurrences} scan{issue.occurrences === 1 ? "" : "s"}
        </dd>
      </dl>
    </Card>
  );
}

function WorkflowCard({ status }: { status: IssueStatus }) {
  const steps = workflowSteps(status);
  const offPath = status === "false_positive" || status === "risk_accepted";
  return (
    <Card title="Workflow" titleId="wf-h">
      <ol className="steps">
        {steps.map((s) => (
          <li key={s.status} className={`step ${s.state}`} aria-current={s.state === "current" ? "step" : undefined}>
            <span className="dot" aria-hidden="true" />
            <span>
              {s.label}
              {s.hint && <span className="muted" style={{ fontWeight: 400 }}> · {s.hint}</span>}
              {s.state === "done" && <span className="visually-hidden"> (done)</span>}
            </span>
          </li>
        ))}
      </ol>
      {offPath && (
        <p style={{ marginTop: 12, fontSize: 13 }}>
          Closed as <strong>{STATUS_LABELS[status]}</strong> through an approved exception.
          {status === "risk_accepted" && " It reopens by itself when the acceptance ends."}
        </p>
      )}
    </Card>
  );
}

function statusText(v: string | null): string {
  if (!v) return "–";
  return v in STATUS_LABELS ? STATUS_LABELS[v as IssueStatus] : v;
}

/** One history line. Values from the server are shown as text. */
export function describeEvent(e: IssueEvent): { who: string; what: string } {
  const who = e.actor ? userName(e.actor) : "";
  switch (e.type) {
    case "created":
      return { who: "Created", what: "from a scan" };
    case "status_changed":
      return { who: who || "Status", what: `${who ? "changed status " : "changed "}from ${statusText(e.from_value)} to ${statusText(e.to_value)}` };
    case "assigned":
      return { who, what: e.to_value ? `assigned to ${e.to_value}` : "removed the assignee" };
    case "seen_again":
      return { who: "Seen again", what: "in a scan" };
    case "severity_changed":
      return { who: who || "Severity", what: `changed from ${e.from_value ?? "–"} to ${e.to_value ?? "–"}` };
    case "commented":
      return { who, what: "commented" };
    case "exception_requested":
      return { who, what: `requested an exception${e.to_value ? ` (${statusText(e.to_value)})` : ""}` };
    case "exception_decided":
      return { who, what: `decided the exception${e.to_value ? `: ${e.to_value}` : ""}` };
    default:
      return { who, what: String(e.type) };
  }
}

function HistoryCard({ issue }: { issue: Issue }) {
  const { orgId } = useOrgCtx();
  const events = useIssueEvents(orgId, issue.id);
  return (
    <Card title="History" titleId="hist-h">
      {events.isPending ? (
        <SkeletonBlock label="history" lines={3} />
      ) : events.isError ? (
        <ActionError always error={events.error} />
      ) : events.data.length === 0 ? (
        <p className="muted">No history yet.</p>
      ) : (
        <ol className="timeline">
          {events.data.map((e) => {
            const d = describeEvent(e);
            return (
              <li key={e.id}>
                <span className="bar" aria-hidden="true" />
                <span>
                  <strong>{d.who}</strong> {d.what}
                  {e.note && <span className="prose"> “{e.note}”</span>}
                  <span className="muted">
                    {" "}
                    · {relativeTime(e.created_at)}
                    {!e.actor && " · system"}
                  </span>
                </span>
              </li>
            );
          })}
        </ol>
      )}
    </Card>
  );
}

function Comments({ issue, projectRole }: { issue: Issue; projectRole: ProjectRole | null | undefined }) {
  const { orgId, org } = useOrgCtx();
  const comments = useIssueComments(orgId, issue.id);
  const add = useAddComment(orgId, issue.id);
  const [body, setBody] = useState("");
  const allowed = canComment(org.role, projectRole);

  async function submit(e: FormEvent<HTMLFormElement>) {
    e.preventDefault();
    const form = e.currentTarget;
    const text = body.trim();
    if (!text) return;
    const ok = await add.mutateAsync(text).then(
      () => true,
      () => false,
    );
    if (ok) setBody("");
    else focusFirstInvalid(form);
  }

  return (
    <Card title="Comments" titleId="comments-h">
      <div className="stack" style={{ gap: 16 }}>
        {comments.isPending ? (
          <SkeletonBlock label="comments" lines={2} />
        ) : comments.isError ? (
          <ActionError always error={comments.error} />
        ) : comments.data.length === 0 ? (
          <p className="muted">No comments yet.</p>
        ) : (
          <ul className="stack" style={{ listStyle: "none", margin: 0, padding: 0, gap: 14 }}>
            {comments.data.map((c) => (
              <li key={c.id} className="comment">
                <span className="avatar light" aria-hidden="true">
                  {initials(userName(c.author))}
                </span>
                <div style={{ minWidth: 0 }}>
                  <div>
                    <strong>{userName(c.author)}</strong>{" "}
                    <span className="muted" style={{ fontSize: 12 }}>
                      {relativeTime(c.created_at)}
                      {c.edited_at && " · edited"}
                    </span>
                  </div>
                  {/* User input: rendered as plain text. */}
                  <p className="body">{c.body}</p>
                </div>
              </li>
            ))}
          </ul>
        )}
        {allowed && (
          <form className="form-grid" onSubmit={submit} noValidate>
            <TextArea
              label="Add a comment"
              placeholder="Write a comment. Never paste secrets here."
              hint="Everyone on the project can read comments, and they are kept in the history. Never paste a secret, token or password."
              value={body}
              maxLength={10000}
              onChange={(e) => setBody(e.target.value)}
              error={fieldErrors(add.error).body}
            />
            {!fieldErrors(add.error).body && <ActionError error={add.error} />}
            <div className="row" style={{ justifyContent: "flex-end" }}>
              <Button type="submit" variant="primary" disabled={!body.trim()} busy={add.isPending}>
                Comment
              </Button>
            </div>
          </form>
        )}
      </div>
    </Card>
  );
}

// ---- Actions ----

type OpenDialog = { kind: "assign"; via: "transition" | "bulk" } | { kind: "reason"; to: IssueStatus } | { kind: "exception" } | null;

function IssueActions({
  issue,
  disabled,
  onConflict,
}: {
  issue: Issue;
  disabled: boolean;
  onConflict: (err: unknown, to?: IssueStatus) => void;
}) {
  const { orgId } = useOrgCtx();
  const transition = useTransitionIssue(orgId, issue.id);
  const [dialog, setDialog] = useState<OpenDialog>(null);
  const actions = issueActions(issue);
  if (actions.length === 0) return null;

  function run(a: IssueAction) {
    switch (a.kind) {
      case "transition":
        if (a.needsReason) setDialog({ kind: "reason", to: a.to });
        else
          transition.mutate(
            { to: a.to, version: issue.version },
            {
              onSuccess: () => showToast({ tone: "success", message: `${issue.key} moved to ${STATUS_LABELS[a.to]}.` }),
              onError: (err) => {
                if (isConflict(err)) onConflict(err, a.to);
              },
            },
          );
        break;
      case "assign":
        setDialog({ kind: "assign", via: a.via });
        break;
      case "request_exception":
        setDialog({ kind: "exception" });
        break;
      case "exception_pending":
        break;
    }
  }

  const close = () => setDialog(null);
  return (
    <div className="stack" style={{ gap: 8, alignItems: "flex-end" }}>
      <div className="actions row issue-actions" style={{ gap: 12, justifyContent: "flex-end" }}>
        {actions.map((a) =>
          a.kind === "exception_pending" ? (
            <ButtonLink key="pending" to={`/orgs/${orgId}/exceptions?tab=pending&id=${encodeURIComponent(a.exceptionId)}`}>
              Exception requested
            </ButtonLink>
          ) : (
            <Button
              key={a.kind === "transition" ? a.to : a.kind}
              variant={a.kind === "transition" && a.primary ? "primary" : "ghost"}
              onClick={() => run(a)}
              disabled={disabled}
              busy={a.kind === "transition" && transition.isPending && transition.variables?.to === a.to}
            >
              {a.kind === "transition" ? a.label : a.kind === "assign" ? a.label : "Request exception"}
            </Button>
          ),
        )}
      </div>
      {!isConflict(transition.error) && (
        <div style={{ maxWidth: 520 }}>
          <ActionError error={transition.error} />
        </div>
      )}

      <Dialog open={dialog?.kind === "assign"} onClose={close} title={issue.assignee ? "Reassign issue" : "Assign issue"}>
        {dialog?.kind === "assign" && (
          <AssignForm
            issues={[issue]}
            version={dialog.via === "transition" ? issue.version : undefined}
            onDone={close}
            onConflict={(err) => {
              close();
              onConflict(err, "assigned");
            }}
          />
        )}
      </Dialog>
      <Dialog open={dialog?.kind === "reason"} onClose={close} title="Reopen issue" description="Say why this is not a false positive after all.">
        {dialog?.kind === "reason" && (
          <ReasonForm
            issue={issue}
            to={dialog.to}
            onDone={close}
            onConflict={(err) => {
              close();
              onConflict(err, dialog.to);
            }}
          />
        )}
      </Dialog>
      <Dialog open={dialog?.kind === "exception"} onClose={close} title="Request an exception">
        {dialog?.kind === "exception" && <ExceptionForm issue={issue} onDone={close} />}
      </Dialog>
    </div>
  );
}

function ReasonForm({
  issue,
  to,
  onDone,
  onConflict,
}: {
  issue: Issue;
  to: IssueStatus;
  onDone: () => void;
  onConflict: (err: unknown) => void;
}) {
  const { orgId } = useOrgCtx();
  const transition = useTransitionIssue(orgId, issue.id);
  const [reason, setReason] = useState("");

  async function submit(e: FormEvent) {
    e.preventDefault();
    if (!reason.trim()) return;
    const ok = await transition.mutateAsync({ to, version: issue.version, reason: reason.trim() }).then(
      () => true,
      (err: unknown) => {
        if (isConflict(err)) onConflict(err);
        return false;
      },
    );
    if (ok) {
      showToast({ tone: "success", message: `${issue.key} moved to ${STATUS_LABELS[to]}.` });
      onDone();
    }
  }

  return (
    <form className="form-grid" onSubmit={submit}>
      <TextArea
        label="Reason"
        value={reason}
        onChange={(e) => setReason(e.target.value)}
        maxLength={2000}
        required
        error={fieldErrors(transition.error).reason}
      />
      {!isConflict(transition.error) && <ActionError error={transition.error} />}
      <div className="dialog-actions">
        <Button onClick={onDone}>Cancel</Button>
        <Button type="submit" variant="primary" disabled={!reason.trim()} busy={transition.isPending}>
          Reopen issue
        </Button>
      </div>
    </form>
  );
}

export const MAX_RISK_DAYS = 180;
export const MIN_REASON = 20;

function ExceptionForm({ issue, onDone }: { issue: Issue; onDone: () => void }) {
  const { orgId } = useOrgCtx();
  const request = useRequestException(orgId, issue.id);
  const [type, setType] = useState<ExceptionType>("false_positive");
  const [reason, setReason] = useState("");
  const now = new Date();
  const minDate = toDateInput(addDays(now, 1));
  const lastDay = addDays(now, MAX_RISK_DAYS);
  const maxDate = toDateInput(lastDay);
  const [until, setUntil] = useState(toDateInput(addDays(now, 90)));
  const [touched, setTouched] = useState(false);
  const server = fieldErrors(request.error);
  const count = reason.trim().length;

  const reasonError = touched && count < MIN_REASON ? `Write at least ${MIN_REASON} characters.` : server.reason;
  const untilError =
    type === "risk_accepted" && touched && (until < minDate || until > maxDate || !fromDateInput(until))
      ? `Pick a date from tomorrow to ${formatDate(lastDay.toISOString())}.`
      : server.expires_at;

  async function submit(e: FormEvent<HTMLFormElement>) {
    e.preventDefault();
    const form = e.currentTarget;
    setTouched(true);
    const expires = type === "risk_accepted" ? fromDateInput(until) : null;
    if (count < MIN_REASON || (type === "risk_accepted" && (!expires || until < minDate || until > maxDate))) {
      focusFirstInvalid(form);
      return;
    }
    const ok = await request
      .mutateAsync({ type, reason: reason.trim(), ...(expires ? { expires_at: expires } : {}) })
      .then(
        () => true,
        () => false,
      );
    if (ok) {
      showToast({ tone: "success", message: `Exception requested for ${issue.key}. A security lead will decide.` });
      onDone();
    } else focusFirstInvalid(form);
  }

  return (
    <form className="form-grid" onSubmit={submit} noValidate>
      <p className="row" style={{ gap: 8 }}>
        <span className="mono muted">{issue.key}</span>
        <strong>{issue.title}</strong>
        <SeverityBadge severity={issue.severity} />
      </p>
      <ActionError
        error={request.error && Object.keys(server).length === 0 ? request.error : null}
        overrides={{
          CONFLICT: "This issue already has a pending exception request.",
          INVALID_TRANSITION: "Exceptions can only be requested for active issues.",
        }}
      />
      <fieldset>
        <legend>Type</legend>
        <div className="choices">
          {(["false_positive", "risk_accepted"] as ExceptionType[]).map((t) => (
            <label key={t} className="choice-card">
              <input type="radio" name="exc-type" checked={type === t} onChange={() => setType(t)} />
              <span>
                <strong>{EXCEPTION_TYPE_LABELS[t]}</strong>
                <span className="desc">
                  {t === "false_positive"
                    ? "The finding is wrong. Closed for good if approved."
                    : "It's real, but we accept it until a date. Then it reopens."}
                </span>
              </span>
            </label>
          ))}
        </div>
      </fieldset>
      <TextArea
        label="Reason"
        hint={
          <span className="row-between" style={{ display: "flex" }}>
            <span>At least {MIN_REASON} characters. The security lead sees this. Never paste a secret here.</span>
            <span aria-live="polite">
              {count} character{count === 1 ? "" : "s"}
            </span>
          </span>
        }
        value={reason}
        onChange={(e) => setReason(e.target.value)}
        maxLength={5000}
        error={reasonError}
        required
      />
      {type === "risk_accepted" && (
        <TextField
          label="Accepted until"
          type="date"
          min={minDate}
          max={maxDate}
          value={until}
          onChange={(e) => setUntil(e.target.value)}
          hint={`Up to ${formatDate(lastDay.toISOString())} (${MAX_RISK_DAYS} days from today). The issue reopens by itself on that date.`}
          error={untilError}
          required
        />
      )}
      <p className="muted" style={{ fontSize: 13 }}>
        A security lead decides; you can't decide your own request. The issue keeps its status until then.
      </p>
      <div className="dialog-actions">
        <Button onClick={onDone}>Cancel</Button>
        <Button type="submit" variant="primary" busy={request.isPending}>
          Send request
        </Button>
      </div>
    </form>
  );
}
