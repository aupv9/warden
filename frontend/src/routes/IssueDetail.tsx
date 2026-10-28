import { useEffect, useId, useMemo, useRef, useState } from "react";
import type { FormEvent } from "react";
import { Link, useSearchParams } from "react-router";
import { fieldErrors, isNotFound } from "../api/errors";
import { useRequestException } from "../api/hooks/exceptions";
import { useAddComment, useIssue, useIssueComments, useIssueEvents, useTransitionIssue } from "../api/hooks/issues";
import { useOrg } from "../api/hooks/orgs";
import { useProject } from "../api/hooks/projects";
import type { ExceptionType, Issue, IssueEvent, IssueStatus, ProjectRole } from "../api/types";
import { Avatar } from "../components/Avatar";
import { SeverityMark, StatusMark } from "../components/Badges";
import { Button, ButtonLink } from "../components/Button";
import { Card } from "../components/Card";
import { Dialog } from "../components/Dialog";
import { focusFirstInvalid, TextArea, TextField } from "../components/Field";
import { BackIcon, CheckIcon, ChevronIcon, CloseIcon, LockIcon, RefreshIcon } from "../components/Icons";
import { PageHeader } from "../components/PageHeader";
import { ActionError, ErrorState, Loading, NotFoundState, Skeleton, SkeletonBlock } from "../components/States";
import { useOrgCtx } from "../layout/OrgLayout";
import {
  addDays,
  dueText,
  EXCEPTION_TYPE_LABELS,
  formatDate,
  formatDateTime,
  fromDateInput,
  relativeTime,
  SEVERITY_LABELS,
  STATUS_LABELS,
  toDateInput,
  TOOL_LABELS,
  userName,
} from "../lib/format";
import { issueActions, workflowSteps } from "../lib/issueActions";
import type { IssueAction } from "../lib/issueActions";
import { formatEpss, isVulnIssue, KEV_CATALOG_URL, licenseOf, nvdUrl, percentileText } from "../lib/intel";
import { maliciousAdvisory, MALICIOUS_REMEDIATION } from "../lib/malicious";
import { issueListHref, parseIssueFilters } from "../lib/issueFilters";
import { canComment } from "../lib/permissions";
import { showToast } from "../lib/toast";
import { usePageTitle } from "../lib/usePageTitle";
import { AssignForm, isConflict } from "./AssignForm";

/** Below 1200 px: the issue as its own page, with a back link to the list it came from (the
 *  list's filters travel in the query string). */
export function IssueDetailPage({ issueId }: { issueId: string }) {
  const { orgId } = useOrgCtx();
  const [params] = useSearchParams();
  const back = issueListHref(orgId, parseIssueFilters(params));
  const issue = useIssue(orgId, issueId);
  return (
    <div className="page">
      <PageHeader
        titleAs="div"
        title={
          <nav aria-label="Breadcrumb" className="crumbs">
            <Link to={back} className="back-link">
              <BackIcon /> Issues
            </Link>
            <span className="crumb-sep" aria-hidden="true">
              /
            </span>
            <span className="mono">{issue.data?.key ?? "…"}</span>
          </nav>
        }
      />
      <div className="page-body">
        <IssueDetail issueId={issueId} mode="page" backHref={back} />
      </div>
    </div>
  );
}

export interface PaneNav {
  onClose: () => void;
  onPrev?: () => void;
  onNext?: () => void;
  position?: string;
}

/** The issue itself: as a page (narrow screens) or in the split view's right-hand pane. */
export function IssueDetail({
  issueId,
  mode,
  backHref,
  pane,
  assignSignal = 0,
  autoFocus,
}: {
  issueId: string;
  mode: "page" | "pane";
  backHref: string;
  pane?: PaneNav;
  /** Bumped by the list's "A" shortcut: open the assign dialog if this issue offers it. */
  assignSignal?: number;
  autoFocus?: boolean;
}) {
  const { orgId } = useOrgCtx();
  const issue = useIssue(orgId, issueId);
  usePageTitle(issue.data ? `${issue.data.key} ${issue.data.title}` : "Issue");

  let body;
  if (issue.isError && isNotFound(issue.error)) {
    body = <NotFoundState backTo={backHref} backLabel="Back to issues" />;
  } else if (issue.isPending) {
    body = (
      <Loading label="issue">
        <div className="stack" style={{ gap: 14 }}>
          <Skeleton width="40%" height={12} />
          <Skeleton width="70%" height={22} />
          <div className="row">
            <Skeleton width={64} height={16} />
            <Skeleton width={76} height={16} />
            <Skeleton width={140} height={16} />
          </div>
          <Skeleton height={56} />
          <div className="card stack" style={{ gap: 10 }}>
            <Skeleton width="30%" />
            <Skeleton height={88} style={{ background: "var(--code-bg)", opacity: 0.85 }} />
          </div>
        </div>
      </Loading>
    );
  } else if (issue.isError) {
    body = <ErrorState error={issue.error} onRetry={() => void issue.refetch()} what="this issue" />;
  } else {
    body = (
      <IssueView key={issue.data.id} issue={issue.data} mode={mode} reload={() => issue.refetch()} assignSignal={assignSignal} autoFocus={autoFocus} />
    );
  }

  if (mode === "page") return body;
  return (
    <>
      <div className="pane-bar">
        <div className="row" style={{ gap: 2 }}>
          <button type="button" className="icon-btn sm" aria-label="Previous issue (K)" onClick={pane?.onPrev} disabled={!pane?.onPrev}>
            <ChevronIcon up />
          </button>
          <button type="button" className="icon-btn sm" aria-label="Next issue (J)" onClick={pane?.onNext} disabled={!pane?.onNext}>
            <ChevronIcon />
          </button>
          {pane?.position && <span className="faint num">{pane.position}</span>}
        </div>
        <button type="button" className="icon-btn sm" aria-label="Close issue (Esc)" onClick={pane?.onClose}>
          <CloseIcon />
        </button>
      </div>
      <div className="pane-body">{body}</div>
    </>
  );
}

function IssueView({
  issue,
  mode,
  reload,
  assignSignal,
  autoFocus,
}: {
  issue: Issue;
  mode: "page" | "pane";
  reload: () => Promise<unknown>;
  assignSignal: number;
  autoFocus?: boolean;
}) {
  const { orgId } = useOrgCtx();
  const project = useProject(orgId, issue.project_id);
  const due = dueText(issue.due_at);
  const titleId = useId();
  const headingRef = useRef<HTMLHeadingElement>(null);
  // A stale-version or no-longer-valid change: actions stay disabled until "Reload issue".
  const [conflict, setConflict] = useState<{ code: string; to?: IssueStatus } | null>(null);
  const [reloading, setReloading] = useState(false);

  useEffect(() => {
    if (autoFocus) headingRef.current?.focus({ preventScroll: true });
  }, [autoFocus]);

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

  const Heading = mode === "page" ? "h1" : "h2";
  return (
    <article className="issue-detail" aria-labelledby={titleId}>
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

      <header className="detail-head">
        <div className="detail-titles">
          <p className="detail-meta">
            <span className="mono">{issue.key}</span>
            {project.data && (
              <>
                {" · "}
                <Link to={`/orgs/${orgId}/projects/${project.data.id}/issues`}>{project.data.name}</Link>
              </>
            )}
            {" · "}first seen {formatDate(issue.first_seen_scan.created_at)}
          </p>
          <Heading id={titleId} className="detail-title" ref={headingRef} tabIndex={-1}>
            {issue.title}
          </Heading>
          <div className="detail-sub">
            <SeverityMark severity={issue.severity} />
            <StatusMark status={issue.status} />
            {issue.due_at && (
              <span className={due.overdue || issue.past_sla ? "danger-text" : "muted"}>
                SLA: {due.text} <span className="faint-in">(due {formatDate(issue.due_at)})</span>
              </span>
            )}
          </div>
        </div>
        <IssueActions issue={issue} disabled={!!conflict} onConflict={onConflict} assignSignal={assignSignal} />
      </header>

      <Stepper issue={issue} />

      <div className="detail-grid">
        <div className="stack detail-main">
          <MaliciousCard issue={issue} />
          <ExploitCard issue={issue} />
          <WhereCard issue={issue} />
          {issue.description && (
            <Card title="What was found" titleId={`${titleId}-desc`}>
              <p className="prose">{issue.description}</p>
            </Card>
          )}
          <Card title="How to fix" titleId={`${titleId}-fix`}>
            {issue.remediation ? (
              <p className="prose">{issue.remediation}</p>
            ) : maliciousAdvisory(issue) ? (
              <p className="prose">{MALICIOUS_REMEDIATION}</p>
            ) : (
              <p className="muted">The scanner gave no fix advice for this rule.</p>
            )}
          </Card>
          <Comments issue={issue} projectRole={project.data?.my_role} />
        </div>
        <div className="stack detail-side">
          <DetailsCard issue={issue} />
          <ActivityCard issue={issue} />
        </div>
      </div>
    </article>
  );
}

/** The main workflow path as a horizontal stepper (vertical on phones). */
function Stepper({ issue }: { issue: Issue }) {
  const steps = workflowSteps(issue.status);
  const offPath = issue.status === "false_positive" || issue.status === "risk_accepted";
  const who = issue.assignee ? userName(issue.assignee) : undefined;
  return (
    <section className="stepper-card" aria-label="Workflow">
      <ol className="stepper">
        {steps.map((s, i) => {
          const hint = (s.status === "assigned" || s.status === "in_progress") && who && s.state !== "todo" ? who : s.hint;
          return (
            <li key={s.status} className={`step ${s.state}`} aria-current={s.state === "current" ? "step" : undefined}>
              <span className="step-dot" aria-hidden="true">
                {s.state === "done" ? <CheckIcon size={12} /> : i + 1}
              </span>
              <span className="step-text">
                <span className="step-label">{s.label}</span>
                {hint && <span className="step-hint">{hint}</span>}
                {s.state === "done" && <span className="visually-hidden"> (done)</span>}
              </span>
            </li>
          );
        })}
      </ol>
      {offPath && (
        <p className="stepper-note">
          Closed as <strong>{STATUS_LABELS[issue.status]}</strong> through an approved exception.
          {issue.status === "risk_accepted" && " It reopens by itself when the acceptance ends."}
        </p>
      )}
    </section>
  );
}

/** v0.3: what CISA KEV and FIRST EPSS say about the issue's CVEs. Ranking information only:
 *  the severity and status above don't change because of it. */
function ExploitCard({ issue }: { issue: Issue }) {
  const epss = formatEpss(issue.epss);
  if (!isVulnIssue(issue) || (!issue.kev && !epss)) return null;
  const pct = percentileText(issue.epss_percentile);
  const titleId = `exploit-${issue.id}`;
  return (
    <Card title="Exploitation" titleId={titleId} className={issue.kev ? "exploit-card is-kev" : "exploit-card"}>
      <div className="stack" style={{ gap: 12 }}>
        {issue.kev && (
          <div className="kev-block">
            <span className="tag tag-danger kev-tag" aria-hidden="true">
              KEV
            </span>
            <div className="stack" style={{ gap: 4 }}>
              <strong>Known exploited (CISA KEV)</strong>
              <span>
                CISA lists {issue.cve.length === 1 ? "this CVE" : "one of these CVEs"} as exploited in the wild
                {issue.kev_added ? `, added to the catalog on ${formatDate(`${issue.kev_added}T00:00:00`)}` : ""}.
              </span>
              {issue.kev_ransomware && (
                <span className="danger-text">
                  <strong>Used in ransomware campaigns</strong>, according to CISA.
                </span>
              )}
              <span>
                <a href={KEV_CATALOG_URL} target="_blank" rel="noopener noreferrer">
                  CISA KEV catalog<span className="visually-hidden"> (opens in a new tab)</span>
                </a>
              </span>
            </div>
          </div>
        )}
        {epss && (
          <p className="epss-line">
            <span className="epss-value num">{epss}</span>
            <span>
              chance of exploitation in the next 30 days (FIRST EPSS)
              {pct && <span className="muted">, {pct}</span>}.
            </span>
          </p>
        )}
        <p className="faint small">KEV and EPSS help decide what to fix first. They don't change the severity or the SLA.</p>
      </div>
    </Card>
  );
}

/** v0.4: an OSV malicious-package advisory lists this package version. Shown first: unlike a
 *  vulnerability, there is no safe version of the same release to upgrade to. The OSV link is
 *  built only from a well-formed MAL id (lib/malicious.ts); package names stay text. */
function MaliciousCard({ issue }: { issue: Issue }) {
  const advisory = maliciousAdvisory(issue);
  if (!advisory) return null;
  const titleId = `malicious-${issue.id}`;
  return (
    <Card title="Malicious package" titleId={titleId} className="malicious-card">
      <div className="stack" style={{ gap: 12 }}>
        <div className="kev-block mal-block">
          <span className="tag mal-tag" aria-hidden="true">
            Malicious
          </span>
          <div className="stack" style={{ gap: 4 }}>
            <strong>
              {issue.package_name ? (
                <>
                  <span className="mono">
                    {issue.package_name} {issue.package_version}
                  </span>{" "}
                  is listed as malicious
                </>
              ) : (
                "This package version is listed as malicious"
              )}
            </strong>
            <span>
              Installing it can run the attacker's code wherever it was installed: developer machines, CI runners and the images built
              from them.
            </span>
            <span>
              Advisory{" "}
              {advisory.url ? (
                <a href={advisory.url} target="_blank" rel="noopener noreferrer" className="mono">
                  {advisory.id}
                  <span className="visually-hidden"> on OSV (opens in a new tab)</span>
                </a>
              ) : (
                <span className="mono">{advisory.id}</span>
              )}
            </span>
          </div>
        </div>
        <p className="mal-fix">
          <strong>{MALICIOUS_REMEDIATION}</strong> Treat secrets the build or the installing machines could read as exposed.
        </p>
        <p className="faint small">
          The advisory raised this issue as Critical. It moves to Fixed when the package is gone from the next scan; advisories never
          close an issue.
        </p>
      </div>
    </Card>
  );
}

function WhereCard({ issue }: { issue: Issue }) {
  const lines = issue.snippet ? issue.snippet.replace(/\n$/, "").split("\n") : [];
  const first = issue.start_line ?? 1;
  const last = issue.end_line ?? issue.start_line ?? 0;
  const where = issue.file_path ?? issue.package_name ?? "";
  const license = licenseOf(issue);
  const malicious = !!maliciousAdvisory(issue);
  return (
    <Card
      title="Where"
      titleId={`where-${issue.id}`}
      actions={
        where ? (
          <span className="mono faint where-path">
            {where}
            {issue.start_line ? `:${issue.start_line}` : ""}
          </span>
        ) : undefined
      }
    >
      <div className="stack" style={{ gap: 12 }}>
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
        ) : issue.package_name ? null : (
          <p className="muted">No code snippet for this finding.</p>
        )}
        {license && (
          // v0.3: a license-policy issue: the license, not a version to upgrade to.
          <p className="where-line">
            License <span className="mono">{license.spdx}</span>
            {license.category && <span className="muted"> ({license.category})</span>}
            {issue.package_name && (
              <>
                {" "}
                in <span className="mono">{issue.package_name} {issue.package_version}</span>
              </>
            )}
          </p>
        )}
        {issue.package_name && !license && (
          <p className="where-line">
            {issue.target && (
              <>
                Image <span className="mono">{issue.target}</span>
                {issue.file_path && (
                  <>
                    {" · "}
                    <span className="mono">{issue.file_path}</span>
                  </>
                )}
                {" · "}
              </>
            )}
            <span className="mono">
              {issue.package_name} {issue.package_version}
            </span>
            {malicious ? (
              <span className="muted"> · remove this version</span>
            ) : issue.fixed_version ? (
              <>
                {" "}
                → upgrade to <span className="mono">{issue.fixed_version}</span>
              </>
            ) : (
              <span className="muted"> · no fixed version yet</span>
            )}
          </p>
        )}
        {issue.target && license && (
          <p className="where-line">
            Image <span className="mono">{issue.target}</span>
            {issue.file_path && (
              <>
                {" · "}
                <span className="mono">{issue.file_path}</span>
              </>
            )}
          </p>
        )}
        {license && (
          <p className="muted small">
            From your org's license policy (Settings). License data comes from lockfiles and image packages, so it is only as
            complete as they are.
          </p>
        )}
        {issue.tool === "gitleaks" && (
          <p className="note">
            <LockIcon size={14} />
            <span>
              The secret was masked inside the scanner sandbox. Warden stores only its first 4 characters and a keyed
              fingerprint, so this issue is tracked without keeping the secret.
            </span>
          </p>
        )}
      </div>
    </Card>
  );
}

function DetailsCard({ issue }: { issue: Issue }) {
  const { orgId } = useOrgCtx();
  const org = useOrg(orgId);
  const sla = issue.severity !== "info" ? org.data?.sla_days[issue.severity] : undefined;
  const license = licenseOf(issue);
  const advisory = maliciousAdvisory(issue);
  const scanLink = (scan: { id: string; created_at: string }) => (
    <Link to={`/orgs/${orgId}/projects/${issue.project_id}/scans?scan=${encodeURIComponent(scan.id)}`}>
      Scan of {formatDateTime(scan.created_at)}
    </Link>
  );
  return (
    <Card title="Details" titleId={`details-${issue.id}`}>
      <dl className="kv">
        <dt>Assignee</dt>
        <dd>
          {issue.assignee ? (
            <span className="person">
              <Avatar name={userName(issue.assignee)} />
              {userName(issue.assignee)}
            </span>
          ) : (
            <span className="muted">Unassigned</span>
          )}
        </dd>
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
        <dd className="mono">{issue.rule_id}</dd>
        {advisory && (
          <>
            <dt>Advisory</dt>
            <dd className="mono">
              {advisory.url ? (
                <a href={advisory.url} target="_blank" rel="noopener noreferrer">
                  {advisory.id}
                  <span className="visually-hidden"> on OSV (opens in a new tab)</span>
                </a>
              ) : (
                advisory.id
              )}
            </dd>
          </>
        )}
        {issue.cwe.length > 0 && (
          <>
            <dt>CWE</dt>
            <dd>{issue.cwe.join(", ")}</dd>
          </>
        )}
        {issue.cve.length > 0 && (
          <>
            <dt>CVE</dt>
            <dd className="mono cve-list">
              {issue.cve.map((id, n) => {
                // Only a well-formed id becomes part of a URL; anything else stays text.
                const href = nvdUrl(id);
                return (
                  <span key={`${id}-${n}`}>
                    {n > 0 && ", "}
                    {href ? (
                      <a href={href} target="_blank" rel="noopener noreferrer">
                        {id}
                        <span className="visually-hidden"> on NVD (opens in a new tab)</span>
                      </a>
                    ) : (
                      id
                    )}
                  </span>
                );
              })}
            </dd>
          </>
        )}
        {license && (
          <>
            <dt>License</dt>
            <dd>
              <span className="mono">{license.spdx}</span>
              {license.category && <span className="muted"> ({license.category})</span>}
            </dd>
          </>
        )}
        {issue.target && (
          <>
            <dt>Image</dt>
            <dd className="mono">{issue.target}</dd>
          </>
        )}
        {issue.package_name && (
          <>
            <dt>Package</dt>
            <dd className="mono">
              {issue.package_name} {issue.package_version}
              {issue.fixed_version && ` → ${issue.fixed_version}`}
            </dd>
          </>
        )}
        {isVulnIssue(issue) && (issue.kev || issue.epss !== null) && (
          <>
            <dt>Exploitation</dt>
            <dd>
              {[issue.kev ? "Known exploited (KEV)" : null, formatEpss(issue.epss) ? `EPSS ${formatEpss(issue.epss)}` : null]
                .filter(Boolean)
                .join(" · ")}
            </dd>
          </>
        )}
        <dt>First seen</dt>
        <dd>{scanLink(issue.first_seen_scan)}</dd>
        <dt>Last seen</dt>
        <dd>{scanLink(issue.last_seen_scan)}</dd>
        <dt>Occurrences</dt>
        <dd className="num">
          {issue.occurrences} scan{issue.occurrences === 1 ? "" : "s"}
        </dd>
      </dl>
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
      // v0.4: an issue opened by a malicious-package advisory without a scan carries the
      // server's note ("Found by malicious-package advisory MAL-… (no scan)") instead.
      return { who: "Created", what: e.note ? "" : "from a scan" };
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

function ActivityCard({ issue }: { issue: Issue }) {
  const { orgId } = useOrgCtx();
  const events = useIssueEvents(orgId, issue.id);
  return (
    <Card title="Activity" titleId={`activity-${issue.id}`}>
      {events.isPending ? (
        <SkeletonBlock label="activity" lines={3} />
      ) : events.isError ? (
        <ActionError always error={events.error} />
      ) : events.data.length === 0 ? (
        <p className="muted">No activity yet.</p>
      ) : (
        <ol className="timeline">
          {events.data.map((e) => {
            const d = describeEvent(e);
            return (
              <li key={e.id}>
                <span className="tl-dot" aria-hidden="true" />
                <span>
                  <strong>{d.who}</strong> {d.what}
                  {e.note && <span className="prose"> “{e.note}”</span>}
                  <span className="tl-time">
                    {relativeTime(e.created_at)}
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
    <Card title="Comments" titleId={`comments-${issue.id}`}>
      <div className="stack" style={{ gap: 14 }}>
        {comments.isPending ? (
          <SkeletonBlock label="comments" lines={2} />
        ) : comments.isError ? (
          <ActionError always error={comments.error} />
        ) : comments.data.length === 0 ? (
          <p className="muted">No comments yet.</p>
        ) : (
          <ul className="comments">
            {comments.data.map((c) => (
              <li key={c.id} className="comment">
                <Avatar name={userName(c.author)} size={24} />
                <div style={{ minWidth: 0 }}>
                  <div>
                    <strong>{userName(c.author)}</strong>{" "}
                    <span className="faint">
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
              rows={3}
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
  assignSignal,
}: {
  issue: Issue;
  disabled: boolean;
  onConflict: (err: unknown, to?: IssueStatus) => void;
  assignSignal: number;
}) {
  const { orgId } = useOrgCtx();
  const transition = useTransitionIssue(orgId, issue.id);
  const [dialog, setDialog] = useState<OpenDialog>(null);
  const actions = useMemo(() => issueActions(issue), [issue]);
  const assignAction = actions.find((a): a is Extract<IssueAction, { kind: "assign" }> => a.kind === "assign");

  // The list's "A" shortcut. Only opens the dialog when the payload grants assigning.
  const seen = useRef(assignSignal);
  useEffect(() => {
    if (assignSignal === seen.current) return;
    seen.current = assignSignal;
    if (assignAction && !disabled) setDialog({ kind: "assign", via: assignAction.via });
  }, [assignSignal, assignAction, disabled]);

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
    <div className="detail-actions">
      <div className="issue-actions">
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
              aria-keyshortcuts={a.kind === "assign" ? "A" : undefined}
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
      <p className="dialog-issue">
        <span className="mono faint">{issue.key}</span>
        <strong>{issue.title}</strong>
        <SeverityMark severity={issue.severity} />
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
            <span aria-live="polite" className="num">
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
      <p className="muted small">A security lead decides; you can't decide your own request. The issue keeps its status until then.</p>
      <div className="dialog-actions">
        <Button onClick={onDone}>Cancel</Button>
        <Button type="submit" variant="primary" busy={request.isPending}>
          Send request
        </Button>
      </div>
    </form>
  );
}

