import { useEffect, useMemo, useRef, useState } from "react";
import { Link, useSearchParams } from "react-router";
import { useIssues } from "../api/hooks/issues";
import { useOrgMembers } from "../api/hooks/orgs";
import { useProjects } from "../api/hooks/projects";
import { flattenPages } from "../api/paging";
import { ISSUE_STATUSES, SEVERITIES, TOOLS } from "../api/types";
import type { IssueSort, IssueSummary, OrgMember, Project, Severity, SeverityCounts, Tool } from "../api/types";
import { SeverityBadge, StatusPill } from "../components/Badges";
import { Button } from "../components/Button";
import { Card } from "../components/Card";
import { Dialog } from "../components/Dialog";
import { Select } from "../components/Field";
import type { Option } from "../components/Field";
import { FilterIcon, SearchIcon } from "../components/Icons";
import { Table } from "../components/Table";
import { EmptyState, ErrorState, SkeletonRows } from "../components/States";
import { useOrgCtx } from "../layout/OrgLayout";
import { dueText, location, SEVERITY_LABELS, STATUS_LABELS, TOOL_LABELS, userName } from "../lib/format";
import {
  DEFAULT_FILTERS,
  describeFilters,
  hasActiveFilters,
  issueFiltersToApiQuery,
  issueFiltersToSearch,
  parseIssueFilters,
  toggleSeverity,
} from "../lib/issueFilters";
import type { IssueFilters, StatusFilter } from "../lib/issueFilters";
import { can } from "../lib/permissions";
import { useIsPhone } from "../lib/useMediaQuery";
import { usePageTitle } from "../lib/usePageTitle";
import { AssignForm } from "./AssignForm";
import { NoScansYet } from "./ProjectScans";

const STATUS_OPTIONS: Option[] = [
  { value: "active", label: "Active (open, assigned, in progress, reopened)" },
  ...ISSUE_STATUSES.map((s) => ({ value: s, label: STATUS_LABELS[s] })),
  { value: "all", label: "All statuses" },
];

const SORT_OPTIONS: Option[] = [
  { value: "due_at", label: "Due date" },
  { value: "-severity", label: "Severity" },
  { value: "-updated_at", label: "Recently updated" },
];

const SORT_TEXT: Record<IssueSort, string> = {
  due_at: "Sorted by due date",
  "-severity": "Sorted by severity",
  "-updated_at": "Sorted by last update",
};

export function IssuesPage() {
  usePageTitle("Issues");
  return <IssueList />;
}

/** The issue list. On a project's Issues tab `fixedProject` pins the project filter. */
export function IssueList({ fixedProject }: { fixedProject?: Project }) {
  const { orgId, org, me } = useOrgCtx();
  const phone = useIsPhone();
  const [params, setParams] = useSearchParams();
  const filters = useMemo(() => parseIssueFilters(params), [params]);
  const apiQuery = useMemo(() => issueFiltersToApiQuery(filters, fixedProject?.id), [filters, fixedProject?.id]);
  const issues = useIssues(orgId, apiQuery);
  const projects = useProjects(orgId);
  const members = useOrgMembers(orgId);
  const [selected, setSelected] = useState<Set<string>>(new Set());
  const [assigning, setAssigning] = useState(false);
  const [sheet, setSheet] = useState(false);

  const items = flattenPages(issues.data?.pages);
  const counts = issues.data?.pages[0]?.counts_by_severity;
  const projectById = new Map((projects.data ?? []).map((p) => [p.id, p]));

  // No checkboxes and no bulk assign on phones (DESIGN.md "Phone layout").
  const canAssign =
    !phone &&
    (fixedProject
      ? can("assign_issue", org.role, fixedProject.my_role)
      : can("assign_issue", org.role) || (projects.data ?? []).some((p) => p.my_role === "owner"));

  // A new filter is a new result set: drop the selection.
  useEffect(() => setSelected(new Set()), [apiQuery]);

  function update(next: IssueFilters, replace = false) {
    setParams(issueFiltersToSearch(next), { replace });
  }

  const matchCount = counts ? countMatches(counts, filters.severity) : undefined;
  const selectedIssues = items.filter((i) => selected.has(i.id));
  const filterWords = describeFilters(filters, {
    project: fixedProject?.name ?? (filters.project ? projectById.get(filters.project)?.name : undefined),
    assignee: filters.assignee ? memberName(members.data, filters.assignee, me.id) : undefined,
  });
  const otherFilterCount =
    (filters.project && !fixedProject ? 1 : 0) + (filters.status !== "active" ? 1 : 0) + (filters.assignee ? 1 : 0) + (filters.tool ? 1 : 0);

  const otherFilters = (
    <>
      {!fixedProject && (
        <Select
          aria-label="Project"
          label={phone ? "Project" : undefined}
          dense
          value={filters.project}
          onChange={(e) => update({ ...filters, project: e.target.value })}
          options={[
            { value: "", label: "All projects" },
            ...(projects.data ?? []).map((p) => ({ value: p.id, label: `${p.key} · ${p.name}` })),
          ]}
        />
      )}
      <Select
        aria-label="Status"
        label={phone ? "Status" : undefined}
        dense
        value={filters.status}
        onChange={(e) => update({ ...filters, status: e.target.value as StatusFilter })}
        options={STATUS_OPTIONS}
      />
      <Select
        aria-label="Assignee"
        label={phone ? "Assignee" : undefined}
        dense
        value={filters.assignee}
        onChange={(e) => update({ ...filters, assignee: e.target.value })}
        options={[
          { value: "", label: "Any assignee" },
          { value: "me", label: "Assigned to me" },
          { value: "none", label: "Unassigned" },
          ...(members.data ?? [])
            .filter((m) => m.user.id !== me.id)
            .map((m) => ({ value: m.user.id, label: userName(m.user) })),
        ]}
      />
      <Select
        aria-label="Scanner"
        label={phone ? "Scanner" : undefined}
        dense
        value={filters.tool}
        onChange={(e) => update({ ...filters, tool: e.target.value as Tool | "" })}
        options={[{ value: "", label: "All scanners" }, ...TOOLS.map((t) => ({ value: t, label: TOOL_LABELS[t] }))]}
      />
    </>
  );

  const sortSelect = (
    <Select
      aria-label="Sort by"
      dense
      value={filters.sort}
      onChange={(e) => update({ ...filters, sort: e.target.value as IssueSort })}
      options={SORT_OPTIONS.map((o) => ({ ...o, label: phone ? o.label : `Sort: ${o.label.toLowerCase()}` }))}
    />
  );

  const noScanYet = fixedProject && !fixedProject.last_scan;

  return (
    <>
      {!fixedProject && (
        <header className="page-head">
          <div className="titles">
            <h1>Issues</h1>
            <p className="muted">One issue per finding, kept across scans. Fixed and reopened automatically when you scan again.</p>
          </div>
        </header>
      )}

      <section className="card filters" aria-label="Filters">
        <div className="row">
          <SearchBox value={filters.q} onChange={(q) => update({ ...filters, q }, true)} />
          {phone ? (
            <div className="row" style={{ width: "100%", flexWrap: "nowrap" }}>
              <Button onClick={() => setSheet(true)} style={{ flex: 1 }}>
                <FilterIcon /> Filters{otherFilterCount ? ` · ${otherFilterCount}` : ""}
              </Button>
              <div style={{ flex: 1 }}>{sortSelect}</div>
            </div>
          ) : (
            <>
              {otherFilters}
              {sortSelect}
            </>
          )}
        </div>
        <div className="row chip-scroll" role="group" aria-label="Severity">
          <span className="stat-label desktop-only" aria-hidden="true">
            Severity
          </span>
          {SEVERITIES.filter((s) => s !== "info" || (counts?.info ?? 0) > 0 || filters.severity.includes("info")).map((s) => (
            <button key={s} type="button" className="chip" aria-pressed={filters.severity.includes(s)} onClick={() => update(toggleSeverity(filters, s))}>
              {SEVERITY_LABELS[s]}
              {counts && <span> · {counts[s]}</span>}
            </button>
          ))}
          <span className="chip-sep" aria-hidden="true" />
          <button type="button" className="chip" aria-pressed={filters.pastSla} onClick={() => update({ ...filters, pastSla: !filters.pastSla })}>
            Past SLA only
          </button>
        </div>
      </section>

      <Card flush aria-label="Results" className={phone ? "card-plain" : undefined}>
        <div className="card-head">
          <p aria-live="polite">
            {matchCount === undefined ? (
              <span className="muted">Loading issues…</span>
            ) : (
              <>
                <strong>{`${matchCount} issue${matchCount === 1 ? "" : "s"}`}</strong>{" "}
                {phone ? <span className="muted">· {filterWords.join(", ")}</span> : "match"}
              </>
            )}
          </p>
          {phone && <span className="muted">{SORT_TEXT[filters.sort].replace("Sorted ", "")}</span>}
          {canAssign && (
            <div className="row">
              {selected.size > 0 && <span className="muted">{selected.size} selected</span>}
              <Button size="sm" disabled={selected.size === 0} onClick={() => setAssigning(true)}>
                Assign…
              </Button>
            </div>
          )}
        </div>
        {issues.isPending ? (
          <SkeletonRows label="issues" />
        ) : issues.isError ? (
          <ErrorState error={issues.error} onRetry={() => void issues.refetch()} what="issues" />
        ) : items.length === 0 ? (
          noScanYet && !hasActiveFilters(filters) ? (
            <NoScansYet uploadTo={can("run_scan", org.role, fixedProject.my_role) ? `/orgs/${orgId}/projects/${fixedProject.id}/scans` : undefined} />
          ) : hasActiveFilters({ ...filters, project: fixedProject ? "" : filters.project }) ? (
            <EmptyState
              icon={<SearchIcon size={20} />}
              title="No issues match these filters"
              action={
                <Button onClick={() => update({ ...DEFAULT_FILTERS })}>Clear filters</Button>
              }
            >
              {filterWords.join(" · ")}
            </EmptyState>
          ) : (
            <EmptyState title="No active issues">New findings appear here after a scan.</EmptyState>
          )
        ) : phone ? (
          <ul className="issue-cards">
            {items.map((i) => (
              <li key={i.id}>
                <IssueCard issue={i} />
              </li>
            ))}
          </ul>
        ) : (
          <Table
            caption="Issues"
            stack={false}
            head={
              <tr>
                {canAssign && (
                  <th style={{ width: 40 }}>
                    <input
                      type="checkbox"
                      className="check"
                      aria-label="Select all shown issues"
                      checked={selected.size > 0 && selected.size === items.length}
                      ref={(el) => {
                        if (el) el.indeterminate = selected.size > 0 && selected.size < items.length;
                      }}
                      onChange={(e) => setSelected(e.target.checked ? new Set(items.map((i) => i.id)) : new Set())}
                    />
                  </th>
                )}
                <th>Issue</th>
                <th>Severity</th>
                <th>Scanner · rule</th>
                <th>Status</th>
                <th>Assignee</th>
                <th>Due</th>
              </tr>
            }
          >
            {items.map((i) => (
              <IssueRow
                key={i.id}
                issue={i}
                showProject={!fixedProject && !filters.project ? projectById.get(i.project_id) : undefined}
                selectable={canAssign}
                selected={selected.has(i.id)}
                onToggle={(on) =>
                  setSelected((prev) => {
                    const next = new Set(prev);
                    if (on) next.add(i.id);
                    else next.delete(i.id);
                    return next;
                  })
                }
              />
            ))}
          </Table>
        )}
        {items.length > 0 && (
          <div className="table-foot">
            <span className="desktop-only">{SORT_TEXT[filters.sort]}</span>
            <div className="row">
              <span>
                {items.length} shown{matchCount !== undefined ? ` of ${matchCount}` : ""}
              </span>
              {issues.hasNextPage && (
                <Button size="sm" busy={issues.isFetchingNextPage} onClick={() => void issues.fetchNextPage()}>
                  {issues.isFetchingNextPage ? "Loading…" : "Load more"}
                </Button>
              )}
            </div>
          </div>
        )}
      </Card>

      <Dialog
        open={assigning}
        onClose={() => setAssigning(false)}
        title={`Assign ${selectedIssues.length} issue${selectedIssues.length === 1 ? "" : "s"}`}
      >
        <AssignForm
          issues={selectedIssues}
          onDone={(assigned) => {
            setAssigning(false);
            if (assigned) setSelected(new Set());
          }}
        />
      </Dialog>

      <Dialog open={sheet} onClose={() => setSheet(false)} title="Filters" className="dialog sheet">
        <div className="form-grid">
          {otherFilters}
          <div className="dialog-actions">
            <Button onClick={() => update({ ...DEFAULT_FILTERS, q: filters.q, sort: filters.sort })}>Clear</Button>
            <Button variant="primary" onClick={() => setSheet(false)}>
              Show {matchCount ?? ""} issues
            </Button>
          </div>
        </div>
      </Dialog>
    </>
  );
}

function memberName(members: OrgMember[] | undefined, id: string, meId: string): string {
  if (id === "me" || id === meId) return "Assigned to me";
  if (id === "none") return "Unassigned";
  const m = members?.find((x) => x.user.id === id);
  return m ? `Assigned to ${userName(m.user)}` : "One assignee";
}

function countMatches(counts: SeverityCounts, selected: Severity[]): number {
  const keys = selected.length ? selected : SEVERITIES;
  return keys.reduce((n, s) => n + counts[s], 0);
}

function SearchBox({ value, onChange }: { value: string; onChange: (q: string) => void }) {
  const [text, setText] = useState(value);
  const latest = useRef(onChange);
  latest.current = onChange;
  // Follow the URL when it changes from outside (back button, "Clear filters").
  useEffect(() => setText(value), [value]);
  // Debounce typing into the URL.
  useEffect(() => {
    if (text.trim() === value) return;
    const t = setTimeout(() => latest.current(text.trim()), 300);
    return () => clearTimeout(t);
  }, [text, value]);
  return (
    <label className="search">
      <SearchIcon />
      <span className="visually-hidden">Search issues</span>
      <input type="search" placeholder="Search title, rule, file or WEB-41" value={text} maxLength={200} onChange={(e) => setText(e.target.value)} />
    </label>
  );
}

function whereText(i: IssueSummary): string {
  return i.package_name
    ? `${i.file_path ?? i.package_name} · ${i.package_version ?? ""}${i.fixed_version ? ` → ${i.fixed_version}` : ""}`
    : location(i.file_path, i.start_line);
}

/** Phone: the whole row is one link (DESIGN.md "Phone layout"). */
function IssueCard({ issue: i }: { issue: IssueSummary }) {
  const { orgId } = useOrgCtx();
  const due = dueText(i.due_at);
  return (
    <Link to={`/orgs/${orgId}/issues/${i.id}`} className="issue-card">
      <span className="row" style={{ gap: 6 }}>
        <span className="mono muted" style={{ fontWeight: 600 }}>
          {i.key}
        </span>
        <SeverityBadge severity={i.severity} />
        <StatusPill status={i.status} />
      </span>
      <span className="title">{i.title}</span>
      <span className="where">
        {whereText(i)} · {TOOL_LABELS[i.tool]}
      </span>
      <span className="row-between">
        <span>{i.assignee ? userName(i.assignee) : <span className="muted">Unassigned</span>}</span>
        <span className={due.overdue || i.past_sla ? "danger-text" : undefined}>{due.text}</span>
      </span>
    </Link>
  );
}

function IssueRow({
  issue: i,
  showProject,
  selectable,
  selected,
  onToggle,
}: {
  issue: IssueSummary;
  showProject?: Project;
  selectable: boolean;
  selected: boolean;
  onToggle: (on: boolean) => void;
}) {
  const { orgId } = useOrgCtx();
  const due = dueText(i.due_at);
  const where = whereText(i);
  return (
    <tr className={selected ? "selected" : undefined}>
      {selectable && (
        <td>
          <input type="checkbox" className="check" aria-label={`Select ${i.key}`} checked={selected} onChange={(e) => onToggle(e.target.checked)} />
        </td>
      )}
      <td style={{ minWidth: 260 }}>
        <Link to={`/orgs/${orgId}/issues/${i.id}`} className="row-link">
          <span className="mono muted" style={{ fontWeight: 500 }}>
            {i.key}
          </span>{" "}
          {i.title}
        </Link>
        {where && <div className="sub">{where}</div>}
        {showProject && (
          <div className="muted" style={{ fontSize: 12 }}>
            {showProject.name}
          </div>
        )}
      </td>
      <td>
        <SeverityBadge severity={i.severity} />
      </td>
      <td>
        {TOOL_LABELS[i.tool]}
        <div className="sub">{i.rule_id}</div>
      </td>
      <td>
        <StatusPill status={i.status} />
      </td>
      <td className="nowrap">{i.assignee ? userName(i.assignee) : <span className="muted">Unassigned</span>}</td>
      <td className="nowrap">
        <span className={due.overdue || i.past_sla ? "danger-text" : undefined}>{due.text}</span>
      </td>
    </tr>
  );
}
