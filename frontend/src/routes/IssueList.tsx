import { useEffect, useId, useMemo, useRef, useState } from "react";
import type { KeyboardEvent, ReactNode, RefObject } from "react";
import { Link, useLocation, useMatch, useNavigate, useSearchParams } from "react-router";
import { useIssues } from "../api/hooks/issues";
import { useOrgMembers } from "../api/hooks/orgs";
import { useProjects } from "../api/hooks/projects";
import { flattenPages } from "../api/paging";
import { ISSUE_STATUSES, SEVERITIES, TOOLS } from "../api/types";
import type { IssueSort, IssueStatus, IssueSummary, OrgMember, Project, Severity, SeverityCounts, Tool } from "../api/types";
import { Avatar, ProjectDot } from "../components/Avatar";
import { SeverityMark, StatusMark } from "../components/Badges";
import { Button } from "../components/Button";
import { Dialog } from "../components/Dialog";
import { Select } from "../components/Field";
import type { Option } from "../components/Field";
import { BackIcon, ChevronIcon, ChevronRightIcon, CloseIcon, FilterIcon, PlusIcon, SearchIcon } from "../components/Icons";
import { Kbd, PageHeader, Segmented } from "../components/PageHeader";
import { Popover } from "../components/Popover";
import { EmptyState, ErrorState, SkeletonRows } from "../components/States";
import { useOrgCtx } from "../layout/OrgLayout";
import { dueShort, location, SEVERITY_LABELS, STATUS_LABELS, TOOL_LABELS, userName } from "../lib/format";
import {
  applyView,
  currentView,
  DEFAULT_FILTERS,
  describeFilters,
  EPSS_PRESETS,
  epssMinText,
  hasActiveFilters,
  ISSUE_KINDS,
  ISSUE_SOURCES,
  issueFiltersToApiQuery,
  issueFiltersToSearch,
  issueHref,
  issueListHref,
  KIND_LABELS,
  parseEpssMin,
  parseIssueFilters,
  SAVED_VIEWS,
  SOURCE_LABELS,
  toggleSeverity,
} from "../lib/issueFilters";
import type { IssueFilters, IssueKindFilter, IssueSourceFilter, SavedView, StatusFilter } from "../lib/issueFilters";
import { formatEpss, isLicenseIssue, isVulnIssue, KEV_LABEL } from "../lib/intel";
import { validateImageTarget } from "../lib/upload";
import { useIssueCounts } from "../api/hooks/metrics";
import type { IssueCounts } from "../api/types";
import { can } from "../lib/permissions";
import { useShortcuts } from "../lib/shortcuts";
import { useIsPhone, useIsWide, useMediaQuery } from "../lib/useMediaQuery";
import { usePageTitle } from "../lib/usePageTitle";
import { AssignForm } from "./AssignForm";
import { IssueDetail, IssueDetailPage } from "./IssueDetail";
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
  { value: "-epss", label: "Exploit probability" },
];

const KIND_OPTIONS: Option[] = [{ value: "", label: "Any type" }, ...ISSUE_KINDS.map((k) => ({ value: k, label: KIND_LABELS[k] }))];
const SOURCE_OPTIONS: Option[] = [{ value: "", label: "Code and images" }, ...ISSUE_SOURCES.map((k) => ({ value: k, label: SOURCE_LABELS[k] }))];
const EPSS_OPTIONS: Option[] = [{ value: "", label: "Any EPSS" }, ...EPSS_PRESETS.map((n) => ({ value: String(n), label: epssMinText(n) }))];

type GroupBy = "severity" | "none";
const GROUP_KEY = "warden.issues.groupBy";

// A per-viewer convenience only: storage may be unavailable (private mode, blocked site data).
function useGroupBy(): [GroupBy, (g: GroupBy) => void] {
  const [g, setG] = useState<GroupBy>(() => {
    try {
      return localStorage.getItem(GROUP_KEY) === "none" ? "none" : "severity";
    } catch {
      return "severity";
    }
  });
  const set = (next: GroupBy) => {
    setG(next);
    try {
      localStorage.setItem(GROUP_KEY, next);
    } catch {
      // ignore
    }
  };
  return [g, set];
}

/** /orgs/:org/issues and /orgs/:org/issues/:issue. From 1200 px an opened issue shows in a
 *  pane beside the list; below that it is a page of its own with a back link to the list. */
export function IssuesPage() {
  const match = useMatch("/orgs/:orgId/issues/:issueId");
  const issueId = match?.params.issueId;
  const wide = useIsWide();
  usePageTitle(issueId ? null : "Issues");
  if (issueId && !wide) return <IssueDetailPage issueId={issueId} />;
  return <IssueList selectedId={issueId} />;
}

/** The issue list. On a project's Issues tab `fixedProject` pins the project filter. */
export function IssueList({ fixedProject, selectedId }: { fixedProject?: Project; selectedId?: string }) {
  const { orgId, org, me } = useOrgCtx();
  const phone = useIsPhone();
  const roomy = useMediaQuery("(min-width: 1100px)");
  const navigate = useNavigate();
  const { pathname } = useLocation();
  const [params, setParams] = useSearchParams();
  const filters = useMemo(() => parseIssueFilters(params), [params]);
  const apiQuery = useMemo(() => issueFiltersToApiQuery(filters, fixedProject?.id), [filters, fixedProject?.id]);
  const issues = useIssues(orgId, apiQuery);
  // v0.2: a count on every saved view, for the project in scope.
  const viewCounts = useIssueCounts(orgId, fixedProject?.id ?? (filters.project || undefined));
  const projects = useProjects(orgId);
  const members = useOrgMembers(orgId);
  const [selected, setSelected] = useState<Set<string>>(new Set());
  const [assigning, setAssigning] = useState<IssueSummary[] | null>(null);
  const [sheet, setSheet] = useState(false);
  const [groupBy, setGroupBy] = useGroupBy();
  const [collapsed, setCollapsed] = useState<Partial<Record<Severity, boolean>>>({});
  const [cursor, setCursor] = useState<string | undefined>(selectedId);
  const [assignSignal, setAssignSignal] = useState(0);
  const [focusPaneFor, setFocusPaneFor] = useState<string | undefined>();
  const searchRef = useRef<HTMLInputElement>(null);
  const listRef = useRef<HTMLElement>(null);

  const items = flattenPages(issues.data?.pages);
  const counts = issues.data?.pages[0]?.counts_by_severity;
  const projectById = new Map((projects.data ?? []).map((p) => [p.id, p]));
  const pane = !!selectedId;
  const compact = phone || pane;

  // No checkboxes and no bulk assign on phones (DESIGN.md "Phone layout").
  const canAssign =
    !phone &&
    (fixedProject
      ? can("assign_issue", org.role, fixedProject.my_role)
      : can("assign_issue", org.role) || (projects.data ?? []).some((p) => p.my_role === "owner"));

  // Links carry the list's filters, so the opened issue (pane or page) can lead back to them.
  // From a project's tab the project becomes an ordinary filter on the org-wide list.
  const linkFilters = fixedProject ? { ...filters, project: fixedProject.id } : filters;
  const hrefFor = (id: string) => issueHref(orgId, id, linkFilters);
  const listHref = issueListHref(orgId, linkFilters);

  // A new filter is a new result set: drop the selection.
  useEffect(() => setSelected(new Set()), [apiQuery]);
  useEffect(() => {
    if (selectedId) setCursor(selectedId);
  }, [selectedId]);

  // Pane opened from a closed list: move focus to the issue's title. Pane closed: back to its row.
  const prevSelected = useRef(selectedId);
  const mounted = useRef(false);
  useEffect(() => {
    const prev = prevSelected.current;
    prevSelected.current = selectedId;
    if (!mounted.current) {
      mounted.current = true;
      return;
    }
    if (selectedId && !prev) setFocusPaneFor(selectedId);
    if (prev && !selectedId) rowLink(listRef, prev)?.focus();
  }, [selectedId]);

  function update(next: IssueFilters, replace = false) {
    setParams(issueFiltersToSearch(next), { replace });
  }

  const matchCount = counts ? countMatches(counts, filters.severity) : undefined;
  const filterWords = describeFilters(filters, {
    project: fixedProject?.name ?? (filters.project ? projectById.get(filters.project)?.name : undefined),
    assignee: filters.assignee ? memberName(members.data, filters.assignee, me.id) : undefined,
  });

  // ---- Groups and the rows that keyboard navigation moves through ----
  const groups = useMemo(() => {
    if (groupBy === "none") return [{ id: "all", severity: undefined as Severity | undefined, rows: items, total: items.length }];
    return SEVERITIES.map((s) => ({ id: s, severity: s as Severity | undefined, rows: items.filter((i) => i.severity === s), total: counts?.[s] ?? 0 })).filter(
      (g) => g.rows.length > 0,
    );
  }, [groupBy, items, counts]);
  const isCollapsed = (g: (typeof groups)[number]) =>
    g.severity !== undefined &&
    (collapsed[g.severity] ??
      ((g.severity === "medium" || g.severity === "low" || g.severity === "info") && g.total >= 10 && !g.rows.some((r) => r.id === selectedId)));
  const visible = groups.flatMap((g) => (isCollapsed(g) ? [] : g.rows));
  const visibleIds = visible.map((i) => i.id);

  useEffect(() => {
    if (cursor) rowEl(listRef, cursor)?.scrollIntoView({ block: "nearest" });
  }, [cursor]);

  function step(d: 1 | -1): string | undefined {
    if (visibleIds.length === 0) return undefined;
    const from = selectedId ?? cursor;
    const idx = from ? visibleIds.indexOf(from) : -1;
    const next = idx < 0 ? (d > 0 ? 0 : visibleIds.length - 1) : Math.min(visibleIds.length - 1, Math.max(0, idx + d));
    return visibleIds[next];
  }
  function move(d: 1 | -1) {
    const id = step(d);
    if (!id) return;
    setCursor(id);
    // With the pane open the pane follows; replace, so Back leaves the list instead of replaying J/K.
    if (selectedId && id !== selectedId) {
      navigate(hrefFor(id), { replace: true });
      // The new issue's title takes focus, so screen readers announce it (J/K still work there).
      setFocusPaneFor(id);
    }
  }
  const closePane = () => navigate(listHref);
  const toggle = (id: string, on: boolean) =>
    setSelected((prev) => {
      const next = new Set(prev);
      if (on) next.add(id);
      else next.delete(id);
      return next;
    });

  useShortcuts({
    next: () => move(1),
    prev: () => move(-1),
    open: () => {
      if (!cursor || cursor === selectedId) return false;
      navigate(hrefFor(cursor));
    },
    close: () => {
      if (!selectedId) return false;
      closePane();
    },
    assign: () => {
      if (canAssign && selected.size > 0) {
        setAssigning(items.filter((i) => selected.has(i.id)));
        return;
      }
      if (selectedId) {
        setAssignSignal((n) => n + 1);
        return;
      }
      const row = items.find((i) => i.id === cursor);
      if (!canAssign || !row) return false;
      setAssigning([row]);
    },
    select: () => {
      if (!canAssign || !cursor) return false;
      toggle(cursor, !selected.has(cursor));
    },
    search: () => {
      searchRef.current?.focus();
    },
  });

  const noScanYet = fixedProject && !fixedProject.last_scan;
  const viewHref = (f: IssueFilters) => {
    const s = issueFiltersToSearch(f).toString();
    return s ? `${pathname}?${s}` : pathname;
  };
  const views = <SavedViews filters={filters} counts={viewCounts.data} count={matchCount} hrefFor={viewHref} />;
  const otherFilterCount =
    (filters.project && !fixedProject ? 1 : 0) +
    (filters.status !== "active" ? 1 : 0) +
    (filters.assignee ? 1 : 0) +
    (filters.tool ? 1 : 0) +
    (filters.kind ? 1 : 0) +
    (filters.source ? 1 : 0) +
    (filters.epssMin !== null ? 1 : 0) +
    (filters.target ? 1 : 0);
  // Image repositories to suggest in the Target filter: the contract has no list of an org's
  // targets, so these come from the issues loaded so far (any other is typed).
  const targets = [...new Set(items.map((i) => i.target).filter(Boolean))].sort();

  const phoneFilters = (
    <>
      {!fixedProject && (
        <Select
          label="Project"
          value={filters.project}
          onChange={(e) => update({ ...filters, project: e.target.value })}
          options={[{ value: "", label: "All projects" }, ...(projects.data ?? []).map((p) => ({ value: p.id, label: `${p.key} · ${p.name}` }))]}
        />
      )}
      <Select label="Status" value={filters.status} onChange={(e) => update({ ...filters, status: e.target.value as StatusFilter })} options={STATUS_OPTIONS} />
      <Select
        label="Assignee"
        value={filters.assignee}
        onChange={(e) => update({ ...filters, assignee: e.target.value })}
        options={[
          { value: "", label: "Any assignee" },
          { value: "me", label: "Assigned to me" },
          { value: "none", label: "Unassigned" },
          ...(members.data ?? []).filter((m) => m.user.id !== me.id).map((m) => ({ value: m.user.id, label: userName(m.user) })),
        ]}
      />
      <Select
        label="Scanner"
        value={filters.tool}
        onChange={(e) => update({ ...filters, tool: e.target.value as Tool | "" })}
        options={[{ value: "", label: "All scanners" }, ...TOOLS.map((t) => ({ value: t, label: TOOL_LABELS[t] }))]}
      />
      <Select label="Type" value={filters.kind} onChange={(e) => update({ ...filters, kind: e.target.value as IssueKindFilter | "" })} options={KIND_OPTIONS} />
      <Select
        label="Exploit probability"
        value={filters.epssMin === null ? "" : String(filters.epssMin)}
        onChange={(e) => update({ ...filters, epssMin: parseEpssMin(e.target.value) })}
        options={
          filters.epssMin !== null && !(EPSS_PRESETS as readonly number[]).includes(filters.epssMin)
            ? [...EPSS_OPTIONS, { value: String(filters.epssMin), label: epssMinText(filters.epssMin) }]
            : EPSS_OPTIONS
        }
      />
      <Select label="Source" value={filters.source} onChange={(e) => update({ ...filters, source: e.target.value as IssueSourceFilter | "" })} options={SOURCE_OPTIONS} />
      <TargetField value={filters.target} targets={targets} onApply={(target) => update({ ...filters, target })} />
    </>
  );

  const filterBar = phone ? (
    <section className="filter-bar phone" aria-label="Filters">
      {fixedProject && <div className="seg-scroll">{views}</div>}
      <SearchBox inputRef={searchRef} value={filters.q} onChange={(q) => update({ ...filters, q }, true)} />
      <div className="row" style={{ flexWrap: "nowrap", width: "100%" }}>
        <Button onClick={() => setSheet(true)} style={{ flex: 1 }}>
          <FilterIcon /> Filters{otherFilterCount ? ` · ${otherFilterCount}` : ""}
        </Button>
        <div style={{ flex: 1 }}>
          <Select aria-label="Sort by" value={filters.sort} onChange={(e) => update({ ...filters, sort: e.target.value as IssueSort })} options={SORT_OPTIONS} />
        </div>
      </div>
      <div className="chip-scroll" role="group" aria-label="Severity">
        {SEVERITIES.filter((s) => s !== "info" || (counts?.info ?? 0) > 0 || filters.severity.includes(s)).map((s) => (
          <button key={s} type="button" className="chip" aria-pressed={filters.severity.includes(s)} onClick={() => update(toggleSeverity(filters, s))}>
            <SeverityMark severity={s} />
            {counts && <span className="num faint">{counts[s]}</span>}
          </button>
        ))}
        <button type="button" className="chip" aria-pressed={filters.pastSla} onClick={() => update({ ...filters, pastSla: !filters.pastSla })}>
          Past SLA only
        </button>
        <button type="button" className="chip" aria-pressed={filters.kev} onClick={() => update({ ...filters, kev: !filters.kev })}>
          Known exploited
        </button>
      </div>
    </section>
  ) : (
    <section className="filter-bar" aria-label="Filters">
      {fixedProject && views}
      <SearchBox inputRef={searchRef} value={filters.q} onChange={(q) => update({ ...filters, q }, true)} />
      <FilterChips
        filters={filters}
        update={update}
        counts={counts}
        projects={fixedProject ? undefined : (projects.data ?? [])}
        members={members.data ?? []}
        meId={me.id}
        targets={targets}
      />
      <span className="filter-bar-end">
        {canAssign && selected.size > 0 && (
          <span className="bulk">
            <span className="num">{selected.size} selected</span>
            <Button size="sm" onClick={() => setAssigning(items.filter((i) => selected.has(i.id)))} aria-keyshortcuts="A">
              Assign…
            </Button>
            <button type="button" className="btn-link" onClick={() => setSelected(new Set())}>
              Clear
            </button>
          </span>
        )}
        <label className="inline-select">
          <span>Group by</span>
          <select value={groupBy} onChange={(e) => setGroupBy(e.target.value as GroupBy)}>
            <option value="severity">Severity</option>
            <option value="none">None</option>
          </select>
        </label>
        <label className="inline-select">
          <span>Sort</span>
          <select value={filters.sort} onChange={(e) => update({ ...filters, sort: e.target.value as IssueSort })}>
            {SORT_OPTIONS.map((o) => (
              <option key={o.value} value={o.value}>
                {o.label}
              </option>
            ))}
          </select>
        </label>
      </span>
    </section>
  );

  let results: ReactNode;
  if (issues.isPending) results = <SkeletonRows label="issues" />;
  else if (issues.isError) results = <ErrorState error={issues.error} onRetry={() => void issues.refetch()} what="issues" />;
  else if (items.length === 0) {
    results =
      noScanYet && !hasActiveFilters(filters) ? (
        <NoScansYet uploadTo={can("run_scan", org.role, fixedProject.my_role) ? `/orgs/${orgId}/projects/${fixedProject.id}/scans` : undefined} />
      ) : hasActiveFilters({ ...filters, project: fixedProject ? "" : filters.project }) ? (
        <EmptyState icon={<SearchIcon size={18} />} title="No issues match these filters" action={<Button onClick={() => update({ ...DEFAULT_FILTERS })}>Clear filters</Button>}>
          {filterWords.join(" · ")}
        </EmptyState>
      ) : (
        <EmptyState title="No active issues">New findings appear here after a scan.</EmptyState>
      );
  } else {
    const rowProps = (i: IssueSummary) => ({
      issue: i,
      href: hrefFor(i.id),
      open: i.id === selectedId,
      cursor: i.id === cursor && i.id !== selectedId,
      selectable: canAssign,
      checked: selected.has(i.id),
      onToggle: (on: boolean) => toggle(i.id, on),
      onFocus: () => setCursor(i.id),
      project: !fixedProject && !filters.project ? projectById.get(i.project_id) : undefined,
    });
    const groupHead = (g: (typeof groups)[number], bodyId: string) =>
      g.severity === undefined ? null : (
        <button
          type="button"
          className="group-toggle"
          aria-expanded={!isCollapsed(g)}
          aria-controls={bodyId}
          onClick={() => setCollapsed((c) => ({ ...c, [g.severity!]: !isCollapsed(g) }))}
        >
          {isCollapsed(g) ? <ChevronRightIcon /> : <ChevronIcon />}
          <SeverityMark severity={g.severity} />
          <span className="num faint">{g.total}</span>
          {g.rows.length < g.total && <span className="faint group-note">· {g.rows.length} loaded</span>}
          <span className="visually-hidden">{isCollapsed(g) ? " (collapsed)" : ""}</span>
        </button>
      );

    results = compact ? (
      <div className="issue-queue">
        {groups.map((g) => (
          <QueueGroup key={g.id} head={(id) => groupHead(g, id)} collapsed={isCollapsed(g)}>
            {g.rows.map((i) => (
              <QueueItem key={i.id} {...rowProps(i)} showSeverity={phone || g.severity === undefined} phone={phone} />
            ))}
          </QueueGroup>
        ))}
      </div>
    ) : (
      <table className="issue-table">
        <caption className="visually-hidden">Issues</caption>
        <colgroup>
          {canAssign && <col style={{ width: 40 }} />}
          <col />
          <col style={{ width: 128 }} />
          {roomy && <col style={{ width: 96 }} />}
          <col style={{ width: roomy ? 168 : 144 }} />
          <col style={{ width: 104 }} />
        </colgroup>
        <thead>
          <tr>
            {canAssign && (
              <th scope="col">
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
            <th scope="col">Issue</th>
            <th scope="col">Status</th>
            {roomy && <th scope="col">Source</th>}
            <th scope="col">Assignee</th>
            <th scope="col" className="num">
              Due
            </th>
          </tr>
        </thead>
        {groups.map((g) => (
          <TableGroup key={g.id} cols={4 + (canAssign ? 1 : 0) + (roomy ? 1 : 0)} head={(id) => groupHead(g, id)} collapsed={isCollapsed(g)}>
            {g.rows.map((i) => (
              <IssueRow key={i.id} {...rowProps(i)} showSource={roomy} />
            ))}
          </TableGroup>
        ))}
      </table>
    );
  }

  const position = selectedId && visibleIds.includes(selectedId) ? `${visibleIds.indexOf(selectedId) + 1} of ${visibleIds.length}` : undefined;
  const prevId = selectedId ? step(-1) : undefined;
  const nextId = selectedId ? step(1) : undefined;

  return (
    <div className={["issues-page", fixedProject ? "embedded" : "", pane ? "with-pane" : ""].filter(Boolean).join(" ")}>
      {!fixedProject && <PageHeader title="Issues">{views}</PageHeader>}
      {filterBar}
      <div className="issues-split">
        <section className="issues-list" aria-label="Results" ref={listRef}>
          {results}
          {items.length > 0 && issues.hasNextPage && (
            <div className="list-more">
              <Button size="sm" busy={issues.isFetchingNextPage} onClick={() => void issues.fetchNextPage()}>
                {issues.isFetchingNextPage ? "Loading…" : "Load more"}
              </Button>
            </div>
          )}
        </section>
        {selectedId && (
          <aside className="issue-pane" aria-label="Selected issue">
            <IssueDetail
              issueId={selectedId}
              mode="pane"
              backHref={listHref}
              assignSignal={assignSignal}
              autoFocus={focusPaneFor === selectedId}
              pane={{
                onClose: closePane,
                onPrev: prevId && prevId !== selectedId ? () => move(-1) : undefined,
                onNext: nextId && nextId !== selectedId ? () => move(1) : undefined,
                position,
              }}
            />
          </aside>
        )}
      </div>
      <footer className="kbd-bar">
        {!phone && (
          <ul className="kbd-hints" aria-label="Keyboard shortcuts">
            <li>
              <Kbd>J</Kbd> <Kbd>K</Kbd> move
            </li>
            <li>
              <Kbd>↵</Kbd> open
            </li>
            {pane && (
              <li>
                <Kbd>Esc</Kbd> close
              </li>
            )}
            {(canAssign || pane) && (
              <li>
                <Kbd>A</Kbd> assign
              </li>
            )}
            {canAssign && (
              <li>
                <Kbd>X</Kbd> select
              </li>
            )}
            <li>
              <Kbd>/</Kbd> search
            </li>
            <li>
              <Kbd>⌘K</Kbd> jump
            </li>
          </ul>
        )}
        <p className="result-count" aria-live="polite">
          {matchCount === undefined ? (
            "Loading issues…"
          ) : (
            <>
              <strong className="num">{`${matchCount} issue${matchCount === 1 ? "" : "s"}`}</strong> match
              {items.length > 0 && items.length < matchCount ? <span className="num"> · {items.length} shown</span> : null}
              {phone && <span> · {filterWords.join(", ")}</span>}
            </>
          )}
        </p>
      </footer>

      <Dialog
        open={assigning !== null}
        onClose={() => setAssigning(null)}
        title={`Assign ${assigning?.length ?? 0} issue${assigning?.length === 1 ? "" : "s"}`}
      >
        {assigning && (
          <AssignForm
            issues={assigning}
            onDone={(assigned) => {
              setAssigning(null);
              if (assigned) setSelected(new Set());
            }}
          />
        )}
      </Dialog>

      <Dialog open={sheet} onClose={() => setSheet(false)} title="Filters" className="dialog sheet">
        <div className="form-grid">
          {phoneFilters}
          <div className="dialog-actions">
            <Button onClick={() => update({ ...DEFAULT_FILTERS, q: filters.q, sort: filters.sort })}>Clear</Button>
            <Button variant="primary" onClick={() => setSheet(false)}>
              Show {matchCount ?? ""} issues
            </Button>
          </div>
        </div>
      </Dialog>
    </div>
  );
}

function rowEl(list: RefObject<HTMLElement | null>, id: string): HTMLElement | null {
  return list.current?.querySelector<HTMLElement>(`[data-row="${CSS.escape(id)}"]`) ?? null;
}
function rowLink(list: RefObject<HTMLElement | null>, id: string): HTMLElement | null {
  return rowEl(list, id)?.querySelector<HTMLElement>("a") ?? null;
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

/** Saved views: presets of the URL filters. Links, so they can open in a new tab. Each shows its
 *  count from /issues/counts (v0.2); the current view shows the live match count instead when
 *  a search narrows it. */
function SavedViews({
  filters,
  counts,
  count,
  hrefFor,
}: {
  filters: IssueFilters;
  counts?: IssueCounts;
  count?: number;
  hrefFor: (f: IssueFilters) => string;
}) {
  const current = currentView(filters);
  return (
    <Segmented label="Saved views">
      {SAVED_VIEWS.map((v) => {
        const n = current === v.id && (filters.q || !counts) ? count : counts?.[VIEW_COUNT_KEY[v.id]];
        return (
          <Link key={v.id} to={hrefFor(applyView(filters, v.id))} className={current === v.id ? "active" : undefined} aria-current={current === v.id ? "true" : undefined}>
            {v.label}
            {n !== undefined && (
              <span className="seg-count num">
                <span className="visually-hidden">, </span>
                {n}
                <span className="visually-hidden"> issues</span>
              </span>
            )}
          </Link>
        );
      })}
    </Segmented>
  );
}

const VIEW_COUNT_KEY: Record<SavedView, keyof IssueCounts> = {
  active: "active",
  mine: "mine",
  past_sla: "past_sla",
  kev: "kev",
  secrets: "secrets",
  licenses: "licenses",
};

/** The image repository filter: typed (checked against the contract's pattern) or picked from
 *  the repositories of the issues loaded so far. Applies on Enter or the button. */
function TargetField({ value, targets, onApply, autoFocus }: { value: string; targets: string[]; onApply: (t: string) => void; autoFocus?: boolean }) {
  const [text, setText] = useState(value);
  const [error, setError] = useState<string | null>(null);
  const id = useId();
  useEffect(() => setText(value), [value]);
  const apply = () => {
    const t = text.trim();
    if (!t) {
      setError(null);
      onApply("");
      return;
    }
    const problem = validateImageTarget(t);
    setError(problem);
    if (!problem) onApply(t);
  };
  return (
    <div className="field target-field">
      <label htmlFor={`${id}-t`}>Image repository</label>
      <div className="row" style={{ flexWrap: "nowrap", gap: 6 }}>
        <input
          id={`${id}-t`}
          className="input mono"
          list={targets.length ? `${id}-l` : undefined}
          value={text}
          placeholder="ghcr.io/acme/api"
          autoComplete="off"
          autoCapitalize="none"
          spellCheck={false}
          maxLength={300}
          autoFocus={autoFocus}
          aria-invalid={error ? true : undefined}
          aria-describedby={error ? `${id}-e` : undefined}
          onChange={(e) => {
            setText(e.target.value);
            if (error) setError(null);
          }}
          onKeyDown={(e) => {
            if (e.key === "Enter") {
              e.preventDefault();
              apply();
            }
          }}
        />
        <Button size="sm" onClick={apply}>
          Apply
        </Button>
      </div>
      {targets.length > 0 && (
        <datalist id={`${id}-l`}>
          {targets.map((t) => (
            <option key={t} value={t} />
          ))}
        </datalist>
      )}
      {error && (
        <span id={`${id}-e`} className="error">
          {error}
        </span>
      )}
    </div>
  );
}

function SearchBox({ value, onChange, inputRef }: { value: string; onChange: (q: string) => void; inputRef: RefObject<HTMLInputElement | null> }) {
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
      <input
        ref={inputRef}
        type="search"
        placeholder="Search title, rule, file or WEB-41"
        value={text}
        maxLength={200}
        aria-keyshortcuts="/"
        onChange={(e) => setText(e.target.value)}
        onKeyDown={(e) => {
          // Esc in the box leaves it, so J/K work again.
          if (e.key === "Escape" && !text) e.currentTarget.blur();
        }}
      />
    </label>
  );
}

// ---- Filter chips ("Severity is Critical, High ×") and the "+ Filter" menu ----

type Field = "severity" | "status" | "project" | "assignee" | "tool" | "pastSla" | "kind" | "kev" | "epss" | "source" | "target";
const FIELD_LABELS: Record<Field, string> = {
  severity: "Severity",
  status: "Status",
  project: "Project",
  assignee: "Assignee",
  tool: "Scanner",
  pastSla: "Past SLA",
  kind: "Type",
  kev: "Known exploited",
  epss: "Exploit probability",
  source: "Source",
  target: "Image",
};
/** On/off filters: picking one in "+ Filter" applies it, and its chip has nothing to edit. */
const TOGGLES: Partial<Record<Field, (f: IssueFilters) => IssueFilters>> = {
  pastSla: (f) => ({ ...f, pastSla: true }),
  kev: (f) => ({ ...f, kev: true }),
};

interface ChipCtx {
  filters: IssueFilters;
  update: (f: IssueFilters) => void;
  counts?: SeverityCounts;
  /** undefined on a project's tab (the project is fixed). */
  projects?: Project[];
  members: OrgMember[];
  meId: string;
  /** Image repositories seen in the loaded issues (suggestions for the Image filter). */
  targets: string[];
}

function FilterChips(ctx: ChipCtx) {
  const { filters: f, update, projects, members } = ctx;
  const chips: { field: Field; k: string; v: string; clear: IssueFilters }[] = [];
  if (f.severity.length) chips.push({ field: "severity", k: "Severity is", v: f.severity.map((s) => SEVERITY_LABELS[s]).join(", "), clear: { ...f, severity: [] } });
  if (f.status !== "active")
    chips.push({ field: "status", k: "Status is", v: f.status === "all" ? "any" : STATUS_LABELS[f.status as IssueStatus], clear: { ...f, status: "active" } });
  if (f.project && projects)
    chips.push({ field: "project", k: "Project is", v: projects.find((p) => p.id === f.project)?.name ?? "one project", clear: { ...f, project: "" } });
  if (f.assignee)
    chips.push({
      field: "assignee",
      k: f.assignee === "none" ? "" : "Assignee is",
      v: f.assignee === "none" ? "Unassigned" : f.assignee === "me" || f.assignee === ctx.meId ? "me" : userName(members.find((m) => m.user.id === f.assignee)?.user),
      clear: { ...f, assignee: "" },
    });
  if (f.tool) chips.push({ field: "tool", k: "Scanner is", v: TOOL_LABELS[f.tool], clear: { ...f, tool: "" } });
  if (f.pastSla) chips.push({ field: "pastSla", k: "", v: "Past SLA", clear: { ...f, pastSla: false } });
  if (f.kev) chips.push({ field: "kev", k: "", v: "Known exploited", clear: { ...f, kev: false } });
  if (f.epssMin !== null) chips.push({ field: "epss", k: "", v: epssMinText(f.epssMin), clear: { ...f, epssMin: null } });
  if (f.kind) chips.push({ field: "kind", k: "Type is", v: KIND_LABELS[f.kind], clear: { ...f, kind: "" } });
  if (f.source) chips.push({ field: "source", k: "Source is", v: SOURCE_LABELS[f.source], clear: { ...f, source: "" } });
  if (f.target) chips.push({ field: "target", k: "Image is", v: f.target, clear: { ...f, target: "" } });

  const available: Field[] = (
    ["severity", "status", "project", "assignee", "tool", "pastSla", "kev", "epss", "kind", "source", "target"] as Field[]
  ).filter((x) => !(x === "project" && !projects) && !chips.some((c) => c.field === x));

  return (
    <div className="fchips" role="group" aria-label="Active filters">
      {chips.map((c) => (
        <span key={c.field} className="fchip">
          {TOGGLES[c.field] ? (
            <span className="fchip-main static">{c.v}</span>
          ) : (
            <Popover
              buttonClassName="fchip-main"
              buttonLabel={`${FIELD_LABELS[c.field]} filter: ${c.v}. Change`}
              panelLabel={`${FIELD_LABELS[c.field]} filter`}
              button={
                <>
                  {c.k && <span className="k">{c.k}</span>} {c.v}
                </>
              }
            >
              {(close) => <FieldEditor field={c.field} ctx={ctx} close={close} />}
            </Popover>
          )}
          <button type="button" className="fchip-x" aria-label={`Remove ${FIELD_LABELS[c.field]} filter`} onClick={() => update(c.clear)}>
            <CloseIcon size={12} />
          </button>
        </span>
      ))}
      {available.length > 0 && <AddFilter ctx={ctx} fields={available} />}
    </div>
  );
}

function AddFilter({ ctx, fields }: { ctx: ChipCtx; fields: Field[] }) {
  const [open, setOpen] = useState(false);
  const [field, setField] = useState<Field | null>(null);
  return (
    <Popover
      open={open}
      onOpenChange={(o) => {
        setOpen(o);
        if (!o) setField(null);
      }}
      buttonClassName="fchip-add"
      panelLabel={field ? `${FIELD_LABELS[field]} filter` : "Add a filter"}
      button={
        <>
          <PlusIcon size={12} /> Filter
        </>
      }
    >
      {(close) =>
        field ? (
          <FieldEditor field={field} ctx={ctx} close={close} onBack={() => setField(null)} />
        ) : (
          <MenuList>
            {fields.map((x) => (
              <button
                key={x}
                type="button"
                className="menu-item"
                onClick={() => {
                  const toggle = TOGGLES[x];
                  if (toggle) {
                    ctx.update(toggle(ctx.filters));
                    close();
                  } else setField(x);
                }}
              >
                <span className="grow">{FIELD_LABELS[x]}</span>
                {!TOGGLES[x] && <ChevronRightIcon size={12} />}
              </button>
            ))}
          </MenuList>
        )
      }
    </Popover>
  );
}

/** Arrow keys move between the menu's items (Tab works too). */
function MenuList({ children, label }: { children: ReactNode; label?: string }) {
  const ref = useRef<HTMLDivElement>(null);
  useEffect(() => {
    ref.current?.querySelector<HTMLElement>("[data-autofocus], .menu-item, input")?.focus();
  }, []);
  const onKeyDown = (e: KeyboardEvent<HTMLDivElement>) => {
    if (e.key !== "ArrowDown" && e.key !== "ArrowUp") return;
    const els = Array.from(ref.current?.querySelectorAll<HTMLElement>(".menu-item, .menu-check input") ?? []);
    const i = els.indexOf(document.activeElement as HTMLElement);
    const next = els[e.key === "ArrowDown" ? Math.min(els.length - 1, i + 1) : Math.max(0, i - 1)];
    if (next) {
      e.preventDefault();
      next.focus();
    }
  };
  return (
    <div className="menu-list" ref={ref} onKeyDown={onKeyDown} aria-label={label}>
      {children}
    </div>
  );
}

function FieldEditor({ field, ctx, close, onBack }: { field: Field; ctx: ChipCtx; close: (refocus?: boolean) => void; onBack?: () => void }) {
  const { filters: f, update } = ctx;
  const titleId = useId();
  const pick = (next: IssueFilters) => {
    update(next);
    close();
  };
  const radio = (options: { value: string; label: ReactNode }[], value: string, set: (v: string) => IssueFilters) =>
    options.map((o) => (
      <button
        key={o.value}
        type="button"
        className="menu-item"
        aria-pressed={value === o.value}
        data-autofocus={value === o.value ? "" : undefined}
        onClick={() => pick(set(o.value))}
      >
        <span className="grow">{o.label}</span>
        {value === o.value && <span className="menu-tick" aria-hidden="true" />}
      </button>
    ));

  let body: ReactNode;
  switch (field) {
    case "severity":
      body = SEVERITIES.map((s) => (
        <label key={s} className="menu-check">
          <input type="checkbox" checked={f.severity.includes(s)} onChange={() => update(toggleSeverity(f, s))} />
          <SeverityMark severity={s} />
          {ctx.counts && <span className="num faint menu-count">{ctx.counts[s]}</span>}
        </label>
      ));
      break;
    case "status":
      body = radio(
        [
          { value: "active", label: "Active" },
          ...ISSUE_STATUSES.map((s) => ({ value: s, label: <StatusMark status={s} /> })),
          { value: "all", label: "Any status" },
        ],
        f.status,
        (v) => ({ ...f, status: v as StatusFilter }),
      );
      break;
    case "project":
      body = radio(
        (ctx.projects ?? []).map((p) => ({
          value: p.id,
          label: (
            <span className="row" style={{ gap: 8, flexWrap: "nowrap" }}>
              <ProjectDot projectKey={p.key} />
              {p.name}
              <span className="mono faint">{p.key}</span>
            </span>
          ),
        })),
        f.project,
        (v) => ({ ...f, project: v }),
      );
      break;
    case "assignee":
      body = radio(
        [
          { value: "me", label: "Me" },
          { value: "none", label: "Unassigned" },
          ...ctx.members
            .filter((m) => m.user.id !== ctx.meId)
            .map((m) => ({
              value: m.user.id,
              label: (
                <span className="person">
                  <Avatar name={userName(m.user)} />
                  {userName(m.user)}
                </span>
              ),
            })),
        ],
        f.assignee,
        (v) => ({ ...f, assignee: v }),
      );
      break;
    case "tool":
      body = radio(
        TOOLS.map((t) => ({ value: t, label: TOOL_LABELS[t] })),
        f.tool,
        (v) => ({ ...f, tool: v as Tool }),
      );
      break;
    case "kind":
      body = radio(
        ISSUE_KINDS.map((k) => ({ value: k, label: KIND_LABELS[k] })),
        f.kind,
        (v) => ({ ...f, kind: v as IssueKindFilter }),
      );
      break;
    case "source":
      body = radio(
        ISSUE_SOURCES.map((k) => ({ value: k, label: SOURCE_LABELS[k] })),
        f.source,
        (v) => ({ ...f, source: v as IssueSourceFilter }),
      );
      break;
    case "epss":
      body = radio(
        EPSS_PRESETS.map((n) => ({ value: String(n), label: epssMinText(n) })),
        f.epssMin === null ? "" : String(f.epssMin),
        (v) => ({ ...f, epssMin: parseEpssMin(v) }),
      );
      break;
    case "target":
      body = <TargetField value={f.target} targets={ctx.targets} autoFocus onApply={(target) => pick({ ...f, target })} />;
      break;
    case "pastSla":
    case "kev":
      body = null;
  }
  return (
    <div className="menu-editor">
      <div className="menu-title" id={titleId}>
        {onBack && (
          <button type="button" className="icon-btn sm" aria-label="Back to filters" onClick={onBack}>
            <BackIcon size={12} />
          </button>
        )}
        {FIELD_LABELS[field]}
      </div>
      <MenuList label={FIELD_LABELS[field]}>{body}</MenuList>
    </div>
  );
}

// ---- Rows ----

interface RowProps {
  issue: IssueSummary;
  href: string;
  open: boolean;
  cursor: boolean;
  selectable: boolean;
  checked: boolean;
  onToggle: (on: boolean) => void;
  onFocus: () => void;
  project?: Project;
}

function whereText(i: IssueSummary): string {
  let where: string;
  if (i.package_name) {
    const v = `${i.package_version ?? ""}${i.fixed_version ? ` → ${i.fixed_version}` : ""}`;
    where = i.file_path ? `${i.file_path} · ${v}` : v;
  } else where = location(i.file_path, i.start_line);
  // v0.3: issues from an image scan say which image first.
  return i.target ? [i.target, where].filter(Boolean).join(" · ") : where;
}

/** v0.3: KEV and EPSS beside the title of a dependency vulnerability (ranking signals, never
 *  instead of the severity), and a tag on license-policy issues. */
function IntelMarks({ issue: i }: { issue: IssueSummary }) {
  if (isLicenseIssue(i)) {
    return (
      <span className="intel-marks">
        <span className="tag">License</span>
      </span>
    );
  }
  if (!isVulnIssue(i)) return null;
  const epss = formatEpss(i.epss);
  if (!i.kev && !epss) return null;
  return (
    <span className="intel-marks">
      {i.kev && (
        <span className="tag tag-danger kev-tag" title={KEV_LABEL}>
          <span aria-hidden="true">KEV</span>
          <span className="visually-hidden">{KEV_LABEL}</span>
        </span>
      )}
      {epss && (
        <span className="tag epss-tag num" title="Probability of exploitation in the next 30 days (FIRST EPSS)">
          <span aria-hidden="true">EPSS {epss}</span>
          <span className="visually-hidden">Exploit probability {epss}</span>
        </span>
      )}
    </span>
  );
}

function Due({ dueAt }: { dueAt: string | null }) {
  const d = dueShort(dueAt);
  return (
    <span className={d.overdue ? "danger-text" : d.text === "Today" ? "due-today" : "muted"} title={d.long}>
      <span aria-hidden="true">{d.text}</span>
      <span className="visually-hidden">{d.long}</span>
    </span>
  );
}

function Assignee({ issue: i }: { issue: IssueSummary }) {
  return i.assignee ? (
    <span className="person">
      <Avatar name={userName(i.assignee)} />
      <span className="ellipsis">{userName(i.assignee)}</span>
    </span>
  ) : (
    <span className="faint">Unassigned</span>
  );
}

function rowClass(base: string, p: RowProps): string {
  return [base, p.open ? "is-open" : "", p.cursor ? "is-cursor" : "", p.checked ? "is-checked" : ""].filter(Boolean).join(" ");
}

function TableGroup({ head, collapsed, cols, children }: { head: (bodyId: string) => ReactNode; collapsed: boolean; cols: number; children: ReactNode }) {
  const id = useId();
  const h = head(id);
  return (
    <tbody id={id}>
      {h && (
        <tr className="group-row">
          <th colSpan={cols} scope="colgroup">
            {h}
          </th>
        </tr>
      )}
      {!collapsed && children}
    </tbody>
  );
}

function IssueRow(p: RowProps & { showSource: boolean }) {
  const i = p.issue;
  const where = whereText(i);
  const navigate = useNavigate();
  return (
    <tr
      data-row={i.id}
      className={rowClass("issue-row", p)}
      // A mouse convenience: the whole row opens the issue. Keyboard and screen-reader users
      // have the title link; clicks on the checkbox or a link keep their own meaning.
      onClick={(e) => {
        if ((e.target as HTMLElement).closest("a, button, input, label, select")) return;
        if (window.getSelection()?.toString()) return;
        navigate(p.href);
      }}
    >
      {p.selectable && (
        <td className="cell-check">
          <input type="checkbox" className="check" aria-label={`Select ${i.key}`} checked={p.checked} onChange={(e) => p.onToggle(e.target.checked)} />
        </td>
      )}
      <td className="cell-issue">
        <span className="issue-line">
          <span className="key">{i.key}</span>
          <Link to={p.href} className="row-link" aria-current={p.open ? "true" : undefined} onFocus={p.onFocus}>
            {i.title}
          </Link>
          <IntelMarks issue={i} />
          {where && <span className="where">{where}</span>}
          {p.project && <span className="where where-project">{p.project.name}</span>}
        </span>
      </td>
      <td>
        <StatusMark status={i.status} />
      </td>
      {p.showSource && <td className="text-2">{TOOL_LABELS[i.tool]}</td>}
      <td>
        <Assignee issue={i} />
      </td>
      <td className="num">
        <Due dueAt={i.due_at} />
      </td>
    </tr>
  );
}

function QueueGroup({ head, collapsed, children }: { head: (bodyId: string) => ReactNode; collapsed: boolean; children: ReactNode }) {
  const id = useId();
  const h = head(id);
  return (
    <div className="queue-group">
      {h && <div className="queue-head">{h}</div>}
      <ul id={id} className="queue-list" hidden={collapsed}>
        {!collapsed && children}
      </ul>
    </div>
  );
}

/** Compact two-line rows: beside the open pane, and on phones (where the whole row is one link). */
function QueueItem(p: RowProps & { showSeverity: boolean; phone: boolean }) {
  const i = p.issue;
  const where = whereText(i);
  return (
    <li data-row={i.id} className={rowClass("queue-row", p)}>
      {p.selectable && !p.phone && (
        <input type="checkbox" className="check queue-check" aria-label={`Select ${i.key}`} checked={p.checked} onChange={(e) => p.onToggle(e.target.checked)} />
      )}
      <Link to={p.href} className="queue-item" aria-current={p.open ? "true" : undefined} onFocus={p.onFocus}>
        <span className="q-line">
          <span className="key">{i.key}</span>
          {p.showSeverity && <SeverityMark severity={i.severity} />}
          <StatusMark status={i.status} />
          <IntelMarks issue={i} />
          <span className="q-due">
            <Due dueAt={i.due_at} />
          </span>
        </span>
        <span className="q-title">{i.title}</span>
        <span className="q-meta">
          {where && <span className="mono">{where}</span>}
          <span>{TOOL_LABELS[i.tool]}</span>
          <span>{i.assignee ? userName(i.assignee) : "Unassigned"}</span>
        </span>
      </Link>
    </li>
  );
}
