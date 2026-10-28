import { useEffect, useId, useMemo, useRef, useState } from "react";
import type { ReactNode } from "react";
import { Link, useSearchParams } from "react-router";
import { useComponents, useComponentUsage } from "../api/hooks/components";
import type { ComponentRef } from "../api/hooks/components";
import { useProjects } from "../api/hooks/projects";
import { flattenPages } from "../api/paging";
import type { ComponentSummary, ComponentUsage } from "../api/types";
import { ProjectDot } from "../components/Avatar";
import { MaliciousTag } from "../components/Badges";
import { Button } from "../components/Button";
import { Card } from "../components/Card";
import { Dialog } from "../components/Dialog";
import { Select } from "../components/Field";
import type { Option } from "../components/Field";
import { CloseIcon, FilterIcon, SearchIcon } from "../components/Icons";
import { PageHeader } from "../components/PageHeader";
import { SearchField } from "../components/SearchField";
import { EmptyState, ErrorState, SkeletonBlock, SkeletonRows } from "../components/States";
import { LoadMore, Table } from "../components/Table";
import { useOrgCtx } from "../layout/OrgLayout";
import {
  COMPONENT_Q_MAX,
  COMPONENT_VERSION_MAX,
  componentFiltersToApiQuery,
  componentFiltersToSearch,
  DEFAULT_COMPONENT_FILTERS,
  ecosystemLabel,
  ecosystemOptions,
  hasComponentFilters,
  licensesText,
  parseComponentFilters,
  projectComponentsHref,
  SOURCE_TARGET,
  splitSearch,
} from "../lib/components";
import type { ComponentFilters } from "../lib/components";
import { formatDate, relativeTime } from "../lib/format";
import { isImageTarget } from "../lib/intel";
import { DEFAULT_FILTERS, issueListHref } from "../lib/issueFilters";
import { useIsPhone, useIsWide } from "../lib/useMediaQuery";
import { usePageTitle } from "../lib/usePageTitle";

// v0.4: /orgs/:org/components, "which projects use xz 5.6.0?". One row per (ecosystem, name,
// version) from each (project, target)'s latest scan where Trivy ran; a row opens "Used in"
// (GET …/components/usage) beside the table from 1200 px, as a full-screen sheet below that.
//
// Names, versions, paths and purls come from scanned lockfiles and images (hostile input):
// they are rendered as text only. Links are built from ids and validated targets, and a name
// only ever travels encoded in a query string, as data for a search box.

const refOf = (c: ComponentRef) => `${c.ecosystem}\u0000${c.name}\u0000${c.version}`;

export function ComponentsPage() {
  usePageTitle("Components");
  const { orgId } = useOrgCtx();
  const phone = useIsPhone();
  const wide = useIsWide();
  const [params, setParams] = useSearchParams();
  const filters = useMemo(() => parseComponentFilters(params), [params]);
  const apiQuery = useMemo(() => componentFiltersToApiQuery(filters), [filters]);
  const list = useComponents(orgId, apiQuery);
  const projects = useProjects(orgId);
  const items = flattenPages(list.data?.pages);
  const [selected, setSelected] = useState<ComponentSummary | null>(null);
  const [sheet, setSheet] = useState(false);
  const panelId = useId();
  const tableRef = useRef<HTMLDivElement>(null);

  // A new filter is a new result set: close the panel.
  useEffect(() => setSelected(null), [apiQuery]);

  const update = (next: ComponentFilters, replace = false) => setParams(componentFiltersToSearch(next), { replace });
  const close = () => {
    const key = selected ? refOf(selected) : null;
    setSelected(null);
    // Back to the row that opened the panel.
    if (key) tableRef.current?.querySelector<HTMLElement>(`[data-ref="${CSS.escape(key)}"]`)?.focus();
  };

  const projectOptions: Option[] = [{ value: "", label: "All projects" }, ...(projects.data ?? []).map((p) => ({ value: p.id, label: `${p.key} · ${p.name}` }))];
  const { version } = splitSearch(filters.search);
  const otherCount = (filters.ecosystem ? 1 : 0) + (filters.project ? 1 : 0) + (filters.malicious ? 1 : 0);
  const projectName = (projects.data ?? []).find((p) => p.id === filters.project)?.name;

  const malToggle = (
    <button type="button" className="toggle-chip" aria-pressed={filters.malicious} onClick={() => update({ ...filters, malicious: !filters.malicious })}>
      <span className="mal-dot" aria-hidden="true" />
      Malicious only
    </button>
  );
  const search = (
    <SearchField
      value={filters.search}
      onChange={(search) => update({ ...filters, search }, true)}
      label="Search components by name, or name and version"
      placeholder="Name, or name and version: xz 5.6.0"
      maxLength={COMPONENT_Q_MAX + 1 + COMPONENT_VERSION_MAX}
    />
  );

  let results: ReactNode;
  if (list.isPending) results = <SkeletonRows label="components" />;
  else if (list.isError) results = <ErrorState error={list.error} onRetry={() => void list.refetch()} what="components" />;
  else if (items.length === 0) {
    results = hasComponentFilters(filters) ? (
      <EmptyState icon={<SearchIcon size={18} />} title="No components match these filters" action={<Button onClick={() => update(DEFAULT_COMPONENT_FILTERS)}>Clear filters</Button>}>
        {describeComponentFilters(filters, projectName).join(" · ")}
      </EmptyState>
    ) : (
      <EmptyState title="No components yet">
        Components appear after a scan where Trivy runs: lockfiles such as package-lock.json, go.mod or poetry.lock, and container images.
      </EmptyState>
    );
  } else {
    results = (
      <>
        <div ref={tableRef}>
          <Table
            caption="Components"
            head={
              <tr>
                <th scope="col">Component</th>
                <th scope="col">Version</th>
                <th scope="col">Ecosystem</th>
                <th scope="col">Licenses</th>
                <th scope="col" className="num">
                  Projects
                </th>
                <th scope="col" className="num">
                  Open issues
                </th>
              </tr>
            }
          >
            {items.map((c) => (
              <ComponentRow
                key={refOf(c)}
                c={c}
                selected={!!selected && refOf(selected) === refOf(c)}
                panelId={wide ? panelId : undefined}
                onSelect={() => setSelected(selected && refOf(selected) === refOf(c) ? null : c)}
              />
            ))}
          </Table>
        </div>
        <LoadMore hasNext={!!list.hasNextPage} loading={list.isFetchingNextPage} onLoad={() => void list.fetchNextPage()} shown={items.length} noun="components" />
      </>
    );
  }

  return (
    <div className="page">
      <PageHeader title="Components" />
      <div className="page-body">
        <p className="faint small comp-intro">
          Every package in the latest scan of each project and container image you can see. Search by name, or by name and version
          {version ? "" : " (xz 5.6.0)"}, to find where it is used.
        </p>
        {phone ? (
          <section className="comp-filters phone" aria-label="Filters">
            {search}
            <Button onClick={() => setSheet(true)}>
              <FilterIcon /> Filters{otherCount ? ` · ${otherCount}` : ""}
            </Button>
          </section>
        ) : (
          <section className="comp-filters" aria-label="Filters">
            {search}
            <Select dense aria-label="Ecosystem" value={filters.ecosystem} onChange={(e) => update({ ...filters, ecosystem: e.target.value })} options={ecosystemOptions(filters.ecosystem)} />
            <Select dense aria-label="Project" value={filters.project} onChange={(e) => update({ ...filters, project: e.target.value })} options={projectOptions} />
            {malToggle}
            {hasComponentFilters(filters) && (
              <button type="button" className="btn-link" onClick={() => update(DEFAULT_COMPONENT_FILTERS)}>
                Clear
              </button>
            )}
          </section>
        )}
        <div className={selected && wide ? "comp-split with-panel" : "comp-split"}>
          <Card flush className="comp-list" aria-label="Results">
            {results}
          </Card>
          {selected && wide && (
            <aside id={panelId} className="card comp-panel" aria-label={`Where ${selected.name} ${selected.version} is used`}>
              <UsedIn component={selected} onClose={close} autoFocus />
            </aside>
          )}
        </div>
      </div>

      <Dialog open={!!selected && !wide} onClose={close} title="Used in" className={phone ? "dialog sheet" : "dialog used-in-dialog"}>
        {selected && <UsedIn component={selected} />}
      </Dialog>

      <Dialog open={sheet} onClose={() => setSheet(false)} title="Filters" className="dialog sheet">
        <div className="form-grid">
          <Select label="Ecosystem" value={filters.ecosystem} onChange={(e) => update({ ...filters, ecosystem: e.target.value })} options={ecosystemOptions(filters.ecosystem)} />
          <Select label="Project" value={filters.project} onChange={(e) => update({ ...filters, project: e.target.value })} options={projectOptions} />
          <label className="check-row">
            <input type="checkbox" className="check" checked={filters.malicious} onChange={(e) => update({ ...filters, malicious: e.target.checked })} />
            <span>Only malicious packages</span>
          </label>
          <div className="dialog-actions">
            <Button onClick={() => update({ ...DEFAULT_COMPONENT_FILTERS, search: filters.search })}>Clear</Button>
            <Button variant="primary" onClick={() => setSheet(false)}>
              Show components
            </Button>
          </div>
        </div>
      </Dialog>
    </div>
  );
}

export function describeComponentFilters(f: ComponentFilters, projectName?: string): string[] {
  const words: string[] = [];
  const { q, version } = splitSearch(f.search);
  if (q) words.push(`Name starts with “${q}”`);
  if (version) words.push(`Version ${version}`);
  if (f.ecosystem) words.push(ecosystemLabel(f.ecosystem));
  if (f.project) words.push(projectName ?? "One project");
  if (f.malicious) words.push("Malicious only");
  return words;
}

function ComponentRow({ c, selected, panelId, onSelect }: { c: ComponentSummary; selected: boolean; panelId?: string; onSelect: () => void }) {
  return (
    <tr className={selected ? "selected" : undefined}>
      <td className="comp-cell">
        <span className="comp-name-line">
          <button
            type="button"
            className="row-button mono comp-name"
            data-ref={refOf(c)}
            onClick={onSelect}
            aria-expanded={selected}
            aria-controls={selected ? panelId : undefined}
          >
            {c.name}
            <span className="visually-hidden">
              {" "}
              {c.version}, show where it is used
            </span>
          </button>
          {c.malicious && <MaliciousTag />}
        </span>
      </td>
      <td data-label="Version" className="mono comp-version">
        {c.version}
      </td>
      <td data-label="Ecosystem">{c.ecosystem}</td>
      <td data-label="Licenses" className="comp-licenses">
        {licensesText(c.licenses)}
      </td>
      <td data-label="Projects" className="num">
        {c.projects}
        {c.targets > c.projects && <span className="faint small"> · {c.targets} targets</span>}
      </td>
      <td data-label="Open issues" className="num">
        {c.open_issues > 0 ? <strong>{c.open_issues}</strong> : <span className="faint">0</span>}
      </td>
    </tr>
  );
}

/** "Used in": the projects, targets and paths where one component is, from the usage endpoint. */
export function UsedIn({ component: c, onClose, autoFocus }: { component: ComponentSummary; onClose?: () => void; autoFocus?: boolean }) {
  const { orgId } = useOrgCtx();
  const usage = useComponentUsage(orgId, c);
  const items = flattenPages(usage.data?.pages);
  const headingRef = useRef<HTMLHeadingElement>(null);
  const headingId = useId();
  useEffect(() => {
    if (autoFocus) headingRef.current?.focus({ preventScroll: true });
  }, [autoFocus, c]);

  return (
    <div className="used-in">
      <div className="used-in-head">
        <div className="stack" style={{ gap: 4, minWidth: 0 }}>
          {onClose && <p className="faint small">Used in</p>}
          <h2 id={headingId} className="used-in-title mono" ref={headingRef} tabIndex={-1}>
            {c.name} <span className="muted">{c.version}</span>
          </h2>
          <p className="muted small">
            {ecosystemLabel(c.ecosystem)} · {licensesText(c.licenses)}
          </p>
        </div>
        {onClose && (
          <button type="button" className="icon-btn sm" aria-label="Close" onClick={onClose}>
            <CloseIcon />
          </button>
        )}
      </div>
      {c.purl && <p className="mono faint small comp-purl-full">{c.purl}</p>}
      {c.malicious && (
        <div className="banner banner-error used-in-mal" role="status">
          <MaliciousTag />
          <span>
            An OSV advisory lists this version as malicious. Remove it and rotate any credentials the build had access to.{" "}
            <Link to={issueListHref(orgId, { ...DEFAULT_FILTERS, kind: "malicious" })}>Malicious-package issues</Link>
          </span>
        </div>
      )}
      <p className="small">
        <strong>
          {c.projects} project{c.projects === 1 ? "" : "s"}
        </strong>
        {c.targets !== c.projects && <span className="muted"> · {c.targets} targets</span>}
        {c.open_issues > 0 && <span className="muted"> · {c.open_issues} open issue{c.open_issues === 1 ? "" : "s"} on this version</span>}
      </p>
      {usage.isPending ? (
        <SkeletonBlock label="where it is used" lines={3} height={36} />
      ) : usage.isError ? (
        <ErrorState error={usage.error} onRetry={() => void usage.refetch()} what="where it is used" />
      ) : items.length === 0 ? (
        <p className="muted">Not in any project you can see any more.</p>
      ) : (
        <>
          <ul className="usage-list" aria-labelledby={headingId}>
            {items.map((u) => (
              <UsageItem key={`${u.project_id}\u0000${u.target}\u0000${u.path}`} u={u} name={c.name} />
            ))}
          </ul>
          {usage.hasNextPage && (
            <div className="list-more">
              <Button size="sm" busy={usage.isFetchingNextPage} onClick={() => void usage.fetchNextPage()}>
                {usage.isFetchingNextPage ? "Loading…" : "Load more"}
              </Button>
            </div>
          )}
        </>
      )}
    </div>
  );
}

function UsageItem({ u, name }: { u: ComponentUsage; name: string }) {
  const { orgId } = useOrgCtx();
  const image = u.target !== "" && isImageTarget(u.target);
  const pid = encodeURIComponent(u.project_id);
  return (
    <li className="usage-item">
      <Link className="usage-project" to={projectComponentsHref(orgId, u.project_id, { search: name, target: u.target === "" ? SOURCE_TARGET : image ? u.target : "" })}>
        <ProjectDot projectKey={u.project_key} />
        <span className="ellipsis">{u.project_name}</span>
        <span className="mono faint">{u.project_key}</span>
      </Link>
      <span className="usage-target small">
        {u.target === "" ? (
          <span className="muted">Source code</span>
        ) : (
          <>
            <span className="tag">Image</span>{" "}
            {image ? (
              <Link className="mono" to={issueListHref(orgId, { ...DEFAULT_FILTERS, project: u.project_id, target: u.target })}>
                {u.target}
                <span className="visually-hidden"> (issues in this image)</span>
              </Link>
            ) : (
              <span className="mono">{u.target}</span>
            )}
          </>
        )}
      </span>
      <span className="usage-path mono small">{u.path}</span>
      <span className="faint small">
        <Link to={`/orgs/${orgId}/projects/${pid}/scans?scan=${encodeURIComponent(u.scan_id)}`}>Scanned {relativeTime(u.scanned_at)}</Link> · first seen{" "}
        {formatDate(u.first_seen)}
      </span>
    </li>
  );
}
