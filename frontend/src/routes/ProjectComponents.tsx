import { useMemo, useState } from "react";
import type { ReactNode } from "react";
import { useSearchParams } from "react-router";
import { useProjectComponents, useProjectTargets } from "../api/hooks/components";
import { flattenPages } from "../api/paging";
import type { ProjectComponent, ProjectTarget } from "../api/types";
import { Button, ButtonLink } from "../components/Button";
import { Card } from "../components/Card";
import { Dialog } from "../components/Dialog";
import { Select } from "../components/Field";
import type { Option } from "../components/Field";
import { FilterIcon, SearchIcon } from "../components/Icons";
import { SearchField } from "../components/SearchField";
import { EmptyState, ErrorState, SkeletonRows } from "../components/States";
import { LoadMore, Table } from "../components/Table";
import { useOrgCtx } from "../layout/OrgLayout";
import {
  COMPONENT_Q_MAX,
  ecosystemLabel,
  ecosystemOptions,
  licensesText,
  parseProjectComponentFilters,
  projectComponentFiltersToApiQuery,
  projectComponentFiltersToSearch,
  SOURCE_TARGET,
  targetLabel,
} from "../lib/components";
import type { ProjectComponentFilters } from "../lib/components";
import { formatDate } from "../lib/format";
import { isImageTarget } from "../lib/intel";
import { can } from "../lib/permissions";
import { useIsPhone } from "../lib/useMediaQuery";
import { MaliciousTag } from "../components/Badges";
import { useProjectCtx } from "./projectCtx";

const EMPTY: ProjectComponentFilters = { search: "", ecosystem: "", target: "", malicious: false };

/** v0.4: the target filter's options: every target, source code, then each image repository
 *  from GET …/targets (only well-formed ones; a URL value stays listed). */
export function targetOptions(targets: ProjectTarget[] | undefined, current: string): Option[] {
  const images = (targets ?? []).filter((t) => t.kind === "image" && isImageTarget(t.target)).map((t) => t.target);
  const hasSource = (targets ?? []).some((t) => t.target === "");
  const opts: Option[] = [{ value: "", label: "All targets" }];
  if (hasSource || current === SOURCE_TARGET) opts.push({ value: SOURCE_TARGET, label: "Source code" });
  for (const t of images) opts.push({ value: t, label: t });
  if (current && current !== SOURCE_TARGET && !images.includes(current)) opts.push({ value: current, label: current });
  return opts;
}

/** /orgs/:org/projects/:project/components: the project's current components, per target. */
export function ProjectComponentsTab() {
  const { orgId, org } = useOrgCtx();
  const project = useProjectCtx();
  const phone = useIsPhone();
  const [params, setParams] = useSearchParams();
  const filters = useMemo(() => parseProjectComponentFilters(params), [params]);
  const apiQuery = useMemo(() => projectComponentFiltersToApiQuery(filters), [filters]);
  const list = useProjectComponents(orgId, project.id, apiQuery);
  const targets = useProjectTargets(orgId, project.id);
  const items = flattenPages(list.data?.pages);
  const [sheet, setSheet] = useState(false);
  const update = (next: ProjectComponentFilters, replace = false) => setParams(projectComponentFiltersToSearch(next), { replace });
  const filtered = projectComponentFiltersToSearch(filters).toString() !== "";
  const tOptions = targetOptions(targets.data, filters.target);
  const showTarget = tOptions.length > 2 || !!filters.target;
  const otherCount = (filters.ecosystem ? 1 : 0) + (filters.target ? 1 : 0) + (filters.malicious ? 1 : 0);
  const canScan = can("run_scan", org.role, project.my_role) && !project.archived_at;

  const search = (
    <SearchField
      value={filters.search}
      onChange={(search) => update({ ...filters, search }, true)}
      label="Search this project's components by name"
      placeholder="Search by name"
      maxLength={COMPONENT_Q_MAX}
    />
  );

  let results: ReactNode;
  if (list.isPending) results = <SkeletonRows label="components" />;
  else if (list.isError) results = <ErrorState error={list.error} onRetry={() => void list.refetch()} what="components" />;
  else if (items.length === 0) {
    results = filtered ? (
      <EmptyState icon={<SearchIcon size={18} />} title="No components match these filters" action={<Button onClick={() => update(EMPTY)}>Clear filters</Button>}>
        {[
          filters.search && `Name starts with “${filters.search}”`,
          filters.ecosystem && ecosystemLabel(filters.ecosystem),
          filters.target && (filters.target === SOURCE_TARGET ? "Source code" : filters.target),
          filters.malicious && "Malicious only",
        ]
          .filter(Boolean)
          .join(" · ")}
      </EmptyState>
    ) : (
      <EmptyState
        title="No components yet"
        action={canScan ? <ButtonLink to={`/orgs/${orgId}/projects/${project.id}/scans`}>Go to Scans</ButtonLink> : undefined}
      >
        Components come from the latest scan of each target where Trivy ran: lockfiles in the source, or a container image.
      </EmptyState>
    );
  } else {
    results = (
      <>
        <Table
          caption={`Components of ${project.name}`}
          head={
            <tr>
              <th scope="col">Component</th>
              <th scope="col">Version</th>
              <th scope="col">Ecosystem</th>
              <th scope="col">Where</th>
              <th scope="col">Licenses</th>
              <th scope="col" className="num">
                Open issues
              </th>
              <th scope="col">First seen</th>
            </tr>
          }
        >
          {items.map((c) => (
            <ProjectComponentRow key={`${c.target}\u0000${c.path}\u0000${c.ecosystem}\u0000${c.name}\u0000${c.version}`} c={c} />
          ))}
        </Table>
        <LoadMore hasNext={!!list.hasNextPage} loading={list.isFetchingNextPage} onLoad={() => void list.fetchNextPage()} shown={items.length} noun="components" />
      </>
    );
  }

  const malToggle = (
    <button type="button" className="toggle-chip" aria-pressed={filters.malicious} onClick={() => update({ ...filters, malicious: !filters.malicious })}>
      <span className="mal-dot" aria-hidden="true" />
      Malicious only
    </button>
  );

  return (
    <div className="page-body">
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
          {showTarget && (
            <Select dense aria-label="Target" className="mono-options" value={filters.target} onChange={(e) => update({ ...filters, target: e.target.value })} options={tOptions} />
          )}
          {malToggle}
          {filtered && (
            <button type="button" className="btn-link" onClick={() => update(EMPTY)}>
              Clear
            </button>
          )}
        </section>
      )}
      <Card flush aria-label="Components">
        {results}
      </Card>
      <Dialog open={sheet} onClose={() => setSheet(false)} title="Filters" className="dialog sheet">
        <div className="form-grid">
          <Select label="Ecosystem" value={filters.ecosystem} onChange={(e) => update({ ...filters, ecosystem: e.target.value })} options={ecosystemOptions(filters.ecosystem)} />
          {showTarget && <Select label="Target" value={filters.target} onChange={(e) => update({ ...filters, target: e.target.value })} options={tOptions} />}
          <label className="check-row">
            <input type="checkbox" className="check" checked={filters.malicious} onChange={(e) => update({ ...filters, malicious: e.target.checked })} />
            <span>Only malicious packages</span>
          </label>
          <div className="dialog-actions">
            <Button onClick={() => update({ ...EMPTY, search: filters.search })}>Clear</Button>
            <Button variant="primary" onClick={() => setSheet(false)}>
              Show components
            </Button>
          </div>
        </div>
      </Dialog>
    </div>
  );
}

function ProjectComponentRow({ c }: { c: ProjectComponent }) {
  return (
    <tr>
      <td className="comp-cell">
        <span className="comp-name-line">
          <span className="mono comp-name">{c.name}</span>
          {c.malicious && <MaliciousTag />}
        </span>
      </td>
      <td data-label="Version" className="mono comp-version">
        {c.version}
      </td>
      <td data-label="Ecosystem">{c.ecosystem}</td>
      <td data-label="Where">
        <span className="comp-where">
          <span className={c.target ? "mono small" : "muted small"}>{targetLabel(c.target)}</span>
          <span className="mono faint small">{c.path}</span>
        </span>
      </td>
      <td data-label="Licenses" className="comp-licenses">
        {licensesText(c.licenses)}
      </td>
      <td data-label="Open issues" className="num">
        {c.open_issues > 0 ? <strong>{c.open_issues}</strong> : <span className="faint">0</span>}
      </td>
      <td data-label="First seen" className="nowrap muted">
        {formatDate(c.first_seen)}
      </td>
    </tr>
  );
}
