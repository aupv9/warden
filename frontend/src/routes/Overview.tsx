import type { ReactNode } from "react";
import { useSearchParams } from "react-router";
import { useMetrics } from "../api/hooks/metrics";
import { useProjects } from "../api/hooks/projects";
import { METRICS_DAYS } from "../api/types";
import type { Metrics, MetricsDays } from "../api/types";
import { SeverityMark } from "../components/Badges";
import { Card } from "../components/Card";
import { BarRows, Legend, NewFixedChart, StackedBar, TrendPanels } from "../components/Charts";
import { Select } from "../components/Field";
import { PageHeader, Segmented } from "../components/PageHeader";
import { ErrorState, Skeleton, SkeletonBlock } from "../components/States";
import { useOrgCtx } from "../layout/OrgLayout";
import { SEVERITY_LABELS } from "../lib/format";
import { bucketNewFixed, dayLabel, formatHours, openTotal, percent, signed, slaShare, sum, TREND_KEYS } from "../lib/metrics";
import { usePageTitle } from "../lib/usePageTitle";

export function parseDays(v: string | null): MetricsDays {
  const n = Number(v);
  return (METRICS_DAYS as number[]).includes(n) ? (n as MetricsDays) : 30;
}

export function OverviewPage() {
  usePageTitle("Overview");
  const { orgId } = useOrgCtx();
  const [params, setParams] = useSearchParams();
  const days = parseDays(params.get("days"));
  const projectId = params.get("project") ?? "";
  const projects = useProjects(orgId);
  const metrics = useMetrics(orgId, days, projectId || undefined);
  const set = (key: string, value: string | null) =>
    setParams(
      (prev) => {
        const next = new URLSearchParams(prev);
        if (value) next.set(key, value);
        else next.delete(key);
        return next;
      },
      { replace: true },
    );

  const projectName = projects.data?.find((p) => p.id === projectId)?.name;
  const scope = projectName ?? "all projects";

  return (
    <div className="page">
      <PageHeader title="Overview" />
      <div className="page-body">
        {/* One row of filters above everything they scope. */}
        <div className="filter-row" role="group" aria-label="Overview filters">
          <Segmented label="Time range" as="group">
            {METRICS_DAYS.map((d) => (
              <button key={d} type="button" aria-pressed={days === d} className={days === d ? "active" : undefined} onClick={() => set("days", d === 30 ? null : String(d))}>
                {d} days
              </button>
            ))}
          </Segmented>
          <Select
            dense
            aria-label="Project"
            value={projectId}
            onChange={(e) => set("project", e.target.value || null)}
            options={[{ value: "", label: "All projects" }, ...(projects.data ?? []).map((p) => ({ value: p.id, label: `${p.key} · ${p.name}` }))]}
          />
          {metrics.isFetching && metrics.data && (
            <span className="faint small" role="status">
              Updating…
            </span>
          )}
        </div>

        {metrics.isError ? (
          <ErrorState error={metrics.error} onRetry={() => void metrics.refetch()} what="the overview" />
        ) : !metrics.data ? (
          <OverviewSkeleton />
        ) : (
          <div className={metrics.isPlaceholderData ? "overview is-refetching" : "overview"}>
            <OverviewBody m={metrics.data} scope={scope} />
          </div>
        )}
      </div>
    </div>
  );
}

function OverviewSkeleton() {
  return (
    <div className="overview" aria-busy="true">
      <span role="status" className="visually-hidden">
        Loading the overview…
      </span>
      <div className="stat-strip">
        {[0, 1, 2, 3].map((i) => (
          <div key={i} className="stat">
            <Skeleton width="50%" height={10} />
            <Skeleton width="30%" height={20} style={{ marginTop: 8 }} />
          </div>
        ))}
      </div>
      <Card>
        <SkeletonBlock label="charts" lines={5} height={24} />
      </Card>
    </div>
  );
}

function OverviewBody({ m, scope }: { m: Metrics; scope: string }) {
  const last = m.open_by_day[m.open_by_day.length - 1];
  const first = m.open_by_day[0];
  const added = sum(m.new_by_day);
  const fixed = sum(m.fixed_by_day);
  const share = slaShare(m.sla);
  const perWeek = m.days > 30;
  const buckets = bucketNewFixed(m.new_by_day, m.fixed_by_day, m.days);
  const range = first && last ? `${dayLabel(first.date, true)} – ${dayLabel(last.date, true)}` : `${m.days} days`;
  const trendSummary =
    first && last
      ? `Open issues by severity, ${scope}, last ${m.days} days. ` +
        TREND_KEYS.map((k) => `${SEVERITY_LABELS[k]} went from ${first[k]} to ${last[k]}`).join("; ") +
        "."
      : "No data.";
  const mttrMax = Math.max(1, ...TREND_KEYS.map((k) => m.mttr_hours[k] ?? 0));

  return (
    <>
      <div className="stat-strip">
        <Stat label="Open now" value={openTotal(last)} note={`${scope}`} />
        <Stat label={`New in ${m.days} days`} value={added} />
        <Stat label={`Fixed in ${m.days} days`} value={fixed} note={added ? `${signed(fixed - added)} vs new` : undefined} />
        <Stat label="Open past SLA" value={m.sla.open_overdue} danger={m.sla.open_overdue > 0} />
      </div>

      <ChartCard
        id="trend"
        title="Open issues by severity"
        subtitle={`${range}. End-of-day active issues; each panel has its own scale.`}
        table={
          <DataTable
            caption="Open issues by severity per day"
            head={["Date", ...TREND_KEYS.map((k) => SEVERITY_LABELS[k])]}
            rows={[...m.open_by_day].reverse().map((d) => [dayLabel(d.date, true), d.critical, d.high, d.medium, d.low])}
          />
        }
      >
        <TrendPanels data={m.open_by_day} label={trendSummary} />
      </ChartCard>

      <ChartCard
        id="new-fixed"
        title="New vs fixed"
        subtitle={`${perWeek ? "Per week" : "Per day"}. New issues above the line, fixed below.`}
        legend={
          <Legend
            items={[
              { color: "var(--accent)", label: <>New <strong className="num">{added}</strong></> },
              { color: "var(--st-verified)", label: <>Fixed <strong className="num">{fixed}</strong></> },
            ]}
          />
        }
        table={
          <DataTable
            caption={`New and fixed issues per ${perWeek ? "week" : "day"}`}
            head={[perWeek ? "Week" : "Date", "New", "Fixed"]}
            rows={[...buckets].reverse().map((b) => [b.label, b.added, b.fixed])}
          />
        }
        figureLabel={`New vs fixed, ${scope}: ${added} new and ${fixed} fixed in the last ${m.days} days.`}
      >
        <NewFixedChart buckets={buckets} perWeek={perWeek} />
      </ChartCard>

      <div className="grid grid-2">
        <ChartCard
          id="mttr"
          title="Time to fix"
          subtitle="Mean time from found to fixed, for issues fixed in this period."
          table={
            <DataTable
              caption="Mean time to fix per severity"
              head={["Severity", "Mean time to fix", "Hours"]}
              rows={TREND_KEYS.map((k) => [SEVERITY_LABELS[k], formatHours(m.mttr_hours[k]), m.mttr_hours[k] === null ? "–" : Math.round(m.mttr_hours[k]!)])}
            />
          }
          figureLabel={`Mean time to fix: ${TREND_KEYS.map((k) => `${SEVERITY_LABELS[k]} ${formatHours(m.mttr_hours[k])}`).join(", ")}.`}
        >
          <BarRows
            max={mttrMax}
            rows={TREND_KEYS.map((k) => ({ key: k, label: <SeverityMark severity={k} quiet />, value: m.mttr_hours[k], text: formatHours(m.mttr_hours[k]) }))}
          />
        </ChartCard>

        <ChartCard
          id="sla"
          title="SLA compliance"
          subtitle="Issues fixed within their SLA, out of all SLA outcomes in this period."
          table={
            <DataTable
              caption="SLA outcomes"
              head={["Outcome", "Issues", "Share"]}
              rows={[
                ["Fixed in time", m.sla.fixed_in_time, percent(share.total ? share.inTime : null)],
                ["Fixed late", m.sla.fixed_late, percent(share.total ? share.late : null)],
                ["Open past SLA", m.sla.open_overdue, percent(share.total ? share.overdue : null)],
              ]}
            />
          }
          figureLabel={`SLA compliance ${percent(share.compliance)}: ${m.sla.fixed_in_time} fixed in time, ${m.sla.fixed_late} fixed late, ${m.sla.open_overdue} open past SLA.`}
        >
          <div className="sla-figure">
            <span className="sla-hero">{percent(share.compliance)}</span>
            <span className="muted">{share.total ? "met the SLA" : "No SLA outcomes in this period"}</span>
          </div>
          <StackedBar
            label={`${percent(share.inTime)} fixed in time, ${percent(share.late)} fixed late, ${percent(share.overdue)} open past SLA`}
            parts={[
              { key: "in", share: share.inTime, color: "var(--st-verified)", title: `Fixed in time: ${m.sla.fixed_in_time}` },
              { key: "late", share: share.late, color: "var(--st-reopened)", title: `Fixed late: ${m.sla.fixed_late}` },
              { key: "over", share: share.overdue, color: "var(--sev-critical)", title: `Open past SLA: ${m.sla.open_overdue}` },
            ]}
          />
          <Legend
            items={[
              { color: "var(--st-verified)", label: <>Fixed in time <strong className="num">{m.sla.fixed_in_time}</strong></> },
              { color: "var(--st-reopened)", label: <>Fixed late <strong className="num">{m.sla.fixed_late}</strong></> },
              { color: "var(--sev-critical)", label: <>Open past SLA <strong className="num">{m.sla.open_overdue}</strong></> },
            ]}
          />
        </ChartCard>
      </div>
    </>
  );
}

function Stat({ label, value, note, danger }: { label: string; value: number; note?: string; danger?: boolean }) {
  return (
    <div className="stat">
      <div className="stat-label">{label}</div>
      <div className={danger ? "stat-value danger-text" : "stat-value"}>{value.toLocaleString("en-US")}</div>
      {note && <div className="stat-note faint">{note}</div>}
    </div>
  );
}

/** A chart in a card: title, subtitle, legend, the chart as a labelled figure, and its data as
 *  a table behind a disclosure (the text alternative, also for keyboard and screen readers). */
function ChartCard({
  id,
  title,
  subtitle,
  legend,
  table,
  figureLabel,
  children,
}: {
  id: string;
  title: string;
  subtitle: string;
  legend?: ReactNode;
  table: ReactNode;
  figureLabel?: string;
  children: ReactNode;
}) {
  const titleId = `${id}-h`;
  return (
    <Card title={title} titleId={titleId} className="chart-card" actions={legend}>
      <p className="chart-sub muted">{subtitle}</p>
      <figure className="chart-figure" role={figureLabel ? "img" : undefined} aria-label={figureLabel}>
        {children}
      </figure>
      <details className="chart-table">
        <summary>Show the data as a table</summary>
        {table}
      </details>
    </Card>
  );
}

function DataTable({ caption, head, rows }: { caption: string; head: string[]; rows: (string | number)[][] }) {
  return (
    <div className="data-table-wrap" tabIndex={0} role="region" aria-label={caption}>
      <table className="table data-table">
        <caption className="visually-hidden">{caption}</caption>
        <thead>
          <tr>
            {head.map((h, i) => (
              <th key={h} className={i ? "num" : undefined} scope="col">
                {h}
              </th>
            ))}
          </tr>
        </thead>
        <tbody>
          {rows.map((r, i) => (
            <tr key={i}>
              {r.map((c, j) =>
                j === 0 ? (
                  <th key={j} scope="row" className="row-head">
                    {c}
                  </th>
                ) : (
                  <td key={j} className="num">
                    {c}
                  </td>
                ),
              )}
            </tr>
          ))}
        </tbody>
      </table>
    </div>
  );
}
