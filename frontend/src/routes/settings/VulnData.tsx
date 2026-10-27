import { useVulnData } from "../../api/hooks/orgs";
import type { VulnDataSource } from "../../api/types";
import { DotMark } from "../../components/Badges";
import { Card } from "../../components/Card";
import { AlertIcon } from "../../components/Icons";
import { ErrorState, SkeletonBlock } from "../../components/States";
import { useOrgCtx } from "../../layout/OrgLayout";
import { formatDateTime, relativeTime } from "../../lib/format";

const SOURCE_TEXT: Record<string, { name: string; what: string; unit: string }> = {
  trivy_db: { name: "Trivy vulnerability database", what: "Which package versions have known vulnerabilities.", unit: "" },
  kev: { name: "CISA KEV catalog", what: "CVEs known to be exploited in the wild.", unit: "CVEs" },
  epss: { name: "FIRST EPSS scores", what: "The chance each CVE is exploited in the next 30 days.", unit: "scored CVEs" },
};

/** Org Settings → Vulnerability data (read-only, every member): how fresh the mirror's feeds
 *  are. Stale data means missed CVEs and an outdated KEV/EPSS ranking. */
export function VulnDataCard({ now = new Date() }: { now?: Date }) {
  const { orgId } = useOrgCtx();
  const data = useVulnData(orgId);
  const stale = data.data?.sources.filter((s) => s.stale) ?? [];
  return (
    <Card title="Vulnerability data" titleId="vuln-data-h">
      <p className="card-intro-plain muted">
        Warden scans offline, from a mirror your operator keeps up to date. KEV and EPSS only rank issues: they never change an issue's
        severity or status.
      </p>
      {data.isPending ? (
        <SkeletonBlock label="the vulnerability data" lines={3} />
      ) : data.isError ? (
        <ErrorState error={data.error} onRetry={() => void data.refetch()} what="the vulnerability data" />
      ) : (
        <>
          {stale.length > 0 && (
            <div className="banner banner-warning vuln-stale" role="status">
              <AlertIcon />
              <span>
                <strong>
                  Out of date or missing:{" "}
                  {stale.length === data.data.sources.length ? "all the vulnerability data" : stale.map((s) => SOURCE_TEXT[s.name]?.name ?? s.name).join(" and ")}.
                </strong>{" "}
                New CVEs aren't found and the ranking gets old. Ask your operator to run <code>make mirror</code> daily.
              </span>
            </div>
          )}
          <ul className="vuln-sources">
            {data.data.sources.map((s) => (
              <SourceRow key={s.name} source={s} now={now} />
            ))}
          </ul>
          <p className="faint small" style={{ marginTop: 12 }}>
            Updated is when the publisher last changed the data. Operators: run <code>make mirror</code> daily (cron or a Kubernetes
            CronJob); a feed older than 7 days is shown as out of date.
          </p>
        </>
      )}
    </Card>
  );
}

function SourceRow({ source: s, now }: { source: VulnDataSource; now: Date }) {
  const text = SOURCE_TEXT[s.name] ?? { name: s.name, what: "", unit: "records" };
  return (
    <li className={s.stale ? "vuln-source is-stale" : "vuln-source"}>
      <div className="vuln-source-name">
        <strong>{text.name}</strong>
        {text.what && <span className="muted small">{text.what}</span>}
      </div>
      <div className="vuln-source-status">
        <DotMark tone={s.stale ? "warn" : "success"}>{s.updated_at ? (s.stale ? "Out of date" : "Up to date") : "Not loaded yet"}</DotMark>
        {s.updated_at && (
          <span className={s.stale ? "warn-text small" : "muted small"}>
            Updated {relativeTime(s.updated_at, now)} <span className="faint">· {formatDateTime(s.updated_at, now)}</span>
          </span>
        )}
        {(s.records !== null || s.loaded_at) && (
          <span className="faint small">
            {s.records !== null && `${s.records.toLocaleString("en-US")} ${text.unit}`.trim()}
            {s.records !== null && s.loaded_at && " · "}
            {s.loaded_at && `loaded ${relativeTime(s.loaded_at, now)}`}
          </span>
        )}
      </div>
    </li>
  );
}
