import { useRef, useState } from "react";
import { flushSync } from "react-dom";
import { Link, useSearchParams } from "react-router";
import { BAD_DOWNLOAD_URL, IN_PROGRESS, SBOM_GONE, useCancelScan, useScan, useScans, useSbomDownload } from "../api/hooks/scans";
import { flattenPages } from "../api/paging";
import type { Limits, Scan, ScanKind } from "../api/types";
import { DotMark, Pill, ScanStatusMark, ToolStatusMark } from "../components/Badges";
import { Button, ButtonLink } from "../components/Button";
import { Card } from "../components/Card";
import { DownloadIcon, UploadIcon } from "../components/Icons";
import { LoadMore, Table } from "../components/Table";
import { ActionError, EmptyState, ErrorState, SkeletonBlock, SkeletonRows } from "../components/States";
import { useOrgCtx } from "../layout/OrgLayout";
import {
  durationBetween,
  formatBytes,
  formatDateTime,
  formatDuration,
  relativeTime,
  TOOL_LABELS,
  userName,
} from "../lib/format";
import { isImageTarget } from "../lib/intel";
import { isRejected, scanErrorMessages } from "../lib/scanErrors";
import { can } from "../lib/permissions";
import { showToast } from "../lib/toast";
import { NewScan, useLimits } from "./NewScan";
import { useProjectCtx } from "./projectCtx";

export function ProjectScansTab() {
  const { orgId, org } = useOrgCtx();
  const project = useProjectCtx();
  const [params, setParams] = useSearchParams();
  const scans = useScans(orgId, project.id);
  const history = flattenPages(scans.data?.pages);
  const archived = !!project.archived_at;
  // An archived project takes no new scans (the API answers 409 PROJECT_ARCHIVED).
  const canRun = can("run_scan", org.role, project.my_role) && !archived;
  const picker = useRef<HTMLInputElement>(null);
  const [kind, setKind] = useState<ScanKind>("source");

  // The right-hand card shows the scan named in ?scan=, else the newest one still in progress.
  const selectedId =
    params.get("scan") ?? history.find((s) => IN_PROGRESS.includes(s.status) || s.status === "pending_upload")?.id;
  const select = (id: string | null) =>
    setParams(
      (prev) => {
        const next = new URLSearchParams(prev);
        if (id) next.set("scan", id);
        else next.delete("scan");
        return next;
      },
      { replace: true },
    );
  // "Upload a new …" from a rejected scan reopens the picker for the same kind of file. The
  // switch renders first (flushSync) so the picker's `accept` already matches.
  const openPicker = canRun
    ? (k: ScanKind = "source") => {
        if (k !== kind) flushSync(() => setKind(k));
        picker.current?.click();
      }
    : undefined;

  return (
    <div className="page-body">
      <div className="grid grid-2">
        {canRun ? (
          <NewScan pickerRef={picker} kind={kind} setKind={setKind} onStarted={(scan) => select(scan.id)} />
        ) : archived ? (
          <Card title="New scan" titleId="new-scan-h">
            <div className="dropzone is-disabled" aria-hidden="true">
              <UploadIcon size={22} />
              <span>Uploads are turned off</span>
            </div>
            <p className="muted" style={{ marginTop: 12 }}>
              This project is archived, so it doesn't take new scans. Its issues and scan history stay readable.
              {can("create_archive_project", org.role) && (
                <>
                  {" "}
                  <Link to={`/orgs/${orgId}/projects/${project.id}/settings#archive`}>Unarchive it in Settings</Link> to scan
                  again.
                </>
              )}
            </p>
          </Card>
        ) : (
          <Card title="New scan" titleId="new-scan-h">
            <p className="muted">
              Only project owners, developers and security leads can run scans. Ask a project owner for the developer
              role if you need to upload code.
            </p>
          </Card>
        )}
        <ScanPanel scanId={selectedId} canRun={canRun} onUploadNew={openPicker} onClear={() => select(null)} />
      </div>

      <Card title="Scan history" titleId="history-h" flush>
        {scans.isPending ? (
          <SkeletonRows label="scan history" />
        ) : scans.isError ? (
          <ErrorState error={scans.error} onRetry={() => void scans.refetch()} what="the scan history" />
        ) : history.length === 0 ? (
          <NoScansYet onUpload={openPicker ? () => openPicker("source") : undefined} />
        ) : (
          <>
            <Table
              caption="Scan history"
              head={
                <tr>
                  <th>Started</th>
                  <th>File</th>
                  <th>By</th>
                  <th>Status</th>
                  <th className="num">New</th>
                  <th className="num">Fixed</th>
                  <th className="num">Reopened</th>
                  <th className="num">Duration</th>
                </tr>
              }
            >
              {history.map((s) => (
                <HistoryRow key={s.id} scan={s} selected={s.id === selectedId} onSelect={() => select(s.id)} />
              ))}
            </Table>
            <LoadMore
              hasNext={!!scans.hasNextPage}
              loading={scans.isFetchingNextPage}
              onLoad={() => void scans.fetchNextPage()}
              shown={history.length}
              noun="scans"
              label="Load older scans"
            />
          </>
        )}
      </Card>
    </div>
  );
}

/** Shared with the project's Issues tab. Viewers see the text without the button. */
export function NoScansYet({ onUpload, uploadTo }: { onUpload?: () => void; uploadTo?: string }) {
  return (
    <EmptyState
      icon={<UploadIcon size={18} />}
      title="No scans yet"
      action={
        onUpload ? (
          <Button variant="primary" onClick={onUpload}>
            Upload a .zip
          </Button>
        ) : uploadTo ? (
          <ButtonLink variant="primary" to={uploadTo}>
            Upload a .zip
          </ButtonLink>
        ) : undefined
      }
    >
      Upload a .zip of the source to run the first scan. Issues appear here when it finishes.
    </EmptyState>
  );
}

function historyStatus(s: Scan, limits: Limits): { pill: React.ReactNode; note?: string } {
  if (isRejected(s)) return { pill: <DotMark tone="danger">Rejected</DotMark>, note: scanErrorMessages(s.error_code!, limits).short };
  if (s.status === "failed")
    return { pill: <DotMark tone="danger">Failed</DotMark>, note: s.error_code ? scanErrorMessages(s.error_code, limits).short : undefined };
  if (s.status === "queued") return { pill: <ScanStatusMark status="queued">Queued · waiting for a worker</ScanStatusMark> };
  if (s.status === "partial") return { pill: <ScanStatusMark status="partial">Partial · a scanner failed</ScanStatusMark> };
  return { pill: <ScanStatusMark status={s.status} /> };
}

/** v0.3: an image scan's kind and the image it scanned (the reference given at upload, else the
 *  repository its issues are tracked under). Text from the uploader, shown as text. */
function ImageLine({ scan: s }: { scan: Scan }) {
  return (
    <span className="scan-image">
      <Pill>Image</Pill>
      <span className="mono" title={s.image_ref && s.image_ref !== s.target ? `Issues tracked under ${s.target}` : undefined}>
        {s.image_ref || s.target}
      </span>
    </span>
  );
}

function HistoryRow({ scan: s, selected, onSelect }: { scan: Scan; selected: boolean; onSelect: () => void }) {
  const limits = useLimits();
  const finished = s.status === "completed" || s.status === "partial";
  const dash = <span className="muted">–</span>;
  const status = historyStatus(s, limits);
  const duration = durationBetween(s.started_at ?? s.queued_at ?? s.created_at, s.finished_at);
  return (
    <tr className={selected ? "selected" : undefined}>
      <td className="nowrap">
        <button type="button" className="row-button" onClick={onSelect} aria-pressed={selected}>
          {formatDateTime(s.created_at)}
        </button>
      </td>
      <td data-label="File" className="mono" style={{ fontSize: 13, wordBreak: "break-all" }}>
        {s.file_name}
        {s.kind === "image" && <ImageLine scan={s} />}
      </td>
      <td data-label="By">
        <span className="nowrap">{userName(s.created_by)}</span>
        {s.via_token && (
          <span className="via-token" title={`API token wdn_${s.via_token.prefix}_…`}>
            via token {s.via_token.name}
          </span>
        )}
      </td>
      <td data-label="Status">
        <span className="row" style={{ display: "inline-flex" }}>
          {status.pill}
          {status.note && (
            <span className="muted" style={{ fontSize: 13 }}>
              {status.note}
            </span>
          )}
        </span>
      </td>
      <td data-label="New" className="num">
        {finished ? <strong>{s.stats.new}</strong> : dash}
      </td>
      <td data-label="Fixed" className="num">
        {finished ? s.stats.fixed : dash}
      </td>
      <td data-label="Reopened" className="num">
        {finished ? s.stats.reopened : dash}
      </td>
      <td data-label="Duration" className="num nowrap">
        {formatDuration(duration)}
      </td>
    </tr>
  );
}

function ScanPanel({
  scanId,
  canRun,
  onUploadNew,
  onClear,
}: {
  scanId: string | undefined;
  canRun: boolean;
  onUploadNew?: (kind: ScanKind) => void;
  onClear: () => void;
}) {
  const { orgId } = useOrgCtx();
  const project = useProjectCtx();
  const limits = useLimits();
  const scan = useScan(orgId, scanId);
  const cancel = useCancelScan(orgId);

  if (!scanId) {
    return (
      <Card title="Scan progress" titleId="panel-h">
        <p className="muted">No scan is running. Start one, or pick a scan in the history to see each scanner.</p>
      </Card>
    );
  }
  if (scan.isPending) {
    return (
      <Card title="Scan" titleId="panel-h">
        <SkeletonBlock label="scan" />
      </Card>
    );
  }
  if (scan.isError) {
    return (
      <Card title="Scan" titleId="panel-h">
        <ErrorState error={scan.error} onRetry={() => void scan.refetch()} what="this scan" />
      </Card>
    );
  }

  const s = scan.data;
  const runs = s.tool_runs ?? [];
  const done = runs.filter((r) => r.status !== "queued" && r.status !== "running").length;
  const total = runs.length || s.tools.length;
  const inProgress = IN_PROGRESS.includes(s.status) || s.status === "pending_upload";
  const rejected = isRejected(s);
  const failedTool = runs.find((r) => r.status === "failed" || r.status === "timeout");
  const errorText = s.error_code ? scanErrorMessages(s.error_code, limits) : undefined;
  const duration = durationBetween(s.started_at ?? s.queued_at ?? s.created_at, s.finished_at);
  // An image scan's issues are its target's: "View issues" opens them filtered to that image.
  const issuesLink = `/orgs/${orgId}/projects/${project.id}/issues${
    s.kind === "image" && isImageTarget(s.target) ? `?${new URLSearchParams({ target: s.target })}` : ""
  }`;

  const title = rejected
    ? s.kind === "image"
      ? "Image rejected"
      : "Archive rejected"
    : s.status === "cancelled"
      ? "Scan cancelled"
      : s.status === "failed"
        ? "Scan failed"
        : inProgress
          ? "Scan in progress"
          : "Scan finished";

  const pill = rejected ? (
    <DotMark tone="danger">Rejected</DotMark>
  ) : s.status === "running" ? (
    <ScanStatusMark status="running">{`Running · ${done} of ${total} done`}</ScanStatusMark>
  ) : s.status === "queued" ? (
    <ScanStatusMark status="queued">Queued · waiting for a worker</ScanStatusMark>
  ) : s.status === "partial" && failedTool ? (
    <ScanStatusMark status="partial">
      {`Partial · ${TOOL_LABELS[failedTool.tool]} ${failedTool.status === "timeout" ? "timed out" : "failed"}`}
    </ScanStatusMark>
  ) : (
    <ScanStatusMark status={s.status} />
  );

  return (
    <Card
      title={title}
      titleId="panel-h"
      actions={<span aria-live="polite">{pill}</span>}
    >
      <div className="stack" style={{ gap: 14 }}>
        <p className="muted" style={{ fontSize: 13 }}>
          <span className="mono">{s.file_name}</span> · {formatBytes(s.file_size)}
          {s.status === "cancelled"
            ? ` · cancelled ${formatDateTime(s.finished_at)}${duration !== null ? `, after ${formatDuration(duration)}` : ""}`
            : inProgress
              ? ` · started ${relativeTime(s.started_at ?? s.created_at)} by ${userName(s.created_by)}`
              : ` · ${formatDuration(duration)} · by ${userName(s.created_by)}`}
        </p>
        {s.kind === "image" && (
          <p className="scan-image-line small">
            <ImageLine scan={s} />
            {s.target && s.image_ref && s.image_ref !== s.target && (
              <span className="muted">
                Issues tracked under <span className="mono">{s.target}</span>
              </span>
            )}
          </p>
        )}
        {s.status === "running" && (
          <div className="progress" role="progressbar" aria-label="Scanners finished" aria-valuemin={0} aria-valuemax={total} aria-valuenow={done}>
            <div style={{ width: `${total ? (done / total) * 100 : 0}%` }} />
          </div>
        )}
        {errorText && (s.status === "failed" || s.status === "cancelled") && (
          <div className="banner banner-error" role="status">
            <div className="stack" style={{ gap: 6 }}>
              <strong>{errorText.full.split(". ")[0]}.</strong>
              {errorText.full.split(". ").length > 1 && <span>{errorText.full.split(". ").slice(1).join(". ")}</span>}
              <span className="mono" style={{ fontSize: 12 }}>
                {s.error_code}
              </span>
            </div>
          </div>
        )}
        {runs.length > 0 && !rejected && (
          <Table
            caption="Scanners"
            stack={false}
            head={
              <tr>
                <th>Scanner</th>
                <th>Status</th>
                <th className="num">Findings</th>
                <th className="num">Time</th>
              </tr>
            }
          >
            {runs.map((r) => (
              <tr key={r.tool}>
                <td>
                  <strong>{TOOL_LABELS[r.tool]}</strong>{" "}
                  {r.tool_version && (
                    <span className="mono muted" style={{ fontSize: 12 }}>
                      {r.tool_version}
                    </span>
                  )}
                  {r.error && (
                    <div className="muted" style={{ fontSize: 12 }}>
                      {r.error}
                    </div>
                  )}
                </td>
                <td>
                  <ToolStatusMark status={r.status} />
                </td>
                <td className="num">{r.findings_count ?? "–"}</td>
                <td className="num nowrap">{formatDuration(r.duration_ms)}</td>
              </tr>
            ))}
          </Table>
        )}
        {(s.status === "completed" || s.status === "partial") && (
          <p>
            <strong>{s.stats.new}</strong> new · {s.stats.fixed} fixed · {s.stats.reopened} reopened · {s.stats.total}{" "}
            findings in total
          </p>
        )}
        {s.sbom && (s.status === "completed" || s.status === "partial") && <SbomRow scan={s} sbom={s.sbom} />}
        {rejected && <p className="muted">Nothing was scanned and no issues changed.</p>}
        {s.status === "cancelled" && <p className="muted">A cancelled scan doesn't change any issue.</p>}
        <ActionError error={cancel.error} overrides={{ CONFLICT: "This scan already finished." }} />
        <div className="row" style={{ justifyContent: "flex-end" }}>
          {!inProgress && (
            <button type="button" className="btn-link" onClick={onClear}>
              Close
            </button>
          )}
          {inProgress && canRun && (
            <Button onClick={() => cancel.mutate(s.id)} busy={cancel.isPending}>
              Cancel scan
            </Button>
          )}
          {(s.status === "completed" || s.status === "partial") && (
            <ButtonLink variant="primary" to={issuesLink}>
              View issues
            </ButtonLink>
          )}
          {(rejected || s.status === "cancelled" || s.status === "failed") && onUploadNew && (
            <Button variant="primary" onClick={() => onUploadNew(s.kind)}>
              {s.kind === "image" ? "Upload a new .tar" : "Upload a new .zip"}
            </Button>
          )}
        </div>
      </div>
    </Card>
  );
}

/** v0.3: the scan's CycloneDX SBOM. Each click asks for a fresh 5-minute link and hands it to
 *  the browser as a download; the page never opens or shows the file. */
function SbomRow({ scan: s, sbom: meta }: { scan: Scan; sbom: NonNullable<Scan["sbom"]> }) {
  const { orgId } = useOrgCtx();
  const project = useProjectCtx();
  const download = useSbomDownload(orgId);
  const fileName = `${project.key.toLowerCase()}-${s.id.slice(0, 8)}.cdx.json`;
  const what = `${meta.components.toLocaleString("en-US")} component${meta.components === 1 ? "" : "s"} · ${formatBytes(meta.size)}`;
  return (
    <div className="sbom-box">
      <div className="sbom-row">
        <div className="sbom-text">
          <strong>Software bill of materials</strong>
          <span className="muted small">CycloneDX JSON · {what}</span>
        </div>
        <Button
          size="sm"
          busy={download.isPending}
          onClick={() =>
            download.mutate(
              { scanId: s.id, fileName },
              { onSuccess: () => showToast({ tone: "success", message: `SBOM download started (${what}).` }) },
            )
          }
        >
          <DownloadIcon /> Download SBOM (CycloneDX)
        </Button>
      </div>
      {download.data && (
        <p className="faint small sbom-sum">
          SHA-256 <span className="mono">{download.data.sha256}</span>
        </p>
      )}
      <ActionError
        error={download.error}
        overrides={{
          [SBOM_GONE]: "This scan's SBOM is no longer available. SBOMs are kept for a limited time; run a new scan to get one.",
          [BAD_DOWNLOAD_URL]: "The server sent a download link Warden doesn't follow. Tell your operator.",
        }}
      />
    </div>
  );
}
