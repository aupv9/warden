import { useRef, useState } from "react";
import type { DragEvent, RefObject } from "react";
import { useSearchParams } from "react-router";
import { errorMessage, waitText } from "../api/errors";
import { IN_PROGRESS, useCancelScan, useScan, useScans, useUploadScan } from "../api/hooks/scans";
import { isApiError } from "../api/client";
import { flattenPages } from "../api/paging";
import { TOOLS } from "../api/types";
import type { Limits, Scan, Tool } from "../api/types";
import { Pill, ScanStatusPill, ToolStatusPill } from "../components/Badges";
import { Button, ButtonLink } from "../components/Button";
import { Card } from "../components/Card";
import { FileIcon, UploadIcon } from "../components/Icons";
import { LoadMore, Table } from "../components/Table";
import { ActionError, Banner, EmptyState, ErrorState, SkeletonBlock, SkeletonRows } from "../components/States";
import { useOrgCtx } from "../layout/OrgLayout";
import {
  DEFAULT_LIMITS,
  durationBetween,
  formatBytes,
  formatDateTime,
  formatDuration,
  formatMb,
  isRejected,
  relativeTime,
  scanErrorMessages,
  TOOL_KIND,
  TOOL_LABELS,
  userName,
} from "../lib/format";
import { can } from "../lib/permissions";
import { validateArchive } from "../lib/upload";
import { useProjectCtx } from "./ProjectLayout";

function useLimits(): Limits {
  return useOrgCtx().me.limits ?? DEFAULT_LIMITS;
}

export function ProjectScansTab() {
  const { orgId, org } = useOrgCtx();
  const project = useProjectCtx();
  const [params, setParams] = useSearchParams();
  const scans = useScans(orgId, project.id);
  const history = flattenPages(scans.data?.pages);
  const canRun = can("run_scan", org.role, project.my_role);
  const picker = useRef<HTMLInputElement>(null);

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
  const openPicker = canRun ? () => picker.current?.click() : undefined;

  return (
    <div className="stack">
      <div className="grid grid-2">
        {canRun ? (
          <NewScan pickerRef={picker} onStarted={(scan) => select(scan.id)} />
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
          <NoScansYet onUpload={openPicker} />
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
      icon={<UploadIcon size={22} />}
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
  if (isRejected(s)) return { pill: <Pill tone="danger">Rejected</Pill>, note: scanErrorMessages(s.error_code!, limits).short };
  if (s.status === "failed")
    return { pill: <Pill tone="danger">Failed</Pill>, note: s.error_code ? scanErrorMessages(s.error_code, limits).short : undefined };
  if (s.status === "queued") return { pill: <ScanStatusPill status="queued">Queued · waiting for a worker</ScanStatusPill> };
  if (s.status === "partial") return { pill: <ScanStatusPill status="partial">Partial · a scanner failed</ScanStatusPill> };
  return { pill: <ScanStatusPill status={s.status} /> };
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
      </td>
      <td data-label="By" className="nowrap">
        {userName(s.created_by)}
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

function ToolChecks({ tools, setTools, disabled }: { tools: Tool[]; setTools: (t: Tool[]) => void; disabled?: boolean }) {
  return (
    <fieldset disabled={disabled}>
      <legend>
        Scanners <span className="muted" style={{ fontWeight: 400 }}>(project defaults)</span>
      </legend>
      <div className="checks-grid">
        {TOOLS.map((t) => (
          <label key={t} className="checkbox-card">
            <input
              type="checkbox"
              checked={tools.includes(t)}
              onChange={(e) =>
                setTools(e.target.checked ? TOOLS.filter((x) => x === t || tools.includes(x)) : tools.filter((x) => x !== t))
              }
            />
            <span>
              <strong>{TOOL_LABELS[t]}</strong> <span className="muted">{TOOL_KIND[t]}</span>
            </span>
          </label>
        ))}
      </div>
      {tools.length === 0 && (
        <p className="field" style={{ marginTop: 8 }}>
          <span className="error">Choose at least one scanner.</span>
        </p>
      )}
    </fieldset>
  );
}

function ProgressBar({ label, value, right }: { label: string; value: number; right?: string }) {
  const pct = Math.round(Math.min(1, Math.max(0, value)) * 100);
  return (
    <div className="stack" style={{ gap: 6 }}>
      <div className="row-between" style={{ fontSize: 13 }}>
        <strong>{label}</strong>
        <span className="muted">{right ?? `${pct}%`}</span>
      </div>
      <div className="progress" role="progressbar" aria-label={label} aria-valuemin={0} aria-valuemax={100} aria-valuenow={pct}>
        <div style={{ width: `${pct}%` }} />
      </div>
    </div>
  );
}

function NewScan({ pickerRef, onStarted }: { pickerRef: RefObject<HTMLInputElement | null>; onStarted: (scan: Scan) => void }) {
  const { orgId } = useOrgCtx();
  const project = useProjectCtx();
  const limits = useLimits();
  const upload = useUploadScan(orgId, project.id);
  const [file, setFile] = useState<File | null>(null);
  const [fileError, setFileError] = useState<string | null>(null);
  const [tools, setTools] = useState<Tool[]>(project.default_tools);
  const [dragging, setDragging] = useState(false);
  const s = upload.state;
  const locked = upload.busy || s.phase === "upload_failed";

  function choose(f: File | undefined) {
    if (!f) return;
    upload.reset();
    const problem = validateArchive(f, limits);
    setFileError(problem);
    setFile(problem ? null : f);
    if (pickerRef.current) pickerRef.current.value = "";
  }

  function removeFile() {
    upload.reset();
    setFile(null);
    setFileError(null);
  }

  async function start() {
    if (!file || tools.length === 0) return;
    const scan = await upload.start(file, tools);
    if (scan) {
      setFile(null);
      upload.reset();
      onStarted(scan);
    }
  }

  async function retry() {
    const scan = await upload.retry();
    if (scan) {
      setFile(null);
      upload.reset();
      onStarted(scan);
    }
  }

  const input = (
    <input
      ref={pickerRef}
      type="file"
      accept=".zip,application/zip"
      className="visually-hidden"
      tabIndex={-1}
      aria-hidden="true"
      onChange={(e) => choose(e.target.files?.[0])}
    />
  );

  return (
    <Card title="New scan" titleId="new-scan-h">
      <div className="stack" style={{ gap: 16 }}>
        {input}
        {!file ? (
          <div
            className={dragging ? "dropzone dragging" : "dropzone"}
            onDragOver={(e) => {
              e.preventDefault();
              setDragging(true);
            }}
            onDragLeave={() => setDragging(false)}
            onDrop={(e: DragEvent) => {
              e.preventDefault();
              setDragging(false);
              choose(e.dataTransfer.files[0]);
            }}
          >
            <UploadIcon />
            <strong>
              Drop a .zip here, or{" "}
              <button type="button" className="btn-link" onClick={() => pickerRef.current?.click()}>
                browse
              </button>
            </strong>
            <span className="muted">
              Up to {formatMb(limits.upload_max_mb)} zipped, {formatMb(limits.unzip_max_mb)} unpacked,{" "}
              {limits.unzip_max_files.toLocaleString("en-US")} files
            </span>
          </div>
        ) : (
          <div className="file-box">
            <FileIcon />
            <span className="name" title={file.name}>
              {file.name}
            </span>
            <span className="muted">{formatBytes(file.size)}</span>
          </div>
        )}
        {fileError && (
          <p className="field" role="alert">
            <span className="error">{fileError}</span>
          </p>
        )}

        {s.phase === "hashing" && (
          <>
            <ProgressBar label="Checking the file" value={s.hashed} />
            <p className="muted" style={{ fontSize: 13 }}>
              Computing the SHA-256 in this browser, so the server can tell if the upload arrives changed.
            </p>
          </>
        )}
        {(s.phase === "creating" || s.phase === "starting") && (
          <ProgressBar
            label={s.phase === "creating" ? "Preparing the upload" : "Starting the scan"}
            value={s.phase === "creating" ? 0 : 1}
            right="…"
          />
        )}
        {s.phase === "uploading" && (
          <>
            <ProgressBar
              label={`Uploading · ${formatBytes(s.loaded)} of ${formatBytes(s.total)}`}
              value={s.total ? s.loaded / s.total : 0}
            />
            <p className="muted" style={{ fontSize: 13 }}>
              The file goes straight to storage, not through the Warden API. Keep this tab open until it finishes; the
              scan then starts by itself.
            </p>
          </>
        )}
        {s.phase === "upload_failed" && (
          <>
            <Banner title={isApiError(s.error, "UPLOAD_MISMATCH") ? "Upload incomplete." : `Upload failed at ${Math.round((s.failedAt ?? 0) * 100)}%.`}>
              {isApiError(s.error, "UPLOAD_MISMATCH")
                ? errorMessage(s.error)
                : "The connection dropped. Your file is fine; try again."}
            </Banner>
            <p className="muted" style={{ fontSize: 13 }}>
              Retry restarts the upload from the beginning.
            </p>
          </>
        )}
        {s.phase === "rate_limited" && (
          <Banner tone="warning" title="You've reached the scan limit for this hour.">
            Nothing was uploaded.{" "}
            {isApiError(s.error) && s.error.retryAfter !== undefined
              ? `Try again in ${waitText(s.error.retryAfter)}`
              : "Try again later"}
            ; the limit is {limits.scans_per_hour} scans per hour, per person.
          </Banner>
        )}
        {s.phase === "error" && (
          <ActionError
            always
            error={s.error}
            overrides={{
              VALIDATION_FAILED: `The server refused this file. Check that it is a .zip of ${formatMb(limits.upload_max_mb)} or less.`,
              FORBIDDEN: "You don't have permission to run scans in this project.",
            }}
          />
        )}

        {!upload.busy && s.phase !== "upload_failed" && <ToolChecks tools={tools} setTools={setTools} disabled={locked} />}

        <div className="row-between">
          {s.phase === "idle" || s.phase === "error" ? (
            <span className="muted" style={{ fontSize: 13 }}>
              Source is deleted as soon as the scan ends.
            </span>
          ) : (
            <span />
          )}
          <div className="row">
            {s.phase === "hashing" && <Button onClick={() => void upload.cancel()}>Cancel</Button>}
            {(s.phase === "uploading" || s.phase === "creating") && (
              <Button onClick={() => void upload.cancel()}>Cancel upload</Button>
            )}
            {s.phase === "upload_failed" && (
              <>
                <Button
                  onClick={() => {
                    void upload.cancel().then(() => {
                      removeFile();
                      pickerRef.current?.click();
                    });
                  }}
                >
                  Choose another file
                </Button>
                <Button variant="primary" onClick={() => void retry()}>
                  Retry upload
                </Button>
              </>
            )}
            {file && (s.phase === "idle" || s.phase === "rate_limited" || s.phase === "error") && (
              <Button onClick={removeFile}>Remove file</Button>
            )}
            {s.phase !== "upload_failed" && s.phase !== "uploading" && (
              <Button
                variant="primary"
                onClick={() => void start()}
                disabled={!file || tools.length === 0 || s.phase === "rate_limited"}
                busy={upload.busy}
              >
                Start scan
              </Button>
            )}
          </div>
        </div>
      </div>
    </Card>
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
  onUploadNew?: () => void;
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

  const title = rejected
    ? "Archive rejected"
    : s.status === "cancelled"
      ? "Scan cancelled"
      : s.status === "failed"
        ? "Scan failed"
        : inProgress
          ? "Scan in progress"
          : "Scan finished";

  const pill = rejected ? (
    <Pill tone="danger">Rejected</Pill>
  ) : s.status === "running" ? (
    <ScanStatusPill status="running">{`Running · ${done} of ${total} done`}</ScanStatusPill>
  ) : s.status === "queued" ? (
    <ScanStatusPill status="queued">Queued · waiting for a worker</ScanStatusPill>
  ) : s.status === "partial" && failedTool ? (
    <ScanStatusPill status="partial">
      {`Partial · ${TOOL_LABELS[failedTool.tool]} ${failedTool.status === "timeout" ? "timed out" : "failed"}`}
    </ScanStatusPill>
  ) : (
    <ScanStatusPill status={s.status} />
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
                  <ToolStatusPill status={r.status} />
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
            <ButtonLink variant="primary" to={`/orgs/${orgId}/projects/${project.id}/issues`}>
              View issues
            </ButtonLink>
          )}
          {(rejected || s.status === "cancelled" || s.status === "failed") && onUploadNew && (
            <Button variant="primary" onClick={onUploadNew}>
              Upload a new .zip
            </Button>
          )}
        </div>
      </div>
    </Card>
  );
}
