import { useId, useRef, useState } from "react";
import type { DragEvent, RefObject } from "react";
import { errorMessage, fieldErrors, waitText } from "../api/errors";
import { useUploadScan } from "../api/hooks/scans";
import { isApiError } from "../api/client";
import { TOOLS } from "../api/types";
import type { Limits, Scan, ScanKind, Tool } from "../api/types";
import { Button } from "../components/Button";
import { Card } from "../components/Card";
import { CopyButton } from "../components/CopyButton";
import { AlertIcon, FileIcon, UploadIcon } from "../components/Icons";
import { ActionError, Banner } from "../components/States";
import { useOrgCtx } from "../layout/OrgLayout";
import { formatBytes, formatMb, TOOL_KIND, TOOL_LABELS } from "../lib/format";
import { withDefaults } from "../lib/scanErrors";
import { IMAGE_REF_MAX, isImageTarget, splitImageRef } from "../lib/intel";
import { validateArchive, validateImageArchive, validateImageRef, validateImageTarget } from "../lib/upload";
import { useProjectCtx } from "./projectCtx";

export function useLimits(): Limits {
  return withDefaults(useOrgCtx().me.limits);
}

export const KIND_LABELS: Record<ScanKind, string> = { source: "Source code", image: "Container image" };

/** What the file picker accepts per kind (the checks in lib/upload.ts decide). */
const ACCEPT: Record<ScanKind, string> = { source: ".zip,application/zip", image: ".tar,application/x-tar" };

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

/** One shell command with a Copy button (text only; nothing is run from the page). */
function Command({ text, label }: { text: string; label: string }) {
  return (
    <div className="cmd">
      <code className="cmd-text" aria-label={label}>
        {text}
      </code>
      <CopyButton text={text} label="Copy" copiedText="Command copied to the clipboard." />
    </div>
  );
}

/**
 * The New scan card. v0.3 adds a Source code / Container image switch: an image scan uploads
 * the .tar that `docker save` writes, names the repository its issues are tracked under, and
 * always runs Trivy only. Warden never pulls from a registry, so no registry credentials exist.
 */
export function NewScan({
  pickerRef,
  kind,
  setKind,
  onStarted,
}: {
  pickerRef: RefObject<HTMLInputElement | null>;
  kind: ScanKind;
  setKind: (k: ScanKind) => void;
  onStarted: (scan: Scan) => void;
}) {
  const { orgId } = useOrgCtx();
  const project = useProjectCtx();
  const limits = useLimits();
  const upload = useUploadScan(orgId, project.id);
  const [file, setFile] = useState<File | null>(null);
  const [fileError, setFileError] = useState<string | null>(null);
  const [tools, setTools] = useState<Tool[]>(project.default_tools);
  const [dragging, setDragging] = useState(false);
  const [target, setTarget] = useState("");
  const [imageRef, setImageRef] = useState("");
  const [showErrors, setShowErrors] = useState(false);
  const [announce, setAnnounce] = useState("");
  const targetRef = useRef<HTMLInputElement>(null);
  const id = useId();
  const s = upload.state;
  const locked = upload.busy || s.phase === "upload_failed";
  const image = kind === "image";

  const server = s.phase === "error" ? fieldErrors(s.error) : {};
  const targetError = (showErrors ? validateImageTarget(target) : null) ?? server.target;
  const refError = validateImageRef(imageRef) ?? server.image_ref;

  function switchKind(next: ScanKind) {
    if (next === kind || locked) return;
    upload.reset();
    setFile(null);
    setFileError(null);
    setShowErrors(false);
    setKind(next);
  }

  function choose(f: File | undefined) {
    if (!f) return;
    upload.reset();
    const problem = image ? validateImageArchive(f, limits) : validateArchive(f, limits);
    setFileError(problem);
    setFile(problem ? null : f);
    if (pickerRef.current) pickerRef.current.value = "";
  }

  function removeFile() {
    upload.reset();
    setFile(null);
    setFileError(null);
  }

  // Pasting "ghcr.io/acme/api:1.4.2" into the repository field: keep the repository there
  // and move the full reference to Image reference (if that is still empty).
  function tidyTarget() {
    const { repository, ref } = splitImageRef(target);
    if (ref && isImageTarget(repository)) {
      setTarget(repository);
      if (!imageRef.trim()) setImageRef(ref);
      setAnnounce(`Repository set to ${repository}; ${ref} moved to Image reference.`);
    }
  }

  async function start() {
    if (!file) return;
    if (image) {
      setShowErrors(true);
      if (validateImageTarget(target) || validateImageRef(imageRef)) {
        requestAnimationFrame(() => targetRef.current?.focus());
        return;
      }
    } else if (tools.length === 0) return;
    const scan = await upload.start(file, image ? ["trivy"] : tools, image ? { kind: "image", target: target.trim(), imageRef: imageRef.trim() } : undefined);
    if (scan) {
      setFile(null);
      setShowErrors(false);
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

  const maxMb = image ? limits.image_upload_max_mb : limits.upload_max_mb;
  const ext = image ? ".tar" : ".zip";

  return (
    <Card title="New scan" titleId="new-scan-h">
      <div className="stack" style={{ gap: 16 }}>
        <input
          ref={pickerRef}
          type="file"
          accept={ACCEPT[kind]}
          className="visually-hidden"
          tabIndex={-1}
          aria-hidden="true"
          onChange={(e) => choose(e.target.files?.[0])}
        />
        <span className="visually-hidden" role="status" aria-live="polite">
          {announce}
        </span>
        <div className="segmented kind-switch" role="group" aria-label="What to scan">
          {(["source", "image"] as const).map((k) => (
            <button key={k} type="button" aria-pressed={kind === k} disabled={locked && kind !== k} onClick={() => switchKind(k)}>
              {KIND_LABELS[k]}
            </button>
          ))}
        </div>

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
              Drop a {ext} here, or{" "}
              <button type="button" className="btn-link" onClick={() => pickerRef.current?.click()}>
                browse
              </button>
            </strong>
            <span className="muted">
              {image
                ? `A docker save archive with one image, up to ${formatMb(maxMb)}`
                : `Up to ${formatMb(limits.upload_max_mb)} zipped, ${formatMb(limits.unzip_max_mb)} unpacked, ${limits.unzip_max_files.toLocaleString("en-US")} files`}
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

        {image && !locked && (
          <div className="image-fields">
            <div className="field">
              <label htmlFor={`${id}-target`}>Image repository</label>
              <input
                id={`${id}-target`}
                ref={targetRef}
                className="input mono"
                value={target}
                placeholder="ghcr.io/acme/api"
                autoComplete="off"
                autoCapitalize="none"
                spellCheck={false}
                maxLength={300}
                required
                aria-invalid={targetError ? true : undefined}
                aria-describedby={`${id}-target-h${targetError ? ` ${id}-target-e` : ""}`}
                onChange={(e) => setTarget(e.target.value)}
                onBlur={tidyTarget}
              />
              <span id={`${id}-target-h`} className="hint">
                Without tag or digest. Issues are tracked per repository, apart from the project's source code issues.
              </span>
              {targetError && (
                <span id={`${id}-target-e`} className="error">
                  <AlertIcon size={14} /> {targetError}
                </span>
              )}
            </div>
            <div className="field">
              <label htmlFor={`${id}-ref`}>
                Image reference <span className="muted" style={{ fontWeight: 400 }}>(optional)</span>
              </label>
              <input
                id={`${id}-ref`}
                className="input mono"
                value={imageRef}
                placeholder="ghcr.io/acme/api:1.4.2"
                autoComplete="off"
                autoCapitalize="none"
                spellCheck={false}
                maxLength={IMAGE_REF_MAX}
                aria-invalid={refError ? true : undefined}
                aria-describedby={`${id}-ref-h${refError ? ` ${id}-ref-e` : ""}`}
                onChange={(e) => setImageRef(e.target.value)}
              />
              <span id={`${id}-ref-h`} className="hint">
                The tag or digest you saved, shown on the scan.
              </span>
              {refError && (
                <span id={`${id}-ref-e`} className="error">
                  <AlertIcon size={14} /> {refError}
                </span>
              )}
            </div>
            <div className="image-howto">
              <p className="small text-2">Make the archive on a machine that has the image:</p>
              <Command text="docker save -o app.tar IMAGE" label="docker save command" />
              <p className="small text-2">Or let the CLI save and upload it (from a terminal or CI):</p>
              <Command text="warden scan --image IMAGE" label="warden CLI command" />
              <p className="faint small">
                Warden doesn't pull from registries and keeps no registry credentials. It looks for vulnerable and
                license-restricted packages in the image; secrets inside images aren't scanned.
              </p>
            </div>
          </div>
        )}

        {image && locked && target && (
          <p className="small text-2">
            Image repository <span className="mono">{target.trim()}</span>
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
              VALIDATION_FAILED:
                server.target || server.image_ref
                  ? "The server refused the image details. Check the fields above."
                  : image
                    ? `The server refused this file. Check that it is a docker save .tar of ${formatMb(maxMb)} or less.`
                    : `The server refused this file. Check that it is a .zip of ${formatMb(maxMb)} or less.`,
              FORBIDDEN: "You don't have permission to run scans in this project.",
            }}
          />
        )}

        {!locked &&
          (image ? (
            <p className="small text-2 image-tool">
              <strong>Scanner:</strong> Trivy <span className="muted">(OS and application packages: vulnerabilities and licenses)</span>
            </p>
          ) : (
            <ToolChecks tools={tools} setTools={setTools} disabled={locked} />
          ))}

        <div className="row-between">
          {s.phase === "idle" || s.phase === "error" ? (
            <span className="muted" style={{ fontSize: 13 }}>
              {image ? "The archive is deleted as soon as the scan ends." : "Source is deleted as soon as the scan ends."}
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
                disabled={!file || (!image && tools.length === 0) || s.phase === "rate_limited"}
                busy={upload.busy}
              >
                {image ? "Scan image" : "Start scan"}
              </Button>
            )}
          </div>
        </div>
      </div>
    </Card>
  );
}
