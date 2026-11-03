import { useId, useRef, useState } from "react";
import type { DragEvent, FormEvent, ReactNode, RefObject } from "react";
import { errorMessage, fieldErrors, waitText } from "../api/errors";
import { usePullScan } from "../api/hooks/registries";
import { useUploadScan } from "../api/hooks/scans";
import { isApiError } from "../api/client";
import { TOOLS } from "../api/types";
import type { Limits, Scan, ScanKind, Tool, UploadKind } from "../api/types";
import { Button } from "../components/Button";
import { Card } from "../components/Card";
import { CopyButton } from "../components/CopyButton";
import { AlertIcon, FileIcon, UploadIcon } from "../components/Icons";
import { ActionError, Banner } from "../components/States";
import { useOrgCtx } from "../layout/OrgLayout";
import { formatBytes, formatMb, TOOL_KIND, TOOL_LABELS } from "../lib/format";
import { can } from "../lib/permissions";
import { PULL_REF_EXAMPLE, PULL_REF_MAX, validatePullRef } from "../lib/registries";
import { withDefaults } from "../lib/scanErrors";
import { IMAGE_REF_MAX, isImageTarget, splitImageRef } from "../lib/intel";
import { validateArchive, validateImageArchive, validateImageRef, validateImageTarget } from "../lib/upload";
import { Link } from "react-router";
import { useProjectCtx } from "./projectCtx";

export function useLimits(): Limits {
  return withDefaults(useOrgCtx().me.limits);
}

export const KIND_LABELS: Record<ScanKind, string> = { source: "Source code", image: "Container image", history: "Git history" };

/** v0.7 wave 2: what the New scan card makes: an upload (source .zip, image .tar) or a scan of an
 *  image the worker pulls from its registry by digest. */
export type NewScanMode = UploadKind | "pull";
const MODE_LABELS: Record<NewScanMode, string> = { source: "Source code", image: "Container image", pull: "Image from a registry" };
/** The scanners an image scan runs: Trivy for packages, Gitleaks for secrets in the layers. */
export const IMAGE_TOOLS: Tool[] = ["trivy", "gitleaks"];
const IMAGE_TOOL_KIND: Partial<Record<Tool, string>> = { trivy: "packages", gitleaks: "secrets in every layer" };

/** What the file picker accepts per kind (the checks in lib/upload.ts decide). History scans
 *  (a git bundle) come only from the CLI: a browser can't build a bundle. */
const ACCEPT: Record<UploadKind, string> = { source: ".zip,application/zip", image: ".tar,application/x-tar" };

function ToolChecks({
  tools,
  setTools,
  disabled,
  choices = TOOLS,
  note = "(project defaults)",
}: {
  tools: Tool[];
  setTools: (t: Tool[]) => void;
  disabled?: boolean;
  choices?: Tool[];
  note?: string;
}) {
  const image = choices !== TOOLS;
  return (
    <fieldset disabled={disabled}>
      <legend>
        Scanners <span className="muted" style={{ fontWeight: 400 }}>{note}</span>
      </legend>
      <div className="checks-grid">
        {choices.map((t) => (
          <label key={t} className="checkbox-card">
            <input
              type="checkbox"
              checked={tools.includes(t)}
              onChange={(e) =>
                setTools(e.target.checked ? choices.filter((x) => x === t || tools.includes(x)) : tools.filter((x) => x !== t))
              }
            />
            <span>
              <strong>{TOOL_LABELS[t]}</strong> <span className="muted">{(image && IMAGE_TOOL_KIND[t]) || TOOL_KIND[t]}</span>
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
 * the .tar that `docker save` writes and names the repository its issues are tracked under.
 * v0.7 wave 2: image scans run Trivy and Gitleaks (secrets in the layers), and "Image from a
 * registry" has the worker pull an image by digest (PullScanForm); nothing is uploaded then.
 */
export function NewScan({
  pickerRef,
  kind: mode,
  setKind,
  onStarted,
  pullSeed,
}: {
  pickerRef: RefObject<HTMLInputElement | null>;
  kind: NewScanMode;
  setKind: (k: NewScanMode) => void;
  onStarted: (scan: Scan) => void;
  /** A reference to pull again (from a failed pulled scan); `n` changes on every request. */
  pullSeed?: { ref: string; n: number } | null;
}) {
  const { orgId } = useOrgCtx();
  const project = useProjectCtx();
  const upload = useUploadScan(orgId, project.id);
  const locked = upload.busy || upload.state.phase === "upload_failed";
  const switcher = (
    <div className="segmented kind-switch" role="group" aria-label="What to scan">
      {(["source", "image", "pull"] as const).map((k) => (
        <button
          key={k}
          type="button"
          aria-pressed={mode === k}
          disabled={locked && mode !== k}
          onClick={() => {
            if (k === mode || locked) return;
            upload.reset();
            setKind(k);
          }}
        >
          {MODE_LABELS[k]}
        </button>
      ))}
    </div>
  );
  if (mode === "pull") {
    return (
      <Card title="New scan" titleId="new-scan-h">
        <div className="stack" style={{ gap: 16 }}>
          {switcher}
          <PullScanForm key={pullSeed?.n ?? 0} initialRef={pullSeed?.ref ?? ""} onStarted={onStarted} />
        </div>
      </Card>
    );
  }
  // Keyed by kind, so switching starts with no file and no field errors.
  return <UploadScan key={mode} pickerRef={pickerRef} kind={mode} upload={upload} switcher={switcher} onStarted={onStarted} />;
}

function UploadScan({
  pickerRef,
  kind,
  upload,
  switcher,
  onStarted,
}: {
  pickerRef: RefObject<HTMLInputElement | null>;
  kind: UploadKind;
  upload: ReturnType<typeof useUploadScan>;
  switcher: ReactNode;
  onStarted: (scan: Scan) => void;
}) {
  const { orgId } = useOrgCtx();
  const project = useProjectCtx();
  const limits = useLimits();
  const [file, setFile] = useState<File | null>(null);
  const [fileError, setFileError] = useState<string | null>(null);
  const [tools, setTools] = useState<Tool[]>(project.default_tools);
  const [imageTools, setImageTools] = useState<Tool[]>(IMAGE_TOOLS);
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
    }
    const chosen = image ? imageTools : tools;
    if (chosen.length === 0) return;
    const scan = await upload.start(file, chosen, image ? { kind: "image", target: target.trim(), imageRef: imageRef.trim() } : undefined);
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
        {switcher}

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
                Trivy looks for vulnerable and license-restricted packages; Gitleaks reads every layer for secrets, also files a
                later layer deletes. To scan an image without saving it, choose Image from a registry.
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
            <ToolChecks tools={imageTools} setTools={setImageTools} choices={IMAGE_TOOLS} note="(for images)" />
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
                disabled={!file || (image ? imageTools : tools).length === 0 || s.phase === "rate_limited"}
                busy={upload.busy}
              >
                {image ? "Scan image" : "Start scan"}
              </Button>
            )}
          </div>
        </div>
        {/* v0.4 wave 2: history scans can't be made here (a browser can't build a git bundle). */}
        <p className="faint small history-note">
          Secrets in git history are scanned from CI with <code>warden scan --history</code>, which needs the full history (
          <code>fetch-depth: 0</code> on GitHub, <code>GIT_DEPTH: 0</code> on GitLab).{" "}
          <Link to={`/orgs/${orgId}/projects/${project.id}/settings#ci-setup`}>Set it up in CI setup</Link>.
        </p>
      </div>
    </Card>
  );
}

/** v0.7 wave 2: New scan › Image from a registry. The worker pulls the image itself, by digest
 *  only (validatePullRef checks the contract's pattern before anything is sent), with the org's
 *  credentials for its host or anonymously. Nothing is uploaded from the browser. */
function PullScanForm({ initialRef, onStarted }: { initialRef: string; onStarted: (scan: Scan) => void }) {
  const { orgId, org } = useOrgCtx();
  const project = useProjectCtx();
  const limits = useLimits();
  const pull = usePullScan(orgId, project.id);
  const [ref, setRef] = useState(initialRef);
  const [tools, setTools] = useState<Tool[]>(IMAGE_TOOLS);
  const [touched, setTouched] = useState(!!initialRef);
  const inputRef = useRef<HTMLInputElement>(null);
  const id = useId();

  const server = fieldErrors(pull.error);
  const refError = (touched ? validatePullRef(ref) : null) ?? server.image_ref;
  const rateLimited = isApiError(pull.error, "RATE_LIMITED");

  const submit = (e: FormEvent) => {
    e.preventDefault();
    setTouched(true);
    if (validatePullRef(ref)) {
      requestAnimationFrame(() => inputRef.current?.focus());
      return;
    }
    if (tools.length === 0) return;
    pull.mutate(
      { image_ref: ref.trim(), tools },
      {
        onSuccess: (scan) => {
          setRef("");
          setTouched(false);
          onStarted(scan);
        },
        onError: (err) => {
          if (fieldErrors(err).image_ref) requestAnimationFrame(() => inputRef.current?.focus());
        },
      },
    );
  };

  return (
    <form className="pull-fields" onSubmit={submit} noValidate>
      <div className="field">
        <label htmlFor={`${id}-ref`}>Image reference</label>
        <input
          id={`${id}-ref`}
          ref={inputRef}
          className="input mono"
          value={ref}
          placeholder={PULL_REF_EXAMPLE}
          autoComplete="off"
          autoCapitalize="none"
          spellCheck={false}
          maxLength={PULL_REF_MAX + 20}
          required
          aria-invalid={refError ? true : undefined}
          aria-describedby={`${id}-ref-h${refError ? ` ${id}-ref-e` : ""}`}
          onChange={(e) => setRef(e.target.value)}
          onBlur={() => ref.trim() && setTouched(true)}
        />
        <span id={`${id}-ref-h`} className="hint">
          Pin by digest: registry/repo@sha256:…. Warden never pulls by tag, because a tag can point to another image tomorrow.
        </span>
        {refError && (
          <span id={`${id}-ref-e`} className="error">
            <AlertIcon size={14} /> {refError}
          </span>
        )}
      </div>
      <div className="image-howto">
        <p className="small text-2">Print the digest of an image you have pulled or pushed:</p>
        <Command text="docker inspect --format '{{index .RepoDigests 0}}' IMAGE" label="docker inspect command" />
      </div>
      <ToolChecks tools={tools} setTools={setTools} choices={IMAGE_TOOLS} note="(for images)" disabled={pull.isPending} />
      <p className="faint small">
        Warden pulls the image itself and signs in with your org's credentials for its host, if an org admin or security lead added them
        {can("manage_registries", org.role) ? (
          <>
            {" "}
            under <Link to={`/orgs/${orgId}/settings/registries`}>Registries</Link>
          </>
        ) : (
          " under Registries"
        )}
        ; otherwise it pulls anonymously. Hosts that resolve to private or internal addresses are refused.
      </p>
      {rateLimited ? (
        <Banner tone="warning" title="You've reached the scan limit for this hour.">
          Nothing was pulled.{" "}
          {isApiError(pull.error) && pull.error.retryAfter !== undefined ? `Try again in ${waitText(pull.error.retryAfter)}` : "Try again later"}; the limit
          is {limits.scans_per_hour} scans per hour, per person.
        </Banner>
      ) : (
        <ActionError
          always
          error={pull.error}
          overrides={{
            VALIDATION_FAILED: server.image_ref ? "The server refused the image reference. Check the field above." : "The server refused this scan. Check the reference and the scanners.",
            FORBIDDEN: "You don't have permission to run scans in this project.",
          }}
        />
      )}
      <div className="row-between">
        <span className="muted" style={{ fontSize: 13 }}>
          Nothing is uploaded from this browser. The image is deleted as soon as the scan ends.
        </span>
        <Button type="submit" variant="primary" busy={pull.isPending} disabled={tools.length === 0}>
          Pull and scan
        </Button>
      </div>
    </form>
  );
}
