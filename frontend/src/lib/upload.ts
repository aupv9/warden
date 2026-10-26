import { ApiError, isApiError } from "../api/client";
import type { CreateScanBody, CreateScanResponse, Limits, PresignedUpload, Scan, Tool } from "../api/types";
import { hashBlob } from "./sha256";
import type { HashMessage } from "./hashWorker";

// The upload flow (DESIGN.md "Upload flow"):
//   hash in the browser → POST …/scans → PUT the file straight to object storage with the
//   presigned URL → POST …/start.
// The API never receives the archive and the UI never interprets its contents; it only hashes
// the bytes. A failed PUT can be retried while the URL is valid; after expiry the old scan is
// cancelled and a new one created with the same hash (no second hashing pass).

export const UPLOAD_FAILED = "UPLOAD_FAILED";
export const UPLOAD_ABORTED = "UPLOAD_ABORTED";
/** Treat the presigned URL as expired a little early, so a retry never starts on a dying link. */
const EXPIRY_MARGIN_MS = 30_000;

export type UploadPhase =
  | "idle"
  | "hashing"
  | "creating"
  | "uploading"
  | "upload_failed"
  | "rate_limited"
  | "starting"
  | "started"
  | "error";

export interface UploadSnapshot {
  phase: UploadPhase;
  /** 0..1 of the file hashed. */
  hashed: number;
  loaded: number;
  total: number;
  /** Fraction reached when the PUT failed. */
  failedAt?: number;
  error?: unknown;
  scan?: Scan;
}

export interface UploadDeps {
  hash(file: Blob, onProgress: (done: number, total: number) => void, signal: AbortSignal): Promise<string>;
  createScan(body: CreateScanBody): Promise<CreateScanResponse>;
  put(upload: PresignedUpload, file: Blob, onProgress: (loaded: number, total: number) => void, signal: AbortSignal): Promise<void>;
  startScan(scanId: string): Promise<Scan>;
  cancelScan(scanId: string): Promise<unknown>;
  now?(): number;
}

/** Client-side checks that mirror the server's rules, before anything is sent. */
export function validateArchive(file: { name: string; size: number }, limits: Pick<Limits, "upload_max_mb">): string | null {
  if (!file.name.toLowerCase().endsWith(".zip")) return "Choose a .zip file.";
  if (file.name.length > 255) return "The file name is too long (255 characters at most).";
  if (/[/\\]/.test(file.name)) return "The file name can't contain / or \\.";
  if (file.size < 1) return "The file is empty.";
  if (file.size > limits.upload_max_mb * 1024 * 1024) return `The file is larger than ${limits.upload_max_mb} MB.`;
  return null;
}

export class UploadSession {
  private snap: UploadSnapshot;
  private ctrl = new AbortController();
  private sha256?: string;
  private upload?: PresignedUpload;
  private scan?: Scan;
  private cancelled = false;

  constructor(
    readonly file: File,
    readonly tools: Tool[],
    private deps: UploadDeps,
    private onChange: (s: UploadSnapshot) => void,
  ) {
    this.snap = { phase: "idle", hashed: 0, loaded: 0, total: file.size };
  }

  get snapshot(): UploadSnapshot {
    return this.snap;
  }

  /** Runs the whole flow. Resolves with the started scan, or undefined if it stopped early
   *  (cancelled, rate limited, failed: see the snapshot). */
  async start(): Promise<Scan | undefined> {
    this.set({ phase: "hashing", hashed: 0 });
    try {
      this.sha256 = await this.deps.hash(
        this.file,
        (done, total) => this.set({ hashed: total ? done / total : 1 }),
        this.ctrl.signal,
      );
    } catch (err) {
      return this.fail(err);
    }
    if (!(await this.create())) return undefined;
    return this.putAndStart();
  }

  /** After "upload_failed": PUT again, or start over from POST …/scans if the link expired. */
  async retry(): Promise<Scan | undefined> {
    if (this.snap.phase !== "upload_failed" || !this.upload || !this.scan) return undefined;
    this.ctrl = new AbortController();
    const now = this.deps.now?.() ?? Date.now();
    if (Date.parse(this.upload.expires_at) - EXPIRY_MARGIN_MS <= now) {
      const old = this.scan.id;
      await this.deps.cancelScan(old).catch(() => undefined);
      if (!(await this.create())) return undefined;
    }
    return this.putAndStart();
  }

  /** Stops whatever is running. A scan that was created but not started is cancelled on the
   *  server too, so it doesn't sit in "pending_upload". */
  async cancel(): Promise<void> {
    if (this.cancelled) return;
    this.cancelled = true;
    this.ctrl.abort();
    const pending = this.scan && this.snap.phase !== "started" ? this.scan.id : undefined;
    this.set({ phase: "idle", error: undefined });
    if (pending) await this.deps.cancelScan(pending).catch(() => undefined);
  }

  private async create(): Promise<boolean> {
    this.set({ phase: "creating", loaded: 0, failedAt: undefined, error: undefined });
    try {
      const res = await this.deps.createScan({
        file_name: this.file.name,
        file_size: this.file.size,
        sha256: this.sha256 ?? "",
        ...(this.tools.length > 0 ? { tools: this.tools } : {}),
      });
      if (this.cancelled) {
        await this.deps.cancelScan(res.scan.id).catch(() => undefined);
        return false;
      }
      this.scan = res.scan;
      this.upload = res.upload;
      this.set({ scan: res.scan });
      return true;
    } catch (err) {
      if (isApiError(err, "RATE_LIMITED")) {
        this.set({ phase: "rate_limited", error: err });
        return false;
      }
      this.fail(err);
      return false;
    }
  }

  private async putAndStart(): Promise<Scan | undefined> {
    const upload = this.upload!;
    const scan = this.scan!;
    this.set({ phase: "uploading", loaded: 0, failedAt: undefined, error: undefined });
    try {
      await this.deps.put(upload, this.file, (loaded, total) => this.set({ loaded, total }), this.ctrl.signal);
    } catch (err) {
      if (this.cancelled) return undefined;
      this.set({ phase: "upload_failed", failedAt: this.snap.total ? this.snap.loaded / this.snap.total : 0, error: err });
      return undefined;
    }
    if (this.cancelled) return undefined;
    this.set({ phase: "starting", loaded: this.snap.total });
    try {
      const started = await this.deps.startScan(scan.id);
      this.scan = started;
      this.set({ phase: "started", scan: started });
      return started;
    } catch (err) {
      if (isApiError(err, "UPLOAD_MISMATCH")) {
        this.set({ phase: "upload_failed", failedAt: 1, error: err });
        return undefined;
      }
      return this.fail(err);
    }
  }

  private fail(err: unknown): undefined {
    if (this.cancelled || (err instanceof DOMException && err.name === "AbortError")) {
      this.set({ phase: "idle" });
      return undefined;
    }
    this.set({ phase: "error", error: err });
    return undefined;
  }

  private set(patch: Partial<UploadSnapshot>): void {
    this.snap = { ...this.snap, ...patch };
    this.onChange(this.snap);
  }
}

/** Hashes in a Web Worker when there is one (the browser), else on this thread (tests). */
export function hashFile(file: Blob, onProgress: (done: number, total: number) => void, signal: AbortSignal): Promise<string> {
  if (typeof Worker === "undefined") return hashBlob(file, onProgress, () => signal.aborted);
  return new Promise((resolve, reject) => {
    const worker = new Worker(new URL("./hashWorker.ts", import.meta.url), { type: "module" });
    const stop = () => {
      worker.terminate();
      reject(new DOMException("hash cancelled", "AbortError"));
    };
    if (signal.aborted) return stop();
    signal.addEventListener("abort", stop, { once: true });
    worker.onmessage = (e: MessageEvent<HashMessage>) => {
      const m = e.data;
      if (m.type === "progress") onProgress(m.done, m.total);
      else {
        signal.removeEventListener("abort", stop);
        worker.terminate();
        if (m.type === "done") resolve(m.hex);
        else reject(new ApiError(0, { code: "HASH_FAILED", message: "could not read the file" }));
      }
    };
    worker.onerror = () => {
      signal.removeEventListener("abort", stop);
      worker.terminate();
      reject(new ApiError(0, { code: "HASH_FAILED", message: "could not read the file" }));
    };
    worker.postMessage({ file });
  });
}

// Headers a page may not set on XMLHttpRequest (the browser computes them, e.g. Content-Length
// from the body, or refuses). The presigned URL pins Content-Length; the browser sends the
// file's exact size, which is what the signature covers.
const FORBIDDEN_HEADER =
  /^(accept-charset|accept-encoding|access-control-request-.*|connection|content-length|cookie2?|date|dnt|expect|host|keep-alive|origin|referer|te|trailer|transfer-encoding|upgrade|via|proxy-.*|sec-.*)$/i;

export function settableHeaders(headers: Record<string, string>): [string, string][] {
  return Object.entries(headers).filter(([name]) => !FORBIDDEN_HEADER.test(name));
}

/** PUT with progress events (fetch has no upload progress). Sends exactly the presigned
 *  headers: never the Warden access token, never cookies. */
export function xhrPut(
  upload: PresignedUpload,
  file: Blob,
  onProgress: (loaded: number, total: number) => void,
  signal: AbortSignal,
): Promise<void> {
  return new Promise((resolve, reject) => {
    const failed = (message: string, status = 0) => new ApiError(status, { code: UPLOAD_FAILED, message });
    let target: URL;
    try {
      target = new URL(upload.url, globalThis.location?.origin);
    } catch {
      return reject(failed("invalid upload URL"));
    }
    if (target.protocol !== "https:" && target.protocol !== "http:") return reject(failed("invalid upload URL"));
    if (signal.aborted) return reject(new ApiError(0, { code: UPLOAD_ABORTED, message: "upload cancelled" }));

    const xhr = new XMLHttpRequest();
    xhr.open(upload.method || "PUT", target.toString());
    xhr.withCredentials = false;
    for (const [name, value] of settableHeaders(upload.headers)) xhr.setRequestHeader(name, value);
    xhr.upload.onprogress = (e: ProgressEvent) => onProgress(e.loaded, e.lengthComputable ? e.total : file.size);
    xhr.onload = () => {
      if (xhr.status >= 200 && xhr.status < 300) resolve();
      else reject(failed(`storage returned ${xhr.status}`, xhr.status));
    };
    xhr.onerror = () => reject(failed("network error during upload"));
    xhr.onabort = () => reject(new ApiError(0, { code: UPLOAD_ABORTED, message: "upload cancelled" }));
    signal.addEventListener("abort", () => xhr.abort(), { once: true });
    xhr.send(file);
  });
}
