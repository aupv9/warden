import { afterEach, describe, expect, it, vi } from "vitest";
import { ApiError } from "../api/client";
import type { CreateScanResponse, PresignedUpload, Scan } from "../api/types";
import { settableHeaders, UploadSession, validateArchive, xhrPut } from "./upload";
import type { UploadDeps, UploadSnapshot } from "./upload";

const T0 = Date.parse("2026-10-26T10:00:00Z");
const scan = (id: string, status: Scan["status"] = "pending_upload") => ({ id, status }) as Scan;
const upload = (expiresInMs: number): PresignedUpload => ({
  method: "PUT",
  url: "https://s3.example.test/bucket/scans/o/s.zip?X-Amz-Signature=abc",
  headers: { "Content-Type": "application/zip", "Content-Length": "4", "x-amz-checksum-sha256": "q83v" },
  expires_at: new Date(T0 + expiresInMs).toISOString(),
});
const file = () => new File([new Uint8Array([1, 2, 3, 4])], "app.zip", { type: "application/zip" });

/** Deps that log each call in order; individual steps can be overridden per test. */
function fakeDeps(over: Partial<UploadDeps> = {}) {
  const calls: string[] = [];
  let n = 0;
  let clock = T0;
  const deps: UploadDeps = {
    hash: vi.fn(async (_f, onProgress) => {
      calls.push("hash");
      onProgress(4, 4);
      return "a".repeat(64);
    }),
    createScan: vi.fn(async (body) => {
      n += 1;
      calls.push(`create:${body.sha256.slice(0, 4)}:${body.file_name}:${body.tools?.join(",")}`);
      return { scan: scan(`s${n}`), upload: upload(15 * 60_000) } satisfies CreateScanResponse;
    }),
    put: vi.fn(async (u, _f, onProgress) => {
      calls.push(`put:${u.expires_at}`);
      onProgress(2, 4);
      onProgress(4, 4);
    }),
    startScan: vi.fn(async (id) => {
      calls.push(`start:${id}`);
      return scan(id, "queued");
    }),
    cancelScan: vi.fn(async (id) => {
      calls.push(`cancel:${id}`);
      return scan(id, "cancelled");
    }),
    now: () => clock,
    ...over,
  };
  return { deps, calls, advance: (ms: number) => (clock += ms) };
}

function session(deps: UploadDeps) {
  const phases: string[] = [];
  const s = new UploadSession(file(), ["gitleaks", "trivy"], deps, (snap: UploadSnapshot) => {
    if (phases.at(-1) !== snap.phase) phases.push(snap.phase);
  });
  return { s, phases };
}

describe("UploadSession", () => {
  it("hashes, creates, PUTs, then starts, in that order", async () => {
    const { deps, calls } = fakeDeps();
    const { s, phases } = session(deps);
    const started = await s.start();
    expect(started?.status).toBe("queued");
    expect(calls).toEqual([`hash`, `create:aaaa:app.zip:gitleaks,trivy`, `put:${upload(15 * 60_000).expires_at}`, "start:s1"]);
    expect(phases).toEqual(["hashing", "creating", "uploading", "starting", "started"]);
    expect(s.snapshot.hashed).toBe(1);
  });

  it("stops before uploading anything on 429 (hourly limit)", async () => {
    const { deps, calls } = fakeDeps({
      createScan: vi.fn(async () => {
        throw new ApiError(429, { code: "RATE_LIMITED", message: "" }, undefined, 600);
      }),
    });
    const { s } = session(deps);
    expect(await s.start()).toBeUndefined();
    expect(s.snapshot.phase).toBe("rate_limited");
    expect(calls).toEqual(["hash"]);
    expect(deps.put).not.toHaveBeenCalled();
  });

  it("a failed PUT is retried on the same URL while it is valid", async () => {
    let attempt = 0;
    const { deps, calls } = fakeDeps({
      put: vi.fn(async (_u, _f, onProgress) => {
        attempt += 1;
        calls.push(`put#${attempt}`);
        onProgress(2, 4);
        if (attempt === 1) throw new ApiError(0, { code: "UPLOAD_FAILED", message: "" });
      }),
    });
    const { s } = session(deps);
    expect(await s.start()).toBeUndefined();
    expect(s.snapshot).toMatchObject({ phase: "upload_failed", failedAt: 0.5 });
    const started = await s.retry();
    expect(started?.id).toBe("s1");
    expect(calls).toEqual(["hash", "create:aaaa:app.zip:gitleaks,trivy", "put#1", "put#2", "start:s1"]);
  });

  it("after the URL expires, retry cancels the old scan and creates a new one without hashing again", async () => {
    let attempt = 0;
    const { deps, calls, advance } = fakeDeps({
      put: vi.fn(async () => {
        attempt += 1;
        calls.push(`put#${attempt}`);
        if (attempt === 1) throw new ApiError(0, { code: "UPLOAD_FAILED", message: "" });
      }),
    });
    const { s } = session(deps);
    await s.start();
    advance(16 * 60_000);
    const started = await s.retry();
    expect(started?.id).toBe("s2");
    expect(calls).toEqual([
      "hash",
      "create:aaaa:app.zip:gitleaks,trivy",
      "put#1",
      "cancel:s1",
      "create:aaaa:app.zip:gitleaks,trivy",
      "put#2",
      "start:s2",
    ]);
    expect(deps.hash).toHaveBeenCalledOnce();
  });

  it("cancelling while hashing sends nothing to the server", async () => {
    let release!: () => void;
    const { deps, calls } = fakeDeps({
      hash: vi.fn(
        (_f, _p, signal: AbortSignal) =>
          new Promise<string>((_resolve, reject) => {
            release = () => reject(new DOMException("aborted", "AbortError"));
            signal.addEventListener("abort", () => release());
          }),
      ),
    });
    const { s } = session(deps);
    const run = s.start();
    await s.cancel();
    expect(await run).toBeUndefined();
    expect(s.snapshot.phase).toBe("idle");
    expect(calls).toEqual([]);
  });

  it("cancelling during the upload aborts the PUT and cancels the scan on the server", async () => {
    const { deps, calls } = fakeDeps({
      put: vi.fn(
        (_u, _f, _p, signal: AbortSignal) =>
          new Promise<void>((_resolve, reject) => {
            calls.push("put");
            signal.addEventListener("abort", () => reject(new ApiError(0, { code: "UPLOAD_ABORTED", message: "" })));
          }),
      ),
    });
    const { s } = session(deps);
    const run = s.start();
    await vi.waitFor(() => expect(calls).toContain("put"));
    await s.cancel();
    expect(await run).toBeUndefined();
    expect(calls).toEqual(["hash", "create:aaaa:app.zip:gitleaks,trivy", "put", "cancel:s1"]);
    expect(deps.startScan).not.toHaveBeenCalled();
    expect(s.snapshot.phase).toBe("idle");
  });

  it("UPLOAD_MISMATCH from start shows the upload-failed state; retry uploads again", async () => {
    let starts = 0;
    const { deps, calls } = fakeDeps({
      startScan: vi.fn(async (id) => {
        starts += 1;
        calls.push(`start#${starts}`);
        if (starts === 1) throw new ApiError(422, { code: "UPLOAD_MISMATCH", message: "" });
        return scan(id, "queued");
      }),
    });
    const { s } = session(deps);
    await s.start();
    expect(s.snapshot).toMatchObject({ phase: "upload_failed", failedAt: 1 });
    expect((await s.retry())?.status).toBe("queued");
    expect(calls.filter((c) => c.startsWith("put"))).toHaveLength(2);
  });

  it("other API errors end in the error state", async () => {
    const { deps } = fakeDeps({
      createScan: vi.fn(async () => {
        throw new ApiError(403, { code: "FORBIDDEN", message: "" });
      }),
    });
    const { s } = session(deps);
    await s.start();
    expect(s.snapshot.phase).toBe("error");
  });
});

describe("validateArchive", () => {
  const limits = { upload_max_mb: 200 };
  it("checks extension, name and size before anything is sent", () => {
    expect(validateArchive({ name: "a.zip", size: 10 }, limits)).toBeNull();
    expect(validateArchive({ name: "A.ZIP", size: 10 }, limits)).toBeNull();
    expect(validateArchive({ name: "a.tar.gz", size: 10 }, limits)).toMatch(/\.zip/);
    expect(validateArchive({ name: `${"a".repeat(252)}.zip`, size: 10 }, limits)).toMatch(/too long/);
    expect(validateArchive({ name: "..\\evil.zip", size: 10 }, limits)).toMatch(/can't contain/);
    expect(validateArchive({ name: "a.zip", size: 0 }, limits)).toMatch(/empty/);
    expect(validateArchive({ name: "a.zip", size: 200 * 1024 * 1024 + 1 }, limits)).toMatch(/200 MB/);
    expect(validateArchive({ name: "a.zip", size: 60 * 1024 * 1024 }, { upload_max_mb: 50 })).toMatch(/50 MB/);
  });
});

class FakeXHR {
  static last: FakeXHR;
  method = "";
  url = "";
  headers: Record<string, string> = {};
  withCredentials = true;
  status = 0;
  body: unknown;
  upload: { onprogress: ((e: ProgressEvent) => void) | null } = { onprogress: null };
  onload: (() => void) | null = null;
  onerror: (() => void) | null = null;
  onabort: (() => void) | null = null;
  constructor() {
    FakeXHR.last = this;
  }
  open(method: string, url: string) {
    this.method = method;
    this.url = url;
  }
  setRequestHeader(k: string, v: string) {
    this.headers[k] = v;
  }
  send(body: unknown) {
    this.body = body;
  }
  abort() {
    this.onabort?.();
  }
}

describe("xhrPut", () => {
  afterEach(() => vi.unstubAllGlobals());

  it("PUTs the file with only the presigned headers: no token, no cookies, no forbidden headers", async () => {
    vi.stubGlobal("XMLHttpRequest", FakeXHR);
    const progress: number[] = [];
    const f = file();
    const done = xhrPut(upload(60_000), f, (l) => progress.push(l), new AbortController().signal);
    const x = FakeXHR.last;
    expect(x.method).toBe("PUT");
    expect(x.url).toContain("X-Amz-Signature=abc");
    expect(x.withCredentials).toBe(false);
    expect(x.headers).toEqual({ "Content-Type": "application/zip", "x-amz-checksum-sha256": "q83v" });
    expect(Object.keys(x.headers).some((h) => h.toLowerCase() === "authorization")).toBe(false);
    expect(x.body).toBe(f);
    x.upload.onprogress?.({ loaded: 2, total: 4, lengthComputable: true } as ProgressEvent);
    x.status = 200;
    x.onload?.();
    await done;
    expect(progress).toEqual([2]);
  });

  it("rejects with UPLOAD_FAILED on a storage error or network error", async () => {
    vi.stubGlobal("XMLHttpRequest", FakeXHR);
    const p1 = xhrPut(upload(60_000), file(), () => {}, new AbortController().signal);
    FakeXHR.last.status = 403;
    FakeXHR.last.onload?.();
    await expect(p1).rejects.toMatchObject({ code: "UPLOAD_FAILED", status: 403 });
    const p2 = xhrPut(upload(60_000), file(), () => {}, new AbortController().signal);
    FakeXHR.last.onerror?.();
    await expect(p2).rejects.toMatchObject({ code: "UPLOAD_FAILED" });
  });

  it("aborts on signal and refuses non-http URLs", async () => {
    vi.stubGlobal("XMLHttpRequest", FakeXHR);
    const ctrl = new AbortController();
    const p = xhrPut(upload(60_000), file(), () => {}, ctrl.signal);
    ctrl.abort();
    await expect(p).rejects.toMatchObject({ code: "UPLOAD_ABORTED" });
    await expect(xhrPut({ ...upload(60_000), url: "javascript:alert(1)" }, file(), () => {}, new AbortController().signal)).rejects.toMatchObject({
      code: "UPLOAD_FAILED",
    });
  });

  it("filters headers a page may not set", () => {
    expect(settableHeaders({ Host: "x", "content-length": "1", "Sec-Fetch-Mode": "y", "x-amz-meta": "ok" })).toEqual([["x-amz-meta", "ok"]]);
  });
});
