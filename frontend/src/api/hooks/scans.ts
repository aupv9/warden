import { useMutation, useQuery, useQueryClient } from "@tanstack/react-query";
import { useCallback, useEffect, useRef, useState } from "react";
import { api, ApiError, isMockMode } from "../client";
import { isNotFound } from "../errors";
import { qk } from "../keys";
import { useCursorList } from "../paging";
import type { CreateScanBody, CreateScanResponse, Page, SbomDownload, SbomFormatParam, Scan, ScanStatus, Tool } from "../types";
import { hashFile, UploadSession, xhrPut } from "../../lib/upload";
import type { ScanOptions, UploadDeps, UploadSnapshot } from "../../lib/upload";
import { safeExternalUrl, startDownload } from "../../lib/url";

const orgBase = (orgId: string) => `/orgs/${encodeURIComponent(orgId)}`;
const projectScans = (orgId: string, projectId: string) =>
  `${orgBase(orgId)}/projects/${encodeURIComponent(projectId)}/scans`;
const scanPath = (orgId: string, scanId: string) => `${orgBase(orgId)}/scans/${encodeURIComponent(scanId)}`;

export const IN_PROGRESS: ScanStatus[] = ["queued", "running"];
/** DESIGN.md: poll every 3 s while a scan is queued or running. */
export const POLL_MS = 3000;

export function useScans(orgId: string, projectId: string) {
  return useCursorList<Page<Scan>>(qk.scans(orgId, projectId), projectScans(orgId, projectId), { limit: 20 });
}

/** One scan with tool runs; polls while it is queued or running and refreshes what depends on
 *  it when it finishes. */
export function useScan(orgId: string, scanId: string | undefined) {
  const qc = useQueryClient();
  const query = useQuery({
    queryKey: qk.scan(orgId, scanId ?? ""),
    queryFn: ({ signal }) => api<Scan>(scanPath(orgId, scanId ?? ""), { signal }),
    enabled: !!scanId,
    refetchInterval: (q) => (q.state.data && IN_PROGRESS.includes(q.state.data.status) ? POLL_MS : false),
  });
  const status = query.data?.status;
  const projectId = query.data?.project_id;
  const prev = useRef(status);
  useEffect(() => {
    const was = prev.current;
    prev.current = status;
    if (!projectId || !was || !status || was === status) return;
    if (IN_PROGRESS.includes(was) && !IN_PROGRESS.includes(status)) {
      void qc.invalidateQueries({ queryKey: qk.scans(orgId, projectId) });
      void qc.invalidateQueries({ queryKey: qk.projects(orgId) });
      void qc.invalidateQueries({ queryKey: qk.issueLists(orgId) });
      void qc.invalidateQueries({ queryKey: qk.summary(orgId) });
    }
  }, [status, projectId, orgId, qc]);
  return query;
}

function useInvalidateScans(orgId: string) {
  const qc = useQueryClient();
  return useCallback(
    (scan: Scan) => {
      qc.setQueryData(qk.scan(orgId, scan.id), scan);
      return Promise.all([
        qc.invalidateQueries({ queryKey: qk.scans(orgId, scan.project_id) }),
        qc.invalidateQueries({ queryKey: qk.projects(orgId), exact: true }),
        qc.invalidateQueries({ queryKey: qk.project(orgId, scan.project_id), exact: true }),
      ]);
    },
    [orgId, qc],
  );
}

export function useCancelScan(orgId: string) {
  const invalidate = useInvalidateScans(orgId);
  return useMutation({
    mutationFn: (scanId: string) => api<Scan>(`${scanPath(orgId, scanId)}/cancel`, { method: "POST" }),
    onSuccess: invalidate,
  });
}

/** The link's URL isn't an absolute http(s) URL, so it is not followed. */
export const BAD_DOWNLOAD_URL = "BAD_DOWNLOAD_URL";
/** 404 from …/sbom: the SBOM expired (scan.sbom_retention) or the scan isn't visible any more.
 *  Shown under the button rather than as the generic "no longer exists" toast. */
export const SBOM_GONE = "SBOM_GONE";

/**
 * v0.3: asks for a fresh 5-minute link to the scan's SBOM and starts the browser download.
 * v0.4: `format` picks CycloneDX (the server's default) or SPDX. The link is used at once and
 * not cached (it expires); the page never reads the file. Resolves with the link's metadata
 * (format, size, SHA-256, components) for the panel.
 */
export function useSbomDownload(orgId: string) {
  return useMutation({
    mutationFn: async ({ scanId, fileName, format = "cyclonedx" }: { scanId: string; fileName: string; format?: SbomFormatParam }) => {
      const link = await api<SbomDownload>(`${scanPath(orgId, scanId)}/sbom`, { query: { format } }).catch((err: unknown) => {
        throw isNotFound(err) ? new ApiError(0, { code: SBOM_GONE, message: "no SBOM" }) : err;
      });
      // Mock mode has no object store behind the URL: check it, but don't follow it.
      const started = isMockMode ? safeExternalUrl(link.url) !== null : startDownload(link.url, fileName);
      if (!started) throw new ApiError(0, { code: BAD_DOWNLOAD_URL, message: "invalid download URL" });
      const { url: _url, ...meta } = link;
      return meta;
    },
  });
}

export function uploadDeps(orgId: string, projectId: string): UploadDeps {
  return {
    hash: hashFile,
    createScan: (body: CreateScanBody) =>
      api<CreateScanResponse>(projectScans(orgId, projectId), { method: "POST", body }),
    put: isMockMode ? mockPut : xhrPut,
    startScan: (scanId) => api<Scan>(`${scanPath(orgId, scanId)}/start`, { method: "POST" }),
    cancelScan: (scanId) => api<Scan>(`${scanPath(orgId, scanId)}/cancel`, { method: "POST" }),
  };
}

// Mock mode has no object store: simulate the PUT's progress.
async function mockPut(_u: unknown, file: Blob, onProgress: (l: number, t: number) => void, signal: AbortSignal) {
  for (let i = 1; i <= 10; i++) {
    await new Promise((r) => setTimeout(r, 150));
    if (signal.aborted) throw new DOMException("aborted", "AbortError");
    onProgress((file.size * i) / 10, file.size);
  }
}

const IDLE: UploadSnapshot = { phase: "idle", hashed: 0, loaded: 0, total: 0 };
const BUSY: UploadSnapshot["phase"][] = ["hashing", "creating", "uploading", "starting"];

export function isUploadBusy(s: UploadSnapshot): boolean {
  return BUSY.includes(s.phase);
}

/** Drives one UploadSession for the New scan card, and asks before leaving the page while
 *  hashing or uploading (DESIGN.md: keep the tab open during steps 2–5). */
export function useUploadScan(orgId: string, projectId: string) {
  const [state, setState] = useState<UploadSnapshot>(IDLE);
  const session = useRef<UploadSession | null>(null);
  const invalidate = useInvalidateScans(orgId);
  const qc = useQueryClient();

  const busy = isUploadBusy(state);
  useEffect(() => {
    if (!busy) return;
    const warn = (e: BeforeUnloadEvent) => {
      e.preventDefault();
    };
    window.addEventListener("beforeunload", warn);
    return () => window.removeEventListener("beforeunload", warn);
  }, [busy]);

  // Leaving the page mid-upload (in-app navigation) cancels it.
  useEffect(() => () => void session.current?.cancel(), []);

  const finish = useCallback(
    async (scan: Scan | undefined) => {
      if (scan) await invalidate(scan);
      else await qc.invalidateQueries({ queryKey: qk.scans(orgId, projectId) });
      return scan;
    },
    [invalidate, qc, orgId, projectId],
  );

  const start = useCallback(
    async (file: File, tools: Tool[], options?: ScanOptions) => {
      await session.current?.cancel();
      const s = new UploadSession(file, tools, uploadDeps(orgId, projectId), setState, options);
      session.current = s;
      return finish(await s.start());
    },
    [orgId, projectId, finish],
  );

  const retry = useCallback(async () => finish(await session.current?.retry()), [finish]);

  const cancel = useCallback(async () => {
    await session.current?.cancel();
    await qc.invalidateQueries({ queryKey: qk.scans(orgId, projectId) });
  }, [qc, orgId, projectId]);

  const reset = useCallback(() => {
    session.current = null;
    setState(IDLE);
  }, []);

  return { state, busy, start, retry, cancel, reset };
}
