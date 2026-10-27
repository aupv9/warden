import type { Limits, ScanStatus } from "../api/types";
import { formatMb } from "./format";

// Scan limits and the words for scan error codes (DESIGN.md "Scan error_code"). Only the Scans
// tab uses them, so they load with that page instead of sitting in the entry chunk.

/** Server defaults, used when /me has no limits (older server). */
export const DEFAULT_LIMITS: Limits = {
  upload_max_mb: 200,
  unzip_max_mb: 1024,
  unzip_max_files: 100_000,
  scan_timeout_minutes: 30,
  scans_per_hour: 20,
  image_upload_max_mb: 2048,
};

/** Limits from /me, with the defaults for any field an older server leaves out. */
export function withDefaults(limits: Partial<Limits> | null | undefined): Limits {
  return { ...DEFAULT_LIMITS, ...(limits ?? {}) };
}

/** Scan.error_code → [short text for history rows, full text for the scan card]
 *  (DESIGN.md "Scan error_code"). Unknown codes use the fallback. */
export function scanErrorMessages(code: string, limits: Limits = DEFAULT_LIMITS): { short: string; full: string } {
  const files = limits.unzip_max_files.toLocaleString("en-US");
  switch (code) {
    case "ZIP_PATH_TRAVERSAL":
      return {
        short: "path outside the root",
        full: "The archive has a path outside its root. An entry such as ../config.yml or /etc/hosts would land outside the folder. Re-create the .zip from inside the project folder.",
      };
    case "ZIP_BOMB":
      return {
        short: "suspected zip bomb",
        full: `The archive unpacks to more than ${formatMb(limits.unzip_max_mb)}, or a file in it is compressed more than 100 to 1. Remove large generated or binary files and try again.`,
      };
    case "ZIP_TOO_LARGE":
      return {
        short: `archive over ${formatMb(limits.upload_max_mb)}`,
        full: `The archive is larger than ${formatMb(limits.upload_max_mb)}. Leave out dependencies and build output (node_modules, vendor, dist).`,
      };
    case "ZIP_TOO_MANY_FILES":
      return {
        short: `over ${files} files`,
        full: `The archive has more than ${files} files. Leave out dependencies and build output.`,
      };
    case "ZIP_ENCRYPTED":
      return { short: "password-protected", full: "The archive is password-protected. Upload a .zip without a password." };
    case "ZIP_INVALID":
      return { short: "not a readable .zip", full: "This isn't a readable .zip file. Create the archive again with a standard zip tool." };
    case "ZIP_EMPTY":
      return {
        short: "no source files",
        full: "No files were left to scan. Warden skips node_modules, vendor, dist, build, .git and .venv.",
      };
    // v0.3: image scans (a `docker save` .tar), checked before Trivy sees it.
    case "IMAGE_INVALID":
      return {
        short: "not a docker save archive",
        full: "The file isn't a docker save archive with one image. Create it with docker save -o app.tar IMAGE and upload the .tar as it is, not compressed.",
      };
    case "IMAGE_TOO_LARGE":
      return {
        short: "image too large",
        full: `The image is larger than Warden accepts (${formatMb(limits.image_upload_max_mb)}, or too many files or layers in the archive). Scan a smaller image, such as the final stage of a multi-stage build.`,
      };
    case "IMAGE_MULTIPLE":
      return {
        short: "more than one image",
        full: "The archive holds more than one image. Save one image per file: docker save -o app.tar IMAGE.",
      };
    case "CHECKSUM_MISMATCH":
      return {
        short: "file changed in upload",
        full: "The stored file doesn't match the one you picked, so it was not scanned. Upload it again.",
      };
    case "ALL_SCANNERS_FAILED":
      return {
        short: "every scanner failed",
        full: "Every scanner failed, so there are no results. Each scanner's error is listed below. If it happens again, tell your operator.",
      };
    case "TIMEOUT":
      return {
        short: `took over ${limits.scan_timeout_minutes} min`,
        full: `The scan took longer than the ${limits.scan_timeout_minutes}-minute limit and was stopped.`,
      };
    default:
      return { short: "failed", full: `The scan failed (${code}). Tell your operator; the worker log has the details.` };
  }
}

/** A failed scan whose archive (.zip, or an image .tar in v0.3) was refused before any scanner
 *  ran is shown as "Rejected"; any other failed scan is "Failed". The API has no "rejected" status. */
export function isRejected(scan: { status: ScanStatus; error_code: string | null }): boolean {
  const code = scan.error_code;
  return scan.status === "failed" && !!code && (code.startsWith("ZIP_") || code.startsWith("IMAGE_") || code === "CHECKSUM_MISMATCH");
}
