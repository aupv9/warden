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
  // v0.4 wave 2. Only used when an older server leaves them out of /me.
  history_upload_max_mb: 1024,
  history_max_commits: 50_000,
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
    // v0.4 wave 2: history scans (a `git bundle` from `warden scan --history`), checked without
    // being unpacked before Gitleaks sees it.
    case "BUNDLE_INVALID":
      return {
        short: "not a git bundle",
        full: "The file isn't a git bundle Warden can read. Create it with warden scan --history, which runs git bundle create.",
      };
    case "BUNDLE_INCOMPLETE":
      return {
        short: "shallow clone",
        full: "The bundle doesn't hold the full history (it was made from a shallow clone). In CI, check out with fetch-depth: 0 (GitHub) or GIT_DEPTH: 0 (GitLab).",
      };
    case "BUNDLE_TOO_LARGE":
      return {
        short: "history too large",
        full: "The repository's history is larger than Warden accepts (or has too many branches and tags). Ask your operator about the limit.",
      };
    // v0.7 wave 2: the worker couldn't pull the image (POST …/scans/pull). Nothing was scanned.
    // The server's details (registry answers, addresses) are never shown: these words say what
    // happened and what to do.
    case "PULL_UNAUTHORIZED":
      return {
        short: "registry refused access",
        full: "The registry refused to give Warden this image. If the image is private, an org admin or security lead must add credentials for its host under Settings › Registries, or fix the ones there (Test shows whether they work). Then scan again.",
      };
    case "PULL_NOT_FOUND":
      return {
        short: "image not found",
        full: "The registry has no image with this digest. Check the repository and the sha256 digest (docker buildx imagetools inspect IMAGE prints it), then scan again.",
      };
    case "PULL_TOO_LARGE":
      return {
        short: "image too large to pull",
        full: "The image is larger than this server pulls. Scan a smaller image, such as the final stage of a multi-stage build, or ask your operator about the limit.",
      };
    case "PULL_BLOCKED":
      return {
        short: "registry address blocked",
        full: "Warden doesn't pull from this registry: its host resolves to a private or internal address, or it redirected there. Use the registry's public host, or ask your operator.",
      };
    case "PULL_PLATFORM":
      return {
        short: "no image for this platform",
        full: "The digest names images for other platforms only, not the one this server scans (linux/amd64 unless your operator changed it). Pin the digest of that platform's image, or of a list that includes it.",
      };
    case "PULL_FAILED":
      return {
        short: "pull failed",
        full: "Warden couldn't pull the image: the registry didn't answer, or sent something Warden can't read. Check that the registry is up, then scan again. If it keeps happening, tell your operator.",
      };
    // v0.8: imports of another tool's report (`warden import`), checked before anything is stored.
    case "IMPORT_INVALID":
      return {
        short: "not a SARIF or GitLab SAST report",
        full: "The file isn't a SARIF 2.1.0 file or a GitLab SAST report Warden can read. Import the file the tool wrote as it is, and pass --format gitlab-sast for a GitLab report.",
      };
    case "IMPORT_TOO_LARGE":
      return {
        short: "report too large",
        full: "The report has more than Warden imports at once (10 runs, 50,000 results or 5,000 rules). Import each run or language separately, with its own --category.",
      };
    case "IMPORT_SCREEN_FAILED":
      return {
        short: "secret check couldn't run",
        full: "Gitleaks couldn't check the report's texts for secrets, so nothing was imported and no issues changed. Run the CI job again; if it keeps happening, tell your operator.",
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
    // v0.5: the server cancels a scan whose upload wasn't started within an hour (tab closed).
    case "UPLOAD_ABANDONED":
      return {
        short: "upload never finished",
        full: "The upload didn't finish within an hour, so Warden cancelled the scan. Nothing was scanned and no issues changed. Upload the file again.",
      };
    default:
      return { short: "failed", full: `The scan failed (${code}). Tell your operator; the worker log has the details.` };
  }
}

/** v0.7 wave 2: the image couldn't be pulled (a pulled scan's failure before any scanner ran).
 *  Shown as Failed, with "Pull failed" on the scan card: nothing was refused, the image never
 *  arrived. */
export function isPullFailure(scan: { status: ScanStatus; error_code: string | null }): boolean {
  return scan.status === "failed" && !!scan.error_code?.startsWith("PULL_");
}

/** A failed scan whose archive (.zip, an image .tar in v0.3, a git bundle in v0.4 wave 2) or
 *  (v0.8) imported report was refused before anything ran is shown as "Rejected"; any other
 *  failed scan is "Failed" (IMPORT_SCREEN_FAILED too: the report was fine, the check didn't run).
 *  The API has no "rejected" status. */
export function isRejected(scan: { status: ScanStatus; error_code: string | null }): boolean {
  const code = scan.error_code;
  return (
    scan.status === "failed" &&
    !!code &&
    (code.startsWith("ZIP_") ||
      code.startsWith("IMAGE_") ||
      code.startsWith("BUNDLE_") ||
      code === "IMPORT_INVALID" ||
      code === "IMPORT_TOO_LARGE" ||
      code === "CHECKSUM_MISMATCH")
  );
}
