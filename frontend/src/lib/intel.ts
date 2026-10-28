import type { IssueSummary, LicenseCategory } from "../api/types";
import { LICENSE_CATEGORIES } from "../api/types";
import { isMaliciousIssue } from "./malicious";

// v0.3 helpers for what an issue says about exploitation (CISA KEV, FIRST EPSS), licenses and
// image targets. KEV and EPSS only rank issues: they never change severity or status, so the
// UI shows them next to the severity, never instead of it.

/** CVE ids are linked to NVD only when they have exactly this shape; the id goes into the URL
 *  path, so anything else (scanner output is hostile input) stays plain text. */
export const CVE_ID_RE = /^CVE-\d{4}-\d{4,7}$/;

export const KEV_CATALOG_URL = "https://www.cisa.gov/known-exploited-vulnerabilities-catalog";
export const KEV_LABEL = "Known exploited (CISA KEV)";

/** https://nvd.nist.gov/vuln/detail/<id>, or null when the id isn't a well-formed CVE id. */
export function nvdUrl(id: string): string | null {
  return CVE_ID_RE.test(id) ? `https://nvd.nist.gov/vuln/detail/${id}` : null;
}

/** EPSS as a percentage: "94%", "2.6%", "0.4%", "<0.1%". Null or out of range: null. */
export function formatEpss(score: number | null | undefined): string | null {
  if (score === null || score === undefined || !Number.isFinite(score) || score < 0 || score > 1) return null;
  const pct = score * 100;
  if (pct >= 10) return `${Math.round(pct)}%`;
  if (pct >= 0.1) return `${(Math.round(pct * 10) / 10).toFixed(1)}%`;
  return pct === 0 ? "0%" : "<0.1%";
}

/** "higher than 99.9% of scored CVEs" from the EPSS percentile (0..1). */
export function percentileText(p: number | null | undefined): string | null {
  if (p === null || p === undefined || !Number.isFinite(p) || p < 0 || p > 1) return null;
  const pct = Math.floor(p * 1000) / 10;
  return `higher than ${pct % 1 === 0 ? pct.toFixed(0) : pct.toFixed(1)}% of scored CVEs`;
}

/** License-policy issues are Trivy issues with rule id `license:<SPDX>`. */
export function isLicenseIssue(i: Pick<IssueSummary, "tool" | "rule_id">): boolean {
  return i.tool === "trivy" && i.rule_id.startsWith("license:");
}

/** Dependency vulnerabilities: every Trivy issue that is neither a license-policy issue nor
 *  (v0.4) a malicious package. Only these carry KEV and EPSS. */
export function isVulnIssue(i: Pick<IssueSummary, "tool" | "rule_id">): boolean {
  return i.tool === "trivy" && !isLicenseIssue(i) && !isMaliciousIssue(i);
}

/**
 * The license of a license issue: the SPDX id from the rule id, and (v0.4) the Trivy category
 * from `license_category`. A value outside the seven categories shows no category; the title
 * is never parsed.
 */
export function licenseOf(i: Pick<IssueSummary, "tool" | "rule_id" | "license_category">): { spdx: string; category: LicenseCategory | null } | null {
  if (!isLicenseIssue(i)) return null;
  const spdx = i.rule_id.slice("license:".length);
  if (!spdx) return null;
  const c = i.license_category;
  return { spdx, category: c && LICENSE_CATEGORIES.includes(c) ? c : null };
}

/** OCI repository name without tag or digest, as the contract's `target` pattern. */
export const IMAGE_TARGET_RE = /^[a-z0-9]+(?:[._-][a-z0-9]+)*(?::[0-9]{1,5})?(?:\/[a-z0-9]+(?:(?:[._]|__|-+)[a-z0-9]+)*)*$/;
export const IMAGE_TARGET_MAX = 255;
export const IMAGE_REF_MAX = 512;

export function isImageTarget(s: string): boolean {
  return s.length > 0 && s.length <= IMAGE_TARGET_MAX && IMAGE_TARGET_RE.test(s);
}

/**
 * Splits what people paste ("ghcr.io/acme/api:1.4.2", "localhost:5000/app@sha256:…") into the
 * repository and the full reference. A ":" counts as a tag only after the last "/", so a
 * registry port stays in the repository. The repository is not lowercased: an invalid one is
 * shown as an error rather than silently changed.
 */
export function splitImageRef(raw: string): { repository: string; ref: string | null } {
  const s = raw.trim();
  const at = s.indexOf("@");
  const name = at >= 0 ? s.slice(0, at) : s;
  const slash = name.lastIndexOf("/");
  const colon = name.lastIndexOf(":");
  const repository = colon > slash ? name.slice(0, colon) : name;
  return { repository, ref: repository === s ? null : s };
}
