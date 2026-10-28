import type { IssueSummary } from "../api/types";

// v0.4: issues raised by OSV malicious-package advisories (typosquats, hijacked releases).
// They are Critical Trivy issues with rule id `malicious:<MAL id>`. Unlike KEV and EPSS, an
// advisory creates or reopens an issue; it never fixes, hides or downgrades one.

/** OSV ids are linked only when they have exactly this shape: the id goes into the URL path,
 *  and the rule id comes from the server (built from advisory data), so anything else stays
 *  plain text. */
export const MAL_ID_RE = /^MAL-\d{4}-\d{1,8}$/;

export const MALICIOUS_LABEL = "Malicious package (OSV advisory)";
export const MALICIOUS_REMEDIATION = "Remove this version and rotate any credentials the build had access to.";

export function isMaliciousIssue(i: Pick<IssueSummary, "tool" | "rule_id">): boolean {
  return i.tool === "trivy" && i.rule_id.startsWith("malicious:");
}

/** https://osv.dev/vulnerability/<id>, or null when the id isn't a well-formed MAL id. */
export function osvUrl(id: string): string | null {
  return MAL_ID_RE.test(id) ? `https://osv.dev/vulnerability/${id}` : null;
}

/** The advisory behind a malicious-package issue: its id as text, and the OSV link only for a
 *  well-formed id. Null for any other issue. */
export function maliciousAdvisory(i: Pick<IssueSummary, "tool" | "rule_id">): { id: string; url: string | null } | null {
  if (!isMaliciousIssue(i)) return null;
  const id = i.rule_id.slice("malicious:".length);
  if (!id) return null;
  return { id, url: osvUrl(id) };
}
