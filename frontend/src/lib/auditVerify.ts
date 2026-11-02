import { ApiError } from "../api/client";
import { errorMessage, waitText } from "../api/errors";
import type { AuditVerification } from "../api/types";
import { formatDateTime } from "./format";

// v0.5 wave 2: "Verify chain" on the audit log (POST /orgs/{org}/audit-log/verify, view_audit_log).
// The server recomputes the org's hash chain the way `warden-admin audit verify` does and says
// whether every entry matches, how many it checked and the first entry that doesn't match.

/** The server's rate limit: checks per org per hour. */
export const VERIFY_PER_HOUR = 10;

export interface VerifySummary {
  ok: boolean;
  title: string;
  text: string;
  /** The first entry that doesn't match, to show in the list. */
  badId: string | null;
}

const n = (x: number) => x.toLocaleString("en-US");
const entriesText = (x: number) => `${n(x)} ${x === 1 ? "entry" : "entries"}`;

export function verificationSummary(v: AuditVerification): VerifySummary {
  const when = formatDateTime(v.verified_at);
  if (v.ok) {
    return {
      ok: true,
      title: "Chain intact.",
      text: `${entriesText(v.entries)} checked ${when}: every hash matches its entry and the one before it.`,
      badId: null,
    };
  }
  const at = v.first_bad_id ? `Entry ${v.first_bad_id} is the first whose hash doesn't match` : "An entry's hash doesn't match";
  return {
    ok: false,
    title: "Chain broken.",
    text: `${at}: it, or an entry before it, was changed or removed after it was written. ${entriesText(v.entries)} checked ${when}. Tell your operator; \`warden-admin audit verify\` shows the same.`,
    badId: v.first_bad_id,
  };
}

/** Where the first bad entry is, relative to the entries on screen. */
export function badEntryHint(badId: string | null, loadedIds: readonly string[], filtered: boolean): string | null {
  if (!badId || loadedIds.includes(badId)) return null;
  return filtered
    ? `Entry ${badId} isn't among the entries shown. Clear the filters or load older entries to find it.`
    : `Entry ${badId} isn't among the entries loaded yet. Load older entries to find it.`;
}

/** The verify call's error in words: 429 has its own (the hourly limit, and when to retry). */
export function verifyErrorText(err: unknown): string {
  if (err instanceof ApiError && err.code === "RATE_LIMITED") {
    const retry = err.retryAfter !== undefined ? `Try again in ${waitText(err.retryAfter)}.` : "Try again later.";
    return `The chain can be checked ${VERIFY_PER_HOUR} times an hour in each organization. ${retry}`;
  }
  return errorMessage(err);
}
