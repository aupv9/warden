import { ApiError, HTTP_ERROR, NETWORK_ERROR } from "./client";

// Readable messages for API error codes, worded as in DESIGN.md "Error messages". Server
// `message` strings are not shown: they are written for developers, and authentication
// failures must stay generic (README "Security invariants"). Screens pass overrides where a
// code means something specific (CONFLICT especially).

export type ErrorOverrides = Partial<Record<string, string>>;

export const MESSAGES: Record<string, string> = {
  UNAUTHORIZED: "We couldn't sign you in. Try again.",
  FORBIDDEN: "You don't have permission to do that. The page now shows only what your role allows.",
  NOT_FOUND: "This no longer exists, or you no longer have access to it.",
  VALIDATION_FAILED: "Some fields need attention.",
  CONFLICT: "This conflicts with a change made in the meantime. Reload and try again.",
  VERSION_CONFLICT:
    "Someone changed this issue while you had it open. Your change wasn't saved. Reload to see the latest version, then try again.",
  INVALID_TRANSITION: "This issue can't make that change any more. Reload to see what changed.",
  USER_NOT_FOUND: "No one with this email has signed in to Warden yet. Ask them to sign in once, then add them here.",
  UPLOAD_MISMATCH: "The upload didn't arrive complete. Upload the file again.",
  RATE_LIMITED: "Too many requests in a short time. Wait a minute, then try again.",
  // v0.2
  MFA_REQUIRED: "Your role requires two-factor sign-in. Sign out, then sign in again with your second factor.",
  TOKEN_SCOPE: "This API token isn't allowed to do that.",
  PROJECT_ARCHIVED: "This project is archived, so it doesn't take new scans. Unarchive it first.",
  MFA_NOT_ENABLED:
    "Your current sign-in didn't use a second factor. Sign in with a second factor first, then require it for your own role.",
  [NETWORK_ERROR]: "Warden didn't answer. Check your connection and try again.",
  // Client-side codes from the upload (lib/upload.ts).
  UPLOAD_FAILED: "The connection dropped. Your file is fine; try again.",
  UPLOAD_ABORTED: "Upload cancelled.",
  HASH_FAILED: "The browser couldn't read this file. Choose it again.",
};

const SERVER_ERROR = "Warden didn't answer. Check your connection and try again.";
const UNKNOWN = "Something went wrong. Try again.";

export function errorMessage(err: unknown, overrides: ErrorOverrides = {}): string {
  if (!(err instanceof ApiError)) return UNKNOWN;
  const override = overrides[err.code];
  if (override) return override;
  if (err.code === "RATE_LIMITED" && err.retryAfter !== undefined) {
    return `Too many requests in a short time. Try again in ${waitText(err.retryAfter)}.`;
  }
  const known = MESSAGES[err.code];
  if (known) return known;
  if (isServerError(err)) return SERVER_ERROR;
  return UNKNOWN;
}

export function waitText(seconds: number): string {
  if (seconds < 60) return seconds <= 1 ? "a second" : `${seconds} seconds`;
  const m = Math.ceil(seconds / 60);
  return m === 1 ? "a minute" : `${m} minutes`;
}

export function isServerError(err: unknown): boolean {
  return err instanceof ApiError && (err.status >= 500 || err.code === HTTP_ERROR || err.code === NETWORK_ERROR);
}

/** The request ID to quote to an operator, for server-side failures only. */
export function supportReference(err: unknown): string | undefined {
  if (err instanceof ApiError && isServerError(err)) return err.requestId;
  return undefined;
}

/** Per-field messages from a VALIDATION_FAILED error (`metadata.fields`), as plain strings. */
export function fieldErrors(err: unknown): Record<string, string> {
  if (!(err instanceof ApiError) || err.code !== "VALIDATION_FAILED") return {};
  const fields = err.body.metadata?.fields;
  if (!fields || typeof fields !== "object") return {};
  const out: Record<string, string> = {};
  for (const [k, v] of Object.entries(fields as Record<string, unknown>)) {
    if (typeof v === "string") out[k] = v;
  }
  return out;
}

/** Field errors the form has no field for: they go in a banner instead. */
export function leftoverFieldErrors(err: unknown, known: string[]): string[] {
  return Object.entries(fieldErrors(err))
    .filter(([k]) => !known.includes(k))
    .map(([k, v]) => `${k}: ${v}`);
}

export function isNotFound(err: unknown): boolean {
  return err instanceof ApiError && (err.status === 404 || err.code === "NOT_FOUND") && err.code !== "USER_NOT_FOUND";
}

/** v0.2: the org's MFA rule blocks this session. The org layout shows a full-page state for it
 *  (lib/mfa.ts), so it is neither a 403 page nor a toast. */
export function isMfaRequired(err: unknown): boolean {
  return err instanceof ApiError && err.code === "MFA_REQUIRED";
}

export function isForbidden(err: unknown): boolean {
  return err instanceof ApiError && (err.status === 403 || err.code === "FORBIDDEN") && !isMfaRequired(err);
}

export function isUnauthorized(err: unknown): boolean {
  return err instanceof ApiError && (err.status === 401 || err.code === "UNAUTHORIZED");
}

/** A failed action (mutation) is reported as a toast for these; everything else is shown
 *  where the problem is (field, dialog banner, issue banner, upload card). */
export function isToastedActionError(err: unknown): boolean {
  if (!(err instanceof ApiError)) return true;
  if (isMfaRequired(err)) return false;
  return isForbidden(err) || isNotFound(err) || err.code === "RATE_LIMITED" || isServerError(err);
}
