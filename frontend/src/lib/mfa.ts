import { useSyncExternalStore } from "react";
import type { Me } from "../api/types";

// v0.2 MFA rule (contract C): an org can require two-factor sign-in for some roles. The UI
// knows it two ways: `me.mfa_required_orgs` (before any call), and an `MFA_REQUIRED` answer
// from any org-scoped endpoint (the rule changed after /me was loaded). Either way the org's
// pages are replaced by one full-page explanation. This store holds the orgs learned from
// errors for the life of the page; signing in again reloads the app and clears it.

let blocked: ReadonlySet<string> = new Set();
const listeners = new Set<() => void>();

const ORG_PATH = /^\/orgs\/([^/?#]+)/;

/** Called by api() when a request under /orgs/{id} answers MFA_REQUIRED. */
export function reportMfaRequired(path: string): void {
  const id = ORG_PATH.exec(path)?.[1];
  if (!id) return;
  const orgId = decodeURIComponent(id);
  if (blocked.has(orgId)) return;
  blocked = new Set([...blocked, orgId]);
  listeners.forEach((l) => l());
}

export function mfaBlockedOrgs(): ReadonlySet<string> {
  return blocked;
}

/** For tests. */
export function resetMfaBlocked(): void {
  blocked = new Set();
  listeners.forEach((l) => l());
}

export function isMfaBlocked(me: Pick<Me, "mfa_required_orgs">, orgId: string, fromErrors: ReadonlySet<string> = blocked): boolean {
  return (me.mfa_required_orgs ?? []).includes(orgId) || fromErrors.has(orgId);
}

function subscribe(l: () => void): () => void {
  listeners.add(l);
  return () => listeners.delete(l);
}

export function useMfaBlocked(me: Pick<Me, "mfa_required_orgs">, orgId: string): boolean {
  const fromErrors = useSyncExternalStore(subscribe, mfaBlockedOrgs, mfaBlockedOrgs);
  return isMfaBlocked(me, orgId, fromErrors);
}
