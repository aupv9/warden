import { ORG_ROLES } from "../api/types";
import type { OrgMember, OrgRole, SignInKeyError, SignInSettings } from "../api/types";
import { userName } from "./format";

// Helpers for the org Settings "Sign-in" section (DESIGN.md "Sign-in settings"). The server
// checks the same rules; these only let the form point at a problem before it is sent.

/** GET …/sign-in answers org admins and security leads (others get 403); only org admins may
 *  PUT …/sign-in-policy. Not an rbac.Matrix permission, so it isn't in lib/permissions.ts. */
export const SIGN_IN_VIEW_ROLES: readonly OrgRole[] = ["org_admin", "security_lead"];
export const SIGN_IN_EDIT_ROLES: readonly OrgRole[] = ["org_admin"];

export function canViewSignIn(role: OrgRole | undefined): boolean {
  return !!role && SIGN_IN_VIEW_ROLES.includes(role);
}

export function canEditSignInPolicy(role: OrgRole | undefined): boolean {
  return !!role && SIGN_IN_EDIT_ROLES.includes(role);
}

// ---- Allowed email domains ----

export const MAX_DOMAINS = 20;
const MAX_DOMAIN_LEN = 253;
const MAX_LABEL_LEN = 63;
const LABEL = /^[a-z0-9-]+$/;

/** What the form sends for a typed value: trimmed and lowercased, as the server normalises it. */
export function normalizeDomain(raw: string): string {
  return raw.trim().toLowerCase();
}

/** The problem with one domain (already normalised), or undefined if it is a valid DNS name:
 *  letters, digits, hyphens and dots; 1–253 characters; at least one dot; no empty label; no
 *  label that starts or ends with a hyphen; no wildcard. */
export function domainProblem(d: string): string | undefined {
  if (!d) return "Enter a domain, or remove this row.";
  if (d.includes("*")) return "Wildcards aren't allowed. List each domain, and each subdomain, on its own row.";
  if (d.includes("@")) return "Enter only the part after the @, such as example.com.";
  if (/\s/.test(d)) return "A domain can't contain spaces.";
  if (d.length > MAX_DOMAIN_LEN) return `A domain has at most ${MAX_DOMAIN_LEN} characters.`;
  if (!/^[a-z0-9.-]+$/.test(d)) return "Use only letters a–z, digits, hyphens and dots. For an international domain, enter its xn-- form.";
  if (!d.includes(".")) return "Enter the full domain, with a dot, such as example.com.";
  const labels = d.split(".");
  if (labels.some((l) => l === "")) return "A domain can't start or end with a dot, or have two dots in a row.";
  if (labels.some((l) => !LABEL.test(l) || l.startsWith("-") || l.endsWith("-"))) return "No part of a domain can start or end with a hyphen.";
  if (labels.some((l) => l.length > MAX_LABEL_LEN)) return `Each part between dots has at most ${MAX_LABEL_LEN} characters.`;
  return undefined;
}

export interface DomainValidation {
  /** Normalised, in the order typed: what the form sends. */
  domains: string[];
  /** One entry per row: the problem, or undefined. */
  rows: (string | undefined)[];
  /** A problem with the list as a whole. */
  list?: string;
  valid: boolean;
}

export function validateDomains(raw: readonly string[]): DomainValidation {
  const domains = raw.map(normalizeDomain);
  const seen = new Set<string>();
  const rows = domains.map((d) => {
    const problem = domainProblem(d);
    if (problem) return problem;
    if (seen.has(d)) return `${d} is already in the list.`;
    seen.add(d);
    return undefined;
  });
  const list = domains.length > MAX_DOMAINS ? `At most ${MAX_DOMAINS} domains. Remove ${domains.length - MAX_DOMAINS}.` : undefined;
  return { domains, rows, list, valid: !list && rows.every((r) => r === undefined) };
}

/** Server field errors for the policy form: `allowed_email_domains[i]` → row i,
 *  `allowed_email_domains` → the list, `mfa_roles` → the role group, the rest → a banner. */
export function serverPolicyErrors(
  fields: Record<string, string>,
  rowCount: number,
): { rows: (string | undefined)[]; list?: string; roles?: string; other: string[] } {
  const rows: (string | undefined)[] = Array.from({ length: rowCount }, () => undefined);
  const other: string[] = [];
  let list: string | undefined;
  let roles: string | undefined;
  for (const [k, v] of Object.entries(fields)) {
    const m = /^allowed_email_domains\[(\d+)\]$/.exec(k);
    const idx = m ? Number(m[1]) : -1;
    if (m && idx < rowCount) rows[idx] = v;
    else if (k === "allowed_email_domains") list = v;
    else if (k === "mfa_roles" || /^mfa_roles\[\d+\]$/.test(k)) roles = v;
    else other.push(`${k}: ${v}`);
  }
  return { rows, list, roles, other };
}

// ---- Two-factor roles ----

/** instance ∪ org, in the order org_admin, security_lead, member (as the server returns it). */
export function effectiveRoles(instance: readonly OrgRole[], org: readonly OrgRole[]): OrgRole[] {
  return ORG_ROLES.filter((r) => instance.includes(r) || org.includes(r));
}

export function sameRoles(a: readonly OrgRole[], b: readonly OrgRole[]): boolean {
  return ORG_ROLES.every((r) => a.includes(r) === b.includes(r));
}

export interface MfaGap {
  /** Active members in a role that requires two-factor whose last sign-in had no second factor. */
  members: OrgMember[];
  /** The first names to show. */
  shown: string[];
  /** How many more there are beyond `shown`. */
  more: number;
}

/** Who would be stopped by the two-factor rule. `mfa: null` means Warden has no record of a
 *  sign-in with a second factor, which for the rule is the same as none. Deactivated members
 *  can't sign in at all, so they aren't listed. */
export function mfaGap(members: readonly OrgMember[], roles: readonly OrgRole[], max = 5): MfaGap {
  const missing = members
    .filter((m) => m.user.is_active && roles.includes(m.role) && m.mfa !== true)
    .sort((a, b) => ORG_ROLES.indexOf(a.role) - ORG_ROLES.indexOf(b.role) || userName(a.user).localeCompare(userName(b.user)));
  const shown = missing.slice(0, max).map((m) => userName(m.user));
  return { members: missing, shown, more: missing.length - shown.length };
}

/** "Huy Do", "Huy Do and An Nguyen", "Huy Do, An Nguyen and 3 more". */
export function namesText(shown: readonly string[], more: number): string {
  if (more > 0) return `${shown.join(", ")} and ${more} more`;
  if (shown.length <= 1) return shown.join("");
  return `${shown.slice(0, -1).join(", ")} and ${shown[shown.length - 1]}`;
}

/** "Org admins and security leads" */
export function rolesText(roles: readonly OrgRole[]): string {
  const plural: Record<OrgRole, string> = { org_admin: "org admins", security_lead: "security leads", member: "members" };
  const words = roles.map((r) => plural[r]);
  const text = words.length <= 1 ? words.join("") : `${words.slice(0, -1).join(", ")} and ${words[words.length - 1]}`;
  return text.charAt(0).toUpperCase() + text.slice(1);
}

// ---- Identity provider ----

/** The operator's console link, only if it is an absolute http(s) URL; anything else
 *  (javascript:, data:, relative paths, junk) is not rendered as a link. */
export function safeExternalUrl(raw: string | null | undefined): string | null {
  if (!raw) return null;
  let url: URL;
  try {
    url = new URL(raw);
  } catch {
    return null;
  }
  if (url.protocol !== "https:" && url.protocol !== "http:") return null;
  if (!url.hostname) return null;
  return url.href;
}

const KEY_ERRORS: Record<SignInKeyError, string> = {
  unreachable: "Warden couldn't reach the identity provider to fetch its signing keys.",
  http_status: "The identity provider answered the request for its signing keys with an error.",
  invalid_document: "The identity provider's discovery document or key set couldn't be read.",
  issuer_mismatch: "The identity provider's discovery document names a different issuer than the one Warden is set up with.",
  no_usable_keys: "The identity provider's key set has no signing key Warden can use.",
};

export interface KeyStatusText {
  tone: "success" | "danger" | "neutral";
  label: string;
  detail: string;
}

/** The key status in words. `fetched` is the relative time of the last good fetch, if any. */
export function keyStatusText(keys: SignInSettings["keys"], algorithms: readonly string[], fetched: string | null): KeyStatusText {
  const n = keys.count;
  const keysWord = `${n} signing key${n === 1 ? "" : "s"}`;
  if (keys.status === "ok") {
    return { tone: "success", label: "OK", detail: `${keysWord} loaded${fetched ? `, last refreshed ${fetched}` : ""}.` };
  }
  if (keys.status === "error") {
    const known = keys.error !== null && Object.hasOwn(KEY_ERRORS, keys.error);
    let why = known ? KEY_ERRORS[keys.error as SignInKeyError] : "Warden couldn't load the identity provider's signing keys.";
    if (keys.error === "no_usable_keys" && algorithms.length) why = `${why.slice(0, -1)} (${algorithms.join(" or ")}).`;
    const fallback =
      n > 0
        ? ` Warden keeps using the ${keysWord} it already has${fetched ? ` (last refreshed ${fetched})` : ""}.`
        : " Until this is fixed, nobody can sign in. Tell your operator.";
    return { tone: "danger", label: "Error", detail: `${why}${fallback}` };
  }
  return { tone: "neutral", label: "Not loaded yet", detail: "Warden fetches the signing keys when it first checks a sign-in." };
}
