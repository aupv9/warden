import { LICENSE_ACTIONS, LICENSE_CATEGORIES } from "../api/types";
import type { LicenseAction, LicenseCategory, LicensePolicy, LicensePolicyInput } from "../api/types";

// The org license policy form (Settings → License policy). The server checks the same rules;
// the browser checks first so mistakes show next to the field before anything is sent.

/** The contract's pattern for an SPDX id in deny/allow. */
export const SPDX_ID_RE = /^(LicenseRef-)?[A-Za-z0-9][A-Za-z0-9.+-]{0,63}$/;
export const MAX_LICENSE_IDS = 100;

export const CATEGORY_LABELS: Record<LicenseCategory, string> = {
  forbidden: "Forbidden",
  restricted: "Restricted",
  reciprocal: "Reciprocal",
  notice: "Notice",
  permissive: "Permissive",
  unencumbered: "Unencumbered",
  unknown: "Unknown",
};

/** One line each, with examples, under the category name. */
export const CATEGORY_HELP: Record<LicenseCategory, string> = {
  forbidden: "Licenses most companies don't allow in what they ship, such as AGPL-3.0 and SSPL-1.0.",
  restricted: "Strong copyleft such as GPL-2.0 and GPL-3.0: shipping the code can oblige you to publish your source.",
  reciprocal: "Weak copyleft such as MPL-2.0 and EPL-2.0: changes to those files must be shared.",
  notice: "Permissive licenses that ask you to keep a notice, such as MIT, BSD-3-Clause and Apache-2.0.",
  permissive: "Licenses with even fewer conditions than the notice group.",
  unencumbered: "Public-domain dedications such as CC0-1.0 and Unlicense.",
  unknown: "A license Trivy couldn't put in any category.",
};

export const ACTION_LABELS: Record<LicenseAction, string> = {
  allow: "Allow",
  review: "Review · Medium issue",
  block: "Block · High issue",
};

/** Short words for the read-only view. */
export const ACTION_WORDS: Record<LicenseAction, string> = { allow: "Allow", review: "Review (Medium)", block: "Block (High)" };

export const ALL_ALLOW: Record<LicenseCategory, LicenseAction> = {
  forbidden: "allow",
  restricted: "allow",
  reciprocal: "allow",
  notice: "allow",
  permissive: "allow",
  unencumbered: "allow",
  unknown: "allow",
};

/** "Apply recommended preset": forbidden → block, restricted → review, the rest allowed. */
export const RECOMMENDED: Record<LicenseCategory, LicenseAction> = { ...ALL_ALLOW, forbidden: "block", restricted: "review" };

/** Off = no license issue can come out of it (the server's `enabled` is the same rule). */
export function isPolicyOff(p: LicensePolicyInput): boolean {
  return p.deny.length === 0 && LICENSE_CATEGORIES.every((c) => p.categories[c] === "allow");
}

export function isLicenseAction(v: string): v is LicenseAction {
  return (LICENSE_ACTIONS as string[]).includes(v);
}

/** What someone typed or pasted into a list box: ids split on commas, semicolons and spaces. */
export function splitIds(text: string): string[] {
  return text
    .split(/[\s,;]+/)
    .map((s) => s.trim())
    .filter(Boolean);
}

const same = (a: string, b: string) => a.toLowerCase() === b.toLowerCase();

export type ListName = "deny" | "allow";

/** Adds ids to one list, or says why not. SPDX matching is case-insensitive, so duplicates and
 *  the overlap check ignore case. Nothing is added unless every id is acceptable. */
export function addIds(draft: LicensePolicyInput, list: ListName, ids: string[]): { next?: LicensePolicyInput; error?: string } {
  const other: ListName = list === "deny" ? "allow" : "deny";
  const current = draft[list];
  const added: string[] = [];
  for (const id of ids) {
    if (!SPDX_ID_RE.test(id)) {
      return { error: `“${id.slice(0, 80)}” isn't an SPDX license id. Use ids such as GPL-3.0-only, MIT or LicenseRef-acme.` };
    }
    if (draft[other].some((x) => same(x, id))) {
      return { error: `${id} is already in ${other === "deny" ? "Deny" : "Allow"}. A license can't be in both lists.` };
    }
    if (current.some((x) => same(x, id)) || added.some((x) => same(x, id))) continue;
    added.push(id);
  }
  if (added.length === 0) return ids.length ? { error: ids.length === 1 ? `${ids[0]} is already in the list.` : "These are already in the list." } : {};
  if (current.length + added.length > MAX_LICENSE_IDS) {
    return { error: `At most ${MAX_LICENSE_IDS} licenses per list.` };
  }
  return { next: { ...draft, [list]: [...current, ...added] } };
}

/** Per-list problems with a whole draft (what Save checks): bad ids, duplicates, overlap, size. */
export function validateLicensePolicy(p: LicensePolicyInput): { valid: boolean; deny?: string; allow?: string } {
  const out: { deny?: string; allow?: string } = {};
  for (const list of ["deny", "allow"] as const) {
    const ids = p[list];
    const bad = ids.find((id) => !SPDX_ID_RE.test(id));
    if (bad !== undefined) out[list] = `“${bad.slice(0, 80)}” isn't an SPDX license id.`;
    else if (ids.length > MAX_LICENSE_IDS) out[list] = `At most ${MAX_LICENSE_IDS} licenses per list.`;
    else if (new Set(ids.map((x) => x.toLowerCase())).size !== ids.length) out[list] = "A license is listed twice.";
  }
  const overlap = p.allow.find((a) => p.deny.some((d) => same(a, d)));
  if (overlap && !out.allow) out.allow = `${overlap} is also in Deny. A license can't be in both lists.`;
  return { valid: !out.deny && !out.allow, ...out };
}

/** The request body: categories in the contract's shape, nothing else. */
export function toInput(p: LicensePolicyInput): LicensePolicyInput {
  const categories = {} as Record<LicenseCategory, LicenseAction>;
  for (const c of LICENSE_CATEGORIES) categories[c] = p.categories[c];
  return { categories, deny: [...p.deny], allow: [...p.allow] };
}

export function policyKey(p: LicensePolicyInput): string {
  return JSON.stringify(toInput(p));
}

/** Server field errors (`metadata.fields`) mapped to the form: `categories.<c>`, `deny`,
 *  `deny[i]`, `allow`, `allow[i]`; anything else goes in a banner. */
export function serverLicenseErrors(fields: Record<string, string>, draft: LicensePolicyInput) {
  const categories: Partial<Record<LicenseCategory, string>> = {};
  const lists: Partial<Record<ListName, string>> = {};
  const other: string[] = [];
  for (const [k, v] of Object.entries(fields)) {
    const cat = /^categories\.([a-z]+)$/.exec(k);
    const item = /^(deny|allow)\[(\d+)\]$/.exec(k);
    if (cat && (LICENSE_CATEGORIES as string[]).includes(cat[1]!)) categories[cat[1] as LicenseCategory] = v;
    else if (k === "deny" || k === "allow") lists[k] ??= v;
    else if (item) {
      const list = item[1] as ListName;
      const id = draft[list][Number(item[2])];
      lists[list] ??= id !== undefined ? `${id}: ${v}` : v;
    } else other.push(`${k}: ${v}`);
  }
  return { categories, lists, other };
}

/** The policy in one line, for the audit log: "Block forbidden; review restricted; deny 2". */
export function licensePolicySummary(p: Partial<LicensePolicy> | null | undefined): string | null {
  if (!p || typeof p !== "object" || !p.categories || typeof p.categories !== "object") return null;
  const deny = Array.isArray(p.deny) ? p.deny.filter((x) => typeof x === "string") : [];
  const allow = Array.isArray(p.allow) ? p.allow.filter((x) => typeof x === "string") : [];
  const cats = p.categories as Partial<Record<string, unknown>>;
  const by = (a: LicenseAction) => LICENSE_CATEGORIES.filter((c) => cats[c] === a);
  const parts: string[] = [];
  const block = by("block");
  const review = by("review");
  if (block.length) parts.push(`block ${block.join(", ")}`);
  if (review.length) parts.push(`review ${review.join(", ")}`);
  if (deny.length) parts.push(`deny ${deny.length}`);
  if (allow.length) parts.push(`allow ${allow.length}`);
  if (parts.length === 0 || (block.length === 0 && review.length === 0 && deny.length === 0)) {
    return allow.length ? `Off (allow ${allow.length})` : "Off";
  }
  const text = parts.join("; ");
  return text.charAt(0).toUpperCase() + text.slice(1);
}
