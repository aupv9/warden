import { SEVERITIES, TOOLS } from "../api/types";
import type { AssignRule, ProjectMember, Severity, Tool } from "../api/types";
import { SEVERITY_LABELS, TOOL_LABELS, userName } from "./format";

// The auto-assign rules editor's model (contract D). Rules are ordered: the result processor
// gives a NEW issue to the first rule that matches, so order is part of the data. The checks
// here mirror the server's (at least one matcher, path glob ≤ 200 characters, assignee is a
// project member, ≤ 50 rules); the server checks again.

export const MAX_RULES = 50;
export const GLOB_MAX = 200;

export interface RuleDraft {
  /** Client-side identity for React keys and focus, never sent. */
  key: string;
  path_glob: string;
  tool: Tool | "";
  severity_at_least: Severity | "";
  assignee_id: string;
}

export interface RuleErrors {
  match?: string;
  path_glob?: string;
  assignee_id?: string;
}

let nextKey = 0;
export function newKey(): string {
  nextKey += 1;
  return `r${nextKey}`;
}

export function emptyDraft(): RuleDraft {
  return { key: newKey(), path_glob: "", tool: "", severity_at_least: "", assignee_id: "" };
}

export function toDraft(r: AssignRule): RuleDraft {
  return {
    key: newKey(),
    path_glob: r.match.path_glob ?? "",
    tool: r.match.tool && TOOLS.includes(r.match.tool) ? r.match.tool : "",
    severity_at_least: r.match.severity_at_least && SEVERITIES.includes(r.match.severity_at_least) ? r.match.severity_at_least : "",
    assignee_id: r.assignee_id,
  };
}

/** The API shape: empty matchers are left out, the glob is trimmed. */
export function fromDraft(d: RuleDraft): AssignRule {
  const match: AssignRule["match"] = {};
  const glob = d.path_glob.trim();
  if (glob) match.path_glob = glob;
  if (d.tool) match.tool = d.tool;
  if (d.severity_at_least) match.severity_at_least = d.severity_at_least;
  return { match, assignee_id: d.assignee_id };
}

export function validateRule(d: RuleDraft, memberIds: ReadonlySet<string>): RuleErrors {
  const e: RuleErrors = {};
  const glob = d.path_glob.trim();
  if (!glob && !d.tool && !d.severity_at_least) e.match = "Add at least one condition: a path, a scanner or a severity.";
  if (glob.length > GLOB_MAX) e.path_glob = `Use at most ${GLOB_MAX} characters (now ${glob.length}).`;
  else if (/[\u0000-\u001f\u007f]/.test(glob)) e.path_glob = "Use printable characters only.";
  if (!d.assignee_id) e.assignee_id = "Choose who gets the issue.";
  else if (!memberIds.has(d.assignee_id)) e.assignee_id = "This person is no longer a member of the project. Choose a current member.";
  return e;
}

export function hasErrors(e: RuleErrors): boolean {
  return !!(e.match || e.path_glob || e.assignee_id);
}

export function validateRules(drafts: RuleDraft[], members: ProjectMember[]): { rules: RuleErrors[]; list?: string; valid: boolean } {
  const ids = new Set(members.map((m) => m.user.id));
  const rules = drafts.map((d) => validateRule(d, ids));
  const list = drafts.length > MAX_RULES ? `A project can have at most ${MAX_RULES} rules. Remove ${drafts.length - MAX_RULES}.` : undefined;
  return { rules, list, valid: !list && !rules.some(hasErrors) };
}

/** Moves the item at `index` one place up (-1) or down (+1). Out-of-range moves return the
 *  same array, so callers can compare by reference. */
export function moveRule<T>(list: readonly T[], index: number, delta: -1 | 1): T[] {
  const to = index + delta;
  if (index < 0 || index >= list.length || to < 0 || to >= list.length) return list as T[];
  const next = [...list];
  const [item] = next.splice(index, 1);
  next.splice(to, 0, item as T);
  return next;
}

export function sameRules(a: AssignRule[], b: AssignRule[]): boolean {
  return JSON.stringify(a) === JSON.stringify(b);
}

/** Maps server field errors (`items[2].assignee_id`, `items[0].match.path_glob`) to rules. */
export function serverRuleErrors(fields: Record<string, string>, count: number): { rules: RuleErrors[]; other: string[] } {
  const rules: RuleErrors[] = Array.from({ length: count }, () => ({}));
  const other: string[] = [];
  for (const [k, v] of Object.entries(fields)) {
    const m = /^items\[(\d+)\](?:\.match)?(?:\.(path_glob|assignee_id|tool|severity_at_least))?$/.exec(k);
    const idx = m ? Number(m[1]) : -1;
    const rule = rules[idx];
    if (!m || !rule) {
      other.push(`${k}: ${v}`);
      continue;
    }
    const f = m[2];
    if (f === "path_glob") rule.path_glob = v;
    else if (f === "assignee_id") rule.assignee_id = v;
    else rule.match = v;
  }
  return { rules, other };
}

/** "Path matches services/** and severity is High or above → Minh Pham" (read-only view). */
export function describeRule(r: AssignRule, members: ProjectMember[]): { when: string; who: string; left: boolean } {
  const parts: string[] = [];
  if (r.match.path_glob) parts.push(`path matches ${r.match.path_glob}`);
  if (r.match.tool) parts.push(`found by ${TOOL_LABELS[r.match.tool] ?? r.match.tool}`);
  if (r.match.severity_at_least) {
    const s = r.match.severity_at_least;
    parts.push(s === "info" ? "any severity" : s === "critical" ? "severity is Critical" : `severity is ${SEVERITY_LABELS[s]} or above`);
  }
  const m = members.find((x) => x.user.id === r.assignee_id);
  const when = parts.length ? parts.join(" and ") : "any new issue";
  return { when: when.charAt(0).toUpperCase() + when.slice(1), who: m ? userName(m.user) : "a former member", left: !m };
}
