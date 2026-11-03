import type { RuleProblem, RuleTest, RuleTestError, ScanRule, ScanRuleRef, ScanRuleTool, ScanRuleVersion, Severity, UpdateScanRuleBody } from "../api/types";
import { SEVERITY_LABELS } from "./format";

// v0.6 wave 1: the org's own Opengrep and Gitleaks rules (DESIGN.md "v0.6 screens: Scan rules").
// Pure helpers for the Scan rules pages, kept apart from the components so they can be tested
// without a DOM. Rule bodies, names, problems and test findings are hostile text: the pages
// render everything here as text, never as HTML (no innerHTML anywhere).

export const SCAN_RULE_TOOL_LABELS: Record<ScanRuleTool, string> = { opengrep: "Opengrep", gitleaks: "Gitleaks" };
export const SCAN_RULE_TOOL_KIND: Record<ScanRuleTool, string> = { opengrep: "code patterns (SAST)", gitleaks: "secrets" };

/** internal/rules: 64 KiB per body (bytes, UTF-8), 200 rules per scanner, 1 MiB per org. */
export const RULE_BODY_MAX_BYTES = 64 << 10;
export const RULES_PER_TOOL_MAX = 200;
export const RULE_NAME_MAX = 200;
export const RULE_PROJECTS_MAX = 200;
/** POST …/tests: the snippet (bytes, UTF-8) and the file name that picks Opengrep's language. */
export const SNIPPET_MAX_BYTES = 64 << 10;
export const TEST_FILENAME_MAX = 255;
const TEST_FILENAME = /^[A-Za-z0-9._-]+$/;
/** What findings and issues of an org rule carry: org.<key>. */
export const ORG_RULE_PREFIX = "org.";
const RULE_KEY = /^[a-z0-9][a-z0-9._-]{0,63}$/;

/** Debounce of the live check while typing. */
export const CHECK_DEBOUNCE_MS = 600;

export function utf8Length(s: string): number {
  return new TextEncoder().encode(s).length;
}

export function kib(bytes: number): string {
  if (bytes < 1024) return `${bytes} bytes`;
  return `${(bytes / 1024).toFixed(bytes < 10 * 1024 ? 1 : 0)} KiB`;
}

/** org.<key>, for a key the contract allows; anything else is shown as it is (text). */
export function orgRuleId(key: string): string {
  return RULE_KEY.test(key) ? `${ORG_RULE_PREFIX}${key}` : key;
}

/** Scope in words: null is every project of the org (including later ones). */
export function scopeText(projectIds: readonly string[] | null): string {
  if (projectIds === null) return "All projects";
  if (projectIds.length === 0) return "No projects";
  return projectIds.length === 1 ? "1 project" : `${projectIds.length} projects`;
}

export function severityText(s: Severity | null | undefined): string {
  return s ? SEVERITY_LABELS[s] : "–";
}

/** Splits a rule's list by scanner, newest change first within each. */
export function rulesByTool(rules: readonly ScanRule[]): Record<ScanRuleTool, ScanRule[]> {
  const out: Record<ScanRuleTool, ScanRule[]> = { opengrep: [], gitleaks: [] };
  for (const r of rules) if (r.tool in out) out[r.tool].push(r);
  for (const t of Object.keys(out) as ScanRuleTool[]) out[t].sort((a, b) => b.updated_at.localeCompare(a.updated_at) || a.name.localeCompare(b.name));
  return out;
}

/** `?tool=` of the list page; anything else is Opengrep. */
export function parseToolParam(v: string | null): ScanRuleTool {
  return v === "gitleaks" ? "gitleaks" : "opengrep";
}

// ---- New rule templates ----

/** A starting point for a new rule. Plain examples; never secret-shaped values. */
export const RULE_TEMPLATES: Record<ScanRuleTool, string> = {
  opengrep: [
    "rules:",
    "  - id: no-eval-of-request-data",
    "    message: Don't pass request data to eval.",
    "    severity: ERROR",
    "    languages: [javascript, typescript]",
    "    pattern: eval($REQ.body)",
    "",
  ].join("\n"),
  gitleaks: [
    "[[rules]]",
    'id = "acme-internal-token"',
    'description = "Acme internal API token"',
    "regex = '''acme_tok_[a-z0-9]{32}'''",
    'keywords = ["acme_tok_"]',
    "",
  ].join("\n"),
};

// ---- Problems by line ----

export interface ProblemIndex {
  /** Problems with a line inside the body, by 1-based line. */
  byLine: Map<number, RuleProblem[]>;
  /** Problems without a line, or with one past the end of the body. */
  general: RuleProblem[];
}

export function indexProblems(problems: readonly RuleProblem[], lineCount: number): ProblemIndex {
  const byLine = new Map<number, RuleProblem[]>();
  const general: RuleProblem[] = [];
  for (const p of problems) {
    if (p.line !== null && p.line >= 1 && p.line <= Math.max(1, lineCount)) {
      const list = byLine.get(p.line) ?? [];
      list.push(p);
      byLine.set(p.line, list);
    } else general.push(p);
  }
  return { byLine, general };
}

export function lineCount(body: string): number {
  return body === "" ? 1 : body.split("\n").length;
}

/** "Line 4, column 3: message" / "message". */
export function problemText(p: RuleProblem): string {
  if (p.line === null) return p.message;
  return `Line ${p.line}${p.column !== null ? `, column ${p.column}` : ""}: ${p.message}`;
}

/** Offset of the start of a 1-based line in the text (for moving the caret to a problem). */
export function lineOffset(text: string, line: number): number {
  let offset = 0;
  for (let i = 1; i < line; i++) {
    const next = text.indexOf("\n", offset);
    if (next === -1) return text.length;
    offset = next + 1;
  }
  return offset;
}

// ---- Client-side checks (the server checks again) ----

export interface RuleForm {
  name: string;
  body: string;
  enabled: boolean;
  allProjects: boolean;
  projectIds: string[];
}

export function newRuleForm(tool: ScanRuleTool): RuleForm {
  return { name: "", body: RULE_TEMPLATES[tool], enabled: true, allProjects: true, projectIds: [] };
}

export function formFromRule(r: Pick<ScanRule, "name" | "body" | "enabled" | "project_ids">): RuleForm {
  return { name: r.name, body: r.body, enabled: r.enabled, allProjects: r.project_ids === null, projectIds: r.project_ids ?? [] };
}

export function validateRuleForm(f: RuleForm): Record<string, string> {
  const e: Record<string, string> = {};
  const name = f.name.trim();
  if (!name) e.name = "Give the rule a name, such as “No eval of request data”.";
  else if (name.length > RULE_NAME_MAX) e.name = `At most ${RULE_NAME_MAX} characters.`;
  if (!f.body.trim()) e.body = "Write the rule.";
  else if (utf8Length(f.body) > RULE_BODY_MAX_BYTES) e.body = `A rule can be at most 64 KiB; this one is ${kib(utf8Length(f.body))}.`;
  if (!f.allProjects) {
    if (f.projectIds.length === 0) e.project_ids = "Choose at least one project, or All projects.";
    else if (f.projectIds.length > RULE_PROJECTS_MAX) e.project_ids = `At most ${RULE_PROJECTS_MAX} projects.`;
  }
  return e;
}

function sameIds(a: readonly string[] | null, b: readonly string[] | null): boolean {
  if (a === null || b === null) return a === b;
  if (a.length !== b.length) return false;
  const s = new Set(a);
  return b.every((x) => s.has(x));
}

/** The PATCH body for what changed, with the version read; null when nothing changed. */
export function updateRuleBody(f: RuleForm, r: ScanRule): UpdateScanRuleBody | null {
  const b: UpdateScanRuleBody = { version: r.version };
  const name = f.name.trim();
  if (name !== r.name) b.name = name;
  if (f.body !== r.body) b.body = f.body;
  if (f.enabled !== r.enabled) b.enabled = f.enabled;
  const ids = f.allProjects ? null : f.projectIds;
  if (!sameIds(ids, r.project_ids)) b.project_ids = ids;
  return Object.keys(b).length > 1 ? b : null;
}

/** Typed confirmation for delete: the rule's key, exactly (org.<key> is accepted too). */
export function deleteConfirmed(typed: string, key: string): boolean {
  const t = typed.trim();
  return t === key || t === `${ORG_RULE_PREFIX}${key}`;
}

// ---- Test on a snippet ----

export function validateTestInput(filename: string, snippet: string): Record<string, string> {
  const e: Record<string, string> = {};
  const f = filename.trim();
  if (!f) e.filename = "Name the file, such as app.js: Opengrep picks the language from it.";
  else if (f.length > TEST_FILENAME_MAX || !TEST_FILENAME.test(f)) e.filename = "Letters, digits, dots, hyphens and underscores only, such as app.js.";
  if (!snippet.trim()) e.snippet = "Paste a few lines the rule should (or shouldn't) find.";
  else if (utf8Length(snippet) > SNIPPET_MAX_BYTES) e.snippet = `At most 64 KiB; this is ${kib(utf8Length(snippet))}.`;
  return e;
}

/** Polling of GET …/tests/{id}: 1 s, 2 s, 3 s, then every 5 s; stop when the run ended, or
 *  after 3 minutes of waiting. */
export const TEST_POLL_MAX_MS = 3 * 60_000;
const POLL_STEPS = [1000, 2000, 3000];
export function nextPollDelay(polls: number): number {
  return POLL_STEPS[polls] ?? 5000;
}

export type PollDecision = { poll: number } | { stop: "finished" | "gave_up" };

export function pollDecision(test: Pick<RuleTest, "state"> | undefined, startedAt: number, now: number, polls: number): PollDecision {
  if (test && (test.state === "done" || test.state === "failed")) return { stop: "finished" };
  if (now - startedAt >= TEST_POLL_MAX_MS) return { stop: "gave_up" };
  return { poll: Math.min(nextPollDelay(polls), Math.max(0, startedAt + TEST_POLL_MAX_MS - now)) };
}

export const TEST_ERROR_TEXT: Record<RuleTestError, string> = {
  timeout: "The scanner didn't finish within its time limit. Make the rule's patterns narrower, or test a shorter snippet.",
  scanner_failed: "The scanner failed on this rule and snippet. Check the file name's extension matches the snippet's language, then try again; if it keeps failing, tell your operator.",
  rule_invalid: "The scanner refused the rule as Warden rendered it. Check the problems above; if there are none, tell your operator.",
};

export function testErrorText(e: RuleTestError | null): string {
  return (e && TEST_ERROR_TEXT[e]) ?? "The test failed. Try again; if it keeps failing, tell your operator.";
}

export const TEST_RATE_LIMITED = "You've run 20 tests in the last hour, the most Warden allows.";

/** Snippet lines a finding covers (1-based, inclusive), clamped to the snippet. */
export function findingLines(findings: RuleTest["findings"], snippetLines: number): Set<number> {
  const out = new Set<number>();
  for (const f of findings) {
    const end = Math.min(f.end_line ?? f.line, f.line + 1000, snippetLines);
    for (let n = Math.max(1, f.line); n <= end; n++) out.add(n);
  }
  return out;
}

export function findingsSummary(findings: RuleTest["findings"]): string {
  if (findings.length === 0) return "No findings. The rule didn't match this snippet.";
  const lines = [...new Set(findings.map((f) => f.line))].sort((a, b) => a - b);
  const which = lines.length === 1 ? `line ${lines[0]}` : `lines ${lines.slice(0, -1).join(", ")} and ${lines[lines.length - 1]}`;
  return `${findings.length} finding${findings.length === 1 ? "" : "s"}, on ${which}.`;
}

export function findingRange(f: { line: number; end_line: number | null }): string {
  return f.end_line && f.end_line > f.line ? `Lines ${f.line}–${f.end_line}` : `Line ${f.line}`;
}

// ---- History ----

/** What a version changed compared with the one before it (null for the first version). */
export function versionChanges(v: ScanRuleVersion, prev: ScanRuleVersion | null): string[] {
  if (!prev) return [`Created${v.enabled ? "" : " (off)"} for ${scopeText(v.project_ids).toLowerCase()}`];
  const out: string[] = [];
  if (v.enabled !== prev.enabled) out.push(v.enabled ? "Turned on" : "Turned off");
  if (!sameIds(v.project_ids, prev.project_ids)) out.push(`Projects: ${scopeText(prev.project_ids)} → ${scopeText(v.project_ids)}`);
  if (v.name !== prev.name) out.push(`Renamed from “${prev.name}”`);
  if (v.sha256 !== prev.sha256 || v.body !== prev.body) out.push("Rule changed");
  if (out.length === 0) out.push("No change to the rule");
  return out;
}

// ---- A plain line diff (LCS), no dependency ----

export type DiffLine = { type: "same" | "add" | "del"; text: string; oldLine: number | null; newLine: number | null };

/** Beyond this many cells the LCS table isn't built: the middle shows as removed, then added. */
const DIFF_MAX_CELLS = 4_000_000;

/** Lines of `a` → lines of `b` with the longest common subsequence kept as "same". Common
 *  prefixes and suffixes are trimmed first, so typical edits stay small. */
export function lineDiff(a: string, b: string): DiffLine[] {
  const A = splitLines(a);
  const B = splitLines(b);
  let start = 0;
  while (start < A.length && start < B.length && A[start] === B[start]) start++;
  let endA = A.length;
  let endB = B.length;
  while (endA > start && endB > start && A[endA - 1] === B[endB - 1]) {
    endA--;
    endB--;
  }
  const out: DiffLine[] = [];
  for (let i = 0; i < start; i++) out.push({ type: "same", text: A[i]!, oldLine: i + 1, newLine: i + 1 });

  const n = endA - start;
  const m = endB - start;
  if (n * m > DIFF_MAX_CELLS) {
    for (let i = 0; i < n; i++) out.push({ type: "del", text: A[start + i]!, oldLine: start + i + 1, newLine: null });
    for (let j = 0; j < m; j++) out.push({ type: "add", text: B[start + j]!, oldLine: null, newLine: start + j + 1 });
  } else {
    // lcs[i][j]: LCS length of A[start+i..endA) and B[start+j..endB), one flat array.
    const w = m + 1;
    const lcs = new Uint32Array((n + 1) * w);
    for (let i = n - 1; i >= 0; i--) {
      for (let j = m - 1; j >= 0; j--) {
        lcs[i * w + j] = A[start + i] === B[start + j] ? lcs[(i + 1) * w + j + 1]! + 1 : Math.max(lcs[(i + 1) * w + j]!, lcs[i * w + j + 1]!);
      }
    }
    let i = 0;
    let j = 0;
    while (i < n || j < m) {
      if (i < n && j < m && A[start + i] === B[start + j]) {
        out.push({ type: "same", text: A[start + i]!, oldLine: start + i + 1, newLine: start + j + 1 });
        i++;
        j++;
      } else if (i < n && (j >= m || lcs[(i + 1) * w + j]! >= lcs[i * w + j + 1]!)) {
        // Removed lines before added ones, as in a unified diff.
        out.push({ type: "del", text: A[start + i]!, oldLine: start + i + 1, newLine: null });
        i++;
      } else {
        out.push({ type: "add", text: B[start + j]!, oldLine: null, newLine: start + j + 1 });
        j++;
      }
    }
  }
  for (let k = 0; k < A.length - endA; k++) out.push({ type: "same", text: A[endA + k]!, oldLine: endA + k + 1, newLine: endB + k + 1 });
  return out;
}

function splitLines(s: string): string[] {
  if (s === "") return [];
  const lines = s.split("\n");
  if (lines[lines.length - 1] === "") lines.pop();
  return lines;
}

// ---- Issues and scans ----

const UUID_RE = /^[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}$/i;

/** The rule page of an issue's org rule, built from its id only, while the rule exists (the
 *  server nulls `scan_rule_id` and `name` when it is deleted). */
export function orgRuleLink(orgId: string, r: { scan_rule_id: string | null; name: string | null }): string | null {
  if (!r.scan_rule_id || r.name === null || !UUID_RE.test(r.scan_rule_id)) return null;
  return `/orgs/${orgId}/settings/scan-rules/${r.scan_rule_id}`;
}

/** The org rules a scan ran, each with the org's current rule of that id if it still exists. */
export function ranRules(refs: readonly ScanRuleRef[], rules: readonly ScanRule[] | undefined): { ref: ScanRuleRef; rule: ScanRule | null }[] {
  return refs.map((ref) => ({ ref, rule: rules?.find((r) => r.tool === ref.tool && r.rule_id === ref.rule_id) ?? null }));
}

export function diffStats(d: readonly DiffLine[]): { added: number; removed: number } {
  let added = 0;
  let removed = 0;
  for (const l of d) {
    if (l.type === "add") added++;
    else if (l.type === "del") removed++;
  }
  return { added, removed };
}
