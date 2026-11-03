// Dev-only (mock mode): a small stand-in for backend/internal/rules, so the Scan rules pages can be
// clicked through without the server. It is not the server's parser: it reads the few lines it
// needs, refuses what the contract refuses (more than one rule, allowlists, ignores, path filters,
// lookaround and backreferences), reports problems at their lines, and renders a "canonical"
// body by dropping comments, blank lines and trailing spaces. It also fakes a snippet test.
import type { RuleProblem, RuleTestError, RuleTestFinding, ScanRuleTool, Severity } from "../types";

const KEY = /^[a-z0-9][a-z0-9._-]{0,63}$/;
const MAX_BYTES = 64 << 10;

export interface ParsedRule {
  key: string | null;
  severity: Severity | null;
  canonical: string | null;
  problems: RuleProblem[];
  /** For the fake test: what the rule looks for, and the message its findings carry. */
  matcher: RegExp | null;
  message: string;
}

const p = (line: number | null, message: string, column: number | null = null): RuleProblem => ({ line, column, message });

function unquote(v: string): string {
  const t = v.trim();
  for (const q of ["'''", '"""', '"', "'"]) if (t.startsWith(q) && t.endsWith(q) && t.length >= q.length * 2) return t.slice(q.length, -q.length);
  return t;
}

/** RE2 has neither lookaround nor backreferences. */
function re2Problem(line: number, text: string): RuleProblem | null {
  const m = /\(\?<?[=!]|\\[1-9]/.exec(text);
  return m ? p(line, "lookaround and backreferences aren't supported (Warden uses RE2 regular expressions)", m.index + 1) : null;
}

function toRegExp(src: string): RegExp | null {
  try {
    return new RegExp(src);
  } catch {
    return null;
  }
}

function escapeRe(s: string): string {
  return s.replace(/[.*+?^${}()|[\]\\]/g, "\\$&");
}

function canonical(lines: string[], fix: (l: string) => string = (l) => l): string {
  const kept = lines.map((l) => l.replace(/\s+$/, "")).filter((l) => l !== "" && !/^\s*#/.test(l));
  return kept.map(fix).join("\n") + "\n";
}

const OPENGREP_SEVERITY: Record<string, Severity> = { CRITICAL: "critical", ERROR: "high", WARNING: "medium", INFO: "low" };

export function parseRule(tool: ScanRuleTool, body: string): ParsedRule {
  const problems: RuleProblem[] = [];
  if (new TextEncoder().encode(body).length > MAX_BYTES) problems.push(p(null, "the rule is larger than 64 KiB"));
  const lines = body.split("\n");
  return tool === "opengrep" ? parseOpengrep(lines, problems) : parseGitleaks(lines, problems);
}

function parseOpengrep(lines: string[], problems: RuleProblem[]): ParsedRule {
  let key: string | null = null;
  let severity: Severity | null = null;
  let matcher: RegExp | null = null;
  let message = "";
  let ids = 0;
  let hasRules = false;
  let hasLanguages = false;
  lines.forEach((raw, i) => {
    const n = i + 1;
    if (/^\s*#/.test(raw) || raw.trim() === "") return;
    if (/^ *\t/.test(raw)) problems.push(p(n, "tabs can't indent YAML; use spaces"));
    if (/^rules:\s*$/.test(raw)) hasRules = true;
    const id = /^\s*(?:-\s+)?id:\s*(.*)$/.exec(raw);
    if (id) {
      ids += 1;
      if (ids > 1) problems.push(p(n, "a body holds exactly one rule; this is a second one"));
      else {
        const v = unquote(id[1]!);
        if (!KEY.test(v)) problems.push(p(n, "the id must be lowercase letters, digits, '.', '_' or '-', starting with a letter or digit, at most 64 characters", raw.indexOf(id[1]!) + 1));
        else key = v;
      }
    }
    const forbidden = /^\s*(?:-\s+)?(paths|exclude|include|allowlist|ignore|fix|fix-regex|options|focus-metavariable-ignore)\s*:/.exec(raw);
    if (forbidden) problems.push(p(n, `“${forbidden[1]}” isn't allowed: org rules only add findings`, raw.indexOf(forbidden[1]!) + 1));
    const sev = /^\s*severity:\s*(\S+)/.exec(raw);
    if (sev) {
      severity = OPENGREP_SEVERITY[unquote(sev[1]!).toUpperCase()] ?? null;
      if (!severity) problems.push(p(n, "severity must be ERROR, WARNING or INFO", raw.indexOf(sev[1]!) + 1));
    }
    const msg = /^\s*message:\s*(.+)$/.exec(raw);
    if (msg) message = unquote(msg[1]!);
    if (/^\s*languages:\s*\S/.test(raw)) hasLanguages = true;
    const pat = /^\s*(?:-\s+)?(pattern|pattern-regex|pattern-either|patterns)\s*:\s*(.*)$/.exec(raw);
    if (pat) {
      const v = unquote(pat[2]!);
      if (pat[1] === "pattern-regex") {
        const bad = re2Problem(n, raw);
        if (bad) problems.push(bad);
        else matcher ??= toRegExp(v);
      } else if (pat[1] === "pattern" && v) {
        // The fake test matches the call's name: "eval($X)" finds lines with "eval(".
        const head = /^[\w.$]+\(/.exec(v.replace(/\$[A-Z_]+\./g, ""));
        matcher ??= toRegExp(head ? escapeRe(head[0]) : escapeRe(v));
      } else matcher ??= /(?!)/;
    }
  });
  if (!hasRules) problems.push(p(1, "the body must start with rules: and hold one rule"));
  if (ids === 0) problems.push(p(null, "the rule has no id"));
  if (!message) problems.push(p(null, "the rule needs a message"));
  if (!severity && !problems.some((x) => x.message.startsWith("severity"))) problems.push(p(null, "the rule needs a severity: ERROR, WARNING or INFO"));
  if (!hasLanguages) problems.push(p(null, "the rule needs languages, such as [javascript]"));
  if (!matcher) problems.push(p(null, "the rule needs a pattern, patterns, pattern-either or pattern-regex"));
  if (problems.length) return { key: null, severity: null, canonical: null, problems, matcher: null, message };
  return { key, severity, canonical: canonical(lines), problems, matcher, message };
}

function parseGitleaks(lines: string[], problems: RuleProblem[]): ParsedRule {
  let key: string | null = null;
  let matcher: RegExp | null = null;
  let message = "";
  let tables = 0;
  lines.forEach((raw, i) => {
    const n = i + 1;
    if (/^\s*#/.test(raw) || raw.trim() === "") return;
    if (/^\s*\[\[rules\]\]\s*$/.test(raw)) {
      tables += 1;
      if (tables > 1) problems.push(p(n, "a body holds exactly one [[rules]] table; this is a second one"));
      return;
    }
    if (/allowlist/i.test(raw)) {
      problems.push(p(n, "allowlists aren't allowed: org rules only add findings", raw.search(/allowlist/i) + 1));
      return;
    }
    if (/^\s*\[/.test(raw)) {
      problems.push(p(n, "only one [[rules]] table is allowed; no other tables"));
      return;
    }
    const kv = /^\s*([A-Za-z]+)\s*=\s*(.*)$/.exec(raw);
    if (!kv) {
      problems.push(p(n, "expected key = value"));
      return;
    }
    const [, k, v] = kv;
    if (k === "id") {
      const id = unquote(v!);
      if (!KEY.test(id)) problems.push(p(n, "the id must be lowercase letters, digits, '.', '_' or '-', starting with a letter or digit, at most 64 characters", raw.indexOf(v!) + 1));
      else key = id;
    } else if (k === "regex") {
      const bad = re2Problem(n, v!);
      if (bad) problems.push({ ...bad, column: raw.indexOf(v!) + (bad.column ?? 1) });
      else {
        matcher = toRegExp(unquote(v!));
        if (!matcher) problems.push(p(n, "the regex doesn't compile"));
      }
    } else if (k === "description") message = unquote(v!);
    else if (k === "path") problems.push(p(n, "path filters aren't allowed: org rules only add findings"));
    else if (!["keywords", "entropy", "secretGroup", "tags"].includes(k!)) problems.push(p(n, `unknown key “${k}”`));
  });
  if (tables === 0) problems.push(p(1, "the body needs one [[rules]] table"));
  if (!key && !problems.some((x) => x.message.startsWith("the id"))) problems.push(p(null, "the rule has no id"));
  if (!matcher && !problems.some((x) => /regex/.test(x.message))) problems.push(p(null, "the rule needs a regex"));
  if (!message) message = key ?? "Org secret";
  if (problems.length) return { key: null, severity: null, canonical: null, problems, matcher: null, message };
  return { key, severity: "high", canonical: canonical(lines, (l) => l.replace(/^\s*([A-Za-z]+)\s*=\s*/, "$1 = ")), problems, matcher, message };
}

/** What a snippet test would answer. The file name picks a failure, so every state can be seen:
 *  timeout.*, crash.* and invalid.* fail with timeout, scanner_failed and rule_invalid. */
export function fakeTest(rule: ParsedRule, filename: string, snippet: string): { error: RuleTestError | null; findings: RuleTestFinding[] } {
  if (filename.startsWith("timeout")) return { error: "timeout", findings: [] };
  if (filename.startsWith("crash")) return { error: "scanner_failed", findings: [] };
  if (filename.startsWith("invalid")) return { error: "rule_invalid", findings: [] };
  const findings: RuleTestFinding[] = [];
  snippet.split("\n").forEach((line, i) => {
    if (rule.matcher?.test(line)) findings.push({ line: i + 1, end_line: null, message: rule.message });
  });
  return { error: null, findings };
}
