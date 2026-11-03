import { describe, expect, it } from "vitest";
import type { ScanRule, ScanRuleVersion } from "../api/types";
import {
  deleteConfirmed,
  diffStats,
  findingLines,
  findingsSummary,
  formFromRule,
  indexProblems,
  lineCount,
  lineDiff,
  lineOffset,
  newRuleForm,
  nextPollDelay,
  orgRuleId,
  orgRuleLink,
  parseToolParam,
  pollDecision,
  problemText,
  ranRules,
  RULE_TEMPLATES,
  rulesByTool,
  scopeText,
  TEST_POLL_MAX_MS,
  testErrorText,
  updateRuleBody,
  validateRuleForm,
  validateTestInput,
  versionChanges,
} from "./scanRules";

const user = { id: "u1", email: "linh@acme.example", display_name: "Linh Tran" };
const rule = (over: Partial<ScanRule> = {}): ScanRule => ({
  id: "00000000-0000-4000-8000-0000000000r1",
  tool: "opengrep",
  key: "no-eval",
  rule_id: "org.no-eval",
  name: "No eval",
  body: "rules:\n  - id: no-eval\n",
  sha256: "a".repeat(64),
  version: 3,
  enabled: true,
  severity: "high",
  project_ids: null,
  created_by: user,
  updated_by: user,
  created_at: "2026-10-01T10:00:00Z",
  updated_at: "2026-10-02T10:00:00Z",
  ...over,
});
const version = (over: Partial<ScanRuleVersion>): ScanRuleVersion => ({
  version: 1,
  body: "a\n",
  sha256: "1".repeat(64),
  name: "No eval",
  enabled: true,
  project_ids: null,
  created_by: user,
  created_at: "2026-10-01T10:00:00Z",
  ...over,
});

describe("scan rules list", () => {
  it("says the scope in words and the rule id as org.<key>", () => {
    expect(scopeText(null)).toBe("All projects");
    expect(scopeText(["p1"])).toBe("1 project");
    expect(scopeText(["p1", "p2"])).toBe("2 projects");
    expect(orgRuleId("no-eval")).toBe("org.no-eval");
    // A key outside the contract's pattern is shown as it is (text), never prefixed.
    expect(orgRuleId("<b>x</b>")).toBe("<b>x</b>");
  });

  it("splits by scanner, newest change first; ?tool= falls back to Opengrep", () => {
    const a = rule({ id: "a", updated_at: "2026-10-01T00:00:00Z" });
    const b = rule({ id: "b", updated_at: "2026-10-05T00:00:00Z" });
    const g = rule({ id: "g", tool: "gitleaks" });
    const by = rulesByTool([a, g, b]);
    expect(by.opengrep.map((r) => r.id)).toEqual(["b", "a"]);
    expect(by.gitleaks.map((r) => r.id)).toEqual(["g"]);
    expect(parseToolParam("gitleaks")).toBe("gitleaks");
    expect(parseToolParam("trivy")).toBe("opengrep");
    expect(parseToolParam(null)).toBe("opengrep");
  });
});

describe("rule editor", () => {
  it("indexes the server's problems by line; lines outside the body go with the general ones", () => {
    const problems = [
      { line: 4, column: 3, message: "“paths” isn't allowed" },
      { line: 4, column: null, message: "second problem on 4" },
      { line: 2, column: null, message: "bad id" },
      { line: null, column: null, message: "the rule needs a message" },
      { line: 99, column: null, message: "past the end" },
    ];
    const idx = indexProblems(problems, 6);
    expect([...idx.byLine.keys()].sort()).toEqual([2, 4]);
    expect(idx.byLine.get(4)).toHaveLength(2);
    expect(idx.general.map((p) => p.message)).toEqual(["the rule needs a message", "past the end"]);
    expect(problemText(problems[0]!)).toBe("Line 4, column 3: “paths” isn't allowed");
    expect(problemText(problems[3]!)).toBe("the rule needs a message");
  });

  it("finds the start of a line for the caret", () => {
    const text = "rules:\n  - id: x\n    message: y";
    expect(lineOffset(text, 1)).toBe(0);
    expect(lineOffset(text, 2)).toBe(7);
    expect(text.slice(lineOffset(text, 3))).toBe("    message: y");
    expect(lineOffset(text, 10)).toBe(text.length);
    expect(lineCount("")).toBe(1);
    expect(lineCount("a\nb\n")).toBe(3);
  });

  it("checks the name, the 64 KiB body (in UTF-8 bytes) and the project scope", () => {
    const ok = newRuleForm("opengrep");
    expect(ok.body).toBe(RULE_TEMPLATES.opengrep);
    expect(validateRuleForm({ ...ok, name: "No eval" })).toEqual({});
    const bad = validateRuleForm({ ...ok, name: " ", body: "é".repeat(33 * 1024), allProjects: false, projectIds: [] });
    expect(Object.keys(bad).sort()).toEqual(["body", "name", "project_ids"]);
    expect(bad.body).toMatch(/at most 64 KiB; this one is 66 KiB/);
  });

  it("sends only what changed, with the version that was read", () => {
    const r = rule({ project_ids: ["p1", "p2"] });
    const f = formFromRule(r);
    expect(f.allProjects).toBe(false);
    expect(updateRuleBody(f, r)).toBeNull();
    // The same projects in another order are no change.
    expect(updateRuleBody({ ...f, projectIds: ["p2", "p1"] }, r)).toBeNull();
    expect(updateRuleBody({ ...f, enabled: false }, r)).toEqual({ version: 3, enabled: false });
    expect(updateRuleBody({ ...f, allProjects: true }, r)).toEqual({ version: 3, project_ids: null });
    expect(updateRuleBody({ ...f, name: "  Renamed ", body: "rules: []\n" }, r)).toEqual({ version: 3, name: "Renamed", body: "rules: []\n" });
  });

  it("deletes only after the key is typed exactly", () => {
    expect(deleteConfirmed("", "no-eval")).toBe(false);
    expect(deleteConfirmed("no-eva", "no-eval")).toBe(false);
    expect(deleteConfirmed("NO-EVAL", "no-eval")).toBe(false);
    expect(deleteConfirmed("No eval", "no-eval")).toBe(false);
    expect(deleteConfirmed(" no-eval ", "no-eval")).toBe(true);
    expect(deleteConfirmed("org.no-eval", "no-eval")).toBe(true);
  });
});

describe("test on a snippet", () => {
  it("checks the file name against the contract and the 64 KiB snippet", () => {
    expect(validateTestInput("app.js", "eval(x)")).toEqual({});
    expect(Object.keys(validateTestInput("", "x"))).toEqual(["filename"]);
    expect(Object.keys(validateTestInput("../etc/passwd", "x"))).toEqual(["filename"]);
    expect(Object.keys(validateTestInput("my file.js", "x"))).toEqual(["filename"]);
    expect(Object.keys(validateTestInput("a.js", "  \n"))).toEqual(["snippet"]);
    expect(validateTestInput("a.js", "x".repeat(64 * 1024 + 1)).snippet).toMatch(/At most 64 KiB/);
  });

  it("polls with backoff, stops when the run ended, and gives up after 3 minutes", () => {
    expect([0, 1, 2, 3, 10].map(nextPollDelay)).toEqual([1000, 2000, 3000, 5000, 5000]);
    const t0 = 1_000_000;
    expect(pollDecision(undefined, t0, t0, 0)).toEqual({ poll: 1000 });
    expect(pollDecision({ state: "queued" }, t0, t0 + 1000, 1)).toEqual({ poll: 2000 });
    expect(pollDecision({ state: "running" }, t0, t0 + 60_000, 7)).toEqual({ poll: 5000 });
    expect(pollDecision({ state: "done" }, t0, t0 + 5000, 3)).toEqual({ stop: "finished" });
    expect(pollDecision({ state: "failed" }, t0, t0 + 5000, 3)).toEqual({ stop: "finished" });
    // The last poll lands on the 3-minute mark, then nothing more.
    expect(pollDecision({ state: "running" }, t0, t0 + TEST_POLL_MAX_MS - 2000, 40)).toEqual({ poll: 2000 });
    expect(pollDecision({ state: "running" }, t0, t0 + TEST_POLL_MAX_MS, 41)).toEqual({ stop: "gave_up" });
  });

  it("highlights the lines findings cover, clamped to the snippet", () => {
    const findings = [
      { line: 3, end_line: null, message: "m" },
      { line: 7, end_line: 8, message: "m" },
      { line: 40, end_line: 1_000_000, message: "past the end" },
    ];
    expect([...findingLines(findings, 9)].sort((a, b) => a - b)).toEqual([3, 7, 8]);
    expect(findingsSummary(findings.slice(0, 2))).toBe("2 findings, on lines 3 and 7.");
    expect(findingsSummary([findings[0]!])).toBe("1 finding, on line 3.");
    expect(findingsSummary([])).toBe("No findings. The rule didn't match this snippet.");
  });

  it("words each failure reason, and anything else generically", () => {
    expect(testErrorText("timeout")).toMatch(/didn't finish within its time limit/);
    expect(testErrorText("scanner_failed")).toMatch(/scanner failed/);
    expect(testErrorText("rule_invalid")).toMatch(/refused the rule/);
    expect(testErrorText(null)).toMatch(/^The test failed\./);
    expect(testErrorText("<script>" as never)).toMatch(/^The test failed\./);
  });
});

describe("history", () => {
  it("says what each version changed", () => {
    const v1 = version({ version: 1, project_ids: ["p1"], name: "Eval" });
    const v2 = version({ version: 2, project_ids: null, name: "No eval" });
    const v3 = version({ version: 3, enabled: false });
    const v4 = version({ version: 4, enabled: false, body: "b\n", sha256: "2".repeat(64) });
    expect(versionChanges(v1, null)).toEqual(["Created for 1 project"]);
    expect(versionChanges(v2, v1)).toEqual(["Projects: 1 project → All projects", "Renamed from “Eval”"]);
    expect(versionChanges(v3, v2)).toEqual(["Turned off"]);
    expect(versionChanges(v4, v3)).toEqual(["Rule changed"]);
    expect(versionChanges(version({ version: 5 }), version({ version: 4 }))).toEqual(["No change to the rule"]);
  });

  it("diffs lines with the longest common subsequence, removed before added", () => {
    const a = "rules:\n  - id: x\n    severity: WARNING\n    pattern: eval(...)\n";
    const b = "rules:\n  - id: x\n    severity: ERROR\n    languages: [js]\n    pattern: eval(...)\n";
    const d = lineDiff(a, b);
    expect(d.map((l) => `${l.type[0]}${l.text}`)).toEqual([
      "srules:",
      "s  - id: x",
      "d    severity: WARNING",
      "a    severity: ERROR",
      "a    languages: [js]",
      "s    pattern: eval(...)",
    ]);
    expect(diffStats(d)).toEqual({ added: 2, removed: 1 });
    // Line numbers on each side.
    expect(d[2]).toMatchObject({ oldLine: 3, newLine: null });
    expect(d[4]).toMatchObject({ oldLine: null, newLine: 4 });
    expect(d[5]).toMatchObject({ oldLine: 4, newLine: 5 });
  });

  it("handles empty sides, identical text and a moved line", () => {
    expect(lineDiff("", "")).toEqual([]);
    expect(diffStats(lineDiff("", "a\nb"))).toEqual({ added: 2, removed: 0 });
    expect(diffStats(lineDiff("a\nb", ""))).toEqual({ added: 0, removed: 2 });
    expect(diffStats(lineDiff("a\nb\nc", "a\nb\nc\n"))).toEqual({ added: 0, removed: 0 });
    const moved = lineDiff("a\nb\nc\nd", "b\nc\nd\na");
    expect(diffStats(moved)).toEqual({ added: 1, removed: 1 });
    expect(moved.filter((l) => l.type === "same").map((l) => l.text)).toEqual(["b", "c", "d"]);
  });

  it("stays usable on big bodies (no quadratic blow-up past the cell limit)", () => {
    const a = Array.from({ length: 3000 }, (_, i) => `a${i}`).join("\n");
    const b = Array.from({ length: 3000 }, (_, i) => `b${i}`).join("\n");
    const t = Date.now();
    const d = lineDiff(a, b);
    expect(Date.now() - t).toBeLessThan(2000);
    expect(diffStats(d)).toEqual({ added: 3000, removed: 3000 });
    // A small edit in a big body is found exactly (common prefix and suffix are trimmed).
    const big = Array.from({ length: 5000 }, (_, i) => `line ${i}`);
    const edited = [...big];
    edited[2500] = "changed";
    expect(diffStats(lineDiff(big.join("\n"), edited.join("\n")))).toEqual({ added: 1, removed: 1 });
  });
});

describe("issues and scans", () => {
  const ORG = "00000000-0000-4000-8000-000000000001";
  const ID = "00000000-0000-4000-8000-0000000000aa";
  it("links an issue's org rule by id while it exists, never from other text", () => {
    expect(orgRuleLink(ORG, { scan_rule_id: ID, name: "No eval" })).toBe(`/orgs/${ORG}/settings/scan-rules/${ID}`);
    expect(orgRuleLink(ORG, { scan_rule_id: null, name: null })).toBeNull();
    expect(orgRuleLink(ORG, { scan_rule_id: ID, name: null })).toBeNull();
    expect(orgRuleLink(ORG, { scan_rule_id: "../../admin", name: "x" })).toBeNull();
    expect(orgRuleLink(ORG, { scan_rule_id: "javascript:alert(1)", name: "x" })).toBeNull();
  });

  it("matches the rules a scan ran to the org's current rules by scanner and rule id", () => {
    const r = rule();
    const refs = [
      { rule_id: "org.no-eval", tool: "opengrep" as const, version: 2, sha256: "b".repeat(64) },
      { rule_id: "org.no-eval", tool: "gitleaks" as const, version: 1, sha256: "c".repeat(64) },
      { rule_id: "org.gone", tool: "opengrep" as const, version: 1, sha256: "d".repeat(64) },
    ];
    expect(ranRules(refs, [r]).map((x) => x.rule?.id ?? null)).toEqual([r.id, null, null]);
    expect(ranRules(refs, undefined).every((x) => x.rule === null)).toBe(true);
  });
});
