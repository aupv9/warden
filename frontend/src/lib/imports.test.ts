import { describe, expect, it } from "vitest";
// The contract, read as text: the UI's pattern must be the server's.
import openapiRaw from "../../../backend/internal/api/openapi.json?raw";
import { buildQuery } from "../api/client";
import type { ScanImport } from "../api/types";
import { describeRule, fromDraft, RULE_TOOLS, toDraft } from "./assignRules";
import { githubActionsSnippet, gitlabCiSnippet } from "./ciSnippets";
import {
  IMPORT_TOOL_RE,
  importCountsText,
  importSourceText,
  importToolChoices,
  importToolLabel,
  importToolOf,
  isImportIssue,
  issueToolLabel,
  onlyScanners,
  parseImportTarget,
  scanToolLabel,
} from "./imports";
import {
  DEFAULT_FILTERS,
  describeFilters,
  issueFilterQuery,
  issueFiltersToApiQuery,
  issueFiltersToSearch,
  parseIssueFilters,
} from "./issueFilters";
import { isRejected, scanErrorMessages } from "./scanErrors";

const schemas = (JSON.parse(openapiRaw) as { components: { schemas: Record<string, { pattern?: string }> } }).components.schemas;
const HOSTILE = '"><img src=x onerror=alert(1)>';

describe("v0.8: imported tools", () => {
  it("the ImportTool pattern is the contract's", () => {
    expect(IMPORT_TOOL_RE.source).toBe(new RegExp(schemas.ImportTool!.pattern!).source);
  });

  it("names the tools; external.<key> reads as its key; anything else stays as it came (text)", () => {
    expect(importToolLabel("codeql")).toBe("CodeQL");
    expect(importToolLabel("gitlab-sast")).toBe("GitLab SAST");
    expect(importToolLabel("snyk-code")).toBe("Snyk Code");
    expect(importToolLabel("sonarqube")).toBe("SonarQube");
    expect(importToolLabel("semgrep")).toBe("Semgrep");
    expect(importToolLabel("external.bandit")).toBe("bandit");
    // Not a well-formed tool: the whole value, never a shortened one that looks like something else.
    expect(importToolLabel(`external.${HOSTILE}`)).toBe(`external.${HOSTILE}`);
    expect(importToolLabel("__proto__")).toBe("__proto__");
    expect(importToolLabel("toString")).toBe("toString");
  });

  it("reads tool and category from an import target, and nothing from any other", () => {
    expect(parseImportTarget("(import) codeql /language:python/")).toEqual({ tool: "codeql", category: "/language:python/" });
    expect(parseImportTarget("(import) gitlab-sast")).toEqual({ tool: "gitlab-sast", category: "" });
    expect(parseImportTarget("(import) external.my-tool cat")).toEqual({ tool: "external.my-tool", category: "cat" });
    for (const t of ["", "(history)", "ghcr.io/acme/api", "(import) ", "(import) gitleaks", "(import) opengrep x", `(import) ${HOSTILE}`, "(import)codeql", "(IMPORT) codeql"]) {
      expect(parseImportTarget(t)).toBeNull();
    }
  });

  it("an issue's tool is its external_tool (list rows and the full issue); Warden's own issues keep their scanner", () => {
    const row = { tool: "external" as const, external_tool: "codeql" };
    expect(isImportIssue(row)).toBe(true);
    expect(importToolOf(row)).toBe("codeql");
    expect(issueToolLabel(row)).toBe("CodeQL");
    expect(issueToolLabel({ tool: "external", external_tool: "external.bandit" })).toBe("bandit");
    expect(issueToolLabel({ tool: "external", external_tool: null })).toBe("Imported");
    expect(issueToolLabel({ tool: "gitleaks", external_tool: null })).toBe("Gitleaks");
    expect(importToolOf({ tool: "trivy", external_tool: "codeql" })).toBeNull();
  });

  const imp: ScanImport = { tool: "codeql", category: "/language:python/", format: "sarif", tool_version: "2.23.1", results: 14, dropped: 1, screened: 2 };

  it("a scan's run of external is named after the imported tool", () => {
    expect(scanToolLabel({ import: imp }, "external")).toBe("CodeQL");
    expect(scanToolLabel({ import: null }, "external")).toBe("Imported");
    expect(scanToolLabel({ import: imp }, "trivy")).toBe("Trivy");
    expect(importSourceText(imp)).toBe("CodeQL · /language:python/");
    expect(importSourceText({ tool: "gitlab-sast", category: "" })).toBe("GitLab SAST");
  });

  it("counts in words, only once processed", () => {
    expect(importCountsText(imp)).toEqual({ results: "14 results read", dropped: "1 dropped", screened: "2 screened by Gitleaks" });
    expect(importCountsText({ ...imp, results: 1, dropped: 0, screened: 1234 })).toEqual({
      results: "1 result read",
      dropped: "0 dropped",
      screened: "1,234 screened by Gitleaks",
    });
    expect(importCountsText({ ...imp, results: null, dropped: null, screened: null })).toBeNull();
  });

  it("the Imported from choices: tools of import targets only, well-formed, once each, by label; the URL's stays", () => {
    const rows = [
      { target: "", kind: "source" },
      { target: "ghcr.io/acme/api", kind: "image" },
      { target: "(import) semgrep", kind: "import" },
      { target: "(import) codeql /language:python/", kind: "import" },
      { target: "(import) codeql /language:go/", kind: "import" },
      { target: `(import) ${HOSTILE}`, kind: "import" },
      // A target whose kind isn't import is never read as one.
      { target: "(import) sonarqube", kind: "image" },
    ];
    expect(importToolChoices(rows, "")).toEqual(["codeql", "semgrep"]);
    expect(importToolChoices(rows, "external.zap")).toEqual(["codeql", "semgrep", "external.zap"]);
    expect(importToolChoices(undefined, "gitlab-sast")).toEqual(["gitlab-sast"]);
    expect(importToolChoices(undefined, HOSTILE)).toEqual([]);
  });

  it("a scan chooses Warden's scanners only, never external", () => {
    expect(onlyScanners(["external", "trivy", "gitleaks"])).toEqual(["gitleaks", "trivy"]);
  });
});

describe("v0.8: issue filters for imports", () => {
  it("Source takes Imported; Imported from takes a well-formed tool only (the URL is untrusted)", () => {
    const f = parseIssueFilters(new URLSearchParams("source=import&external_tool=codeql"));
    expect(f).toEqual({ ...DEFAULT_FILTERS, source: "import", externalTool: "codeql" });
    expect(issueFiltersToSearch(f).toString()).toBe("source=import&external_tool=codeql");
    expect(buildQuery(issueFiltersToApiQuery(f))).toBe("?source=import&external_tool=codeql&limit=50");
    for (const bad of ["gitleaks", "external", "external.", "external.UPPER", `external.${"a".repeat(33)}`, "CodeQL", HOSTILE, "codeql "]) {
      expect(parseIssueFilters(new URLSearchParams({ external_tool: bad })).externalTool).toBe("");
    }
    // tool=external isn't a scanner filter: imported issues are filtered by source or tool.
    expect(parseIssueFilters(new URLSearchParams("tool=external")).tool).toBe("");
  });

  it("describes them in words", () => {
    expect(describeFilters({ ...DEFAULT_FILTERS, source: "import", externalTool: "external.bandit" })).toEqual(["Active", "Imported", "Imported from bandit"]);
  });

  it("the CSV export takes them like the list", () => {
    const q = issueFilterQuery({ ...DEFAULT_FILTERS, source: "import", externalTool: "codeql" });
    expect(q).toMatchObject({ source: "import", external_tool: "codeql" });
  });
});

describe("v0.8: import errors", () => {
  it("an unreadable or oversized report is rejected; a screening that couldn't run is a failure", () => {
    expect(isRejected({ status: "failed", error_code: "IMPORT_INVALID" })).toBe(true);
    expect(isRejected({ status: "failed", error_code: "IMPORT_TOO_LARGE" })).toBe(true);
    expect(isRejected({ status: "failed", error_code: "IMPORT_SCREEN_FAILED" })).toBe(false);
    expect(scanErrorMessages("IMPORT_INVALID").full).toMatch(/SARIF 2\.1\.0.*--format gitlab-sast/);
    expect(scanErrorMessages("IMPORT_TOO_LARGE").full).toMatch(/10 runs, 50,000 results or 5,000 rules/);
    expect(scanErrorMessages("IMPORT_SCREEN_FAILED").full).toMatch(/nothing was imported and no issues changed/);
  });
});

describe("v0.8: auto-assign rules match imported results", () => {
  it("external survives a round trip through the editor (it isn't widened to any scanner) and reads in words", () => {
    expect(RULE_TOOLS).toContain("external");
    const rule = { match: { tool: "external" as const }, assignee_id: "u1" };
    expect(fromDraft(toDraft(rule))).toEqual(rule);
    expect(describeRule(rule, []).when).toBe("Imported from another tool");
  });
});

describe("v0.8: CI setup imports", () => {
  const p = { url: "https://warden.example", orgId: "org-1", projectId: "proj-1" };

  it("GitHub: CodeQL with output: a directory, then warden import per language category; off by default", () => {
    expect(githubActionsSnippet(p)).not.toContain("warden\" import");
    const s = githubActionsSnippet({ ...p, imports: true });
    expect(s).toContain("github/codeql-action/analyze@");
    expect(s).toContain("output: codeql-results");
    expect(s).toContain('"$RUNNER_TEMP/warden" import --tool codeql');
    expect(s).toContain('--category "/language:${{ matrix.language }}/"');
    expect(s).toContain('"codeql-results/${{ matrix.language }}.sarif"');
    expect(s).toContain("--project proj-1");
    // The gate applies to an import as to a scan: both jobs fail on High; the file comes last.
    expect(s.match(/--fail-on high/g)).toHaveLength(2);
    expect(s).toMatch(/--fail-on high\n {10}"codeql-results\/\$\{\{ matrix\.language \}\}\.sarif"$/);
    // The import job reads the token from the CI secret, like the scan job.
    expect(s.match(/WARDEN_TOKEN: \$\{\{ secrets\.WARDEN_TOKEN \}\}/g)).toHaveLength(2);
    // With the nightly history job, the CodeQL job skips scheduled runs.
    expect(githubActionsSnippet({ ...p, imports: true, history: true })).toMatch(/ {2}codeql:\n {4}if: github\.event_name != 'schedule'/);
  });

  it("GitLab: the SAST template and warden import of its report", () => {
    expect(gitlabCiSnippet(p)).not.toContain("warden import");
    const s = gitlabCiSnippet({ ...p, imports: true });
    expect(s).toContain("template: Jobs/SAST.gitlab-ci.yml");
    expect(s).toContain("./warden import --tool gitlab-sast --format gitlab-sast --url https://warden.example --org org-1 --project proj-1 --fail-on high gl-sast-report.json");
    expect(s).toContain("needs: [semgrep-sast]");
  });

  it("no snippet ever carries a token", () => {
    for (const s of [githubActionsSnippet({ ...p, imports: true, history: true, comment: true }), gitlabCiSnippet({ ...p, imports: true, history: true, comment: true })]) {
      expect(s).not.toMatch(/wdn_[a-z2-7]{8}_/);
    }
  });
});
