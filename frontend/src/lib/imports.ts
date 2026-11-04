import { TOOLS } from "../api/types";
import type { ImportFormat, IssueSummary, Scan, ScanImport, ScannerTool, Tool } from "../api/types";
import { TOOL_LABELS } from "./format";

// v0.8: results imported from another tool. CI uploads a SARIF file (CodeQL, Semgrep, …) or a
// GitLab SAST report with `warden import`; the worker parses it as hostile input, screens every
// string it keeps with Gitleaks, and records the findings as issues with tool `external` and
// `external_tool` naming the tool. An import scan's target is `(import) <tool>[ <category>]`, so
// imports of one tool and category only ever fix their own issues, never a Warden scanner's.
//
// The web UI never starts an import (there is no button for it): the report comes from CI. Tool
// keys, categories and versions come from the uploader and the report, so they are text only.

/** The contract's ImportTool pattern (openapi.json; checked in imports.test.ts). */
export const IMPORT_TOOL_RE = /^(codeql|gitlab-sast|semgrep|snyk-code|sonarqube|external\.[a-z0-9-]{1,32})$/;

/** The tools the contract names; any other is `external.<key>`. */
export const NAMED_IMPORT_TOOLS = ["codeql", "gitlab-sast", "semgrep", "snyk-code", "sonarqube"] as const;

const NAMED_LABELS: Record<(typeof NAMED_IMPORT_TOOLS)[number], string> = {
  codeql: "CodeQL",
  "gitlab-sast": "GitLab SAST",
  semgrep: "Semgrep",
  "snyk-code": "Snyk Code",
  sonarqube: "SonarQube",
};

export const IMPORT_FORMAT_LABELS: Record<ImportFormat, string> = { sarif: "SARIF", "gitlab-sast": "GitLab SAST report" };

/** The start of every import scan's (and imported issue's) target. Parentheses can't occur in an
 *  image repository, so it never collides with an image target (like `(history)`). */
export const IMPORT_TARGET_PREFIX = "(import) ";

/** The Warden scanners in a list of tools, in the UI's order: what a scan may choose (the server
 *  answers 422 for `external`, which a project's defaults never hold anyway). */
export function onlyScanners(tools: readonly Tool[]): ScannerTool[] {
  return TOOLS.filter((t) => tools.includes(t));
}

export function isImportTool(v: string | null | undefined): v is string {
  return typeof v === "string" && IMPORT_TOOL_RE.test(v);
}

/** "CodeQL", "GitLab SAST"; `external.<key>` reads as its key. Anything that isn't a well-formed
 *  tool (an older or newer server) is shown as it is: React renders it as text either way. */
export function importToolLabel(tool: string): string {
  // Own keys only: `tool in …` would also match "__proto__" or "toString".
  if (Object.hasOwn(NAMED_LABELS, tool)) return NAMED_LABELS[tool as keyof typeof NAMED_LABELS];
  if (/^external\.[a-z0-9-]{1,32}$/.test(tool)) return tool.slice("external.".length);
  return tool;
}

/** `(import) codeql /language:python/` → { tool: "codeql", category: "/language:python/" }; null
 *  for any other target. Neither part can hold a space (the contract's patterns). */
export function parseImportTarget(target: string): { tool: string; category: string } | null {
  if (!target.startsWith(IMPORT_TARGET_PREFIX)) return null;
  const rest = target.slice(IMPORT_TARGET_PREFIX.length);
  const sp = rest.indexOf(" ");
  const tool = sp < 0 ? rest : rest.slice(0, sp);
  if (!isImportTool(tool)) return null;
  return { tool, category: sp < 0 ? "" : rest.slice(sp + 1) };
}

export function isImportIssue(i: Pick<IssueSummary, "tool">): boolean {
  return i.tool === "external";
}

export function isImportScan(s: Pick<Scan, "kind">): boolean {
  return s.kind === "import";
}

/** The tool an imported issue came from (`external_tool`, on list rows and the full issue); null
 *  for Warden's own issues. */
export function importToolOf(i: Pick<IssueSummary, "tool" | "external_tool">): string | null {
  return isImportIssue(i) ? i.external_tool || null : null;
}

/** Who found the issue: a Warden scanner's name, or the imported tool's ("CodeQL"). */
export function issueToolLabel(i: Pick<IssueSummary, "tool" | "external_tool">): string {
  const t = importToolOf(i);
  if (t) return importToolLabel(t);
  return TOOL_LABELS[i.tool] ?? i.tool;
}

/** A scanner row of a scan: the imported tool instead of "external". */
export function scanToolLabel(s: { import?: ScanImport | null }, tool: Tool): string {
  if (tool === "external" && s.import) return importToolLabel(s.import.tool);
  return TOOL_LABELS[tool] ?? tool;
}

/** "CodeQL · /language:python/" */
export function importSourceText(imp: Pick<ScanImport, "tool" | "category">): string {
  return [importToolLabel(imp.tool), imp.category].filter(Boolean).join(" · ");
}

const n = (v: number) => v.toLocaleString("en-US");

/** The processed counts in words, or null before the worker read the report. */
export function importCountsText(imp: ScanImport): { results: string; dropped: string; screened: string } | null {
  if (imp.results === null) return null;
  return {
    results: `${n(imp.results)} result${imp.results === 1 ? "" : "s"} read`,
    dropped: `${n(imp.dropped ?? 0)} dropped`,
    screened: `${n(imp.screened ?? 0)} screened by Gitleaks`,
  };
}

type TargetRow = { target: string; kind: string };

/** The "Imported from" filter's choices: the tools of the import targets in scope (a project's,
 *  or every visible project's), by label. A tool already in the URL stays listed. */
export function importToolChoices(rows: TargetRow[] | undefined, current: string): string[] {
  const tools = new Set<string>();
  for (const r of rows ?? []) {
    if (r.kind !== "import") continue;
    const t = parseImportTarget(r.target)?.tool;
    if (t) tools.add(t);
  }
  if (current && isImportTool(current)) tools.add(current);
  return [...tools].sort((a, b) => importToolLabel(a).localeCompare(importToolLabel(b)));
}
