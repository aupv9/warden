import { describe, expect, it } from "vitest";
import {
  DEFAULT_FILTERS,
  describeFilters,
  hasActiveFilters,
  issueFiltersToApiQuery,
  issueFiltersToSearch,
  parseIssueFilters,
  toggleSeverity,
} from "./issueFilters";
import type { IssueFilters } from "./issueFilters";
import { buildQuery } from "../api/client";

const P1 = "3f6c1a2b-0000-4000-8000-00000000a9d2";
const U1 = "11111111-2222-4333-8444-555555555555";

describe("issue filters ↔ URL", () => {
  it("an empty URL is the default view", () => {
    expect(parseIssueFilters(new URLSearchParams())).toEqual(DEFAULT_FILTERS);
    expect(issueFiltersToSearch(DEFAULT_FILTERS).toString()).toBe("");
  });

  it("round-trips every filter", () => {
    const f: IssueFilters = {
      q: "WEB-41",
      project: P1,
      status: "in_progress",
      severity: ["critical", "high"],
      assignee: U1,
      tool: "gitleaks",
      pastSla: true,
      sort: "-severity",
    };
    const sp = issueFiltersToSearch(f);
    expect(parseIssueFilters(new URLSearchParams(sp.toString()))).toEqual(f);
  });

  it("drops unknown or malformed values from the URL", () => {
    const f = parseIssueFilters(
      new URLSearchParams(
        "status=hacked&severity=critical&severity=bogus&severity=critical&tool=nmap&assignee=../../etc&project=1%20OR%201=1&sort=drop&past_sla=yes",
      ),
    );
    expect(f).toEqual({ ...DEFAULT_FILTERS, severity: ["critical"] });
  });

  it("keeps severities in canonical order without duplicates", () => {
    const f = parseIssueFilters(new URLSearchParams("severity=low&severity=critical&severity=low"));
    expect(f.severity).toEqual(["critical", "low"]);
  });

  it("accepts the me / none assignee shortcuts and trims and caps the search", () => {
    expect(parseIssueFilters(new URLSearchParams("assignee=me")).assignee).toBe("me");
    expect(parseIssueFilters(new URLSearchParams("assignee=none")).assignee).toBe("none");
    expect(parseIssueFilters(new URLSearchParams(`q=${"x".repeat(500)}`)).q).toHaveLength(200);
    expect(parseIssueFilters(new URLSearchParams("q=%20%20WEB-1%20")).q).toBe("WEB-1");
  });

  it("toggles severity chips", () => {
    const on = toggleSeverity(DEFAULT_FILTERS, "high");
    expect(on.severity).toEqual(["high"]);
    expect(toggleSeverity(toggleSeverity(on, "critical"), "high").severity).toEqual(["critical"]);
  });

  it("knows when filters are active", () => {
    expect(hasActiveFilters(DEFAULT_FILTERS)).toBe(false);
    expect(hasActiveFilters({ ...DEFAULT_FILTERS, sort: "-severity" })).toBe(false);
    expect(hasActiveFilters({ ...DEFAULT_FILTERS, pastSla: true })).toBe(true);
  });

  it("describes filters in words", () => {
    expect(describeFilters({ ...DEFAULT_FILTERS, severity: ["critical"], pastSla: true }, { project: "Web storefront" })).toEqual([
      "Active",
      "Critical",
      "Past SLA only",
      "Web storefront",
    ]);
  });
});

describe("issue filters → API query", () => {
  it("leaves defaults to the server", () => {
    expect(buildQuery(issueFiltersToApiQuery(DEFAULT_FILTERS))).toBe("?limit=50");
  });

  it("maps every filter to the contract's parameters", () => {
    const q = issueFiltersToApiQuery({
      q: "aws",
      project: P1,
      status: "fixed",
      severity: ["critical", "high"],
      assignee: "me",
      tool: "trivy",
      pastSla: true,
      sort: "-updated_at",
    });
    expect(buildQuery(q)).toBe(
      `?project_id=${P1}&status=fixed&severity=critical&severity=high&assignee=me&tool=trivy&past_sla=true&q=aws&sort=-updated_at&limit=50`,
    );
  });

  it("expands 'all' to every status and lets a route pin the project", () => {
    const q = issueFiltersToApiQuery({ ...DEFAULT_FILTERS, status: "all", project: P1 }, "fixed-project");
    expect(q.status).toHaveLength(8);
    expect(q.project_id).toBe("fixed-project");
  });
});
