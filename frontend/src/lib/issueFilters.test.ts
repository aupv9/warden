import { describe, expect, it } from "vitest";
import {
  applyView,
  currentView,
  DEFAULT_FILTERS,
  issueHref,
  issueListHref,
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
      kind: "vulnerability",
      kev: true,
      epssMin: 0.1,
      source: "image",
      target: "ghcr.io/acme/api",
    };
    const sp = issueFiltersToSearch(f);
    expect(parseIssueFilters(new URLSearchParams(sp.toString()))).toEqual(f);
  });

  it("round-trips the v0.3 filters and the EPSS sort on their own", () => {
    for (const patch of [
      { kev: true },
      { kind: "license" as const },
      { epssMin: 0.01 },
      { epssMin: 0.5 },
      { source: "code" as const },
      { target: "localhost:5000/team/app" },
      { sort: "-epss" as const },
    ]) {
      const f = { ...DEFAULT_FILTERS, ...patch };
      expect(parseIssueFilters(new URLSearchParams(issueFiltersToSearch(f).toString()))).toEqual(f);
    }
    expect(issueFiltersToSearch({ ...DEFAULT_FILTERS, kev: true, epssMin: 0.1 }).toString()).toBe("kev=true&epss_min=0.1");
  });

  it("drops malformed v0.3 values (the URL is untrusted)", () => {
    const f = parseIssueFilters(
      new URLSearchParams(
        "kind=secret&kev=1&epss_min=1e-3&source=registry&target=GHCR.IO/Acme&sort=epss",
      ),
    );
    expect(f).toEqual(DEFAULT_FILTERS);
    for (const bad of ["-0.1", "2", "NaN", "0x1", " 0.1", "0.1abc", "Infinity", "0", ""]) {
      expect(parseIssueFilters(new URLSearchParams({ epss_min: bad })).epssMin).toBeNull();
    }
    for (const bad of ["ghcr.io/acme/api:1.2", "ghcr.io/acme/api@sha256:00", "../etc", "a//b", "x".repeat(256), "ghcr.io/acme/api/"]) {
      expect(parseIssueFilters(new URLSearchParams({ target: bad })).target).toBe("");
    }
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
    expect(describeFilters({ ...DEFAULT_FILTERS, kev: true, epssMin: 0.1, kind: "vulnerability", source: "image", target: "ghcr.io/acme/api" })).toEqual([
      "Active",
      "Known exploited",
      "EPSS ≥ 10%",
      "Vulnerabilities",
      "Container images",
      "Image ghcr.io/acme/api",
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
      kind: "license",
      kev: true,
      epssMin: 0.5,
      source: "image",
      target: "ghcr.io/acme/api",
    });
    expect(buildQuery(q)).toBe(
      `?project_id=${P1}&status=fixed&severity=critical&severity=high&assignee=me&tool=trivy&past_sla=true&kind=license&kev=true&epss_min=0.5&source=image&target=ghcr.io%2Facme%2Fapi&q=aws&sort=-updated_at&limit=50`,
    );
  });

  it("sends the EPSS sort and leaves the URL and API in step", () => {
    const f = parseIssueFilters(new URLSearchParams("kev=true&sort=-epss&epss_min=0.1"));
    expect(buildQuery(issueFiltersToApiQuery(f))).toBe("?kev=true&epss_min=0.1&sort=-epss&limit=50");
  });

  it("expands 'all' to every status and lets a route pin the project", () => {
    const q = issueFiltersToApiQuery({ ...DEFAULT_FILTERS, status: "all", project: P1 }, "fixed-project");
    expect(q.status).toHaveLength(8);
    expect(q.project_id).toBe("fixed-project");
  });
});

describe("saved views", () => {
  it("are presets of the URL filters that keep search, sort and project", () => {
    const base = { ...DEFAULT_FILTERS, q: "aws", sort: "-severity" as const, project: P1, severity: ["low" as const] };
    expect(applyView(base, "mine")).toEqual({ ...DEFAULT_FILTERS, q: "aws", sort: "-severity", project: P1, assignee: "me" });
    expect(issueFiltersToSearch(applyView(DEFAULT_FILTERS, "secrets")).toString()).toBe("tool=gitleaks");
    expect(issueFiltersToSearch(applyView(DEFAULT_FILTERS, "past_sla")).toString()).toBe("past_sla=true");
    expect(issueFiltersToSearch(applyView(DEFAULT_FILTERS, "active")).toString()).toBe("");
    expect(issueFiltersToSearch(applyView(DEFAULT_FILTERS, "kev")).toString()).toBe("kev=true");
    expect(issueFiltersToSearch(applyView(DEFAULT_FILTERS, "licenses")).toString()).toBe("kind=license");
    // Switching view drops the other view's filters.
    expect(applyView({ ...DEFAULT_FILTERS, kev: true, epssMin: 0.1, target: "ghcr.io/acme/api" }, "licenses")).toEqual({ ...DEFAULT_FILTERS, kind: "license" });
  });

  it("know which view the filters are, or none", () => {
    expect(currentView(DEFAULT_FILTERS)).toBe("active");
    expect(currentView({ ...DEFAULT_FILTERS, assignee: "me", q: "x" })).toBe("mine");
    expect(currentView({ ...DEFAULT_FILTERS, tool: "gitleaks" })).toBe("secrets");
    expect(currentView({ ...DEFAULT_FILTERS, tool: "gitleaks", pastSla: true })).toBeNull();
    expect(currentView({ ...DEFAULT_FILTERS, kev: true, sort: "-epss" })).toBe("kev");
    expect(currentView({ ...DEFAULT_FILTERS, kind: "license" })).toBe("licenses");
    expect(currentView({ ...DEFAULT_FILTERS, kind: "vulnerability" })).toBeNull();
  });

  it("v0.4: a Malicious view for malicious-package issues (kind=malicious)", () => {
    expect(issueFiltersToSearch(applyView(DEFAULT_FILTERS, "malicious")).toString()).toBe("kind=malicious");
    expect(currentView({ ...DEFAULT_FILTERS, kind: "malicious" })).toBe("malicious");
    expect(parseIssueFilters(new URLSearchParams("kind=malicious")).kind).toBe("malicious");
    expect(parseIssueFilters(new URLSearchParams("kind=MALICIOUS")).kind).toBe("");
    expect(issueFiltersToApiQuery(parseIssueFilters(new URLSearchParams("kind=malicious")))).toMatchObject({ kind: "malicious" });
    expect(describeFilters({ ...DEFAULT_FILTERS, kind: "malicious" })).toContain("Malicious packages");
  });
});

describe("split view links", () => {
  it("carry the list's filters to the issue and back", () => {
    const f = { ...DEFAULT_FILTERS, severity: ["critical" as const], pastSla: true };
    expect(issueHref("o1", "i1", f)).toBe("/orgs/o1/issues/i1?severity=critical&past_sla=true");
    expect(issueListHref("o1", f)).toBe("/orgs/o1/issues?severity=critical&past_sla=true");
    expect(issueHref("o1", "i1", DEFAULT_FILTERS)).toBe("/orgs/o1/issues/i1");
    expect(issueListHref("o1", DEFAULT_FILTERS)).toBe("/orgs/o1/issues");
  });

  it("only carry validated filters (the URL is untrusted)", () => {
    const f = parseIssueFilters(new URLSearchParams("severity=critical&next=//evil.example&status=<x>"));
    expect(issueListHref("o1", f)).toBe("/orgs/o1/issues?severity=critical");
    expect(issueHref("o1", "a/b", DEFAULT_FILTERS)).toBe("/orgs/o1/issues/a%2Fb");
  });
});
