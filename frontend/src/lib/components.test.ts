import { describe, expect, it } from "vitest";
import { buildQuery } from "../api/client";
import type { QueryParams } from "../api/client";
import {
  componentFiltersToApiQuery,
  componentFiltersToSearch,
  DEFAULT_COMPONENT_FILTERS,
  ecosystemLabel,
  ecosystemOptions,
  hasComponentFilters,
  licensesText,
  parseComponentFilters,
  parseProjectComponentFilters,
  projectComponentFiltersToApiQuery,
  projectComponentsHref,
  SOURCE_TARGET,
  splitSearch,
  targetLabel,
} from "./components";

const sp = (s: string) => new URLSearchParams(s);

describe("component search box", () => {
  it("splits a name prefix from an exact version", () => {
    expect(splitSearch("xz")).toEqual({ q: "xz", version: "" });
    expect(splitSearch("xz 5.6.0")).toEqual({ q: "xz", version: "5.6.0" });
    expect(splitSearch("  log4j-core   2.14.1 ")).toEqual({ q: "log4j-core", version: "2.14.1" });
    expect(splitSearch("log4j-core@2.14.1")).toEqual({ q: "log4j-core", version: "2.14.1" });
    // An npm scope is part of the name, not a version separator.
    expect(splitSearch("@acme/ui")).toEqual({ q: "@acme/ui", version: "" });
    expect(splitSearch("@acme/ui@1.2.0")).toEqual({ q: "@acme/ui", version: "1.2.0" });
    expect(splitSearch("name@")).toEqual({ q: "name@", version: "" });
    expect(splitSearch("")).toEqual({ q: "", version: "" });
  });

  it("keeps both parts within the contract's limits", () => {
    const { q, version } = splitSearch(`${"a".repeat(300)} ${"1".repeat(300)}`);
    expect(q).toHaveLength(128);
    expect(version).toHaveLength(128);
  });
});

describe("component filters in the URL (untrusted input)", () => {
  it("round-trips valid values and leaves defaults out", () => {
    const f = { search: "zod 3.25.76", ecosystem: "crates.io", project: "00000000-0000-4000-8000-00000000000a", malicious: true };
    expect(parseComponentFilters(componentFiltersToSearch(f))).toEqual(f);
    expect(componentFiltersToSearch(DEFAULT_COMPONENT_FILTERS).toString()).toBe("");
    expect(hasComponentFilters(DEFAULT_COMPONENT_FILTERS)).toBe(false);
  });

  it("drops values the contract wouldn't accept", () => {
    const f = parseComponentFilters(sp(`ecosystem=${encodeURIComponent("npm/../x")}&project=WEB&malicious=1&q=${"x".repeat(400)}`));
    expect(f.ecosystem).toBe("");
    expect(f.project).toBe("");
    expect(f.malicious).toBe(false);
    expect(f.search.length).toBeLessThanOrEqual(128 + 1 + 128);
    expect(parseComponentFilters(sp(`ecosystem=${"a".repeat(33)}`)).ecosystem).toBe("");
    expect(parseComponentFilters(sp("ecosystem=%3Cscript%3E")).ecosystem).toBe("");
  });

  it("maps to the list endpoint's parameters", () => {
    expect(componentFiltersToApiQuery({ ...DEFAULT_COMPONENT_FILTERS, search: "xz 5.6.0", malicious: true })).toEqual({
      q: "xz",
      version: "5.6.0",
      ecosystem: undefined,
      project_id: undefined,
      malicious: "true",
      limit: 50,
    });
    expect(componentFiltersToApiQuery(DEFAULT_COMPONENT_FILTERS)).toMatchObject({ q: undefined, version: undefined, malicious: undefined });
  });
});

describe("a project's Components tab", () => {
  it("accepts source code or a well-formed image repository as the target", () => {
    expect(parseProjectComponentFilters(sp(`target=${encodeURIComponent(SOURCE_TARGET)}`)).target).toBe(SOURCE_TARGET);
    expect(parseProjectComponentFilters(sp("target=ghcr.io%2Facme%2Fapi")).target).toBe("ghcr.io/acme/api");
    expect(parseProjectComponentFilters(sp("target=ghcr.io%2Facme%2Fapi%3A1.4")).target).toBe("");
    expect(parseProjectComponentFilters(sp("target=javascript%3Aalert(1)")).target).toBe("");
  });

  it("sends source code as an empty target (target=), which buildQuery would otherwise drop", () => {
    const q = projectComponentFiltersToApiQuery({ search: "", ecosystem: "", target: SOURCE_TARGET, malicious: false });
    expect(q.target).toEqual([""]);
    expect(buildQuery(q as unknown as QueryParams)).toBe("?target=&limit=50");
    const img = projectComponentFiltersToApiQuery({ search: "lib", ecosystem: "deb", target: "ghcr.io/acme/api", malicious: true });
    expect(buildQuery(img as unknown as QueryParams)).toBe("?q=lib&ecosystem=deb&target=ghcr.io%2Facme%2Fapi&malicious=true&limit=50");
    expect(buildQuery(projectComponentFiltersToApiQuery({ search: "", ecosystem: "", target: "", malicious: false }) as unknown as QueryParams)).toBe("?limit=50");
  });

  it("builds links whose component name only travels encoded, as search text", () => {
    const hostile = 'x&target=evil#"><img src=x onerror=alert(1)>';
    const href = projectComponentsHref("org-1", "proj/../2", { search: hostile, target: SOURCE_TARGET });
    expect(href.startsWith("/orgs/org-1/projects/proj%2F..%2F2/components?")).toBe(true);
    expect(href).not.toContain("<");
    expect(href).not.toContain('"');
    const back = parseProjectComponentFilters(new URLSearchParams(href.split("?")[1]));
    expect(back.search).toBe(hostile.slice(0, 128));
    expect(back.target).toBe(SOURCE_TARGET);
  });
});

describe("labels", () => {
  it("names ecosystems and keeps an unknown one from the URL", () => {
    expect(ecosystemLabel("deb")).toBe("Debian packages (deb)");
    expect(ecosystemLabel("npm")).toBe("npm");
    expect(ecosystemOptions("").map((o) => o.value)).toContain("PyPI");
    expect(ecosystemOptions("hex").at(-1)).toEqual({ value: "hex", label: "hex" });
    expect(ecosystemOptions("npm").filter((o) => o.value === "npm")).toHaveLength(1);
    expect(targetLabel("")).toBe("Source code");
    expect(targetLabel("ghcr.io/acme/api")).toBe("ghcr.io/acme/api");
    expect(licensesText([])).toBe("–");
    expect(licensesText(["MIT", "Apache-2.0"])).toBe("MIT, Apache-2.0");
  });
});
