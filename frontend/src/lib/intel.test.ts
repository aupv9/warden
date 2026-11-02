import { describe, expect, it } from "vitest";
import { formatEpss, isImageTarget, isLicenseIssue, isVulnIssue, licenseOf, nvdUrl, percentileText, splitImageRef } from "./intel";

describe("CVE links (the id goes into a URL path)", () => {
  it("links well-formed CVE ids to NVD", () => {
    expect(nvdUrl("CVE-2021-44228")).toBe("https://nvd.nist.gov/vuln/detail/CVE-2021-44228");
    expect(nvdUrl("CVE-2024-1234567")).toBe("https://nvd.nist.gov/vuln/detail/CVE-2024-1234567");
  });

  it("never links anything else from scanner output", () => {
    for (const bad of [
      "",
      "cve-2021-44228",
      "CVE-2021-123",
      "CVE-2021-12345678",
      "CVE-21-44228",
      "GHSA-jfh8-c2jp-5v3q",
      "CVE-2021-44228/../../evil",
      "CVE-2021-44228?x=1",
      "CVE-2021-44228#x",
      "CVE-2021-44228\n",
      " CVE-2021-44228",
      'CVE-2021-44228"><script>alert(1)</script>',
      "javascript:alert(1)",
      "https://evil.example/CVE-2021-44228",
    ]) {
      expect(nvdUrl(bad), bad).toBeNull();
    }
  });
});

describe("EPSS", () => {
  it("formats the score as a percentage", () => {
    expect(formatEpss(0.9447)).toBe("94%");
    expect(formatEpss(0.1)).toBe("10%");
    expect(formatEpss(0.0263)).toBe("2.6%");
    expect(formatEpss(0.0045)).toBe("0.5%");
    expect(formatEpss(0.0004)).toBe("<0.1%");
    expect(formatEpss(0)).toBe("0%");
    expect(formatEpss(1)).toBe("100%");
  });

  it("shows nothing for a missing or out-of-range score", () => {
    for (const bad of [null, undefined, NaN, -0.1, 1.5, Infinity]) expect(formatEpss(bad)).toBeNull();
  });

  it("words the percentile", () => {
    expect(percentileText(0.9999)).toBe("higher than 99.9% of scored CVEs");
    expect(percentileText(0.853)).toBe("higher than 85.3% of scored CVEs");
    expect(percentileText(0.5)).toBe("higher than 50% of scored CVEs");
    expect(percentileText(null)).toBeNull();
    expect(percentileText(2)).toBeNull();
  });
});

describe("license and vulnerability issues", () => {
  const lic = { tool: "trivy" as const, rule_id: "license:GPL-3.0-only", license_category: "restricted" as const };
  it("tells license issues from dependency vulnerabilities and malicious packages", () => {
    expect(isLicenseIssue(lic)).toBe(true);
    expect(isVulnIssue(lic)).toBe(false);
    expect(isVulnIssue({ tool: "trivy", rule_id: "CVE-2021-44228" })).toBe(true);
    expect(isLicenseIssue({ tool: "opengrep", rule_id: "license:x" })).toBe(false);
    expect(isVulnIssue({ tool: "gitleaks", rule_id: "aws-access-token" })).toBe(false);
    // v0.4: a malicious package is neither (no KEV/EPSS marks, no license line).
    expect(isVulnIssue({ tool: "trivy", rule_id: "malicious:MAL-2026-1873" })).toBe(false);
    expect(isLicenseIssue({ tool: "trivy", rule_id: "malicious:MAL-2026-1873" })).toBe(false);
  });

  it("reads the SPDX id from the rule and the category from license_category, never the title", () => {
    expect(licenseOf(lic)).toEqual({ spdx: "GPL-3.0-only", category: "restricted" });
    expect(licenseOf({ ...lic, license_category: null })).toEqual({ spdx: "GPL-3.0-only", category: null });
    // A title in the v0.3 shape no longer counts.
    const titled = { ...lic, license_category: null, title: "x uses GPL-3.0-only (restricted)" };
    expect(licenseOf(titled)).toEqual({ spdx: "GPL-3.0-only", category: null });
    // Only a known category counts, whatever the server sends.
    expect(licenseOf({ ...lic, license_category: "dangerous" as never })).toEqual({ spdx: "GPL-3.0-only", category: null });
    expect(licenseOf({ ...lic, rule_id: "license:" })).toBeNull();
    expect(licenseOf({ ...lic, rule_id: "CVE-2021-44228" })).toBeNull();
  });
});

describe("image repositories", () => {
  it("follows the contract's pattern", () => {
    for (const ok of ["ghcr.io/acme/api", "alpine", "localhost:5000/team/app", "registry.example.com/a_b/c__d/e-f", "a.b/c.d"]) {
      expect(isImageTarget(ok), ok).toBe(true);
    }
    for (const bad of ["", "GHCR.io/acme", "ghcr.io/acme/api:1.2", "ghcr.io/acme/api@sha256:00", "/abs", "a//b", "a/", "-a", "a b", "x".repeat(256)]) {
      expect(isImageTarget(bad), bad).toBe(false);
    }
  });

  it("splits a pasted reference into repository and reference", () => {
    expect(splitImageRef("ghcr.io/acme/api:1.4.2")).toEqual({ repository: "ghcr.io/acme/api", ref: "ghcr.io/acme/api:1.4.2" });
    expect(splitImageRef("localhost:5000/app")).toEqual({ repository: "localhost:5000/app", ref: null });
    expect(splitImageRef("localhost:5000/app:dev")).toEqual({ repository: "localhost:5000/app", ref: "localhost:5000/app:dev" });
    expect(splitImageRef("ghcr.io/acme/api@sha256:abc")).toEqual({ repository: "ghcr.io/acme/api", ref: "ghcr.io/acme/api@sha256:abc" });
    expect(splitImageRef("alpine:3.20@sha256:abc")).toEqual({ repository: "alpine", ref: "alpine:3.20@sha256:abc" });
    expect(splitImageRef("  ghcr.io/acme/api  ")).toEqual({ repository: "ghcr.io/acme/api", ref: null });
  });
});
