import { describe, expect, it } from "vitest";
import type { LicensePolicyInput } from "../api/types";
import { auditTargetSummary } from "./auditSummary";
import {
  addIds,
  ALL_ALLOW,
  isPolicyOff,
  licensePolicySummary,
  MAX_LICENSE_IDS,
  RECOMMENDED,
  serverLicenseErrors,
  SPDX_ID_RE,
  splitIds,
  toInput,
  validateLicensePolicy,
} from "./licensePolicy";

const off: LicensePolicyInput = { categories: { ...ALL_ALLOW }, deny: [], allow: [] };

describe("license policy form", () => {
  it("is off when every category allows and Deny is empty (Allow alone doesn't turn it on)", () => {
    expect(isPolicyOff(off)).toBe(true);
    expect(isPolicyOff({ ...off, allow: ["MIT"] })).toBe(true);
    expect(isPolicyOff({ ...off, deny: ["SSPL-1.0"] })).toBe(false);
    expect(isPolicyOff({ ...off, categories: RECOMMENDED })).toBe(false);
  });

  it("the recommended preset blocks forbidden and reviews restricted, nothing else", () => {
    expect(RECOMMENDED).toEqual({ forbidden: "block", restricted: "review", reciprocal: "allow", notice: "allow", permissive: "allow", unencumbered: "allow", unknown: "allow" });
  });

  it("accepts SPDX ids and LicenseRef- ids only (the contract's pattern)", () => {
    for (const ok of ["MIT", "GPL-3.0-only", "GPL-2.0+", "LicenseRef-acme-internal", "Apache-2.0", "0BSD"]) expect(SPDX_ID_RE.test(ok), ok).toBe(true);
    for (const bad of ["", "-MIT", ".MIT", "MIT OR Apache-2.0", "GPL 3", "<script>", "MIT;", "MIT\n", `A${"a".repeat(64)}`, `LicenseRef-${"a".repeat(65)}`]) {
      expect(SPDX_ID_RE.test(bad), bad).toBe(false);
    }
  });

  it("adds pasted ids, skips duplicates whatever the case, and refuses bad ids and overlaps", () => {
    expect(splitIds(" GPL-3.0-only, AGPL-3.0-only;SSPL-1.0\nMIT ")).toEqual(["GPL-3.0-only", "AGPL-3.0-only", "SSPL-1.0", "MIT"]);
    const a = addIds(off, "deny", ["GPL-3.0-only", "gpl-3.0-only", "SSPL-1.0"]);
    expect(a.next?.deny).toEqual(["GPL-3.0-only", "SSPL-1.0"]);
    expect(addIds(a.next!, "deny", ["SSPL-1.0"]).error).toMatch(/already in the list/);
    expect(addIds(a.next!, "allow", ["sspl-1.0"]).error).toMatch(/already in Deny/);
    expect(addIds(off, "allow", ["MIT", "not an id!"]).error).toMatch(/isn't an SPDX license id/);
    // Nothing is added when one id is bad.
    expect(addIds(off, "allow", ["MIT", "<b>"]).next).toBeUndefined();
  });

  it("stops at 100 ids per list", () => {
    const full = { ...off, deny: Array.from({ length: MAX_LICENSE_IDS }, (_, i) => `LicenseRef-x${i}`) };
    expect(addIds(full, "deny", ["MIT"]).error).toMatch(/At most 100/);
    expect(validateLicensePolicy({ ...full, deny: [...full.deny, "MIT"] })).toMatchObject({ valid: false, deny: expect.stringMatching(/At most 100/) });
  });

  it("checks a whole draft before saving", () => {
    expect(validateLicensePolicy({ ...off, deny: ["SSPL-1.0"], allow: ["MIT"] })).toEqual({ valid: true });
    expect(validateLicensePolicy({ ...off, deny: ["MIT"], allow: ["mit"] })).toMatchObject({ valid: false, allow: expect.stringMatching(/also in Deny/) });
    expect(validateLicensePolicy({ ...off, deny: ["MIT", "MIT"] })).toMatchObject({ valid: false, deny: "A license is listed twice." });
    expect(validateLicensePolicy({ ...off, allow: ["bad id"] })).toMatchObject({ valid: false, allow: expect.stringMatching(/isn't an SPDX/) });
  });

  it("sends exactly the contract's fields, categories in a fixed order", () => {
    const withExtra = { ...off, enabled: true, categories: { ...RECOMMENDED, extra: "block" } } as unknown as LicensePolicyInput;
    expect(Object.keys(toInput(withExtra))).toEqual(["categories", "deny", "allow"]);
    expect(Object.keys(toInput(withExtra).categories)).toEqual(["forbidden", "restricted", "reciprocal", "notice", "permissive", "unencumbered", "unknown"]);
  });

  it("maps server field errors to the form, the rest to a banner", () => {
    const draft = { ...off, deny: ["SSPL-1.0", "Bad"], allow: ["MIT"] };
    expect(
      serverLicenseErrors({ "categories.unknown": "must be allow, review or block", "deny[1]": "must be an SPDX license id", allow: "at most 100", "x": "unknown field" }, draft),
    ).toEqual({
      categories: { unknown: "must be allow, review or block" },
      lists: { deny: "Bad: must be an SPDX license id", allow: "at most 100" },
      other: ["x: unknown field"],
    });
  });
});

describe("audit log summary of org.license_policy_changed", () => {
  const entry = (data: unknown) => ({ action: "org.license_policy_changed", target_type: "org", target_id: "o1", data });
  it("says what the policy became", () => {
    expect(auditTargetSummary(entry({ to: { categories: RECOMMENDED, deny: ["SSPL-1.0"], allow: ["MIT"] } }))).toBe(
      "License policy: Block forbidden; review restricted; deny 1; allow 1",
    );
    expect(auditTargetSummary(entry({ to: { categories: ALL_ALLOW, deny: [], allow: [] } }))).toBe("License policy: Off");
    expect(licensePolicySummary(null)).toBeNull();
  });
  it("falls back for data it can't read", () => {
    for (const data of [null, "x", { to: "x" }, { to: { categories: null } }]) {
      expect(auditTargetSummary(entry(data))).not.toContain("License policy");
    }
  });
});
