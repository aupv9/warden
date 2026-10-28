import { describe, expect, it } from "vitest";
import { isMaliciousIssue, MAL_ID_RE, maliciousAdvisory, osvUrl } from "./malicious";

describe("malicious-package issues", () => {
  it("are Trivy issues with a malicious: rule id", () => {
    expect(isMaliciousIssue({ tool: "trivy", rule_id: "malicious:MAL-2026-1873" })).toBe(true);
    expect(isMaliciousIssue({ tool: "trivy", rule_id: "CVE-2021-44228" })).toBe(false);
    expect(isMaliciousIssue({ tool: "trivy", rule_id: "license:MIT" })).toBe(false);
    // Another scanner's rule that happens to start the same way is not one.
    expect(isMaliciousIssue({ tool: "opengrep", rule_id: "malicious:MAL-2026-1873" })).toBe(false);
    expect(maliciousAdvisory({ tool: "opengrep", rule_id: "malicious:MAL-2026-1873" })).toBeNull();
    expect(maliciousAdvisory({ tool: "trivy", rule_id: "malicious:" })).toBeNull();
  });

  it("link to OSV only for a well-formed MAL id", () => {
    expect(osvUrl("MAL-2026-1873")).toBe("https://osv.dev/vulnerability/MAL-2026-1873");
    expect(osvUrl("MAL-2024-1")).toBe("https://osv.dev/vulnerability/MAL-2024-1");
    expect(osvUrl("MAL-2024-12345678")).toBe("https://osv.dev/vulnerability/MAL-2024-12345678");
    expect(maliciousAdvisory({ tool: "trivy", rule_id: "malicious:MAL-2026-1873" })).toEqual({
      id: "MAL-2026-1873",
      url: "https://osv.dev/vulnerability/MAL-2026-1873",
    });
  });

  it("never builds a link from a hostile or malformed id (advisory data is hostile input)", () => {
    const hostile = [
      "MAL-2026-1873/../../evil",
      "MAL-2026-1873?redirect=https://evil.example",
      "MAL-2026-1873#x",
      "MAL-2026-1873\n",
      " MAL-2026-1873",
      "MAL-2026-1873 ",
      "MAL-2026-123456789", // more than 8 digits
      "MAL-26-1873",
      "mal-2026-1873",
      "GHSA-xxxx-yyyy-zzzz",
      "CVE-2021-44228",
      "MAL-２０２６-1873", // full-width digits
      "javascript:alert(1)",
      "//evil.example/MAL-2026-1",
      'MAL-2026-1"><img src=x onerror=alert(1)>',
      "",
    ];
    for (const id of hostile) {
      expect(MAL_ID_RE.test(id), JSON.stringify(id)).toBe(false);
      expect(osvUrl(id), JSON.stringify(id)).toBeNull();
      const a = maliciousAdvisory({ tool: "trivy", rule_id: `malicious:${id}` });
      if (a) {
        // The id is still shown, as text, without a link.
        expect(a).toEqual({ id, url: null });
      }
    }
  });
});
