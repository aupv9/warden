import { describe, expect, it } from "vitest";
import type { OrgMember, OrgRole, SignInSettings } from "../api/types";
import { auditTargetSummary } from "./auditSummary";
import {
  canEditSignInPolicy,
  canViewSignIn,
  domainProblem,
  effectiveRoles,
  keyStatusText,
  MAX_DOMAINS,
  mfaGap,
  namesText,
  rolesText,
  safeExternalUrl,
  sameRoles,
  serverPolicyErrors,
  validateDomains,
} from "./signIn";

describe("allowed email domains", () => {
  it("accepts DNS names with at least one dot", () => {
    for (const d of ["example.com", "corp.example.com", "a-b.example.co.uk", "xn--bcher-kva.example", "1password.com"]) {
      expect(domainProblem(d), d).toBeUndefined();
    }
  });

  it("rejects wildcards, addresses, missing dots and bad labels", () => {
    expect(domainProblem("")).toMatch(/Enter a domain/);
    expect(domainProblem("*.example.com")).toMatch(/Wildcards/);
    expect(domainProblem("example.*")).toMatch(/Wildcards/);
    expect(domainProblem("linh@example.com")).toMatch(/part after the @/);
    expect(domainProblem("@example.com")).toMatch(/part after the @/);
    expect(domainProblem("localhost")).toMatch(/with a dot/);
    expect(domainProblem(".example.com")).toMatch(/start or end with a dot/);
    expect(domainProblem("example.com.")).toMatch(/start or end with a dot/);
    expect(domainProblem("example..com")).toMatch(/two dots/);
    expect(domainProblem("-corp.example.com")).toMatch(/hyphen/);
    expect(domainProblem("corp-.example.com")).toMatch(/hyphen/);
    expect(domainProblem("exa mple.com")).toMatch(/spaces/);
    expect(domainProblem("exa_mple.com")).toMatch(/letters a–z/);
    expect(domainProblem("bücher.example")).toMatch(/xn--/);
    expect(domainProblem("https://example.com")).toMatch(/letters a–z/);
    expect(domainProblem(`${"a".repeat(64)}.com`)).toMatch(/at most 63/);
    expect(domainProblem(`${"a.".repeat(127)}com`)).toMatch(/at most 253/);
  });

  it("normalises case and spaces, and flags duplicates after normalising", () => {
    const v = validateDomains([" Example.COM ", "corp.example.com", "example.com"]);
    expect(v.domains).toEqual(["example.com", "corp.example.com", "example.com"]);
    expect(v.rows[0]).toBeUndefined();
    expect(v.rows[1]).toBeUndefined();
    expect(v.rows[2]).toBe("example.com is already in the list.");
    expect(v.valid).toBe(false);
  });

  it("allows an empty list (any domain) and at most 20 domains", () => {
    expect(validateDomains([]).valid).toBe(true);
    const ok = Array.from({ length: MAX_DOMAINS }, (_, i) => `d${i}.example.com`);
    expect(validateDomains(ok).valid).toBe(true);
    const tooMany = validateDomains([...ok, "one-more.example.com"]);
    expect(tooMany.valid).toBe(false);
    expect(tooMany.list).toBe("At most 20 domains. Remove 1.");
  });

  it("maps server field errors to rows, the list and the role group", () => {
    const e = serverPolicyErrors(
      {
        "allowed_email_domains[1]": "duplicate domain",
        "allowed_email_domains[9]": "out of range",
        allowed_email_domains: "at most 20 domains",
        mfa_roles: "unknown role",
        other: "nope",
      },
      2,
    );
    expect(e.rows).toEqual([undefined, "duplicate domain"]);
    expect(e.list).toBe("at most 20 domains");
    expect(e.roles).toBe("unknown role");
    expect(e.other).toEqual(["allowed_email_domains[9]: out of range", "other: nope"]);
  });
});

const member = (name: string, role: OrgRole, mfa: boolean | null, is_active = true): OrgMember => ({
  user: { id: name, email: `${name.toLowerCase().replace(/ /g, ".")}@acme.example`, display_name: name, is_active },
  role,
  mfa,
  projects: [],
});

describe("two-factor overview", () => {
  const members = [
    member("Linh Tran", "security_lead", true),
    member("Huy Do", "org_admin", false),
    member("An Nguyen", "member", false),
    member("Bao Le", "member", null, false),
    member("Quynh Vo", "member", null),
    member("Minh Pham", "security_lead", null),
  ];

  it("lists active members in the required roles without a second factor, by role then name", () => {
    const gap = mfaGap(members, ["org_admin", "security_lead"]);
    expect(gap.members.map((m) => m.user.display_name)).toEqual(["Huy Do", "Minh Pham"]);
    expect(gap.more).toBe(0);
    const all = mfaGap(members, ["org_admin", "security_lead", "member"]);
    // Bao Le is deactivated; Quynh Vo has no recorded second factor (null) and counts.
    expect(all.members.map((m) => m.user.display_name)).toEqual(["Huy Do", "Minh Pham", "An Nguyen", "Quynh Vo"]);
    expect(mfaGap(members, []).members).toEqual([]);
  });

  it("shows the first names and how many more", () => {
    const many = Array.from({ length: 8 }, (_, i) => member(`Person ${i + 1}`, "member", false));
    const gap = mfaGap(many, ["member"]);
    expect(gap.shown).toHaveLength(5);
    expect(gap.more).toBe(3);
    expect(namesText(gap.shown, gap.more)).toBe("Person 1, Person 2, Person 3, Person 4, Person 5 and 3 more");
    expect(namesText(["Huy Do"], 0)).toBe("Huy Do");
    expect(namesText(["Huy Do", "An Nguyen"], 0)).toBe("Huy Do and An Nguyen");
    expect(namesText(["A", "B", "C"], 0)).toBe("A, B and C");
  });

  it("computes effective roles in the server's order", () => {
    expect(effectiveRoles(["security_lead", "org_admin"], ["member", "org_admin"])).toEqual(["org_admin", "security_lead", "member"]);
    expect(effectiveRoles([], [])).toEqual([]);
    expect(sameRoles(["member", "org_admin"], ["org_admin", "member"])).toBe(true);
    expect(sameRoles(["member"], [])).toBe(false);
    expect(rolesText(["org_admin", "security_lead"])).toBe("Org admins and security leads");
    expect(rolesText(["member"])).toBe("Members");
  });
});

describe("audit summary", () => {
  it("summarises org.sign_in_policy_changed defensively", () => {
    const e = (data: unknown) => ({ action: "org.sign_in_policy_changed", target_type: "org", target_id: "o1", data });
    expect(auditTargetSummary(e({ from: {}, to: { mfa_roles: ["member"], allowed_email_domains: ["a.com", "b.com"] } }))).toBe(
      "Two-factor for member; domains a.com, b.com",
    );
    expect(auditTargetSummary(e({ to: { mfa_roles: [], allowed_email_domains: [] } }))).toBe("Two-factor for no extra roles; domains any");
    expect(auditTargetSummary(e({ to: { mfa_roles: "member" } }))).toBe("org o1");
    expect(auditTargetSummary(e(null))).toBe("org o1");
  });

  it("summarises relink events", () => {
    const e = (action: string, data: unknown) => ({ action, target_type: "user", target_id: "u1", data });
    expect(auditTargetSummary(e("user.relinked", { mode: "next_sign_in", via: "sign-in" }))).toBe("user u1 moved to a new sign-in identity at sign-in");
    expect(auditTargetSummary(e("user.relinked", { mode: "subject", via: "warden-admin" }))).toBe("user u1 moved to a new sign-in identity by the operator");
    expect(auditTargetSummary(e("user.relink_allowed", { until: "2026-10-28T08:00:00Z" }))).toBe(
      "user u1 may move to a new sign-in identity until 2026-10-28T08:00:00Z",
    );
    expect(auditTargetSummary(e("user.relink_allowed", { until: { at: 1 } }))).toBe("user u1");
  });
});

describe("who sees and edits the sign-in settings", () => {
  it("org admins edit, security leads read, members don't see it", () => {
    expect([canViewSignIn("org_admin"), canEditSignInPolicy("org_admin")]).toEqual([true, true]);
    expect([canViewSignIn("security_lead"), canEditSignInPolicy("security_lead")]).toEqual([true, false]);
    expect([canViewSignIn("member"), canEditSignInPolicy("member")]).toEqual([false, false]);
    expect(canViewSignIn(undefined)).toBe(false);
  });
});

describe("identity provider", () => {
  it("links the console only for absolute http(s) URLs", () => {
    expect(safeExternalUrl("https://id.example.com/admin/")).toBe("https://id.example.com/admin/");
    expect(safeExternalUrl("http://localhost:8180/admin/master/console/")).toBe("http://localhost:8180/admin/master/console/");
    expect(safeExternalUrl("javascript:alert(1)")).toBeNull();
    expect(safeExternalUrl("JaVaScRiPt:alert(1)")).toBeNull();
    expect(safeExternalUrl("data:text/html,<script>alert(1)</script>")).toBeNull();
    expect(safeExternalUrl("//evil.example/x")).toBeNull();
    expect(safeExternalUrl("/admin")).toBeNull();
    expect(safeExternalUrl("ftp://id.example.com")).toBeNull();
    expect(safeExternalUrl("not a url")).toBeNull();
    expect(safeExternalUrl("")).toBeNull();
    expect(safeExternalUrl(null)).toBeNull();
  });

  const keys = (k: Partial<SignInSettings["keys"]>): SignInSettings["keys"] => ({ status: "ok", count: 2, fetched_at: null, error: null, ...k });

  it("words each key status", () => {
    expect(keyStatusText(keys({}), ["RS256"], "5 min ago")).toEqual({
      tone: "success",
      label: "OK",
      detail: "2 signing keys loaded, last refreshed 5 min ago.",
    });
    expect(keyStatusText(keys({ count: 1 }), ["RS256"], null).detail).toBe("1 signing key loaded.");
    const unreachable = keyStatusText(keys({ status: "error", error: "unreachable", count: 0 }), ["RS256"], null);
    expect(unreachable.tone).toBe("danger");
    expect(unreachable.detail).toBe("Warden couldn't reach the identity provider to fetch its signing keys. Until this is fixed, nobody can sign in. Tell your operator.");
    const stale = keyStatusText(keys({ status: "error", error: "http_status", count: 2 }), ["RS256"], "3 h ago");
    expect(stale.detail).toMatch(/answered .* with an error\. Warden keeps using the 2 signing keys it already has \(last refreshed 3 h ago\)\.$/);
    expect(keyStatusText(keys({ status: "error", error: "no_usable_keys", count: 0 }), ["RS256", "ES256"], null).detail).toMatch(
      /no signing key Warden can use \(RS256 or ES256\)\./,
    );
    expect(keyStatusText(keys({ status: "error", error: "issuer_mismatch", count: 0 }), [], null).detail).toMatch(/different issuer/);
    expect(keyStatusText(keys({ status: "error", error: "invalid_document", count: 0 }), [], null).detail).toMatch(/couldn't be read/);
    // Unknown categories (and prototype keys) fall back to a generic sentence.
    expect(keyStatusText(keys({ status: "error", error: "toString", count: 0 }), [], null).detail).toMatch(/^Warden couldn't load/);
    expect(keyStatusText(keys({ status: "not_loaded", count: 0 }), [], null)).toMatchObject({ tone: "neutral", label: "Not loaded yet" });
  });
});
