import { afterEach, describe, expect, it, vi } from "vitest";
import { api } from "../api/client";
import { errorMessage, isForbidden, isMfaRequired, isToastedActionError } from "../api/errors";
import { ApiError } from "../api/client";
import { isMfaBlocked, mfaBlockedOrgs, reportMfaRequired, resetMfaBlocked } from "./mfa";
import { bucketNewFixed, formatHours, niceMax, percent, slaShare } from "./metrics";

const ORG = "00000000-0000-4000-8000-000000000003";
const deps = { getToken: async () => "jwt", refreshToken: async () => null };

describe("MFA_REQUIRED", () => {
  afterEach(() => {
    resetMfaBlocked();
    vi.unstubAllGlobals();
  });

  it("is known before any call from me.mfa_required_orgs", () => {
    expect(isMfaBlocked({ mfa_required_orgs: [ORG] }, ORG, new Set())).toBe(true);
    expect(isMfaBlocked({ mfa_required_orgs: [] }, ORG, new Set())).toBe(false);
  });

  it("is learned from an org request's error code", async () => {
    vi.stubGlobal(
      "fetch",
      vi.fn(
        async () =>
          new Response(JSON.stringify({ data: null, error: { code: "MFA_REQUIRED", message: "Your role requires two-factor sign-in." } }), {
            status: 403,
            headers: { "Content-Type": "application/json" },
          }),
      ),
    );
    const err = await api(`/orgs/${ORG}/summary`, {}, deps).catch((e: unknown) => e);
    expect(isMfaRequired(err)).toBe(true);
    expect(mfaBlockedOrgs().has(ORG)).toBe(true);
    expect(isMfaBlocked({ mfa_required_orgs: [] }, ORG)).toBe(true);
    expect(isMfaBlocked({ mfa_required_orgs: [] }, "another-org")).toBe(false);
  });

  it("ignores paths that aren't org-scoped", () => {
    reportMfaRequired("/me/notifications");
    expect(mfaBlockedOrgs().size).toBe(0);
    reportMfaRequired(`/orgs/${ORG}/issues?project_id=x`);
    expect([...mfaBlockedOrgs()]).toEqual([ORG]);
  });

  it("is neither a 403 page nor a toast", () => {
    const err = new ApiError(403, { code: "MFA_REQUIRED", message: "x" });
    expect(isForbidden(err)).toBe(false);
    expect(isToastedActionError(err)).toBe(false);
    expect(errorMessage(err)).toMatch(/two-factor/);
    expect(isForbidden(new ApiError(403, { code: "FORBIDDEN", message: "x" }))).toBe(true);
  });
});

describe("overview metrics helpers", () => {
  const days = (n: number, f: (i: number) => number) =>
    Array.from({ length: n }, (_, i) => ({ date: new Date(Date.UTC(2026, 9, 26 - (n - 1) + i)).toISOString().slice(0, 10), count: f(i) }));

  it("keeps days for 30 days and groups by week beyond", () => {
    const b30 = bucketNewFixed(days(30, () => 1), days(30, () => 2), 30);
    expect(b30).toHaveLength(30);
    expect(b30[29]).toMatchObject({ end: "2026-10-26", added: 1, fixed: 2 });
    const b90 = bucketNewFixed(days(90, () => 1), days(90, () => 1), 90);
    expect(b90).toHaveLength(13);
    expect(b90[12]).toMatchObject({ start: "2026-10-20", end: "2026-10-26", added: 7, fixed: 7 });
    expect(b90.reduce((n, b) => n + b.added, 0)).toBe(90);
  });

  it("computes SLA compliance over all outcomes", () => {
    const s = slaShare({ fixed_in_time: 80, fixed_late: 10, open_overdue: 10 });
    expect(s.compliance).toBeCloseTo(0.8);
    expect(percent(s.compliance)).toBe("80%");
    expect(slaShare({ fixed_in_time: 0, fixed_late: 0, open_overdue: 0 }).compliance).toBeNull();
    expect(percent(null)).toBe("–");
  });

  it("formats MTTR and axis maxima", () => {
    expect(formatHours(null)).toBe("No fixes");
    expect(formatHours(5)).toBe("5 hours");
    expect(formatHours(52)).toBe("2.2 days");
    expect(formatHours(1340)).toBe("56 days");
    expect(niceMax(7)).toBe(10);
    expect(niceMax(23)).toBe(25);
    expect(niceMax(0)).toBe(1);
  });
});
