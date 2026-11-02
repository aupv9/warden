import { describe, expect, it } from "vitest";
import { ApiError } from "../api/client";
import { auditTargetSummary } from "./auditSummary";
import { badEntryHint, verificationSummary, verifyErrorText } from "./auditVerify";
import { formatDateTime } from "./format";

const AT = "2026-11-02T07:05:00Z";

describe("v0.5 wave 2: Verify chain", () => {
  it("an intact chain says how many entries were checked and when", () => {
    const s = verificationSummary({ ok: true, entries: 12_480, first_bad_id: null, verified_at: AT });
    expect(s).toEqual({
      ok: true,
      title: "Chain intact.",
      text: `12,480 entries checked ${formatDateTime(AT)}: every hash matches its entry and the one before it.`,
      badId: null,
    });
    expect(verificationSummary({ ok: true, entries: 1, first_bad_id: null, verified_at: AT }).text).toMatch(/^1 entry checked /);
  });

  it("a broken chain names the first entry that doesn't match", () => {
    const s = verificationSummary({ ok: false, entries: 12_480, first_bad_id: "4812", verified_at: AT });
    expect(s.ok).toBe(false);
    expect(s.title).toBe("Chain broken.");
    expect(s.text).toMatch(/^Entry 4812 is the first whose hash doesn't match: it, or an entry before it, was changed or removed after it was written\. 12,480 entries checked /);
    expect(s.text).toContain("warden-admin audit verify");
    expect(s.badId).toBe("4812");
    // Without an id (shouldn't happen, but the field is nullable).
    expect(verificationSummary({ ok: false, entries: 3, first_bad_id: null, verified_at: AT }).text).toMatch(/^An entry's hash doesn't match/);
  });

  it("links to the bad entry when it is loaded, otherwise says how to find it", () => {
    expect(badEntryHint("4812", ["4813", "4812"], false)).toBeNull();
    expect(badEntryHint("4700", ["4813", "4812"], false)).toBe("Entry 4700 isn't among the entries loaded yet. Load older entries to find it.");
    expect(badEntryHint("4700", ["4813"], true)).toBe("Entry 4700 isn't among the entries shown. Clear the filters or load older entries to find it.");
    expect(badEntryHint(null, [], false)).toBeNull();
  });

  it("429: the hourly limit and when to try again; other errors as usual", () => {
    const limited = (retry?: number) => new ApiError(429, { code: "RATE_LIMITED", message: "server words" }, "r1", retry);
    expect(verifyErrorText(limited(900))).toBe("The chain can be checked 10 times an hour in each organization. Try again in 15 minutes.");
    expect(verifyErrorText(limited())).toBe("The chain can be checked 10 times an hour in each organization. Try again later.");
    expect(verifyErrorText(new ApiError(403, { code: "FORBIDDEN", message: "server words" }))).toMatch(/^You don't have permission/);
    expect(verifyErrorText(new ApiError(500, { code: "INTERNAL", message: "server words" }))).toMatch(/^Warden didn't answer/);
  });

  it("the audit.verified entry reads as a sentence", () => {
    const e = { action: "audit.verified", target_type: "org", target_id: "o1" };
    expect(auditTargetSummary({ ...e, data: { ok: true, entries: 1204 } })).toBe("Chain intact · 1,204 entries");
    expect(auditTargetSummary({ ...e, data: { ok: false, entries: 1204, first_bad_id: "4812" } })).toBe("Chain broken at entry 4812 · 1,204 entries");
    expect(auditTargetSummary({ ...e, data: {} })).toBe("org o1");
  });
});
