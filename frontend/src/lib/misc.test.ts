import { describe, expect, it } from "vitest";
import type { ProjectMember } from "../api/types";
import { assignResultText, intersectMembers } from "../routes/AssignForm";
import { auditApiFilters, parseAuditParams } from "../routes/AuditLog";
import { parseTab } from "../routes/Exceptions";
import { auditDataText, auditTargetSummary } from "./auditSummary";
import { dueText, fromDateInput, isRejected, scanErrorMessages } from "./format";

const m = (id: string, role: ProjectMember["role"] = "developer"): ProjectMember => ({
  user: { id, email: `${id}@example.com`, display_name: id },
  role,
});

describe("assign helpers", () => {
  it("lists only people in every selected issue's project", () => {
    expect(intersectMembers([[m("a"), m("b"), m("c")], [m("b"), m("c", "owner")], [m("c"), m("b")]]).map((x) => x.user.id)).toEqual(["b", "c"]);
    expect(intersectMembers([])).toEqual([]);
  });
  it("reports skipped = selected − updated", () => {
    expect(assignResultText(1, 1, "Minh Pham", "WEB-41")).toBe("WEB-41 assigned to Minh Pham.");
    expect(assignResultText(2, 3, "Minh Pham")).toBe("2 of 3 issues assigned to Minh Pham. 1 was skipped because it is already fixed or closed.");
    expect(assignResultText(1, 3, "An")).toMatch(/2 were skipped because they are/);
  });
});

describe("scan display", () => {
  it("shows refused archives as Rejected and other failures as Failed", () => {
    expect(isRejected({ status: "failed", error_code: "ZIP_BOMB" })).toBe(true);
    expect(isRejected({ status: "failed", error_code: "CHECKSUM_MISMATCH" })).toBe(true);
    expect(isRejected({ status: "failed", error_code: "TIMEOUT" })).toBe(false);
    expect(isRejected({ status: "completed", error_code: "ZIP_BOMB" })).toBe(false);
  });
  it("uses the server limits in messages and falls back for unknown codes", () => {
    const limits = { upload_max_mb: 50, unzip_max_mb: 2048, unzip_max_files: 5000, scan_timeout_minutes: 45, scans_per_hour: 5 };
    expect(scanErrorMessages("ZIP_TOO_LARGE", limits).short).toBe("archive over 50 MB");
    expect(scanErrorMessages("ZIP_BOMB", limits).full).toMatch(/more than 2 GB/);
    expect(scanErrorMessages("TIMEOUT", limits).short).toBe("took over 45 min");
    expect(scanErrorMessages("WEIRD_THING")).toEqual({ short: "failed", full: expect.stringContaining("(WEIRD_THING)") });
  });
});

describe("dates", () => {
  const now = new Date(2026, 9, 26, 10, 0, 0);
  it("SLA wording", () => {
    expect(dueText(new Date(2026, 9, 24, 9).toISOString(), now)).toEqual({ text: "2 days overdue", overdue: true });
    expect(dueText(new Date(2026, 9, 26, 18).toISOString(), now).text).toBe("Due today");
    expect(dueText(new Date(2026, 9, 29, 9).toISOString(), now).text).toBe("Due in 3 days");
    expect(dueText(null, now).text).toBe("No due date");
  });
  it("date inputs become local midnight and reject junk", () => {
    expect(fromDateInput("2027-01-31")).toBe(new Date(2027, 0, 31).toISOString());
    expect(fromDateInput("31/01/2027")).toBeNull();
  });
});

describe("audit log", () => {
  it("summarises known actions from data", () => {
    expect(auditTargetSummary({ action: "issue.transitioned", target_type: "issue", target_id: "x", data: { issue_key: "WEB-41", from: "assigned", to: "in_progress" } })).toBe(
      "WEB-41 assigned → in progress",
    );
    expect(auditTargetSummary({ action: "scan.created", target_type: "scan", target_id: "x", data: { project_key: "WEB", file_name: "a.zip", file_size: 3 * 1024 * 1024 } })).toBe(
      "WEB a.zip · 3.0 MB",
    );
    expect(auditTargetSummary({ action: "issue.assigned", target_type: "issue", target_id: "x", data: { count: 3, assignee_name: "An Nguyen" } })).toBe("3 issues to An Nguyen");
    expect(auditTargetSummary({ action: "member.role_changed", target_type: "user", target_id: "x", data: { member_name: "Bao Le", from: "member", to: "security_lead" } })).toBe(
      "Bao Le member → security lead",
    );
  });
  it("falls back to target type and short id when data is missing or odd", () => {
    const id = "3f6c1a2b-0000-4000-8000-00000000a9d2";
    expect(auditTargetSummary({ action: "issue.transitioned", target_type: "issue", target_id: id, data: null })).toBe("issue 3f6c…a9d2");
    expect(auditTargetSummary({ action: "new.action", target_type: "thing", target_id: "t1", data: ["x"] })).toBe("thing t1");
  });
  it("prints data as JSON text (markup stays text)", () => {
    const text = auditDataText({ note: "<img src=x onerror=alert(1)>" });
    expect(text).toContain('"note": "<img src=x onerror=alert(1)>"');
  });
  it("validates URL filters and makes `to` inclusive", () => {
    const p = parseAuditParams(new URLSearchParams("action=member.added&actor=system&from=2026-10-19&to=2026-10-26"));
    expect(p).toEqual({ action: "member.added", actor: "system", from: "2026-10-19", to: "2026-10-26" });
    expect(parseAuditParams(new URLSearchParams("action=drop.table&actor=1;DROP&from=yesterday"))).toEqual({ action: "", actor: "", from: "", to: "" });
    const f = auditApiFilters(p);
    expect(f.from).toBe(new Date(2026, 9, 19).toISOString());
    expect(f.to).toBe(new Date(2026, 9, 27).toISOString());
  });
});

describe("exceptions tab", () => {
  it("only accepts known tabs", () => {
    expect(parseTab("expiring")).toBe("expiring");
    expect(parseTab("everything")).toBe("pending");
    expect(parseTab(null)).toBe("pending");
  });
});
