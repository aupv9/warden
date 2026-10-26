import { describe, expect, it } from "vitest";
import type { Issue } from "../api/types";
import { issueActions, workflowSteps } from "./issueActions";

type Payload = Parameters<typeof issueActions>[0];
const user = { id: "u1", email: "minh@example.com", display_name: "Minh Pham" };
const base: Payload = {
  status: "open",
  assignee: null,
  allowed_transitions: [],
  can_assign: false,
  can_request_exception: false,
  pending_exception_id: null,
};

const labels = (p: Partial<Payload>) =>
  issueActions({ ...base, ...p }).map((a) =>
    a.kind === "transition" ? `${a.label}${a.primary ? "*" : ""}` : a.kind === "assign" ? `${a.label}(${a.via})` : a.kind,
  );

describe("issue actions from the API payload", () => {
  it("shows nothing when the payload grants nothing (viewer)", () => {
    expect(labels({ status: "assigned", assignee: user })).toEqual([]);
  });

  it("assignee on an assigned issue: request exception, start progress as primary", () => {
    expect(labels({ status: "assigned", assignee: user, allowed_transitions: ["in_progress"], can_request_exception: true })).toEqual([
      "request_exception",
      "Start progress*",
    ]);
  });

  it("owner on an open issue: assign through the transition (with version)", () => {
    expect(labels({ allowed_transitions: ["assigned"], can_assign: true })).toEqual(["Assign(transition)"]);
  });

  it("lead on an assigned issue: reassign via bulk endpoint, unassign", () => {
    expect(labels({ status: "assigned", assignee: user, allowed_transitions: ["open"], can_assign: true })).toEqual([
      "Reassign(bulk)",
      "Unassign",
    ]);
  });

  it("in progress, assignee: mark fixed is primary", () => {
    expect(labels({ status: "in_progress", assignee: user, allowed_transitions: ["fixed"] })).toEqual(["Mark fixed*"]);
  });

  it("fixed, security lead: verify", () => {
    expect(labels({ status: "fixed", allowed_transitions: ["verified"] })).toEqual(["Verify fix*"]);
  });

  it("false positive, security lead: reopen needs a reason", () => {
    const a = issueActions({ ...base, status: "false_positive", allowed_transitions: ["open"] });
    expect(a).toEqual([{ kind: "transition", to: "open", label: "Reopen", primary: false, needsReason: true }]);
  });

  it("never offers exception or system-only statuses as buttons, even if sent", () => {
    expect(labels({ allowed_transitions: ["false_positive", "risk_accepted", "reopened", "in_progress"] })).toEqual(["Start progress*"]);
  });

  it("a pending exception replaces the request button", () => {
    const a = issueActions({ ...base, can_request_exception: true, pending_exception_id: "exc-1" });
    expect(a).toEqual([{ kind: "exception_pending", exceptionId: "exc-1" }]);
  });

  it("does not offer a reassign on a closed issue even with can_assign", () => {
    expect(labels({ status: "verified", can_assign: true })).toEqual([]);
  });

  it("de-duplicates transitions", () => {
    expect(labels({ allowed_transitions: ["in_progress", "in_progress"] as Issue["allowed_transitions"] })).toEqual(["Start progress*"]);
  });
});

describe("workflow steps", () => {
  it("marks done / current / todo", () => {
    expect(workflowSteps("in_progress").map((s) => s.state)).toEqual(["done", "done", "current", "todo", "todo"]);
  });
  it("reopened sits at the start", () => {
    const s = workflowSteps("reopened");
    expect(s[0]).toMatchObject({ label: "Reopened", state: "current" });
  });
  it("exception statuses are off the path", () => {
    expect(workflowSteps("risk_accepted").every((s) => s.state === "todo")).toBe(true);
  });
});
