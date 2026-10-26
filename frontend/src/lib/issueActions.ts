import type { Issue, IssueStatus } from "../api/types";

// Which actions the issue detail page offers. The API computes what this caller may do
// (`allowed_transitions`, `can_assign`, `can_request_exception`, from issuestate + rbac); the UI
// only maps that to buttons and never adds an action the payload doesn't grant. The API checks
// again on every request.

export type IssueAction =
  | { kind: "transition"; to: IssueStatus; label: string; primary: boolean; needsReason: boolean }
  | { kind: "assign"; label: "Assign" | "Reassign"; via: "transition" | "bulk" }
  | { kind: "request_exception" }
  | { kind: "exception_pending"; exceptionId: string };

// Never offered as a button: `assigned` is the Assign action; `reopened` is system-only;
// false_positive / risk_accepted only happen through an approved exception.
const NOT_BUTTONS: IssueStatus[] = ["assigned", "reopened", "false_positive", "risk_accepted"];
const PRIMARY_ORDER: IssueStatus[] = ["in_progress", "fixed", "verified"];

function transitionLabel(from: IssueStatus, to: IssueStatus): string {
  switch (to) {
    case "in_progress":
      return "Start progress";
    case "fixed":
      return "Mark fixed";
    case "verified":
      return "Verify fix";
    case "open":
      return from === "false_positive" ? "Reopen" : "Unassign";
    default:
      return to;
  }
}

export function issueActions(
  issue: Pick<
    Issue,
    "status" | "assignee" | "allowed_transitions" | "can_assign" | "can_request_exception" | "pending_exception_id"
  >,
): IssueAction[] {
  const actions: IssueAction[] = [];
  const allowed = new Set(issue.allowed_transitions);

  if (issue.pending_exception_id) {
    actions.push({ kind: "exception_pending", exceptionId: issue.pending_exception_id });
  } else if (issue.can_request_exception) {
    actions.push({ kind: "request_exception" });
  }

  const label = issue.assignee ? "Reassign" : "Assign";
  if (allowed.has("assigned")) {
    actions.push({ kind: "assign", label, via: "transition" });
  } else if (issue.can_assign && (issue.status === "assigned" || issue.status === "in_progress")) {
    // Changing the assignee without a status change goes through POST /issues/assign.
    actions.push({ kind: "assign", label, via: "bulk" });
  }

  const primary = PRIMARY_ORDER.find((s) => allowed.has(s));
  const transitions = issue.allowed_transitions.filter((s, i, a) => !NOT_BUTTONS.includes(s) && a.indexOf(s) === i);
  // Secondary transitions first, the primary one last (rightmost, as in the wireframe).
  for (const to of transitions) {
    if (to === primary) continue;
    actions.push(transitionAction(issue.status, to, false));
  }
  if (primary) actions.push(transitionAction(issue.status, primary, true));
  return actions;
}

function transitionAction(from: IssueStatus, to: IssueStatus, primary: boolean): IssueAction {
  return {
    kind: "transition",
    to,
    label: transitionLabel(from, to),
    primary,
    // issuestate: false_positive → open RequiresReason.
    needsReason: from === "false_positive" && to === "open",
  };
}

export interface WorkflowStep {
  status: IssueStatus;
  label: string;
  hint?: string;
  state: "done" | "current" | "todo";
}

const MAIN_PATH: { status: IssueStatus; label: string; hint?: string }[] = [
  { status: "open", label: "Open" },
  { status: "assigned", label: "Assigned" },
  { status: "in_progress", label: "In progress", hint: "assignee" },
  { status: "fixed", label: "Fixed", hint: "set by the next scan" },
  { status: "verified", label: "Verified", hint: "security lead or scan" },
];

/** The main path of the workflow, with the issue's place on it. Reopened sits at "Open";
 *  false positive / risk accepted are off the path and shown separately. */
export function workflowSteps(status: IssueStatus): WorkflowStep[] {
  const pos = status === "reopened" ? 0 : MAIN_PATH.findIndex((s) => s.status === status);
  return MAIN_PATH.map((s, i) => ({
    ...s,
    label: i === 0 && status === "reopened" ? "Reopened" : s.label,
    state: pos < 0 ? "todo" : i < pos ? "done" : i === pos ? "current" : "todo",
  }));
}
