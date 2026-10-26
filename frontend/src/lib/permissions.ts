import type { OrgRole, ProjectRole } from "../api/types";

// A copy of backend/internal/domain/rbac.Matrix, used to hide actions the user can't take and
// to draw the read-only permission matrix. The API enforces the real one; permissions.test.ts
// fails if this copy drifts from the Go source.

export type Role = OrgRole | ProjectRole;

export type Perm =
  | "manage_users"
  | "create_archive_project"
  | "manage_project_members"
  | "run_scan"
  | "view_results"
  | "assign_issue"
  | "update_issue"
  | "propose_exception"
  | "decide_exception"
  | "configure_policy"
  | "view_dashboard"
  | "view_audit_log";

export const MATRIX: Record<Perm, Role[]> = {
  manage_users: ["org_admin"],
  create_archive_project: ["org_admin", "security_lead"],
  manage_project_members: ["org_admin", "security_lead", "owner"],
  run_scan: ["security_lead", "owner", "developer"],
  view_results: ["org_admin", "security_lead", "owner", "developer", "viewer"],
  assign_issue: ["security_lead", "owner"],
  update_issue: ["security_lead", "owner", "developer"],
  propose_exception: ["security_lead", "owner", "developer"],
  decide_exception: ["security_lead"],
  configure_policy: ["security_lead"],
  view_dashboard: ["org_admin", "security_lead", "owner", "developer", "viewer"],
  view_audit_log: ["org_admin", "security_lead"],
};

/** rbac: developers may update only issues assigned to them. */
export const OWN_ISSUE_ONLY_FOR_DEVELOPER: Perm[] = ["update_issue"];

export const PERM_LABELS: Record<Perm, string> = {
  manage_users: "Manage org members",
  create_archive_project: "Create projects",
  manage_project_members: "Manage project members",
  run_scan: "Run scans",
  view_results: "View results",
  assign_issue: "Assign issues",
  update_issue: "Update issues",
  propose_exception: "Request exceptions",
  decide_exception: "Decide exceptions",
  configure_policy: "Configure policy",
  view_dashboard: "View dashboard",
  view_audit_log: "View audit log",
};

export const MATRIX_ROLES: Role[] = ["org_admin", "security_lead", "owner", "developer", "viewer"];

/** Like rbac.Can, without the assignee nuance (callers that need it ask the API). */
export function can(perm: Perm, orgRole: OrgRole | undefined, projectRole?: ProjectRole | null): boolean {
  const granted = MATRIX[perm];
  if (orgRole && granted.includes(orgRole)) return true;
  return !!projectRole && granted.includes(projectRole);
}

/** Matrix cell text for the read-only table. */
export function matrixCell(perm: Perm, role: Role): "Yes" | "Own issues" | "–" {
  if (!MATRIX[perm].includes(role)) return "–";
  if (role === "developer" && OWN_ISSUE_ONLY_FOR_DEVELOPER.includes(perm)) return "Own issues";
  return "Yes";
}

/** Comments need update_issue, but the contract lets developers comment on any issue in their
 *  project (not only their own), so this is the plain matrix check. */
export function canComment(orgRole: OrgRole | undefined, projectRole: ProjectRole | null | undefined): boolean {
  return can("update_issue", orgRole, projectRole);
}

export const ORG_ROLE_LABELS: Record<OrgRole, string> = {
  org_admin: "Org admin",
  security_lead: "Security lead",
  member: "Member",
};

export const PROJECT_ROLE_LABELS: Record<ProjectRole, string> = {
  owner: "Owner",
  developer: "Developer",
  viewer: "Viewer",
};

export const ROLE_LABELS: Record<Role, string> = { ...ORG_ROLE_LABELS, ...PROJECT_ROLE_LABELS };
