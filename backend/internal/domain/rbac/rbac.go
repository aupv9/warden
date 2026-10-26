// Package rbac is the role/permission matrix. Services check it before
// touching data; RLS is only the second line of defence.
package rbac

import "slices"

type Role string

// Org roles.
const (
	OrgAdmin     Role = "org_admin"
	SecurityLead Role = "security_lead"
	Member       Role = "member"
)

// Project roles.
const (
	Owner     Role = "owner"
	Developer Role = "developer"
	Viewer    Role = "viewer"
)

type Perm string

const (
	ManageUsers          Perm = "manage_users"
	CreateArchiveProject Perm = "create_archive_project"
	ManageProjectMembers Perm = "manage_project_members"
	RunScan              Perm = "run_scan"
	ViewResults          Perm = "view_results"
	AssignIssue          Perm = "assign_issue"
	UpdateIssue          Perm = "update_issue"
	ProposeException     Perm = "propose_exception"
	DecideException      Perm = "decide_exception"
	ConfigurePolicy      Perm = "configure_policy"
	ViewDashboard        Perm = "view_dashboard"
	ViewAuditLog         Perm = "view_audit_log"
)

var AllPerms = []Perm{
	ManageUsers, CreateArchiveProject, ManageProjectMembers, RunScan, ViewResults, AssignIssue,
	UpdateIssue, ProposeException, DecideException, ConfigurePolicy, ViewDashboard, ViewAuditLog,
}

var Matrix = map[Perm][]Role{
	ManageUsers:          {OrgAdmin},
	CreateArchiveProject: {OrgAdmin, SecurityLead},
	ManageProjectMembers: {OrgAdmin, SecurityLead, Owner},
	RunScan:              {SecurityLead, Owner, Developer},
	ViewResults:          {OrgAdmin, SecurityLead, Owner, Developer, Viewer},
	AssignIssue:          {SecurityLead, Owner},
	UpdateIssue:          {SecurityLead, Owner, Developer},
	ProposeException:     {SecurityLead, Owner, Developer},
	DecideException:      {SecurityLead},
	ConfigurePolicy:      {SecurityLead},
	ViewDashboard:        {OrgAdmin, SecurityLead, Owner, Developer, Viewer},
	ViewAuditLog:         {OrgAdmin, SecurityLead},
}

// ownIssueOnlyForDeveloper: developers may only update issues assigned to them.
var ownIssueOnlyForDeveloper = []Perm{UpdateIssue}

// Can reports whether a user with orgRole (and projectRole in the issue's project,
// "" if not a member) holds perm.
func Can(perm Perm, orgRole, projectRole Role, isAssignee bool) bool {
	granted := Matrix[perm]
	if orgRole != "" && slices.Contains(granted, orgRole) {
		return true
	}
	if projectRole == "" || !slices.Contains(granted, projectRole) {
		return false
	}
	if projectRole == Developer && slices.Contains(ownIssueOnlyForDeveloper, perm) {
		return isAssignee
	}
	return true
}
