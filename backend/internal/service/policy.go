package service

import (
	"context"
	"fmt"
	"strings"

	apperrors "github.com/aupv9/common-go/errors"
	"github.com/google/uuid"

	"github.com/aupv9/warden/backend/internal/domain/autoassign"
	"github.com/aupv9/warden/backend/internal/domain/rbac"
)

// PolicyRepo: org SLA policy, project auto-assign rules and archiving.
type PolicyRepo interface {
	SetOrgSLA(ctx context.Context, orgID uuid.UUID, sla SLADays) error
	// RecomputeDueDates resets due_at of the org's active issues to created_at
	// plus the SLA of their severity (none for info) and returns how many changed.
	RecomputeDueDates(ctx context.Context, orgID uuid.UUID, sla SLADays) (int, error)
	AssignRules(ctx context.Context, projectID uuid.UUID) ([]autoassign.Rule, error)
	SetAssignRules(ctx context.Context, projectID uuid.UUID, rules []autoassign.Rule) error
	// SetProjectArchived sets or clears archived_at and reports whether it changed.
	SetProjectArchived(ctx context.Context, projectID uuid.UUID, archived bool) (bool, error)
	ProjectArchived(ctx context.Context, projectID uuid.UUID) (bool, error)
}

const maxSLADays = 365

func errProjectArchived() error {
	return apperrors.Conflict("PROJECT_ARCHIVED", "the project is archived; unarchive it to run scans")
}

// requireNotArchived refuses scan creation and start in an archived project.
func requireNotArchived(ctx context.Context, r Repo, projectID uuid.UUID) error {
	archived, err := r.ProjectArchived(ctx, projectID)
	if err != nil {
		return notFound(err)
	}
	if archived {
		return errProjectArchived()
	}
	return nil
}

type SLAInput struct {
	Critical *int `json:"critical"`
	High     *int `json:"high"`
	Medium   *int `json:"medium"`
	Low      *int `json:"low"`
}

type OrgPolicyInput struct {
	SLADays       *SLAInput `json:"sla_days"`
	RecomputeOpen *bool     `json:"recompute_open"`
}

func (in OrgPolicyInput) validate() (SLADays, error) {
	fe := fieldErrors{}
	var out SLADays
	if in.SLADays == nil {
		fe.add("sla_days", "is required")
		return out, fe.err()
	}
	for _, f := range []struct {
		name string
		v    *int
		dst  *int
	}{
		{"critical", in.SLADays.Critical, &out.Critical}, {"high", in.SLADays.High, &out.High},
		{"medium", in.SLADays.Medium, &out.Medium}, {"low", in.SLADays.Low, &out.Low},
	} {
		if f.v == nil || *f.v < 1 || *f.v > maxSLADays {
			fe.add("sla_days."+f.name, "must be an integer between 1 and 365")
			continue
		}
		*f.dst = *f.v
	}
	return out, fe.err()
}

// SetOrgPolicy changes the org's SLA days. New issues get due dates from the
// new policy; with recompute_open, active issues are re-dated from created_at.
func (s *Service) SetOrgPolicy(ctx context.Context, a *Actor, in OrgPolicyInput) (Org, error) {
	sla, verr := in.validate()
	var out Org
	err := s.inOrg(ctx, a, func(r Repo) error {
		if !rbac.Can(rbac.ConfigurePolicy, a.OrgRole, "", false) {
			return errForbidden()
		}
		if verr != nil {
			return verr
		}
		cur, err := r.Org(ctx, a.OrgID)
		if err != nil {
			return notFound(err)
		}
		if err := r.SetOrgSLA(ctx, a.OrgID, sla); err != nil {
			return err
		}
		recompute := in.RecomputeOpen != nil && *in.RecomputeOpen
		changed := 0
		if recompute {
			if changed, err = r.RecomputeDueDates(ctx, a.OrgID, sla); err != nil {
				return err
			}
		}
		if out, err = r.Org(ctx, a.OrgID); err != nil {
			return err
		}
		out.MyRole = a.OrgRole
		return s.audit(ctx, r, a, "org.policy_changed", "org", a.OrgID.String(), map[string]any{
			"from": cur.SLADays, "to": sla, "recompute_open": recompute, "recomputed": changed,
		})
	})
	return out, err
}

func (s *Service) AssignRules(ctx context.Context, a *Actor, projectID uuid.UUID) (Items[autoassign.Rule], error) {
	out := Items[autoassign.Rule]{Items: []autoassign.Rule{}}
	err := s.inOrg(ctx, a, func(r Repo) error {
		role, err := projectAccess(ctx, r, a, projectID)
		if err != nil {
			return err
		}
		if !rbac.Can(rbac.ViewResults, a.OrgRole, role, false) {
			return errForbidden()
		}
		rules, err := r.AssignRules(ctx, projectID)
		if err != nil {
			return err
		}
		if rules != nil {
			out.Items = rules
		}
		return nil
	})
	return out, err
}

type AssignRuleInput struct {
	Match      autoassign.Match `json:"match"`
	AssigneeID string           `json:"assignee_id"`
}

type AssignRulesInput struct {
	Items []AssignRuleInput `json:"items"`
}

// SetAssignRules replaces the project's auto-assign rules (ordered; the first
// match wins). Every assignee must be a member of the project.
func (s *Service) SetAssignRules(ctx context.Context, a *Actor, projectID uuid.UUID, in AssignRulesInput) (Items[autoassign.Rule], error) {
	fe := fieldErrors{}
	if in.Items == nil {
		fe.add("items", "is required")
	}
	if len(in.Items) > autoassign.MaxRules {
		fe.add("items", "must contain at most 50 rules")
	}
	rules := make([]autoassign.Rule, 0, len(in.Items))
	for i, it := range in.Items {
		prefix := fmt.Sprintf("items[%d].", i)
		rule := autoassign.Rule{Match: it.Match}
		if id, err := uuid.Parse(it.AssigneeID); err == nil {
			rule.AssigneeID = id
		}
		for k, msg := range autoassign.Validate(rule) {
			if k == "assignee_id" && it.AssigneeID != "" {
				msg = "must be a user id"
			}
			fe.add(prefix+k, msg)
		}
		if it.Match.PathGlob != nil && !validText(*it.Match.PathGlob) {
			fe.add(prefix+"match.path_glob", "must be printable text")
		}
		rules = append(rules, rule)
	}
	out := Items[autoassign.Rule]{Items: rules}
	err := s.inOrg(ctx, a, func(r Repo) error {
		role, err := projectAccess(ctx, r, a, projectID)
		if err != nil {
			return err
		}
		if !rbac.Can(rbac.ManageProjectMembers, a.OrgRole, role, false) {
			return errForbidden()
		}
		if err := fe.err(); err != nil {
			return err
		}
		for i, rule := range rules {
			m, err := r.ProjectRole(ctx, projectID, rule.AssigneeID)
			if err != nil {
				return err
			}
			if m == "" {
				fe.add(fmt.Sprintf("items[%d].assignee_id", i), "must be a member of the project")
			}
		}
		if err := fe.err(); err != nil {
			return err
		}
		if err := r.SetAssignRules(ctx, projectID, rules); err != nil {
			return err
		}
		return s.audit(ctx, r, a, "project.assign_rules_set", "project", projectID.String(), map[string]any{"rules": len(rules)})
	})
	if err != nil {
		return Items[autoassign.Rule]{}, err
	}
	return out, nil
}

// ArchiveProject archives (or with archived=false unarchives) a project.
// Archived projects keep their issues readable but accept no new scans and are
// left out of the project list by default. Repeating the call is a no-op.
func (s *Service) ArchiveProject(ctx context.Context, a *Actor, projectID uuid.UUID, archived bool) (Project, error) {
	var out Project
	err := s.inOrg(ctx, a, func(r Repo) error {
		if _, err := projectAccess(ctx, r, a, projectID); err != nil {
			return err
		}
		if !rbac.Can(rbac.CreateArchiveProject, a.OrgRole, "", false) {
			return errForbidden()
		}
		changed, err := r.SetProjectArchived(ctx, projectID, archived)
		if err != nil {
			return notFound(err)
		}
		if out, err = r.Project(ctx, a.vis(), projectID, s.now()); err != nil {
			return notFound(err)
		}
		if !changed {
			return nil
		}
		action := "project.archived"
		if !archived {
			action = "project.unarchived"
		}
		return s.audit(ctx, r, a, action, "project", projectID.String(), map[string]any{"key": out.Key})
	})
	return out, err
}

// parseBool parses an optional boolean query parameter.
func parseBool(field, raw string) (bool, error) {
	switch strings.ToLower(raw) {
	case "", "false":
		return false, nil
	case "true":
		return true, nil
	}
	return false, errField(field, "must be true or false")
}
