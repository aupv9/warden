package service

import (
	"context"
	"errors"
	"slices"
	"strings"

	apperrors "github.com/aupv9/common-go/errors"
	"github.com/google/uuid"

	"github.com/aupv9/warden/backend/internal/domain/rbac"
)

func (s *Service) Org(ctx context.Context, a *Actor) (Org, error) {
	var out Org
	err := s.inOrg(ctx, a, func(r Repo) error {
		o, err := r.Org(ctx, a.OrgID)
		if err != nil {
			return notFound(err)
		}
		o.MyRole = a.OrgRole
		out = o
		return nil
	})
	return out, err
}

// Summary counts over the projects the caller can see; exceptions_pending only
// for those who can decide exceptions.
func (s *Service) Summary(ctx context.Context, a *Actor) (Summary, error) {
	var out Summary
	err := s.inOrg(ctx, a, func(r Repo) error {
		sum, err := r.Summary(ctx, a.vis(), s.now())
		if err != nil {
			return err
		}
		if rbac.Can(rbac.DecideException, a.OrgRole, "", false) {
			if sum.ExceptionsPending, err = r.CountPendingExceptions(ctx); err != nil {
				return err
			}
		} else {
			sum.ExceptionsPending = 0
		}
		out = sum
		return nil
	})
	return out, err
}

func (s *Service) Members(ctx context.Context, a *Actor) (Items[OrgMember], error) {
	out := Items[OrgMember]{Items: []OrgMember{}}
	err := s.inOrg(ctx, a, func(r Repo) error {
		m, err := r.OrgMembers(ctx, a.OrgID)
		if err != nil {
			return err
		}
		if m != nil {
			out.Items = m
		}
		return nil
	})
	return out, err
}

type AddMemberInput struct {
	Email string `json:"email"`
	Role  string `json:"role"`
}

func (s *Service) AddMember(ctx context.Context, a *Actor, in AddMemberInput) (OrgMember, error) {
	fe := fieldErrors{}
	email := strings.TrimSpace(in.Email)
	if !validEmail(email) {
		fe.add("email", "must be a valid email address")
	}
	if !validOrgRole(in.Role) {
		fe.add("role", "must be one of org_admin, security_lead, member")
	}
	var out OrgMember
	err := s.inOrg(ctx, a, func(r Repo) error {
		if !rbac.Can(rbac.ManageUsers, a.OrgRole, "", false) {
			return errForbidden()
		}
		if err := fe.err(); err != nil {
			return err
		}
		u, err := r.UserByEmail(ctx, email)
		if errors.Is(err, ErrNotFound) {
			return apperrors.NotFound("USER_NOT_FOUND", "no user with this email has signed in to Warden yet")
		}
		if err != nil {
			return err
		}
		if err := r.InsertOrgMember(ctx, a.OrgID, u.ID, rbac.Role(in.Role)); err != nil {
			if errors.Is(err, ErrConflict) {
				return errConflict("the user is already a member of this organization")
			}
			return err
		}
		if out, err = r.OrgMember(ctx, a.OrgID, u.ID); err != nil {
			return err
		}
		return s.audit(ctx, r, a, "member.added", "user", u.ID.String(), map[string]any{"role": in.Role})
	})
	return out, err
}

type SetMemberRoleInput struct {
	Role string `json:"role"`
}

func (s *Service) SetMemberRole(ctx context.Context, a *Actor, userID uuid.UUID, in SetMemberRoleInput) (OrgMember, error) {
	var out OrgMember
	err := s.inOrg(ctx, a, func(r Repo) error {
		if !rbac.Can(rbac.ManageUsers, a.OrgRole, "", false) {
			return errForbidden()
		}
		if !validOrgRole(in.Role) {
			return errField("role", "must be one of org_admin, security_lead, member")
		}
		cur, err := r.OrgMember(ctx, a.OrgID, userID)
		if err != nil {
			return notFound(err)
		}
		if cur.Role == rbac.Role(in.Role) {
			out = cur
			return nil
		}
		if cur.Role == rbac.OrgAdmin {
			if err := lastAdminGuard(ctx, r, a.OrgID, userID); err != nil {
				return err
			}
		}
		if err := r.SetOrgMemberRole(ctx, a.OrgID, userID, rbac.Role(in.Role)); err != nil {
			return err
		}
		if out, err = r.OrgMember(ctx, a.OrgID, userID); err != nil {
			return err
		}
		return s.audit(ctx, r, a, "member.role_changed", "user", userID.String(),
			map[string]any{"from": string(cur.Role), "to": in.Role})
	})
	return out, err
}

// lastAdminGuard refuses to demote or remove the org's last admin. The admin
// rows are locked first, so two concurrent demotions can't both succeed.
func lastAdminGuard(ctx context.Context, r Repo, orgID, userID uuid.UUID) error {
	admins, err := r.LockOrgAdmins(ctx, orgID)
	if err != nil {
		return err
	}
	if len(admins) <= 1 && slices.Contains(admins, userID) {
		return errConflict("an organization must keep at least one org_admin")
	}
	return nil
}

func (s *Service) RemoveMember(ctx context.Context, a *Actor, userID uuid.UUID) error {
	return s.inOrg(ctx, a, func(r Repo) error {
		if !rbac.Can(rbac.ManageUsers, a.OrgRole, "", false) {
			return errForbidden()
		}
		cur, err := r.OrgMember(ctx, a.OrgID, userID)
		if err != nil {
			return notFound(err)
		}
		if cur.Role == rbac.OrgAdmin {
			if err := lastAdminGuard(ctx, r, a.OrgID, userID); err != nil {
				return err
			}
		}
		if err := r.DeleteOrgMember(ctx, a.OrgID, userID); err != nil {
			return err
		}
		return s.audit(ctx, r, a, "member.removed", "user", userID.String(), map[string]any{"role": string(cur.Role)})
	})
}
