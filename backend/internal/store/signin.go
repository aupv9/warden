package store

import (
	"context"

	"github.com/google/uuid"

	"github.com/aupv9/warden/backend/internal/domain/rbac"
	"github.com/aupv9/warden/backend/internal/service"
)

func (r *Repo) OrgSignInPolicy(ctx context.Context, orgID uuid.UUID) (service.SignInPolicy, error) {
	var (
		roles []string
		p     service.SignInPolicy
	)
	err := r.tx.QueryRow(ctx, `SELECT mfa_roles::text[], allowed_email_domains FROM organization WHERE id = $1`, orgID).
		Scan(&roles, &p.AllowedEmailDomains)
	p.MFARoles = toRoles(roles)
	return p, mapErr(err)
}

func (r *Repo) SetOrgSignInPolicy(ctx context.Context, orgID uuid.UUID, p service.SignInPolicy) error {
	tag, err := r.tx.Exec(ctx, `UPDATE organization SET mfa_roles = $2::text[]::org_role[], allowed_email_domains = $3 WHERE id = $1`,
		orgID, fromRoles(p.MFARoles), nonNilStrings(p.AllowedEmailDomains))
	if err == nil && tag.RowsAffected() == 0 {
		return service.ErrNotFound
	}
	return mapErr(err)
}

func (r *Repo) RelinkUser(ctx context.Context, userID uuid.UUID, sub string) error {
	tag, err := r.tx.Exec(ctx, `UPDATE app_user SET keycloak_sub = $2, relink_until = NULL WHERE id = $1`, userID, sub)
	if err == nil && tag.RowsAffected() == 0 {
		return service.ErrNotFound
	}
	return mapErr(err)
}

func toRoles(in []string) []rbac.Role {
	out := make([]rbac.Role, 0, len(in))
	for _, r := range in {
		out = append(out, rbac.Role(r))
	}
	return out
}

func fromRoles(in []rbac.Role) []string {
	out := make([]string, 0, len(in))
	for _, r := range in {
		out = append(out, string(r))
	}
	return out
}

func nonNilStrings(s []string) []string {
	if s == nil {
		return []string{}
	}
	return s
}
