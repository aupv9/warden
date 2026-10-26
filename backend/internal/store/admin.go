package store

import (
	"context"
	"errors"
	"fmt"
	"strings"
	"unicode/utf8"

	"github.com/google/uuid"
	"github.com/jackc/pgx/v5"

	"github.com/aupv9/warden/backend/internal/domain/rbac"
	"github.com/aupv9/warden/backend/internal/ids"
	"github.com/aupv9/warden/backend/internal/service"
)

// ErrAdminNotFound: the admin given to CreateOrg has never signed in.
var ErrAdminNotFound = errors.New("no user with this email has signed in to Warden yet")

// CreateOrg creates an organization with one org_admin, plus its first audit
// entry, in one transaction (operator command; there's no API for it in v0.1).
func CreateOrg(ctx context.Context, d *DB, name, adminEmail string) (uuid.UUID, error) {
	name = strings.TrimSpace(name)
	if name == "" || utf8.RuneCountInString(name) > 200 || !utf8.ValidString(name) || strings.ContainsRune(name, 0) {
		return uuid.Nil, errors.New("name must be 1-200 characters")
	}
	org := ids.New()
	err := d.InOrg(ctx, org, func(sr service.Repo) error {
		r := sr.(*Repo)
		admin, err := r.UserByEmail(ctx, strings.TrimSpace(adminEmail))
		if errors.Is(err, service.ErrNotFound) {
			return ErrAdminNotFound
		}
		if err != nil {
			return err
		}
		if !admin.IsActive {
			return fmt.Errorf("user %s is deactivated", admin.Email)
		}
		if _, err := r.tx.Exec(ctx, `INSERT INTO organization (id, name) VALUES ($1, $2)`, org, name); err != nil {
			return err
		}
		if err := r.InsertOrgMember(ctx, org, admin.ID, rbac.OrgAdmin); err != nil {
			return err
		}
		return r.AppendAudit(ctx, service.AuditRecord{
			OrgID: org, Action: "org.created", TargetType: "org", TargetID: org.String(),
			Data: map[string]any{"name": name, "admin_user_id": admin.ID.String(), "via": "warden-admin"},
		})
	})
	return org, err
}

// ErrNotMember: the user given to SetOrgRole isn't a member of the org.
var ErrNotMember = errors.New("the user is not a member of this organization")

// SetOrgRole changes a member's org role from the command line: the break-glass
// path when no admin can sign in (for example, lost second factor). It keeps the
// API's rule that an org never loses its last org_admin, and is audited as
// member.role_changed with no actor and data.via = "warden-admin". It returns
// the previous role; setting the current role changes and audits nothing.
func SetOrgRole(ctx context.Context, d *DB, org uuid.UUID, email string, role rbac.Role) (rbac.Role, error) {
	switch role {
	case rbac.OrgAdmin, rbac.SecurityLead, rbac.Member:
	default:
		return "", fmt.Errorf("role must be one of org_admin, security_lead, member")
	}
	var from rbac.Role
	err := d.InOrg(ctx, org, func(sr service.Repo) error {
		r := sr.(*Repo)
		u, err := r.UserByEmail(ctx, strings.TrimSpace(email))
		if errors.Is(err, service.ErrNotFound) {
			return ErrNotMember
		}
		if err != nil {
			return err
		}
		if from, err = r.MemberRole(ctx, org, u.ID); errors.Is(err, service.ErrNotFound) {
			return ErrNotMember
		} else if err != nil {
			return err
		}
		if from == role {
			return nil
		}
		if from == rbac.OrgAdmin {
			admins, err := r.LockOrgAdmins(ctx, org)
			if err != nil {
				return err
			}
			if len(admins) <= 1 {
				return errors.New("an organization must keep at least one org_admin")
			}
		}
		if err := r.SetOrgMemberRole(ctx, org, u.ID, role); err != nil {
			return err
		}
		return r.AppendAudit(ctx, service.AuditRecord{
			OrgID: org, Action: "member.role_changed", TargetType: "user", TargetID: u.ID.String(),
			Data: map[string]any{"from": string(from), "to": string(role), "via": "warden-admin"},
		})
	})
	return from, err
}

// VerifyOrgAudit checks an org's audit chain in a read-only transaction.
func VerifyOrgAudit(ctx context.Context, d *DB, org uuid.UUID) (int, error) {
	var n int
	err := pgx.BeginTxFunc(ctx, d.pool, pgx.TxOptions{AccessMode: pgx.ReadOnly}, func(tx pgx.Tx) error {
		var err error
		n, err = VerifyAuditChain(ctx, tx, org)
		return err
	})
	return n, err
}
