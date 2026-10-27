package store

import (
	"context"
	"time"

	"github.com/google/uuid"
	"github.com/jackc/pgx/v5"

	"github.com/aupv9/warden/backend/internal/domain/rbac"
	"github.com/aupv9/warden/backend/internal/service"
)

const userCols = `id, keycloak_sub, email::text, display_name, is_active, last_mfa, relink_until`

func scanUser(row pgx.Row) (service.User, error) {
	var u service.User
	err := row.Scan(&u.ID, &u.Sub, &u.Email, &u.DisplayName, &u.IsActive, &u.MFA, &u.RelinkUntil)
	return u, mapErr(err)
}

func (r *Repo) UserBySub(ctx context.Context, sub string) (service.User, error) {
	return scanUser(r.tx.QueryRow(ctx, `SELECT `+userCols+` FROM app_user WHERE keycloak_sub = $1`, sub))
}

func (r *Repo) UserByEmail(ctx context.Context, email string) (service.User, error) {
	return scanUser(r.tx.QueryRow(ctx, `SELECT `+userCols+` FROM app_user WHERE email = $1`, email))
}

func (r *Repo) InsertUser(ctx context.Context, u service.User) error {
	_, err := r.tx.Exec(ctx, `INSERT INTO app_user (id, keycloak_sub, email, display_name, is_active, last_mfa)
		VALUES ($1, $2, $3, $4, $5, $6)`, u.ID, u.Sub, u.Email, u.DisplayName, u.IsActive, u.MFA)
	return mapErr(err)
}

func (r *Repo) UpdateUser(ctx context.Context, u service.User) error {
	_, err := r.tx.Exec(ctx, `UPDATE app_user SET email = $2, display_name = $3, last_mfa = $4 WHERE id = $1`,
		u.ID, u.Email, u.DisplayName, u.MFA)
	return mapErr(err)
}

func (r *Repo) UserOrgs(ctx context.Context, userID uuid.UUID) ([]service.OrgRef, error) {
	rows, _ := r.tx.Query(ctx, `SELECT o.id, o.name, m.role::text, o.mfa_roles::text[] FROM org_member m
		JOIN organization o ON o.id = m.org_id WHERE m.user_id = $1 ORDER BY o.name, o.id`, userID)
	return collect(rows, func(row pgx.CollectableRow) (service.OrgRef, error) {
		var (
			o     service.OrgRef
			roles []string
		)
		err := row.Scan(&o.ID, &o.Name, (*string)(&o.Role), &roles)
		o.MFARoles = toRoles(roles)
		return o, err
	})
}

func (r *Repo) MemberRole(ctx context.Context, orgID, userID uuid.UUID) (rbac.Role, error) {
	var role string
	err := r.tx.QueryRow(ctx, `SELECT role::text FROM org_member WHERE org_id = $1 AND user_id = $2`, orgID, userID).Scan(&role)
	return rbac.Role(role), mapErr(err)
}

func (r *Repo) UserRef(ctx context.Context, userID uuid.UUID) (service.UserRef, error) {
	var u service.UserRef
	err := r.tx.QueryRow(ctx, `SELECT id, email::text, display_name FROM app_user WHERE id = $1`, userID).
		Scan(&u.ID, &u.Email, &u.DisplayName)
	return u, mapErr(err)
}

func (r *Repo) Org(ctx context.Context, orgID uuid.UUID) (service.Org, error) {
	var o service.Org
	err := r.tx.QueryRow(ctx, `SELECT id, name, sla_days FROM organization WHERE id = $1`, orgID).Scan(&o.ID, &o.Name, &o.SLADays)
	return o, mapErr(err)
}

// visible is the project visibility predicate for alias p; $user and $all are
// the caller's id and whether they see every project.
func visible(a *args, v service.Visibility) string {
	if v.All {
		return "true"
	}
	return `EXISTS (SELECT 1 FROM project_member vm WHERE vm.project_id = p.id AND vm.user_id = ` + a.add(v.UserID) + `)`
}

func (r *Repo) Summary(ctx context.Context, v service.Visibility, now time.Time) (service.Summary, error) {
	var a args
	q := `SELECT count(*), count(*) FILTER (WHERE i.severity IN ('critical','high')),
			count(*) FILTER (WHERE i.due_at < ` + a.add(now) + `)
		FROM issue i JOIN project p ON p.id = i.project_id
		WHERE p.org_id = ` + a.add(v.OrgID) + ` AND p.archived_at IS NULL AND i.status IN ` + activeStatuses + `
		AND ` + visible(&a, v)
	var s service.Summary
	err := r.tx.QueryRow(ctx, q, a...).Scan(&s.OpenIssues, &s.CriticalHighOpen, &s.PastSLA)
	return s, mapErr(err)
}

func (r *Repo) CountPendingExceptions(ctx context.Context) (int, error) {
	var n int
	err := r.tx.QueryRow(ctx, `SELECT count(*) FROM exception_request WHERE status = 'pending'`).Scan(&n)
	return n, mapErr(err)
}

const memberSelect = `SELECT u.id, u.email::text, u.display_name, u.is_active, m.role::text, u.last_mfa,
	coalesce((SELECT json_agg(json_build_object('id', p.id, 'key', p.key, 'role', pm.role) ORDER BY p.key)
		FROM project_member pm JOIN project p ON p.id = pm.project_id
		WHERE pm.user_id = u.id AND pm.org_id = m.org_id AND p.archived_at IS NULL), '[]'::json)
	FROM org_member m JOIN app_user u ON u.id = m.user_id`

func scanMember(row pgx.Row) (service.OrgMember, error) {
	var m service.OrgMember
	err := row.Scan(&m.User.ID, &m.User.Email, &m.User.DisplayName, &m.User.IsActive, (*string)(&m.Role), &m.MFA, &m.Projects)
	if m.Projects == nil {
		m.Projects = []service.MemberProject{}
	}
	return m, err
}

func (r *Repo) OrgMembers(ctx context.Context, orgID uuid.UUID) ([]service.OrgMember, error) {
	rows, _ := r.tx.Query(ctx, memberSelect+` WHERE m.org_id = $1 ORDER BY u.display_name, u.email`, orgID)
	return collect(rows, func(row pgx.CollectableRow) (service.OrgMember, error) { return scanMember(row) })
}

func (r *Repo) OrgMember(ctx context.Context, orgID, userID uuid.UUID) (service.OrgMember, error) {
	m, err := scanMember(r.tx.QueryRow(ctx, memberSelect+` WHERE m.org_id = $1 AND m.user_id = $2`, orgID, userID))
	return m, mapErr(err)
}

func (r *Repo) InsertOrgMember(ctx context.Context, orgID, userID uuid.UUID, role rbac.Role) error {
	_, err := r.tx.Exec(ctx, `INSERT INTO org_member (org_id, user_id, role) VALUES ($1, $2, $3::org_role)`, orgID, userID, string(role))
	return mapErr(err)
}

func (r *Repo) LockOrgAdmins(ctx context.Context, orgID uuid.UUID) ([]uuid.UUID, error) {
	rows, _ := r.tx.Query(ctx, `SELECT user_id FROM org_member WHERE org_id = $1 AND role = 'org_admin' FOR UPDATE`, orgID)
	return collect(rows, pgx.RowTo[uuid.UUID])
}

func (r *Repo) SetOrgMemberRole(ctx context.Context, orgID, userID uuid.UUID, role rbac.Role) error {
	_, err := r.tx.Exec(ctx, `UPDATE org_member SET role = $3::org_role WHERE org_id = $1 AND user_id = $2`, orgID, userID, string(role))
	return mapErr(err)
}

func (r *Repo) DeleteOrgMember(ctx context.Context, orgID, userID uuid.UUID) error {
	if _, err := r.tx.Exec(ctx, `DELETE FROM project_member WHERE org_id = $1 AND user_id = $2`, orgID, userID); err != nil {
		return err
	}
	_, err := r.tx.Exec(ctx, `DELETE FROM org_member WHERE org_id = $1 AND user_id = $2`, orgID, userID)
	return mapErr(err)
}

// collect gathers rows, returning a non-nil slice.
func collect[T any](rows pgx.Rows, fn pgx.RowToFunc[T]) ([]T, error) {
	out, err := pgx.CollectRows(rows, fn)
	if err != nil {
		return nil, err
	}
	if out == nil {
		out = []T{}
	}
	return out, nil
}
