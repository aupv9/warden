package store

import (
	"context"
	"errors"
	"time"

	"github.com/google/uuid"
	"github.com/jackc/pgx/v5"

	"github.com/aupv9/warden/backend/internal/domain/rbac"
	"github.com/aupv9/warden/backend/internal/rules"
	"github.com/aupv9/warden/backend/internal/service"
	"github.com/aupv9/warden/backend/internal/worker"
)

// Org scan rules (v0.6 wave 1). scan_rule, scan_rule_version and
// scan_rule_test have forced RLS; every query runs under the caller's
// app.org_id. Deleted rules (deleted_at) are left out everywhere but the
// issue lookup (Issue.OrgRule, issues.go).

const scanRuleSelect = `SELECT r.id, r.org_id, r.tool, r.key, r.name, r.body_canonical, r.sha256, r.severity::text, r.version,
		r.enabled, r.project_ids, cu.id, cu.email::text, cu.display_name, uu.id, uu.email::text, uu.display_name,
		r.created_at, r.updated_at
	FROM scan_rule r LEFT JOIN app_user cu ON cu.id = r.created_by LEFT JOIN app_user uu ON uu.id = r.updated_by
	WHERE r.deleted_at IS NULL`

func scanScanRule(row pgx.CollectableRow) (service.ScanRule, error) {
	var (
		r             service.ScanRule
		cID, uID      *uuid.UUID
		cEmail, cName *string
		uEmail, uName *string
	)
	err := row.Scan(&r.ID, &r.OrgID, &r.Tool, &r.Key, &r.Name, &r.Body, &r.SHA256, &r.Severity, &r.Version,
		&r.Enabled, &r.ProjectIDs, &cID, &cEmail, &cName, &uID, &uEmail, &uName, &r.CreatedAt, &r.UpdatedAt)
	r.RuleID = rules.Prefix + r.Key
	r.CreatedBy, r.UpdatedBy = userRef(cID, cEmail, cName), userRef(uID, uEmail, uName)
	return r, err
}

func (r *Repo) LockScanRules(ctx context.Context, orgID uuid.UUID) error {
	_, err := r.tx.Exec(ctx, `SELECT pg_advisory_xact_lock(hashtextextended('warden.scan_rules:' || $1::text, 0))`, orgID)
	return err
}

func (r *Repo) ScanRules(ctx context.Context, tool string) ([]service.ScanRule, error) {
	rows, _ := r.tx.Query(ctx, scanRuleSelect+` AND ($1 = '' OR r.tool = $1) ORDER BY r.tool, r.key`, tool)
	return collect(rows, scanScanRule)
}

func (r *Repo) ScanRule(ctx context.Context, id uuid.UUID, forUpdate bool) (service.ScanRule, error) {
	q := scanRuleSelect + ` AND r.id = $1`
	if forUpdate {
		q += ` FOR UPDATE OF r`
	}
	rows, _ := r.tx.Query(ctx, q, id)
	out, err := pgx.CollectExactlyOneRow(rows, scanScanRule)
	return out, mapErr(err)
}

func (r *Repo) ScanRuleUsage(ctx context.Context, tool string) (int, int64, error) {
	var (
		n     int
		bytes int64
	)
	err := r.tx.QueryRow(ctx, `SELECT count(*) FILTER (WHERE tool = $1), coalesce(sum(octet_length(body_canonical)), 0)
		FROM scan_rule WHERE deleted_at IS NULL`, tool).Scan(&n, &bytes)
	return n, bytes, err
}

func (r *Repo) InsertScanRule(ctx context.Context, x service.ScanRule) error {
	by := x.CreatedBy.ID
	if _, err := r.tx.Exec(ctx, `INSERT INTO scan_rule (id, org_id, tool, key, name, body_canonical, sha256, severity, enabled,
			project_ids, version, created_by, updated_by, created_at, updated_at)
		VALUES ($1, $2, $3, $4, $5, $6, $7, $8::severity, $9, $10, $11, $12, $12, $13, $13)`,
		x.ID, x.OrgID, x.Tool, x.Key, x.Name, x.Body, x.SHA256, x.Severity, x.Enabled, x.ProjectIDs, x.Version, by,
		x.CreatedAt.T()); err != nil {
		return mapErr(err)
	}
	return r.appendScanRuleVersion(ctx, x, by, x.CreatedAt.T())
}

func (r *Repo) UpdateScanRule(ctx context.Context, x service.ScanRule) error {
	by := x.UpdatedBy.ID
	if _, err := r.tx.Exec(ctx, `UPDATE scan_rule SET name = $2, body_canonical = $3, sha256 = $4, severity = $5::severity,
			enabled = $6, project_ids = $7, version = $8, updated_by = $9, updated_at = $10
		WHERE id = $1 AND deleted_at IS NULL`,
		x.ID, x.Name, x.Body, x.SHA256, x.Severity, x.Enabled, x.ProjectIDs, x.Version, by, x.UpdatedAt.T()); err != nil {
		return mapErr(err)
	}
	return r.appendScanRuleVersion(ctx, x, by, x.UpdatedAt.T())
}

func (r *Repo) appendScanRuleVersion(ctx context.Context, x service.ScanRule, by uuid.UUID, at time.Time) error {
	_, err := r.tx.Exec(ctx, `INSERT INTO scan_rule_version (org_id, scan_rule_id, version, name, body_canonical, sha256,
			severity, enabled, project_ids, created_by, created_at)
		SELECT org_id, id, version, name, body_canonical, sha256, severity, enabled, project_ids, $2, $3
		FROM scan_rule WHERE id = $1 AND version = $4`, x.ID, by, at, x.Version)
	return mapErr(err)
}

func (r *Repo) DeleteScanRule(ctx context.Context, id, by uuid.UUID, at time.Time) error {
	_, err := r.tx.Exec(ctx, `UPDATE scan_rule SET deleted_at = $3, updated_by = $2, updated_at = $3
		WHERE id = $1 AND deleted_at IS NULL`, id, by, at)
	return mapErr(err)
}

func (r *Repo) ScanRuleVersions(ctx context.Context, id uuid.UUID, before, limit int) ([]service.ScanRuleVersion, error) {
	rows, _ := r.tx.Query(ctx, `SELECT v.version, v.body_canonical, v.sha256, v.name, v.enabled, v.project_ids,
			u.id, u.email::text, u.display_name, v.created_at
		FROM scan_rule_version v LEFT JOIN app_user u ON u.id = v.created_by
		WHERE v.scan_rule_id = $1 AND ($2 = 0 OR v.version < $2)
		ORDER BY v.version DESC LIMIT $3`, id, before, limit)
	return collect(rows, func(row pgx.CollectableRow) (service.ScanRuleVersion, error) {
		var (
			v            service.ScanRuleVersion
			uID          *uuid.UUID
			uEmail, name *string
		)
		err := row.Scan(&v.Version, &v.Body, &v.SHA256, &v.Name, &v.Enabled, &v.ProjectIDs, &uID, &uEmail, &name, &v.CreatedAt)
		v.CreatedBy = userRef(uID, uEmail, name)
		return v, err
	})
}

func (r *Repo) UserProjectRoles(ctx context.Context, userID uuid.UUID) (map[uuid.UUID]rbac.Role, error) {
	rows, _ := r.tx.Query(ctx, `SELECT pm.project_id, pm.role::text FROM project_member pm JOIN project p ON p.id = pm.project_id
		WHERE pm.user_id = $1`, userID)
	out := map[uuid.UUID]rbac.Role{}
	var (
		id   uuid.UUID
		role string
	)
	_, err := pgx.ForEachRow(rows, []any{&id, &role}, func() error {
		out[id] = rbac.Role(role)
		return nil
	})
	return out, err
}

func (r *Repo) LockRuleTests(ctx context.Context, userID uuid.UUID) error {
	_, err := r.tx.Exec(ctx, `SELECT pg_advisory_xact_lock(hashtextextended('warden.rule_tests:' || $1::text, 0))`, userID)
	return err
}

func (r *Repo) RuleTestsSince(ctx context.Context, userID uuid.UUID, since time.Time) (int, time.Time, error) {
	var (
		n      int
		oldest *time.Time
	)
	err := r.tx.QueryRow(ctx, `SELECT count(*), min(created_at) FROM scan_rule_test WHERE created_by = $1 AND created_at > $2`,
		userID, since).Scan(&n, &oldest)
	if oldest == nil {
		return n, time.Time{}, err
	}
	return n, *oldest, err
}

// InsertRuleTest stores a queued test and enqueues its test_rules job in the
// same transaction: the job exists exactly when the row does. The job's
// arguments name the row; the snippet stays in the table.
func (r *Repo) InsertRuleTest(ctx context.Context, t service.NewRuleTest) error {
	if _, err := r.tx.Exec(ctx, `INSERT INTO scan_rule_test (id, org_id, created_by, tool, body_canonical, filename, snippet, created_at)
		VALUES ($1, $2, $3, $4, $5, $6, $7, $8)`,
		t.ID, t.OrgID, t.CreatedBy, t.Tool, string(t.Body), t.Filename, t.Snippet, t.CreatedAt); err != nil {
		return mapErr(err)
	}
	if r.river == nil {
		return errors.New("job queue not configured")
	}
	_, err := r.river.InsertTx(ctx, r.tx, worker.TestRulesArgs{OrgID: t.OrgID, TestID: t.ID}, nil)
	return err
}

func (r *Repo) RuleTest(ctx context.Context, id uuid.UUID) (service.RuleTest, error) {
	var t service.RuleTest
	err := r.tx.QueryRow(ctx, `SELECT id, created_by, state, findings, error, created_at, finished_at
		FROM scan_rule_test WHERE id = $1`, id).Scan(&t.ID, &t.CreatedBy, &t.State, &t.Findings, &t.Error, &t.CreatedAt, &t.FinishedAt)
	return t, mapErr(err)
}
