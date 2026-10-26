package store

import (
	"context"
	"encoding/json"

	"github.com/google/uuid"

	"github.com/aupv9/warden/backend/internal/domain/autoassign"
	"github.com/aupv9/warden/backend/internal/service"
)

// organization has no RLS (it is the tenant list), so every statement on it
// names the org explicitly.

func (r *Repo) SetOrgSLA(ctx context.Context, orgID uuid.UUID, sla service.SLADays) error {
	raw, err := json.Marshal(sla)
	if err != nil {
		return err
	}
	tag, err := r.tx.Exec(ctx, `UPDATE organization SET sla_days = $2 WHERE id = $1`, orgID, raw)
	if err == nil && tag.RowsAffected() == 0 {
		return service.ErrNotFound
	}
	return mapErr(err)
}

func (r *Repo) RecomputeDueDates(ctx context.Context, orgID uuid.UUID, sla service.SLADays) (int, error) {
	tag, err := r.tx.Exec(ctx, `UPDATE issue SET due_at = created_at + make_interval(days => CASE severity
			WHEN 'critical' THEN $2::int WHEN 'high' THEN $3::int WHEN 'medium' THEN $4::int WHEN 'low' THEN $5::int END)
		WHERE org_id = $1 AND status IN `+activeStatuses+` AND severity <> 'info'`,
		orgID, sla.Critical, sla.High, sla.Medium, sla.Low)
	return int(tag.RowsAffected()), mapErr(err)
}

func (r *Repo) AssignRules(ctx context.Context, projectID uuid.UUID) ([]autoassign.Rule, error) {
	var raw []byte
	if err := r.tx.QueryRow(ctx, `SELECT assign_rules FROM project WHERE id = $1`, projectID).Scan(&raw); err != nil {
		return nil, mapErr(err)
	}
	var rules []autoassign.Rule
	if err := json.Unmarshal(raw, &rules); err != nil {
		return nil, err
	}
	return rules, nil
}

func (r *Repo) SetAssignRules(ctx context.Context, projectID uuid.UUID, rules []autoassign.Rule) error {
	if rules == nil {
		rules = []autoassign.Rule{}
	}
	raw, err := json.Marshal(rules)
	if err != nil {
		return err
	}
	_, err = r.tx.Exec(ctx, `UPDATE project SET assign_rules = $2 WHERE id = $1`, projectID, raw)
	return mapErr(err)
}

func (r *Repo) SetProjectArchived(ctx context.Context, projectID uuid.UUID, archived bool) (bool, error) {
	q := `UPDATE project SET archived_at = now() WHERE id = $1 AND archived_at IS NULL`
	if !archived {
		q = `UPDATE project SET archived_at = NULL WHERE id = $1 AND archived_at IS NOT NULL`
	}
	tag, err := r.tx.Exec(ctx, q, projectID)
	return tag.RowsAffected() > 0, mapErr(err)
}

func (r *Repo) ProjectArchived(ctx context.Context, projectID uuid.UUID) (bool, error) {
	var archived bool
	err := r.tx.QueryRow(ctx, `SELECT archived_at IS NOT NULL FROM project WHERE id = $1`, projectID).Scan(&archived)
	return archived, mapErr(err)
}
