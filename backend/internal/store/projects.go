package store

import (
	"context"
	"time"

	"github.com/google/uuid"
	"github.com/jackc/pgx/v5"

	"github.com/aupv9/warden/backend/internal/domain/rbac"
	"github.com/aupv9/warden/backend/internal/service"
)

func projectQuery(v service.Visibility, projectID *uuid.UUID, now time.Time) (string, args) {
	var a args
	user := a.add(v.UserID)
	nowP := a.add(now)
	q := `SELECT p.id, p.key, p.name, p.description, p.default_tools, pm.role::text, p.created_at,
			sev.critical, sev.high, sev.medium, sev.low, sev.info, sev.past_sla,
			ls.id, ls.status::text, ls.created_at, ls.finished_at
		FROM project p
		LEFT JOIN project_member pm ON pm.project_id = p.id AND pm.user_id = ` + user + `
		LEFT JOIN LATERAL (
			SELECT count(*) FILTER (WHERE i.severity = 'critical') AS critical,
				count(*) FILTER (WHERE i.severity = 'high') AS high,
				count(*) FILTER (WHERE i.severity = 'medium') AS medium,
				count(*) FILTER (WHERE i.severity = 'low') AS low,
				count(*) FILTER (WHERE i.severity = 'info') AS info,
				count(*) FILTER (WHERE i.due_at < ` + nowP + `) AS past_sla
			FROM issue i WHERE i.project_id = p.id AND i.status IN ` + activeStatuses + `
		) sev ON true
		LEFT JOIN LATERAL (
			SELECT s.id, s.status, s.created_at, s.finished_at FROM scan s
			WHERE s.project_id = p.id ORDER BY s.created_at DESC, s.id DESC LIMIT 1
		) ls ON true
		WHERE p.org_id = ` + a.add(v.OrgID) + ` AND p.archived_at IS NULL`
	if !v.All {
		q += ` AND pm.user_id IS NOT NULL`
	}
	if projectID != nil {
		q += ` AND p.id = ` + a.add(*projectID)
	}
	return q + ` ORDER BY p.key`, a
}

func scanProject(row pgx.CollectableRow) (service.Project, error) {
	var (
		p                   service.Project
		role                *string
		lsID                *uuid.UUID
		lsStatus            *string
		lsCreated, lsFinish *service.Time
	)
	err := row.Scan(&p.ID, &p.Key, &p.Name, &p.Description, &p.DefaultTools, &role, &p.CreatedAt,
		&p.OpenBySeverity.Critical, &p.OpenBySeverity.High, &p.OpenBySeverity.Medium, &p.OpenBySeverity.Low,
		&p.OpenBySeverity.Info, &p.PastSLA, &lsID, &lsStatus, &lsCreated, &lsFinish)
	if role != nil {
		r := rbac.Role(*role)
		p.MyRole = &r
	}
	if lsID != nil && lsStatus != nil && lsCreated != nil {
		p.LastScan = &service.LastScan{ID: *lsID, Status: *lsStatus, CreatedAt: *lsCreated, FinishedAt: lsFinish}
	}
	if p.DefaultTools == nil {
		p.DefaultTools = []string{}
	}
	return p, err
}

func (r *Repo) Projects(ctx context.Context, v service.Visibility, now time.Time) ([]service.Project, error) {
	q, a := projectQuery(v, nil, now)
	rows, _ := r.tx.Query(ctx, q, a...)
	return collect(rows, scanProject)
}

func (r *Repo) Project(ctx context.Context, v service.Visibility, projectID uuid.UUID, now time.Time) (service.Project, error) {
	q, a := projectQuery(v, &projectID, now)
	rows, _ := r.tx.Query(ctx, q, a...)
	p, err := pgx.CollectExactlyOneRow(rows, scanProject)
	return p, mapErr(err)
}

func (r *Repo) ProjectRole(ctx context.Context, projectID, userID uuid.UUID) (rbac.Role, error) {
	var role *string
	err := r.tx.QueryRow(ctx, `SELECT (SELECT pm.role::text FROM project_member pm WHERE pm.project_id = p.id AND pm.user_id = $2)
		FROM project p WHERE p.id = $1 AND p.archived_at IS NULL`, projectID, userID).Scan(&role)
	if err != nil || role == nil {
		return "", mapErr(err)
	}
	return rbac.Role(*role), nil
}

func (r *Repo) InsertProject(ctx context.Context, p service.NewProject) error {
	_, err := r.tx.Exec(ctx, `INSERT INTO project (id, org_id, key, name, description, default_tools)
		VALUES ($1, $2, $3, $4, $5, $6)`, p.ID, p.OrgID, p.Key, p.Name, p.Description, p.DefaultTools)
	return mapErr(err)
}

func (r *Repo) ProjectMembers(ctx context.Context, projectID uuid.UUID) ([]service.ProjectMember, error) {
	rows, _ := r.tx.Query(ctx, `SELECT u.id, u.email::text, u.display_name, pm.role::text FROM project_member pm
		JOIN app_user u ON u.id = pm.user_id WHERE pm.project_id = $1 ORDER BY u.display_name, u.email`, projectID)
	return collect(rows, func(row pgx.CollectableRow) (service.ProjectMember, error) {
		var m service.ProjectMember
		err := row.Scan(&m.User.ID, &m.User.Email, &m.User.DisplayName, (*string)(&m.Role))
		return m, err
	})
}

func (r *Repo) UpsertProjectMember(ctx context.Context, orgID, projectID, userID uuid.UUID, role rbac.Role) error {
	_, err := r.tx.Exec(ctx, `INSERT INTO project_member (org_id, project_id, user_id, role) VALUES ($1, $2, $3, $4::project_role)
		ON CONFLICT (project_id, user_id) DO UPDATE SET role = EXCLUDED.role`, orgID, projectID, userID, string(role))
	return mapErr(err)
}

func (r *Repo) DeleteProjectMember(ctx context.Context, projectID, userID uuid.UUID) (bool, error) {
	tag, err := r.tx.Exec(ctx, `DELETE FROM project_member WHERE project_id = $1 AND user_id = $2`, projectID, userID)
	return tag.RowsAffected() > 0, mapErr(err)
}

func (r *Repo) OwnsAnyProject(ctx context.Context, userID uuid.UUID) (bool, error) {
	var ok bool
	err := r.tx.QueryRow(ctx, `SELECT EXISTS (SELECT 1 FROM project_member pm JOIN project p ON p.id = pm.project_id
		WHERE pm.user_id = $1 AND pm.role = 'owner' AND p.archived_at IS NULL)`, userID).Scan(&ok)
	return ok, mapErr(err)
}

// Scans.

func (r *Repo) LockScanRate(ctx context.Context, userID uuid.UUID) error {
	_, err := r.tx.Exec(ctx, `SELECT pg_advisory_xact_lock(hashtextextended('warden.scan_rate:' || $1::text, 0))`, userID)
	return err
}

func (r *Repo) ScansSince(ctx context.Context, userID uuid.UUID, since time.Time) (int, time.Time, error) {
	var (
		n      int
		oldest *time.Time
	)
	err := r.tx.QueryRow(ctx, `SELECT count(*), min(created_at) FROM scan WHERE created_by = $1 AND created_at > $2`,
		userID, since).Scan(&n, &oldest)
	if oldest == nil {
		return n, time.Time{}, mapErr(err)
	}
	return n, *oldest, mapErr(err)
}

func (r *Repo) InsertScan(ctx context.Context, s service.NewScan) error {
	_, err := r.tx.Exec(ctx, `INSERT INTO scan (id, org_id, project_id, created_by, status, file_name, object_key, file_size, sha256, tools)
		VALUES ($1, $2, $3, $4, 'pending_upload', $5, $6, $7, $8, $9)`,
		s.ID, s.OrgID, s.ProjectID, s.CreatedBy, s.FileName, s.ObjectKey, s.FileSize, s.SHA256, s.Tools)
	return mapErr(err)
}

const scanSelect = `SELECT s.id, s.org_id, s.project_id, s.status::text, s.file_name, coalesce(s.file_size, 0), s.tools,
	s.error_code, s.stats, s.created_at, s.queued_at, s.started_at, s.finished_at,
	coalesce(s.object_key, ''), coalesce(s.sha256, ''), u.id, u.email::text, u.display_name
	FROM scan s JOIN app_user u ON u.id = s.created_by`

func scanScan(row pgx.CollectableRow) (service.Scan, error) {
	var s service.Scan
	err := row.Scan(&s.ID, &s.OrgID, &s.ProjectID, &s.Status, &s.FileName, &s.FileSize, &s.Tools,
		&s.ErrorCode, &s.Stats, &s.CreatedAt, &s.QueuedAt, &s.StartedAt, &s.FinishedAt,
		&s.ObjectKey, &s.SHA256, &s.CreatedBy.ID, &s.CreatedBy.Email, &s.CreatedBy.DisplayName)
	if s.Tools == nil {
		s.Tools = []string{}
	}
	return s, err
}

func (r *Repo) Scan(ctx context.Context, scanID uuid.UUID, forUpdate bool) (service.Scan, error) {
	q := scanSelect + ` WHERE s.id = $1`
	if forUpdate {
		q += ` FOR UPDATE OF s`
	}
	rows, _ := r.tx.Query(ctx, q, scanID)
	s, err := pgx.CollectExactlyOneRow(rows, scanScan)
	return s, mapErr(err)
}

func (r *Repo) Scans(ctx context.Context, projectID uuid.UUID, after *service.ScanCursor, limit int) ([]service.Scan, error) {
	var a args
	q := scanSelect + ` WHERE s.project_id = ` + a.add(projectID)
	if after != nil {
		q += ` AND (s.created_at, s.id) < (` + a.add(after.CreatedAt) + `, ` + a.add(after.ID) + `)`
	}
	q += ` ORDER BY s.created_at DESC, s.id DESC LIMIT ` + a.add(limit)
	rows, _ := r.tx.Query(ctx, q, a...)
	return collect(rows, scanScan)
}

func (r *Repo) ToolRuns(ctx context.Context, scanID uuid.UUID) ([]service.ToolRun, error) {
	rows, _ := r.tx.Query(ctx, `SELECT tool, tool_version, status::text, findings_count, duration_ms, error
		FROM scan_tool_run WHERE scan_id = $1 ORDER BY tool`, scanID)
	return collect(rows, func(row pgx.CollectableRow) (service.ToolRun, error) {
		var t service.ToolRun
		err := row.Scan(&t.Tool, &t.ToolVersion, &t.Status, &t.FindingsCount, &t.DurationMS, &t.Error)
		return t, err
	})
}

func (r *Repo) MarkScanQueued(ctx context.Context, scanID uuid.UUID) error {
	_, err := r.tx.Exec(ctx, `UPDATE scan SET status = 'queued', queued_at = now() WHERE id = $1`, scanID)
	return mapErr(err)
}

func (r *Repo) MarkScanCancelled(ctx context.Context, scanID uuid.UUID) error {
	_, err := r.tx.Exec(ctx, `UPDATE scan SET status = 'cancelled', finished_at = now() WHERE id = $1`, scanID)
	return mapErr(err)
}
