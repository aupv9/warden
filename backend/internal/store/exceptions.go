package store

import (
	"context"
	"strings"

	"github.com/google/uuid"
	"github.com/jackc/pgx/v5"

	"github.com/aupv9/warden/backend/internal/service"
)

func (r *Repo) InsertException(ctx context.Context, e service.NewException) error {
	_, err := r.tx.Exec(ctx, `INSERT INTO exception_request (id, org_id, issue_id, type, reason, requested_by, expires_at, created_at)
		VALUES ($1, $2, $3, $4::exception_type, $5, $6, $7, $8)`,
		e.ID, e.OrgID, e.IssueID, e.Type, e.Reason, e.RequestedBy, e.ExpiresAt, e.CreatedAt)
	return mapErr(err)
}

const exceptionSelect = `SELECT e.id, e.org_id, e.issue_id, e.requested_by,
	i.id, p.key || '-' || i.number, i.title, i.severity::text, i.status::text,
	e.type::text, e.reason, e.status::text, ru.id, ru.email::text, ru.display_name,
	du.id, du.email::text, du.display_name, e.decision_note, e.expires_at, e.decided_at, e.created_at
	FROM exception_request e JOIN issue i ON i.id = e.issue_id JOIN project p ON p.id = i.project_id
	JOIN app_user ru ON ru.id = e.requested_by LEFT JOIN app_user du ON du.id = e.decided_by`

func scanException(row pgx.CollectableRow) (service.ExceptionMeta, error) {
	var (
		e             service.ExceptionMeta
		dID           *uuid.UUID
		dEmail, dName *string
	)
	x := &e.ExceptionRequest
	err := row.Scan(&x.ID, &e.OrgID, &e.IssueID, &e.RequestedByID,
		&x.Issue.ID, &x.Issue.Key, &x.Issue.Title, &x.Issue.Severity, &x.Issue.Status,
		&x.Type, &x.Reason, &x.Status, &x.RequestedBy.ID, &x.RequestedBy.Email, &x.RequestedBy.DisplayName,
		&dID, &dEmail, &dName, &x.DecisionNote, &x.ExpiresAt, &x.DecidedAt, &x.CreatedAt)
	x.DecidedBy = userRef(dID, dEmail, dName)
	return e, err
}

func (r *Repo) Exception(ctx context.Context, id uuid.UUID, forUpdate bool) (service.ExceptionMeta, error) {
	q := exceptionSelect + ` WHERE e.id = $1`
	if forUpdate {
		q += ` FOR UPDATE OF e`
	}
	rows, _ := r.tx.Query(ctx, q, id)
	e, err := pgx.CollectExactlyOneRow(rows, scanException)
	return e, mapErr(err)
}

// buildExceptionList returns the exception list query for q.
func buildExceptionList(q service.ExceptionQuery) (string, args) {
	var a args
	var w []string
	switch q.Status {
	case "pending", "approved", "rejected":
		w = append(w, `e.status = `+a.add(q.Status)+`::exception_status`)
	case "expiring":
		now := a.add(q.Now)
		w = append(w, `e.status = 'approved' AND e.type = 'risk_accepted' AND e.expires_at > `+now+
			` AND e.expires_at <= `+now+` + interval '14 days'`)
	}
	if q.RequestedBy != nil {
		w = append(w, `e.requested_by = `+a.add(*q.RequestedBy))
	}
	if q.After != nil {
		w = append(w, `(e.created_at, e.id) < (`+a.add(q.After.CreatedAt)+`, `+a.add(q.After.ID)+`)`)
	}
	sql := exceptionSelect
	if len(w) > 0 {
		sql += ` WHERE ` + strings.Join(w, " AND ")
	}
	return sql + ` ORDER BY e.created_at DESC, e.id DESC LIMIT ` + a.add(q.Limit), a
}

func (r *Repo) Exceptions(ctx context.Context, q service.ExceptionQuery) ([]service.ExceptionRequest, error) {
	sql, a := buildExceptionList(q)
	rows, _ := r.tx.Query(ctx, sql, a...)
	return collect(rows, func(row pgx.CollectableRow) (service.ExceptionRequest, error) {
		e, err := scanException(row)
		return e.ExceptionRequest, err
	})
}

func (r *Repo) DecideException(ctx context.Context, d service.Decision) error {
	_, err := r.tx.Exec(ctx, `UPDATE exception_request SET status = $2::exception_status, decided_by = $3, decided_at = now(),
		decision_note = $4, expires_at = coalesce($5, expires_at) WHERE id = $1`,
		d.ID, d.Status, d.DecidedBy, d.Note, d.ExpiresAt)
	return mapErr(err)
}
