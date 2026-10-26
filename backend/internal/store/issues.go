package store

import (
	"context"
	"errors"
	"strings"
	"time"

	"github.com/google/uuid"
	"github.com/jackc/pgx/v5"

	"github.com/aupv9/warden/backend/internal/service"
	"github.com/aupv9/warden/backend/internal/worker"
)

func (r *Repo) EnqueueScan(ctx context.Context, job worker.ScanArgs) error {
	if r.river == nil {
		return errors.New("job queue not configured")
	}
	_, err := r.river.InsertTx(ctx, r.tx, job, nil)
	return err
}

// issueSummaryCols needs the past-due timestamp as its first parameter.
func issueSummaryCols(now string) string {
	return `i.id, p.key || '-' || i.number, i.project_id, i.title, i.severity::text, i.status::text, i.tool, i.rule_id,
		i.file_path, i.start_line, i.package_name, i.package_version, i.fixed_version,
		au.id, au.email::text, au.display_name, i.due_at,
		(i.due_at IS NOT NULL AND i.due_at < ` + now + ` AND i.status IN ` + activeStatuses + `), i.updated_at`
}

const issueFrom = ` FROM issue i JOIN project p ON p.id = i.project_id LEFT JOIN app_user au ON au.id = i.assignee_id`

func summaryDest(s *service.IssueSummary, aID **uuid.UUID, aEmail, aName **string) []any {
	return []any{&s.ID, &s.Key, &s.ProjectID, &s.Title, &s.Severity, &s.Status, &s.Tool, &s.RuleID,
		&s.FilePath, &s.StartLine, &s.PackageName, &s.PackageVersion, &s.FixedVersion,
		aID, aEmail, aName, &s.DueAt, &s.PastSLA, &s.UpdatedAt}
}

func scanSummary(row pgx.CollectableRow) (service.IssueSummary, error) {
	var (
		s             service.IssueSummary
		aID           *uuid.UUID
		aEmail, aName *string
	)
	err := row.Scan(summaryDest(&s, &aID, &aEmail, &aName)...)
	s.Assignee = userRef(aID, aEmail, aName)
	return s, err
}

// likePattern escapes LIKE wildcards so user text matches literally.
func likePattern(s string) string {
	r := strings.NewReplacer(`\`, `\\`, `%`, `\%`, `_`, `\_`)
	return "%" + r.Replace(s) + "%"
}

// issueWhere builds the filter shared by the list and the severity counts.
func issueWhere(a *args, q service.IssueQuery) string {
	w := []string{`p.org_id = ` + a.add(q.Vis.OrgID), `p.archived_at IS NULL`, visible(a, q.Vis)}
	if q.ProjectID != nil {
		w = append(w, `i.project_id = `+a.add(*q.ProjectID))
	}
	if len(q.Statuses) > 0 {
		w = append(w, `i.status = ANY(`+a.add(q.Statuses)+`::issue_status[])`)
	}
	if len(q.Severities) > 0 {
		w = append(w, `i.severity = ANY(`+a.add(q.Severities)+`::severity[])`)
	}
	if q.AssigneeNone {
		w = append(w, `i.assignee_id IS NULL`)
	} else if q.AssigneeID != nil {
		w = append(w, `i.assignee_id = `+a.add(*q.AssigneeID))
	}
	if q.Tool != "" {
		w = append(w, `i.tool = `+a.add(q.Tool))
	}
	if q.PastSLA {
		w = append(w, `i.due_at < `+a.add(q.Now)+` AND i.status IN `+activeStatuses)
	}
	if q.KeyProject != "" {
		w = append(w, `p.key = `+a.add(q.KeyProject)+` AND i.number = `+a.add(q.KeyNumber))
	} else if q.Text != "" {
		pat := a.add(likePattern(q.Text))
		w = append(w, `(i.title ILIKE `+pat+` OR i.rule_id ILIKE `+pat+` OR i.file_path ILIKE `+pat+`)`)
	}
	if c := q.After; c != nil {
		id := a.add(c.ID)
		switch c.Sort {
		case service.SortDueAt:
			if c.DueAt == nil {
				w = append(w, `(i.due_at IS NULL AND i.id > `+id+`)`)
			} else {
				d := a.add(*c.DueAt)
				w = append(w, `(i.due_at > `+d+` OR i.due_at IS NULL OR (i.due_at = `+d+` AND i.id > `+id+`))`)
			}
		case service.SortSeverity:
			w = append(w, `(i.severity, i.id) > (`+a.add(c.Severity)+`::severity, `+id+`)`)
		case service.SortUpdatedAt:
			w = append(w, `(i.updated_at, i.id) < (`+a.add(c.UpdatedAt)+`, `+id+`)`)
		}
	}
	return " WHERE " + strings.Join(w, " AND ")
}

func issueOrder(sort string) string {
	switch sort {
	case service.SortSeverity:
		return ` ORDER BY i.severity ASC, i.id ASC` // enum order: critical first
	case service.SortUpdatedAt:
		return ` ORDER BY i.updated_at DESC, i.id DESC`
	default:
		return ` ORDER BY i.due_at ASC NULLS LAST, i.id ASC`
	}
}

// buildIssueList returns the issue list query for q.
func buildIssueList(q service.IssueQuery) (string, args) {
	var a args
	cols := issueSummaryCols(a.add(q.Now))
	sql := `SELECT ` + cols + issueFrom + issueWhere(&a, q) + issueOrder(q.Sort) + ` LIMIT ` + a.add(q.Limit)
	return sql, a
}

// buildIssueCounts counts q's matches per severity.
func buildIssueCounts(q service.IssueQuery) (string, args) {
	var a args
	return `SELECT i.severity::text, count(*)` + issueFrom + issueWhere(&a, q) + ` GROUP BY 1`, a
}

func (r *Repo) Issues(ctx context.Context, q service.IssueQuery) ([]service.IssueSummary, error) {
	sql, a := buildIssueList(q)
	rows, _ := r.tx.Query(ctx, sql, a...)
	return collect(rows, scanSummary)
}

func (r *Repo) IssueCounts(ctx context.Context, q service.IssueQuery) (service.SeverityCounts, error) {
	var c service.SeverityCounts
	sql, a := buildIssueCounts(q)
	rows, _ := r.tx.Query(ctx, sql, a...)
	var (
		sev string
		n   int
	)
	_, err := pgx.ForEachRow(rows, []any{&sev, &n}, func() error {
		c.Add(sev, n)
		return nil
	})
	return c, err
}

func (r *Repo) Issue(ctx context.Context, issueID uuid.UUID, forUpdate bool, now time.Time) (service.Issue, error) {
	q := `SELECT ` + issueSummaryCols("$2") + `, i.description, i.remediation, i.snippet, i.end_line, i.cwe, i.cve,
			fs.id, fs.created_at, ls.id, ls.created_at,
			(SELECT count(*) FROM occurrence o WHERE o.issue_id = i.id), i.version, i.assignee_id, i.number, p.key` +
		issueFrom + ` JOIN scan fs ON fs.id = i.first_seen_scan_id JOIN scan ls ON ls.id = i.last_seen_scan_id
		WHERE i.id = $1`
	if forUpdate {
		q += ` FOR UPDATE OF i`
	}
	var (
		iss           service.Issue
		aID           *uuid.UUID
		aEmail, aName *string
	)
	dest := append(summaryDest(&iss.IssueSummary, &aID, &aEmail, &aName),
		&iss.Description, &iss.Remediation, &iss.Snippet, &iss.EndLine, &iss.CWE, &iss.CVE,
		&iss.FirstSeenScan.ID, &iss.FirstSeenScan.CreatedAt, &iss.LastSeenScan.ID, &iss.LastSeenScan.CreatedAt,
		&iss.Occurrences, &iss.Version, &iss.AssigneeID, &iss.Number, &iss.ProjectKey)
	err := r.tx.QueryRow(ctx, q, issueID, now).Scan(dest...)
	iss.Assignee = userRef(aID, aEmail, aName)
	return iss, mapErr(err)
}

func (r *Repo) UpdateIssueState(ctx context.Context, issueID uuid.UUID, status string, assignee *uuid.UUID) error {
	_, err := r.tx.Exec(ctx, `UPDATE issue SET status = $2::issue_status, assignee_id = $3, version = version + 1, updated_at = now()
		WHERE id = $1`, issueID, status, assignee)
	return mapErr(err)
}

func (r *Repo) InsertIssueEvent(ctx context.Context, e service.NewEvent) error {
	_, err := r.tx.Exec(ctx, `INSERT INTO issue_event (org_id, issue_id, actor_id, type, from_value, to_value, note)
		VALUES ($1, $2, $3, $4, $5, $6, $7)`, e.OrgID, e.IssueID, e.ActorID, e.Type, e.From, e.To, e.Note)
	return mapErr(err)
}

func (r *Repo) IssueEvents(ctx context.Context, issueID uuid.UUID, limit int) ([]service.Event, error) {
	rows, _ := r.tx.Query(ctx, `SELECT e.id, e.type, au.id, au.email::text, au.display_name, e.from_value, e.to_value, e.note, e.created_at
		FROM issue_event e LEFT JOIN app_user au ON au.id = e.actor_id
		WHERE e.issue_id = $1 ORDER BY e.created_at DESC, e.id DESC LIMIT $2`, issueID, limit)
	return collect(rows, func(row pgx.CollectableRow) (service.Event, error) {
		var (
			e             service.Event
			aID           *uuid.UUID
			aEmail, aName *string
		)
		err := row.Scan(&e.ID, &e.Type, &aID, &aEmail, &aName, &e.FromValue, &e.ToValue, &e.Note, &e.CreatedAt)
		e.Actor = userRef(aID, aEmail, aName)
		return e, err
	})
}

const commentSelect = `SELECT c.id, u.id, u.email::text, u.display_name, c.body, c.created_at, c.edited_at
	FROM comment c JOIN app_user u ON u.id = c.author_id`

func scanComment(row pgx.CollectableRow) (service.Comment, error) {
	var c service.Comment
	err := row.Scan(&c.ID, &c.Author.ID, &c.Author.Email, &c.Author.DisplayName, &c.Body, &c.CreatedAt, &c.EditedAt)
	return c, err
}

func (r *Repo) Comments(ctx context.Context, issueID uuid.UUID) ([]service.Comment, error) {
	rows, _ := r.tx.Query(ctx, commentSelect+` WHERE c.issue_id = $1 ORDER BY c.created_at, c.id`, issueID)
	return collect(rows, scanComment)
}

func (r *Repo) Comment(ctx context.Context, id uuid.UUID) (service.Comment, error) {
	rows, _ := r.tx.Query(ctx, commentSelect+` WHERE c.id = $1`, id)
	c, err := pgx.CollectExactlyOneRow(rows, scanComment)
	return c, mapErr(err)
}

func (r *Repo) InsertComment(ctx context.Context, c service.NewComment) error {
	_, err := r.tx.Exec(ctx, `INSERT INTO comment (id, org_id, issue_id, author_id, body) VALUES ($1, $2, $3, $4, $5)`,
		c.ID, c.OrgID, c.IssueID, c.AuthorID, c.Body)
	return mapErr(err)
}

func (r *Repo) PendingExceptionID(ctx context.Context, issueID uuid.UUID) (*uuid.UUID, error) {
	var id uuid.UUID
	err := r.tx.QueryRow(ctx, `SELECT id FROM exception_request WHERE issue_id = $1 AND status = 'pending'`, issueID).Scan(&id)
	if errors.Is(err, pgx.ErrNoRows) {
		return nil, nil
	}
	if err != nil {
		return nil, err
	}
	return &id, nil
}
