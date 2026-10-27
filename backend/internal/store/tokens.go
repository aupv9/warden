package store

import (
	"context"
	"strings"
	"time"

	"github.com/google/uuid"
	"github.com/jackc/pgx/v5"

	"github.com/aupv9/warden/backend/internal/service"
)

// API tokens. Lookup by prefix is the only query that crosses orgs, and it goes
// through warden_lookup_token (SECURITY DEFINER, see 00003_api_tokens.sql);
// every other query runs under the token's or the caller's app.org_id.

func (r *Repo) LookupToken(ctx context.Context, prefix string) (service.TokenRecord, error) {
	var t service.TokenRecord
	err := r.tx.QueryRow(ctx, `SELECT id, org_id, project_id, user_id, token_hash, scopes, expires_at, revoked_at
		FROM warden_lookup_token($1)`, prefix).
		Scan(&t.ID, &t.OrgID, &t.ProjectID, &t.UserID, &t.Hash, &t.Scopes, &t.ExpiresAt, &t.RevokedAt)
	t.Hash = strings.TrimSpace(t.Hash)
	return t, mapErr(err)
}

func (r *Repo) UserByID(ctx context.Context, userID uuid.UUID) (service.User, error) {
	return scanUser(r.tx.QueryRow(ctx, `SELECT `+userCols+` FROM app_user WHERE id = $1`, userID))
}

// TouchToken updates last_used_at at most once a minute, so a busy pipeline
// doesn't turn every request into a write on the same row.
func (r *Repo) TouchToken(ctx context.Context, tokenID uuid.UUID, now time.Time) error {
	_, err := r.tx.Exec(ctx, `UPDATE api_token SET last_used_at = $2
		WHERE id = $1 AND (last_used_at IS NULL OR last_used_at <= $2::timestamptz - interval '1 minute')`, tokenID, now)
	return mapErr(err)
}

func (r *Repo) InsertToken(ctx context.Context, t service.NewToken) error {
	_, err := r.tx.Exec(ctx, `INSERT INTO api_token (id, org_id, project_id, user_id, created_by, name, prefix, token_hash, scopes, expires_at)
		VALUES ($1, $2, $3, $4, $4, $5, $6, $7, $8, $9)`,
		t.ID, t.OrgID, t.ProjectID, t.CreatedBy, t.Name, t.Prefix, t.Hash, t.Scopes, t.ExpiresAt)
	return mapErr(err)
}

const tokenSelect = `SELECT t.id, t.name, t.prefix::text, t.scopes, u.id, u.email::text, u.display_name,
	t.created_at, t.expires_at, t.last_used_at, t.revoked_at
	FROM api_token t JOIN app_user u ON u.id = t.created_by`

func scanToken(row pgx.CollectableRow) (service.ApiToken, error) {
	var t service.ApiToken
	err := row.Scan(&t.ID, &t.Name, &t.Prefix, &t.Scopes, &t.CreatedBy.ID, &t.CreatedBy.Email, &t.CreatedBy.DisplayName,
		&t.CreatedAt, &t.ExpiresAt, &t.LastUsedAt, &t.RevokedAt)
	if t.Scopes == nil {
		t.Scopes = []string{}
	}
	return t, err
}

func (r *Repo) Tokens(ctx context.Context, projectID uuid.UUID) ([]service.ApiToken, error) {
	rows, _ := r.tx.Query(ctx, tokenSelect+` WHERE t.project_id = $1 ORDER BY t.created_at DESC, t.id DESC`, projectID)
	return collect(rows, scanToken)
}

func (r *Repo) Token(ctx context.Context, projectID, tokenID uuid.UUID) (service.ApiToken, error) {
	rows, _ := r.tx.Query(ctx, tokenSelect+` WHERE t.project_id = $1 AND t.id = $2`, projectID, tokenID)
	t, err := pgx.CollectExactlyOneRow(rows, scanToken)
	return t, mapErr(err)
}

func (r *Repo) RevokeToken(ctx context.Context, tokenID uuid.UUID, at time.Time) error {
	_, err := r.tx.Exec(ctx, `UPDATE api_token SET revoked_at = $2 WHERE id = $1 AND revoked_at IS NULL`, tokenID, at)
	return mapErr(err)
}

// Scan gate. "Seen in this scan" means the issue has an occurrence for it.

const seenInScan = ` JOIN occurrence o ON o.issue_id = i.id AND o.scan_id = `

func (r *Repo) ScanIssueCounts(ctx context.Context, scanID uuid.UUID) (service.SeverityCounts, int, error) {
	var c service.SeverityCounts
	rows, _ := r.tx.Query(ctx, `SELECT i.severity::text, count(*), count(*) FILTER (WHERE `+kevExists+`)
		FROM issue i`+seenInScan+`$1 WHERE i.status IN `+activeStatuses+` GROUP BY 1`, scanID)
	var (
		sev        string
		n, k, kevs int
	)
	_, err := pgx.ForEachRow(rows, []any{&sev, &n, &k}, func() error {
		c.Add(sev, n)
		kevs += k
		return nil
	})
	return c, kevs, err
}

func (r *Repo) ScanIssues(ctx context.Context, scanID uuid.UUID, severities []string, kev bool, now time.Time, limit int) ([]service.IssueSummary, error) {
	var a args
	cols := issueSummaryCols(a.add(now))
	match := `i.severity = ANY(` + a.add(severities) + `::severity[])`
	if kev {
		match = `(` + match + ` OR vi.kev)`
	}
	q := `SELECT ` + cols + issueFrom + seenInScan + a.add(scanID) + `
		WHERE i.status IN ` + activeStatuses + ` AND ` + match + `
		ORDER BY i.severity ASC, i.number ASC LIMIT ` + a.add(limit)
	rows, _ := r.tx.Query(ctx, q, a...)
	return collect(rows, scanSummary)
}
