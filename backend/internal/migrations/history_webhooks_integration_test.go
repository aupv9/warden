//go:build integration

package migrations_test

import (
	"context"
	"database/sql"
	"fmt"
	"os"
	"strings"
	"testing"

	"github.com/google/uuid"
	"github.com/jackc/pgx/v5"
	"github.com/pressly/goose/v3"

	"github.com/aupv9/warden/backend/internal/db"
)

// appExec runs one statement as warden_app in org and returns its error.
func appExec(t *testing.T, org uuid.UUID, stmt string, args ...any) error {
	t.Helper()
	return db.WithOrg(context.Background(), appPool(t), org, func(tx pgx.Tx) error {
		_, err := tx.Exec(context.Background(), stmt, args...)
		return err
	})
}

func seedUserProject(t *testing.T, key string) (org, user, project uuid.UUID) {
	t.Helper()
	org, user, project = uuid.New(), uuid.New(), uuid.New()
	ownerExec(t, org,
		fmt.Sprintf("INSERT INTO organization (id, name) VALUES ('%s', '%s')", org, key),
		fmt.Sprintf("INSERT INTO app_user (id, keycloak_sub, email, display_name) VALUES ('%s', '%s', '%s@x.test', 'u')", user, user, user),
		fmt.Sprintf("INSERT INTO project (id, org_id, key, name) VALUES ('%s', '%s', '%s', 'p')", project, org, key),
	)
	return org, user, project
}

// 00011: a history scan has target (history) and runs Gitleaks only; history
// stats and commit fields can't appear on anything else.
func TestHistoryScanConstraints(t *testing.T) {
	org, user, project := seedUserProject(t, "HIS")
	scan := func(kind, target, tools, extra string) error {
		cols, vals := "", ""
		if extra != "" {
			cols, vals = ", history_commits, history_truncated", ", "+extra
		}
		return appExec(t, org, fmt.Sprintf(`INSERT INTO scan (id, org_id, project_id, created_by, file_name, tools, kind, target%s)
			VALUES ($1, $2, $3, $4, 'r.bundle', $5, $6, $7%s)`, cols, vals), uuid.New(), org, project, user, tools, kind, target)
	}
	if err := scan("history", "(history)", "{gitleaks}", "120, false"); err != nil {
		t.Fatal(err)
	}
	for _, c := range []struct{ kind, target, tools, extra string }{
		{"history", "", "{gitleaks}", ""},
		{"history", "ghcr.io/acme/api", "{gitleaks}", ""},
		{"history", "(history)", "{gitleaks,trivy}", ""},
		{"image", "(history)", "{trivy}", ""},
		{"source", "", "{gitleaks}", "3, false"},
		{"history", "(history)", "{gitleaks}", "3, NULL"},
		{"weird", "(history)", "{gitleaks}", ""},
	} {
		if err := scan(c.kind, c.target, c.tools, c.extra); pgCode(err) != checkViolation {
			t.Errorf("%+v: got %v", c, err)
		}
	}

	scanID := uuid.New()
	ownerExec(t, org, fmt.Sprintf(`INSERT INTO scan (id, org_id, project_id, created_by, file_name, tools, kind, target)
		VALUES ('%s', '%s', '%s', '%s', 'r.bundle', '{gitleaks}', 'history', '(history)')`, scanID, org, project, user))
	n := 0
	issue := func(target, sha string, count any) error {
		n++
		return appExec(t, org, `INSERT INTO issue (id, org_id, project_id, number, fingerprint, tool, rule_id, title, severity,
			first_seen_scan_id, last_seen_scan_id, target, commit_sha, commit_count) VALUES ($1, $2, $3, $4, $5, 'gitleaks', 'aws', 't', 'high', $6, $6, $7, $8, $9)`,
			uuid.New(), org, project, n, fmt.Sprintf("%064d", n), scanID, target, sha, count)
	}
	sha1, sha256 := fmt.Sprintf("%040x", 1), fmt.Sprintf("%064x", 1)
	if err := issue("(history)", sha1, 3); err != nil {
		t.Fatal(err)
	}
	if err := issue("(history)", sha256, 1); err != nil {
		t.Fatal(err)
	}
	for _, c := range []struct {
		target, sha string
		count       any
	}{
		{"", sha1, 1},                             // source issue with a commit
		{"(history)", sha1, nil},                  // sha without count
		{"(history)", sha1, 0},                    // count below 1
		{"(history)", "ABCDEF" + sha1[6:], 1},     // upper case
		{"(history)", sha1[:39], 1},               // short
		{"(history)", sha1 + "; DROP TABLE x", 1}, // not a sha
	} {
		if err := issue(c.target, c.sha, c.count); pgCode(err) != checkViolation {
			t.Errorf("%+v: got %v", c, err)
		}
	}
}

// 00012: a generic webhook has an encrypted secret and a Slack one none; a
// disabled reason needs the webhook off; one delivery per (webhook, event); a
// pending delivery has a next attempt; deliveries go with their webhook.
func TestWebhookConstraints(t *testing.T) {
	org, user, _ := seedUserProject(t, "WHK")
	webhook := func(kind, secret string, enabled bool, reason any) (uuid.UUID, error) {
		id := uuid.New()
		var enc any
		if secret != "" {
			enc = []byte(secret)
		}
		return id, appExec(t, org, `INSERT INTO webhook (id, org_id, kind, name, url_hint, url_enc, secret_enc, key_id, events, enabled, disabled_reason, created_by)
			VALUES ($1, $2, $3, 'n', 'https://example.test', '\x00'::bytea, $4, 'k1', '{scan.finished}', $5, $6, $7)`,
			id, org, kind, enc, enabled, reason, user)
	}
	generic, err := webhook("generic", "ciphertext", true, nil)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := webhook("slack", "", false, "failures"); err != nil {
		t.Fatal(err)
	}
	for _, c := range []struct {
		kind, secret string
		enabled      bool
		reason       any
	}{
		{"generic", "", true, nil},
		{"slack", "ciphertext", true, nil},
		{"generic", "ciphertext", true, "failures"},
		{"generic", "ciphertext", false, "bored"},
		{"teams", "", true, nil},
	} {
		if _, err := webhook(c.kind, c.secret, c.enabled, c.reason); pgCode(err) != checkViolation {
			t.Errorf("%+v: got %v", c, err)
		}
	}

	var event int64
	err = db.WithOrg(context.Background(), appPool(t), org, func(tx pgx.Tx) error {
		return tx.QueryRow(context.Background(), `INSERT INTO outbox_event (org_id, type, payload) VALUES ($1, 'scan.finished', '{}') RETURNING id`, org).Scan(&event)
	})
	if err != nil {
		t.Fatal(err)
	}
	delivery := func(event any, state string, next any) error {
		return appExec(t, org, `INSERT INTO webhook_delivery (id, org_id, webhook_id, event_id, type, payload, state, next_at)
			VALUES ($1, $2, $3, $4, 'scan.finished', '{}', $5, $6)`, uuid.New(), org, generic, event, state, next)
	}
	if err := delivery(event, "pending", "2026-01-01T00:00:00Z"); err != nil {
		t.Fatal(err)
	}
	if err := delivery(event, "pending", "2026-01-01T00:00:00Z"); pgCode(err) != "23505" {
		t.Errorf("duplicate delivery: got %v", err)
	}
	if err := delivery(nil, "delivered", nil); err != nil { // tests have no event, and may repeat
		t.Fatal(err)
	}
	if err := delivery(nil, "pending", nil); pgCode(err) != checkViolation {
		t.Errorf("pending without next_at: got %v", err)
	}
	if err := delivery(nil, "delivered", "2026-01-01T00:00:00Z"); pgCode(err) != checkViolation {
		t.Errorf("delivered with next_at: got %v", err)
	}

	if err := appExec(t, org, "DELETE FROM webhook WHERE id = $1", generic); err != nil {
		t.Fatal(err)
	}
	var left int
	err = db.WithOrg(context.Background(), appPool(t), org, func(tx pgx.Tx) error {
		return tx.QueryRow(context.Background(), "SELECT count(*) FROM webhook_delivery WHERE webhook_id = $1", generic).Scan(&left)
	})
	if err != nil || left != 0 {
		t.Fatal(left, err)
	}

	// Another org sees none of them.
	other, _, _ := seedUserProject(t, "WHL")
	var seen int
	err = db.WithOrg(context.Background(), appPool(t), other, func(tx pgx.Tx) error {
		return tx.QueryRow(context.Background(), "SELECT (SELECT count(*) FROM webhook) + (SELECT count(*) FROM webhook_delivery)").Scan(&seen)
	})
	if err != nil || seen != 0 {
		t.Fatal(seen, err)
	}
}

// 00011 and 00012 go down and up again cleanly on an empty database.
func TestWave2MigrationsDownUp(t *testing.T) {
	ctx := context.Background()
	if _, err := connect(t, ownerURL).Exec(ctx, `CREATE DATABASE downup_v04`); err != nil {
		t.Fatal(err)
	}
	sqlDB, err := sql.Open("pgx", strings.Replace(ownerURL, "/warden?", "/downup_v04?", 1))
	if err != nil {
		t.Fatal(err)
	}
	defer sqlDB.Close()
	p, err := goose.NewProvider(goose.DialectPostgres, sqlDB, os.DirFS("sql"))
	if err != nil {
		t.Fatal(err)
	}
	if _, err := p.Up(ctx); err != nil {
		t.Fatal(err)
	}
	if _, err := p.DownTo(ctx, 10); err != nil {
		t.Fatal(err)
	}
	if _, err := p.Up(ctx); err != nil {
		t.Fatal(err)
	}
}
