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

const uniqueViolation = "23505"

var ruleSum = strings.Repeat("ab", 32)

// insertRule adds a scan_rule (and, when version > 0, its version row) as
// warden_app.
func insertRule(t *testing.T, org, user uuid.UUID, tool, key string) uuid.UUID {
	t.Helper()
	id := uuid.New()
	err := appExec(t, org, `INSERT INTO scan_rule (id, org_id, tool, key, name, body_canonical, sha256, severity, created_by, updated_by)
		VALUES ($1, $2, $3, $4, 'n', 'rules: []', $5, 'high', $6, $6)`, id, org, tool, key, ruleSum, user)
	if err != nil {
		t.Fatal(err)
	}
	err = appExec(t, org, `INSERT INTO scan_rule_version (org_id, scan_rule_id, version, name, body_canonical, sha256, severity, enabled, created_by)
		VALUES ($1, $2, 1, 'n', 'rules: []', $3, 'high', true, $4)`, org, id, ruleSum, user)
	if err != nil {
		t.Fatal(err)
	}
	return id
}

// 00014: a rule's tool, key, digest, severity, version, sizes and project
// list are checked; a key is unique per org and tool among live rules.
func TestScanRuleConstraints(t *testing.T) {
	org, user, project := seedUserProject(t, "SRA")
	rule := func(tool, key, body, sum, sev string, version int, projects any) error {
		return appExec(t, org, `INSERT INTO scan_rule (id, org_id, tool, key, name, body_canonical, sha256, severity, version, project_ids, created_by)
			VALUES ($1, $2, $3, $4, 'n', $5, $6, $7::severity, $8, $9, $10)`, uuid.New(), org, tool, key, body, sum, sev, version, projects, user)
	}
	if err := rule("opengrep", "no-eval", "x", ruleSum, "high", 1, []uuid.UUID{project}); err != nil {
		t.Fatal(err)
	}
	if err := rule("gitleaks", "no-eval", strings.Repeat("b", 65536), ruleSum, "info", 7, nil); err != nil {
		t.Fatal(err)
	}
	for _, c := range []struct {
		tool, key, body, sum string
		version              int
		projects             any
	}{
		{"trivy", "k1", "x", ruleSum, 1, nil},
		{"checkov", "k1", "x", ruleSum, 1, nil},
		{"opengrep", "", "x", ruleSum, 1, nil},
		{"opengrep", "K1", "x", ruleSum, 1, nil},
		{"opengrep", "-k", "x", ruleSum, 1, nil},
		{"opengrep", "a/b", "x", ruleSum, 1, nil},
		{"opengrep", "k1\n", "x", ruleSum, 1, nil},
		{"opengrep", strings.Repeat("k", 65), "x", ruleSum, 1, nil},
		{"opengrep", "k1", "", ruleSum, 1, nil},
		{"opengrep", "k1", strings.Repeat("b", 65537), ruleSum, 1, nil},
		{"opengrep", "k1", "x", strings.ToUpper(ruleSum), 1, nil},
		{"opengrep", "k1", "x", ruleSum[:63], 1, nil},
		{"opengrep", "k1", "x", ruleSum, 0, nil},
		{"opengrep", "k1", "x", ruleSum, 1, []uuid.UUID{}},
	} {
		if err := rule(c.tool, c.key, c.body, c.sum, "high", c.version, c.projects); pgCode(err) != checkViolation {
			t.Errorf("%+v: got %v", c, err)
		}
	}
	if err := rule("opengrep", "k1", "x", ruleSum, "urgent", 1, nil); err == nil {
		t.Error("severity outside the enum")
	}
	// The key is unique per tool among live rules; a deleted key is free.
	if err := rule("opengrep", "no-eval", "x", ruleSum, "high", 1, nil); pgCode(err) != uniqueViolation {
		t.Fatalf("duplicate key: %v", err)
	}
	if err := appExec(t, org, `UPDATE scan_rule SET deleted_at = now() WHERE tool = 'opengrep' AND key = 'no-eval'`); err != nil {
		t.Fatal(err)
	}
	if err := rule("opengrep", "no-eval", "x", ruleSum, "high", 1, nil); err != nil {
		t.Fatal(err)
	}

	// Tests: a plain file name, a snippet only before the run ends, an error
	// only when failed, findings an array.
	test := func(filename string, snippet any, state string, finished bool, errCode any, findings string) error {
		var fin any
		if finished {
			fin = "2026-01-01T00:00:00Z"
		}
		return appExec(t, org, `INSERT INTO scan_rule_test (id, org_id, created_by, tool, body_canonical, filename, snippet, state, finished_at, error, findings)
			VALUES ($1, $2, $3, 'gitleaks', 'x', $4, $5, $6, $7, $8, $9::jsonb)`, uuid.New(), org, user, filename, snippet, state, fin, errCode, findings)
	}
	if err := test("config.py", "x = 1", "queued", false, nil, "[]"); err != nil {
		t.Fatal(err)
	}
	if err := test("config.py", nil, "done", true, nil, `[{"line": 1, "end_line": null, "message": "m"}]`); err != nil {
		t.Fatal(err)
	}
	if err := test("config.py", nil, "failed", true, "timeout", "[]"); err != nil {
		t.Fatal(err)
	}
	for _, c := range []struct {
		filename string
		snippet  any
		state    string
		finished bool
		err      any
		findings string
	}{
		{"..", "x", "queued", false, nil, "[]"},
		{".", "x", "queued", false, nil, "[]"},
		{"a/b.py", "x", "queued", false, nil, "[]"},
		{"", "x", "queued", false, nil, "[]"},
		{strings.Repeat("a", 256), "x", "queued", false, nil, "[]"},
		{"a.py", strings.Repeat("s", 65537), "queued", false, nil, "[]"},
		{"a.py", "x", "done", true, nil, "[]"},          // snippet kept after the run
		{"a.py", nil, "done", false, nil, "[]"},         // done without finished_at
		{"a.py", "x", "queued", true, nil, "[]"},        // finished but queued
		{"a.py", nil, "failed", true, nil, "[]"},        // failed without an error
		{"a.py", nil, "done", true, "timeout", "[]"},    // error but done
		{"a.py", nil, "failed", true, "oops", "[]"},     // unknown error
		{"a.py", "x", "paused", false, nil, "[]"},       // unknown state
		{"a.py", "x", "queued", false, nil, `{"a": 1}`}, // findings not an array
	} {
		if err := test(c.filename, c.snippet, c.state, c.finished, c.err, c.findings); pgCode(err) != checkViolation {
			t.Errorf("%+v: got %v", c, err)
		}
	}

	// scan.org_rules: [] by default, an array only.
	scanID := uuid.New()
	if err := appExec(t, org, `INSERT INTO scan (id, org_id, project_id, created_by, file_name, tools) VALUES ($1, $2, $3, $4, 'a.zip', '{opengrep}')`,
		scanID, org, project, user); err != nil {
		t.Fatal(err)
	}
	var refs string
	err := db.WithOrg(context.Background(), appPool(t), org, func(tx pgx.Tx) error {
		return tx.QueryRow(context.Background(), `SELECT org_rules::text FROM scan WHERE id = $1`, scanID).Scan(&refs)
	})
	if err != nil || refs != "[]" {
		t.Fatal(refs, err)
	}
	if err := appExec(t, org, `UPDATE scan SET org_rules = '{}' WHERE id = $1`, scanID); pgCode(err) != checkViolation {
		t.Fatal(err)
	}
}

// 00014: versions are append-only for the app, rules are never deleted, a
// version stays in its rule's org, and other orgs see none of it.
func TestScanRulesAppendOnlyAndIsolated(t *testing.T) {
	org, user, _ := seedUserProject(t, "SRB")
	id := insertRule(t, org, user, "opengrep", "k")
	for _, stmt := range []string{
		`UPDATE scan_rule_version SET body_canonical = 'tampered'`,
		`DELETE FROM scan_rule_version`,
		`TRUNCATE scan_rule_version`,
		`DELETE FROM scan_rule`,
		`TRUNCATE scan_rule`,
	} {
		if err := appExec(t, org, stmt); pgCode(err) != insufficientPrivilege {
			t.Errorf("%s: %v", stmt, err)
		}
	}
	// The app may update the rule itself (edits, soft delete) and append.
	if err := appExec(t, org, `UPDATE scan_rule SET version = 2, enabled = false WHERE id = $1`, id); err != nil {
		t.Fatal(err)
	}
	if err := appExec(t, org, `INSERT INTO scan_rule_version (org_id, scan_rule_id, version, name, body_canonical, sha256, severity, enabled)
		VALUES ($1, $2, 2, 'n', 'x', $3, 'high', false)`, org, id, ruleSum); err != nil {
		t.Fatal(err)
	}
	if err := appExec(t, org, `INSERT INTO scan_rule_version (org_id, scan_rule_id, version, name, body_canonical, sha256, severity, enabled)
		VALUES ($1, $2, 2, 'n', 'x', $3, 'high', false)`, org, id, ruleSum); pgCode(err) != uniqueViolation {
		t.Fatalf("duplicate version: %v", err)
	}
	// Test rows are updated by the worker and pruned.
	testID := uuid.New()
	if err := appExec(t, org, `INSERT INTO scan_rule_test (id, org_id, created_by, tool, body_canonical, filename, snippet)
		VALUES ($1, $2, $3, 'opengrep', 'x', 'a.py', 's')`, testID, org, user); err != nil {
		t.Fatal(err)
	}
	if err := appExec(t, org, `UPDATE scan_rule_test SET state = 'done', snippet = NULL, finished_at = now() WHERE id = $1`, testID); err != nil {
		t.Fatal(err)
	}
	if err := appExec(t, org, `DELETE FROM scan_rule_test WHERE id = $1`, testID); err != nil {
		t.Fatal(err)
	}

	other, otherUser, _ := seedUserProject(t, "SRC")
	var seen int
	err := db.WithOrg(context.Background(), appPool(t), other, func(tx pgx.Tx) error {
		return tx.QueryRow(context.Background(), `SELECT (SELECT count(*) FROM scan_rule) + (SELECT count(*) FROM scan_rule_version)
			+ (SELECT count(*) FROM scan_rule_test)`).Scan(&seen)
	})
	if err != nil || seen != 0 {
		t.Fatal(seen, err)
	}
	// Writing another org's rows is refused by RLS, and a version can't point
	// at another org's rule (the foreign key doesn't go through RLS).
	if err := appExec(t, other, `INSERT INTO scan_rule (id, org_id, tool, key, name, body_canonical, sha256, severity)
		VALUES ($1, $2, 'opengrep', 'x', 'n', 'x', $3, 'high')`, uuid.New(), org, ruleSum); pgCode(err) != insufficientPrivilege {
		t.Fatal(err)
	}
	if err := appExec(t, other, `INSERT INTO scan_rule_version (org_id, scan_rule_id, version, name, body_canonical, sha256, severity, enabled)
		VALUES ($1, $2, 9, 'n', 'x', $3, 'high', true)`, other, id, ruleSum); pgCode(err) != "23503" {
		t.Fatal(err)
	}
	if err := appExec(t, other, `INSERT INTO scan_rule_test (id, org_id, created_by, tool, body_canonical, filename, snippet)
		VALUES ($1, $2, $3, 'opengrep', 'x', 'a.py', 's')`, uuid.New(), org, otherUser); pgCode(err) != insufficientPrivilege {
		t.Fatal(err)
	}
	// Without an org, nothing at all.
	err = db.WithOrg(context.Background(), appPool(t), uuid.Nil, func(tx pgx.Tx) error {
		return tx.QueryRow(context.Background(), `SELECT count(*) FROM scan_rule`).Scan(&seen)
	})
	if err != nil || seen != 0 {
		t.Fatal(seen, err)
	}
}

// 00014 goes down and up again cleanly on a database with rules in it.
func TestScanRulesMigrationDownUp(t *testing.T) {
	ctx := context.Background()
	if _, err := connect(t, ownerURL).Exec(ctx, `CREATE DATABASE downup_v06`); err != nil {
		t.Fatal(err)
	}
	url := strings.Replace(ownerURL, "/warden?", "/downup_v06?", 1)
	sqlDB, err := sql.Open("pgx", url)
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
	org, user := uuid.New(), uuid.New()
	conn := connect(t, url)
	for _, s := range []string{
		fmt.Sprintf("SELECT set_config('app.org_id', '%s', false)", org),
		fmt.Sprintf("INSERT INTO organization (id, name) VALUES ('%s', 'o')", org),
		fmt.Sprintf("INSERT INTO app_user (id, keycloak_sub, email, display_name) VALUES ('%s', 's', 'u@x.test', 'u')", user),
		fmt.Sprintf("INSERT INTO scan_rule (id, org_id, tool, key, name, body_canonical, sha256, severity) VALUES ('%s', '%s', 'gitleaks', 'k', 'n', 'x', '%s', 'low')",
			uuid.New(), org, ruleSum),
	} {
		if _, err := conn.Exec(ctx, s); err != nil {
			t.Fatalf("%s: %v", s, err)
		}
	}
	if _, err := p.DownTo(ctx, 13); err != nil {
		t.Fatal(err)
	}
	var cols int
	if err := conn.QueryRow(ctx, `SELECT count(*) FROM information_schema.columns WHERE table_name = 'scan' AND column_name = 'org_rules'`).Scan(&cols); err != nil || cols != 0 {
		t.Fatal(cols, err)
	}
	if _, err := p.Up(ctx); err != nil {
		t.Fatal(err)
	}
}
