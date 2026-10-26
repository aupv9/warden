//go:build integration

package results_test

import (
	"context"
	"testing"

	"github.com/google/uuid"
	"github.com/jackc/pgx/v5"

	"github.com/aupv9/warden/backend/internal/domain/severity"
	"github.com/aupv9/warden/backend/internal/scan/sarif"
)

// New issues follow the project's auto-assign rules (first match wins, rules
// whose assignee left the project are skipped); existing issues are left
// alone. Reopens and the finished scan write outbox events. (The test
// container's owner is a superuser, which bypasses RLS: counts name the org.)
func TestAutoAssignAndOutbox(t *testing.T) {
	f := newFixture(t)
	ctx := context.Background()
	gone, dev := uuid.New(), uuid.New()
	ownerTx(t, f.org, func(tx pgx.Tx) error {
		for _, u := range []uuid.UUID{gone, dev} {
			if _, err := tx.Exec(ctx, `INSERT INTO app_user (id, keycloak_sub, email, display_name) VALUES ($1, $2, $3, 'u')`,
				u, u.String(), u.String()+"@x.test"); err != nil {
				return err
			}
		}
		// gone: org member, but no longer in the project. dev: project developer.
		if _, err := tx.Exec(ctx, `INSERT INTO org_member (org_id, user_id, role) VALUES ($1, $2, 'member'), ($1, $3, 'member')`, f.org, gone, dev); err != nil {
			return err
		}
		if _, err := tx.Exec(ctx, `INSERT INTO project_member (org_id, project_id, user_id, role) VALUES ($1, $2, $3, 'developer')`, f.org, f.project, dev); err != nil {
			return err
		}
		_, err := tx.Exec(ctx, `UPDATE project SET assign_rules = $2 WHERE id = $1`, f.project, `[
			{"match": {"path_glob": "src/**/*.py"}, "assignee_id": "`+gone.String()+`"},
			{"match": {"path_glob": "src/**", "severity_at_least": "high"}, "assignee_id": "`+dev.String()+`"},
			{"match": {"tool": "trivy"}, "assignee_id": "`+dev.String()+`"}
		]`)
		return err
	})

	s1 := f.scan("opengrep")
	hit := fnd("opengrep", "sqli", "src/app/db.py", severity.High, "q")
	low := fnd("opengrep", "lint", "src/app/x.py", severity.Low, "q")
	other := fnd("opengrep", "xss", "web/a.js", severity.Critical, "h")
	if _, err := f.process(s1, ok("opengrep"), map[string][]sarif.Finding{"opengrep": {hit, low, other}}); err != nil {
		t.Fatal(err)
	}
	var status string
	var assignee *uuid.UUID
	ownerTx(t, f.org, func(tx pgx.Tx) error {
		return tx.QueryRow(ctx, `SELECT status, assignee_id FROM issue WHERE rule_id = 'sqli' AND org_id = $1`, f.org).Scan(&status, &assignee)
	})
	if status != "assigned" || assignee == nil || *assignee != dev {
		t.Fatal(status, assignee)
	}
	for _, rule := range []string{"lint", "xss"} {
		if n := f.count(`SELECT count(*) FROM issue WHERE rule_id = $1 AND status = 'open' AND assignee_id IS NULL AND org_id = $2`, rule, f.org); n != 1 {
			t.Fatalf("%s was assigned", rule)
		}
	}
	if n := f.count(`SELECT count(*) FROM issue_event e JOIN issue i ON i.id = e.issue_id
		WHERE i.rule_id = 'sqli' AND e.actor_id IS NULL AND e.note = 'auto-assign rule 2' AND e.type IN ('assigned', 'status_changed')
		AND i.org_id = $1`, f.org); n != 2 {
		t.Fatal(n)
	}
	if n := f.count(`SELECT count(*) FROM outbox_event WHERE type = 'issue.assigned' AND payload->>'user_id' = $1`, dev.String()); n != 1 {
		t.Fatal(n)
	}
	if n := f.count(`SELECT count(*) FROM outbox_event WHERE type = 'scan.finished' AND payload->>'scan_id' = $1`, s1.String()); n != 1 {
		t.Fatal(n)
	}

	// Scan 2 fixes sqli; scan 3 brings it back: a reopen (outbox
	// issue.reopened), never a re-assignment.
	s2 := f.scan("opengrep")
	if _, err := f.process(s2, ok("opengrep"), map[string][]sarif.Finding{"opengrep": {low, other}}); err != nil {
		t.Fatal(err)
	}
	s3 := f.scan("opengrep")
	if _, err := f.process(s3, ok("opengrep"), map[string][]sarif.Finding{"opengrep": {hit, low, other}}); err != nil {
		t.Fatal(err)
	}
	if n := f.count(`SELECT count(*) FROM outbox_event WHERE type = 'issue.reopened' AND org_id = $1`, f.org); n != 1 {
		t.Fatal(n)
	}
	if n := f.count(`SELECT count(*) FROM outbox_event WHERE type = 'issue.assigned' AND org_id = $1`, f.org); n != 1 {
		t.Fatal(n)
	}
}
