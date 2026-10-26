//go:build integration

package results_test

import (
	"context"
	"errors"
	"fmt"
	"os"
	"strings"
	"testing"
	"time"

	"github.com/google/uuid"
	"github.com/jackc/pgx/v5"
	"github.com/jackc/pgx/v5/pgxpool"
	"github.com/testcontainers/testcontainers-go"
	tcpostgres "github.com/testcontainers/testcontainers-go/modules/postgres"
	"github.com/testcontainers/testcontainers-go/wait"

	"github.com/aupv9/warden/backend/internal/db"
	"github.com/aupv9/warden/backend/internal/domain/fingerprint"
	"github.com/aupv9/warden/backend/internal/domain/severity"
	"github.com/aupv9/warden/backend/internal/migrations"
	"github.com/aupv9/warden/backend/internal/scan/redact"
	"github.com/aupv9/warden/backend/internal/scan/results"
	"github.com/aupv9/warden/backend/internal/scan/sandbox"
	"github.com/aupv9/warden/backend/internal/scan/sarif"
	st "github.com/aupv9/warden/backend/internal/scan/scantest"
)

var ownerPool, appPool *pgxpool.Pool

func TestMain(m *testing.M) {
	ctx := context.Background()
	c, err := tcpostgres.Run(ctx, "postgres:16-alpine",
		tcpostgres.WithDatabase("warden"), tcpostgres.WithUsername("warden_owner"), tcpostgres.WithPassword("owner-test-pw"),
		testcontainers.WithWaitStrategy(wait.ForLog("database system is ready to accept connections").WithOccurrence(2).WithStartupTimeout(60*time.Second)),
	)
	if err != nil {
		fmt.Fprintln(os.Stderr, "start postgres:", err)
		os.Exit(1)
	}
	code := func() int {
		defer func() { _ = testcontainers.TerminateContainer(c) }()
		ownerURL, err := c.ConnectionString(ctx, "sslmode=disable")
		if err != nil {
			fmt.Fprintln(os.Stderr, err)
			return 1
		}
		if ownerPool, err = pgxpool.New(ctx, ownerURL); err != nil {
			fmt.Fprintln(os.Stderr, err)
			return 1
		}
		if _, err := ownerPool.Exec(ctx, "CREATE ROLE warden_app LOGIN PASSWORD 'app-test-pw' NOSUPERUSER NOBYPASSRLS"); err != nil {
			fmt.Fprintln(os.Stderr, err)
			return 1
		}
		if err := migrations.Up(ctx, ownerURL); err != nil {
			fmt.Fprintln(os.Stderr, err)
			return 1
		}
		host, _ := c.Host(ctx)
		port, _ := c.MappedPort(ctx, "5432/tcp")
		if appPool, err = pgxpool.New(ctx, fmt.Sprintf("postgres://warden_app:app-test-pw@%s:%s/warden?sslmode=disable", host, port.Port())); err != nil {
			fmt.Fprintln(os.Stderr, err)
			return 1
		}
		return m.Run()
	}()
	os.Exit(code)
}

type fixture struct {
	t                  *testing.T
	org, project, user uuid.UUID
}

func ownerTx(t *testing.T, org uuid.UUID, fn func(pgx.Tx) error) {
	t.Helper()
	// The owner is subject to FORCEd RLS too, so seed with app.org_id set.
	if err := db.WithOrg(context.Background(), ownerPool, org, fn); err != nil {
		t.Fatal(err)
	}
}

func newFixture(t *testing.T) *fixture {
	f := &fixture{t: t, org: uuid.New(), project: uuid.New(), user: uuid.New()}
	ctx := context.Background()
	ownerTx(t, f.org, func(tx pgx.Tx) error {
		if _, err := tx.Exec(ctx, `INSERT INTO organization (id, name) VALUES ($1, 'acme')`, f.org); err != nil {
			return err
		}
		if _, err := tx.Exec(ctx, `INSERT INTO app_user (id, keycloak_sub, email, display_name) VALUES ($1, $2, $3, 'Dev')`,
			f.user, f.user.String(), f.user.String()+"@example.com"); err != nil {
			return err
		}
		_, err := tx.Exec(ctx, `INSERT INTO project (id, org_id, key, name) VALUES ($1, $2, 'WEB', 'web')`, f.project, f.org)
		return err
	})
	return f
}

func (f *fixture) scan(tools ...string) uuid.UUID {
	id := uuid.New()
	ctx := context.Background()
	ownerTx(f.t, f.org, func(tx pgx.Tx) error {
		if _, err := tx.Exec(ctx, `INSERT INTO scan (id, org_id, project_id, created_by, status, file_name, tools)
			VALUES ($1, $2, $3, $4, 'running', 'a.zip', $5)`, id, f.org, f.project, f.user, tools); err != nil {
			return err
		}
		for _, t := range tools {
			if _, err := tx.Exec(ctx, `INSERT INTO scan_tool_run (id, org_id, scan_id, tool, tool_version, image_digest, status)
				VALUES ($1, $2, $3, $4, '', '', 'succeeded')`, uuid.New(), f.org, id, t); err != nil {
				return err
			}
		}
		return nil
	})
	return id
}

func (f *fixture) process(scanID uuid.UUID, runs []sandbox.ToolRun, findings map[string][]sarif.Finding) (results.Plan, error) {
	var plan results.Plan
	err := db.WithOrg(context.Background(), appPool, f.org, func(tx pgx.Tx) error {
		var err error
		plan, err = results.Process(context.Background(), tx, results.Input{
			OrgID: f.org, ProjectID: f.project, ScanID: scanID, Status: "completed",
			Runs: runs, Findings: findings, GuardRatio: 0.5, Now: time.Now().UTC(),
		})
		return err
	})
	return plan, err
}

type issueRow struct {
	Number int
	Status string
	Due    *time.Time
	Snip   *string
}

func (f *fixture) issues() map[string]issueRow {
	out := map[string]issueRow{}
	ownerTx(f.t, f.org, func(tx pgx.Tx) error {
		rows, err := tx.Query(context.Background(), `SELECT rule_id, number, status, due_at, snippet FROM issue WHERE project_id = $1`, f.project)
		if err != nil {
			return err
		}
		defer rows.Close()
		for rows.Next() {
			var rule string
			var r issueRow
			if err := rows.Scan(&rule, &r.Number, &r.Status, &r.Due, &r.Snip); err != nil {
				return err
			}
			out[rule] = r
		}
		return rows.Err()
	})
	return out
}

func (f *fixture) count(q string, args ...any) int {
	var n int
	ownerTx(f.t, f.org, func(tx pgx.Tx) error { return tx.QueryRow(context.Background(), q, args...).Scan(&n) })
	return n
}

func ok(tools ...string) []sandbox.ToolRun {
	var r []sandbox.ToolRun
	for _, t := range tools {
		r = append(r, sandbox.ToolRun{Tool: t, Status: sandbox.Succeeded})
	}
	return r
}

func fnd(tool, rule, path string, sev severity.Severity, snippet string) sarif.Finding {
	l := 3
	return sarif.Finding{Tool: tool, RuleID: rule, Title: rule, Severity: sev, FilePath: path, StartLine: &l, EndLine: &l,
		Snippet: snippet, ContentKey: fingerprint.CodeContentKey([]string{rule})}
}

func TestProcessLifecycle(t *testing.T) {
	f := newFixture(t)
	a := fnd("opengrep", "sqli", "a.py", severity.High, "q = 'x' + y")
	b := fnd("opengrep", "xss", "b.py", severity.Low, "h(y)")
	c := fnd("opengrep", "info-rule", "c.py", severity.Info, "z")

	// Scan 1: three new issues.
	s1 := f.scan("opengrep")
	p, err := f.process(s1, ok("opengrep"), map[string][]sarif.Finding{"opengrep": {a, b, c}})
	if err != nil {
		t.Fatal(err)
	}
	if p.Stats != (results.Stats{New: 3, Total: 3}) {
		t.Fatalf("%+v", p.Stats)
	}
	is := f.issues()
	if is["sqli"].Status != "open" || is["sqli"].Due == nil || is["info-rule"].Due != nil {
		t.Fatalf("%+v", is)
	}
	if d := time.Until(*is["sqli"].Due); d < 29*24*time.Hour || d > 31*24*time.Hour {
		t.Fatalf("high SLA should be 30 days, got %v", d)
	}
	nums := map[int]bool{is["sqli"].Number: true, is["xss"].Number: true, is["info-rule"].Number: true}
	if !nums[1] || !nums[2] || !nums[3] || f.count(`SELECT issue_seq FROM project WHERE id = $1`, f.project) != 3 {
		t.Fatalf("numbers %v", nums)
	}
	if f.count(`SELECT count(*) FROM issue_event WHERE type = 'created' AND actor_id IS NULL AND org_id = $1`, f.org) != 3 ||
		f.count(`SELECT count(*) FROM occurrence WHERE scan_id = $1`, s1) != 3 {
		t.Fatal("events/occurrences")
	}
	var stats string
	ownerTx(t, f.org, func(tx pgx.Tx) error {
		return tx.QueryRow(context.Background(), `SELECT status || ' ' || stats::text || ' ' || (finished_at IS NOT NULL)::text FROM scan WHERE id = $1`, s1).Scan(&stats)
	})
	if stats != `completed {"new": 3, "fixed": 0, "total": 3, "reopened": 0} true` { // jsonb key order
		t.Fatal(stats)
	}
	if f.count(`SELECT findings_count FROM scan_tool_run WHERE scan_id = $1`, s1) != 3 {
		t.Fatal("findings_count")
	}

	// A retried attempt sees the finished scan and changes nothing.
	if _, err := f.process(s1, ok("opengrep"), map[string][]sarif.Finding{"opengrep": {a, b, c}}); !errors.Is(err, results.ErrScanNotRunning) {
		t.Fatalf("retry: %v", err)
	}

	// Scan 2: xss is gone (1 of 3 ≤ 50%) → fixed; sqli seen again.
	s2 := f.scan("opengrep")
	if p, err = f.process(s2, ok("opengrep"), map[string][]sarif.Finding{"opengrep": {a, c}}); err != nil {
		t.Fatal(err)
	}
	if p.Stats != (results.Stats{Fixed: 1, Total: 2}) || f.issues()["xss"].Status != "fixed" {
		t.Fatalf("%+v %+v", p.Stats, f.issues())
	}
	if f.count(`SELECT count(*) FROM issue_event WHERE type = 'seen_again' AND org_id = $1`, f.org) != 2 ||
		f.count(`SELECT count(*) FROM issue_event WHERE type = 'status_changed' AND to_value = 'fixed' AND org_id = $1`, f.org) != 1 {
		t.Fatal("events after scan 2")
	}

	// Scan 3: xss is back → reopened with a fresh due date.
	s3 := f.scan("opengrep")
	if p, err = f.process(s3, ok("opengrep"), map[string][]sarif.Finding{"opengrep": {a, b, c}}); err != nil {
		t.Fatal(err)
	}
	if p.Stats.Reopened != 1 || f.issues()["xss"].Status != "reopened" || f.issues()["xss"].Due == nil {
		t.Fatalf("%+v %+v", p.Stats, f.issues())
	}

	// Scan 4: opengrep failed → nothing is fixed even though there are no findings.
	s4 := f.scan("opengrep")
	if p, err = f.process(s4, []sandbox.ToolRun{{Tool: "opengrep", Status: sandbox.Failed}}, nil); err != nil {
		t.Fatal(err)
	}
	if len(p.Fix) != 0 || p.NeedsConfirmation {
		t.Fatalf("%+v", p)
	}

	// Scan 5: everything vanishes → guard trips, nothing fixed, scan flagged.
	s5 := f.scan("opengrep")
	if p, err = f.process(s5, ok("opengrep"), map[string][]sarif.Finding{"opengrep": {}}); err != nil {
		t.Fatal(err)
	}
	if !p.NeedsConfirmation || f.count(`SELECT count(*) FROM scan WHERE id = $1 AND needs_confirmation`, s5) != 1 ||
		f.count(`SELECT count(*) FROM issue WHERE status = 'fixed' AND project_id = $1`, f.project) != 0 {
		t.Fatalf("guard: %+v", p)
	}
}

func TestCancelledScanChangesNoIssue(t *testing.T) {
	f := newFixture(t)
	s := f.scan("opengrep")
	ownerTx(t, f.org, func(tx pgx.Tx) error {
		_, err := tx.Exec(context.Background(), `UPDATE scan SET status = 'cancelled' WHERE id = $1`, s)
		return err
	})
	_, err := f.process(s, ok("opengrep"), map[string][]sarif.Finding{"opengrep": {fnd("opengrep", "r", "a.py", severity.High, "")}})
	if !errors.Is(err, results.ErrScanNotRunning) || f.count(`SELECT count(*) FROM issue WHERE project_id = $1`, f.project) != 0 {
		t.Fatal(err)
	}
}

// Only masked secrets reach the database: the stored snippet and occurrence come
// from the redacted SARIF that Gitleaks' sandbox writes.
func TestGitleaksSecretsAreStoredMasked(t *testing.T) {
	f := newFixture(t)
	doc, err := redact.Doc(st.RoundTrip(st.GitleaksDoc()), st.HMACKey)
	if err != nil {
		t.Fatal(err)
	}
	fs, err := sarif.Parse(st.RoundTrip(doc), "gitleaks", sarif.Options{})
	if err != nil || len(fs) != 1 {
		t.Fatal(fs, err)
	}
	s := f.scan("gitleaks")
	if _, err := f.process(s, ok("gitleaks"), map[string][]sarif.Finding{"gitleaks": fs}); err != nil {
		t.Fatal(err)
	}
	var dump string
	ownerTx(t, f.org, func(tx pgx.Tx) error {
		return tx.QueryRow(context.Background(), `SELECT coalesce(string_agg(i::text, ''), '') || coalesce((SELECT string_agg(o::text, '') FROM occurrence o), '')
			FROM issue i WHERE project_id = $1`, f.project).Scan(&dump)
	})
	if strings.Contains(dump, st.FakeSecret) || !strings.Contains(dump, redact.Mask(st.FakeSecret)) {
		t.Fatalf("raw secret stored or mask missing: %s", dump)
	}
	if f.issues()["aws-access-token"].Due == nil {
		t.Fatal("critical issue without due date")
	}
}

func TestRLSScopesProcessing(t *testing.T) {
	f, other := newFixture(t), newFixture(t)
	s := f.scan("opengrep")
	// Processing in another org's context can't see (or touch) the scan.
	err := db.WithOrg(context.Background(), appPool, other.org, func(tx pgx.Tx) error {
		_, err := results.Process(context.Background(), tx, results.Input{OrgID: other.org, ProjectID: f.project, ScanID: s, Status: "completed", Now: time.Now()})
		return err
	})
	if !errors.Is(err, results.ErrScanNotRunning) {
		t.Fatal(err)
	}
}
