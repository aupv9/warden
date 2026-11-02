//go:build integration

package results_test

import (
	"context"
	"strings"
	"testing"
	"time"

	"github.com/google/uuid"
	"github.com/jackc/pgx/v5"

	"github.com/aupv9/warden/backend/internal/db"
	"github.com/aupv9/warden/backend/internal/domain/fingerprint"
	"github.com/aupv9/warden/backend/internal/scan/redact"
	"github.com/aupv9/warden/backend/internal/scan/results"
	"github.com/aupv9/warden/backend/internal/scan/sarif"
	st "github.com/aupv9/warden/backend/internal/scan/scantest"
)

func (f *fixture) historyScan() uuid.UUID {
	id := uuid.New()
	ownerTx(f.t, f.org, func(tx pgx.Tx) error {
		_, err := tx.Exec(context.Background(), `INSERT INTO scan (id, org_id, project_id, created_by, status, file_name, tools, kind, target)
			VALUES ($1, $2, $3, $4, 'running', 'r.bundle', '{gitleaks}', 'history', '(history)')`, id, f.org, f.project, f.user)
		return err
	})
	return id
}

func (f *fixture) processHistory(scanID uuid.UUID, fs []sarif.Finding, h *results.History) results.Plan {
	f.t.Helper()
	var plan results.Plan
	err := db.WithOrg(context.Background(), appPool, f.org, func(tx pgx.Tx) error {
		var err error
		plan, err = results.Process(context.Background(), tx, results.Input{
			OrgID: f.org, ProjectID: f.project, ScanID: scanID, Status: "completed", Target: fingerprint.HistoryPath,
			Runs: ok("gitleaks"), Findings: map[string][]sarif.Finding{"gitleaks": fs}, GuardRatio: 0.5, Now: time.Now().UTC(),
			History: h,
		})
		return err
	})
	if err != nil {
		f.t.Fatal(err)
	}
	return plan
}

// historyFindings parses Gitleaks git-mode results the way the worker does.
func historyFindings(t *testing.T, results ...any) []sarif.Finding {
	t.Helper()
	doc, err := redact.Doc(st.RoundTrip(st.Doc(results)), st.HMACKey)
	if err != nil {
		t.Fatal(err)
	}
	fs, err := sarif.Parse(st.RoundTrip(doc), "gitleaks", sarif.Options{History: true})
	if err != nil {
		t.Fatal(err)
	}
	return fs
}

type commitRow struct {
	Count             int
	SHA, Path, Status string
	Line              int
	At                *time.Time
}

func (f *fixture) historyIssue() (rows []commitRow) {
	ownerTx(f.t, f.org, func(tx pgx.Tx) error {
		r, err := tx.Query(context.Background(), `SELECT commit_count, commit_sha, file_path, status::text, start_line, committed_at
			FROM issue WHERE project_id = $1 AND target = '(history)' ORDER BY number`, f.project)
		if err != nil {
			return err
		}
		rows, err = pgx.CollectRows(r, func(row pgx.CollectableRow) (commitRow, error) {
			var c commitRow
			return c, row.Scan(&c.Count, &c.SHA, &c.Path, &c.Status, &c.Line, &c.At)
		})
		return err
	})
	return rows
}

// One issue per (rule, secret) at the oldest commit that added it, with the
// commit count; the scan records how many commits Gitleaks read. A later
// history scan updates the commit, fixes the issue once no commit has the
// secret, and never touches source issues (nor do source scans touch it).
func TestHistoryProcessing(t *testing.T) {
	f := newFixture(t)
	sha := func(c byte) string { return strings.Repeat(string(c), 40) }
	commit := func(s, date string) st.Commit {
		return st.Commit{SHA: s, Date: date, Author: "A", Email: "a@x.test", Message: "m"}
	}

	// The same secret is in the source too: a source issue of its own.
	src := f.scan("gitleaks")
	srcFindings, err := sarif.Parse(st.RoundTrip(mustRedact(t, st.GitleaksDoc())), "gitleaks", sarif.Options{})
	if err != nil {
		t.Fatal(err)
	}
	if _, err := f.process(src, ok("gitleaks"), map[string][]sarif.Finding{"gitleaks": srcFindings}); err != nil {
		t.Fatal(err)
	}

	s1 := f.historyScan()
	p := f.processHistory(s1, historyFindings(t,
		st.HistoryResult("aws-access-token", "app/new.py", 9, st.FakeSecret, commit(sha('c'), "2025-01-01T00:00:00Z")),
		st.HistoryResult("aws-access-token", "app/config.py", 3, st.FakeSecret, commit(sha('a'), "2023-05-06T07:08:09Z")),
		st.HistoryResult("aws-access-token", "app/copy.py", 1, st.FakeSecret, commit(sha('b'), "2024-01-01T00:00:00Z")),
		st.HistoryResult("aws-access-token", "app/copy2.py", 1, st.FakeSecret, commit(sha('b'), "2024-01-01T00:00:00Z")),
	), &results.History{Commits: 2481, Truncated: true})
	if p.Stats != (results.Stats{New: 1, Total: 1}) || p.ToolCounts["gitleaks"] != 1 {
		t.Fatalf("%+v", p)
	}
	rows := f.historyIssue()
	if len(rows) != 1 || rows[0].Count != 3 || rows[0].SHA != sha('a') || rows[0].Path != "app/config.py" || rows[0].Line != 3 ||
		rows[0].At == nil || !rows[0].At.Equal(time.Date(2023, 5, 6, 7, 8, 9, 0, time.UTC)) {
		t.Fatalf("%+v", rows)
	}
	var commits int
	var truncated bool
	ownerTx(t, f.org, func(tx pgx.Tx) error {
		return tx.QueryRow(context.Background(), `SELECT history_commits, history_truncated FROM scan WHERE id = $1`, s1).Scan(&commits, &truncated)
	})
	if commits != 2481 || !truncated {
		t.Fatal(commits, truncated)
	}
	if f.count(`SELECT count(*) FROM issue WHERE project_id = $1 AND target = '' AND status = 'open'`, f.project) != 1 {
		t.Fatal("source issue changed")
	}
	// Nothing personal or secret is stored, in the issue or its occurrence.
	var dump string
	ownerTx(t, f.org, func(tx pgx.Tx) error {
		return tx.QueryRow(context.Background(), `SELECT string_agg(i::text, '') || (SELECT string_agg(o::text, '') FROM occurrence o WHERE o.scan_id = $2)
			FROM issue i WHERE project_id = $1`, f.project, s1).Scan(&dump)
	})
	if strings.Contains(dump, st.FakeSecret) || strings.Contains(dump, "a@x.test") {
		t.Fatal(dump)
	}

	// A source scan without the secret fixes the source issue only.
	if _, err := f.process(f.scan("gitleaks"), ok("gitleaks"), map[string][]sarif.Finding{"gitleaks": {}}); err != nil {
		t.Fatal(err)
	}
	if f.historyIssue()[0].Status != "open" ||
		f.count(`SELECT count(*) FROM issue WHERE project_id = $1 AND target = '' AND status = 'fixed'`, f.project) != 1 {
		t.Fatal("source scan reached across targets")
	}

	// History rewritten: only the newest commit still has it; the issue follows.
	s2 := f.historyScan()
	f.processHistory(s2, historyFindings(t,
		st.HistoryResult("aws-access-token", "app/new.py", 9, st.FakeSecret, commit(sha('c'), "2025-01-01T00:00:00Z")),
	), &results.History{Commits: 10, Truncated: false})
	if rows := f.historyIssue(); len(rows) != 1 || rows[0].Count != 1 || rows[0].SHA != sha('c') || rows[0].Path != "app/new.py" {
		t.Fatalf("%+v", rows)
	}

	// Gone from every commit: fixed.
	s3 := f.historyScan()
	if p := f.processHistory(s3, nil, &results.History{Commits: 9, Truncated: false}); p.Stats.Fixed != 1 || f.historyIssue()[0].Status != "fixed" {
		t.Fatalf("%+v %+v", p.Stats, f.historyIssue())
	}
}

func mustRedact(t *testing.T, doc st.M) st.M {
	t.Helper()
	out, err := redact.Doc(st.RoundTrip(doc), st.HMACKey)
	if err != nil {
		t.Fatal(err)
	}
	return out
}
