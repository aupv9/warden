//go:build integration

package results_test

import (
	"context"
	"testing"
	"time"

	"github.com/google/uuid"
	"github.com/jackc/pgx/v5"

	"github.com/aupv9/warden/backend/internal/db"
	"github.com/aupv9/warden/backend/internal/scan/results"
	"github.com/aupv9/warden/backend/internal/scan/trivyjson"
)

func evilPkg(path string) trivyjson.Package {
	return trivyjson.Package{Ecosystem: "npm", Name: "Evil", MatchName: "evil", Version: "1.0.0", MatchVersion: "1.0.0", FilePath: path}
}

func (f *fixture) inject(target string, matches ...results.MaliciousMatch) (int, int) {
	f.t.Helper()
	var created, reopened int
	if err := db.WithOrg(context.Background(), appPool, f.org, func(tx pgx.Tx) error {
		var err error
		created, reopened, err = results.Inject(context.Background(), tx, results.InjectInput{OrgID: f.org, ProjectID: f.project,
			Target: target, Matches: matches, Now: time.Now().UTC()})
		return err
	}); err != nil {
		f.t.Fatal(err)
	}
	return created, reopened
}

func (f *fixture) malFP() (string, string) {
	var fp, status string
	ownerTx(f.t, f.org, func(tx pgx.Tx) error {
		return tx.QueryRow(context.Background(), `SELECT fingerprint, status FROM issue WHERE project_id = $1 AND rule_id = 'malicious:MAL-2033-1'`,
			f.project).Scan(&fp, &status)
	})
	return fp, status
}

func (f *fixture) setStatus(status string) {
	ownerTx(f.t, f.org, func(tx pgx.Tx) error {
		_, err := tx.Exec(context.Background(), `UPDATE issue SET status = $2 WHERE project_id = $1 AND rule_id = 'malicious:MAL-2033-1'`, f.project, status)
		return err
	})
}

func TestMaliciousScanTimeAndInject(t *testing.T) {
	ctx := context.Background()
	if err := db.WithOrg(ctx, ownerPool, uuid.Nil, func(tx pgx.Tx) error {
		_, err := tx.Exec(ctx, `INSERT INTO malicious_package (id, ecosystem, name, match_name, all_versions, versions, summary, modified)
			VALUES ('MAL-2033-1', 'npm', 'evil', 'evil', true, '{}', 'Malicious code in evil (npm)', now()),
			       ('MAL-2033-2', 'npm', 'typo', 'typo', false, '{2.0.0}', 'Malicious code in typo (npm)', now())`)
		return err
	}); err != nil {
		t.Fatal(err)
	}

	// Scan time: a Critical issue, announced once.
	f := newFixture(t)
	scan := f.scan("trivy")
	packages := []trivyjson.Package{evilPkg("package-lock.json"),
		{Ecosystem: "npm", Name: "typo", MatchName: "typo", Version: "2.0.1", MatchVersion: "2.0.1", FilePath: "package-lock.json"}}
	if err := db.WithOrg(ctx, appPool, f.org, func(tx pgx.Tx) error {
		p, err := results.Process(ctx, tx, results.Input{OrgID: f.org, ProjectID: f.project, ScanID: scan, Status: "completed",
			Runs: ok("trivy"), Packages: packages, GuardRatio: 1, Now: time.Now().UTC()})
		if err == nil && p.Stats.New != 1 {
			t.Errorf("%+v", p.Stats)
		}
		return err
	}); err != nil {
		t.Fatal(err)
	}
	scanFP, status := f.malFP()
	if status != "open" || f.count(`SELECT count(*) FROM issue WHERE project_id = $1 AND severity = 'critical' AND due_at IS NOT NULL`, f.project) != 1 ||
		f.count(`SELECT count(*) FROM outbox_event WHERE org_id = $1 AND type = 'component.malicious'`, f.org) != 1 {
		t.Fatal("scan-time issue", status)
	}

	// Inject in another org's inventory builds the same fingerprint.
	g := newFixture(t)
	gScan := g.scan("trivy")
	match := results.MaliciousMatch{Package: evilPkg("package-lock.json"), ScanID: gScan,
		Advisory: results.Advisory{ID: "MAL-2033-1", Summary: "Malicious code in evil (npm)"}}
	if c, r := g.inject("", match); c != 1 || r != 0 {
		t.Fatal(c, r)
	}
	if fp, st := g.malFP(); fp != scanFP || st != "open" {
		t.Fatal(fp, scanFP, st)
	}
	if g.count(`SELECT count(*) FROM issue WHERE first_seen_scan_id = $1 AND last_seen_scan_id = $1`, gScan) != 1 ||
		g.count(`SELECT count(*) FROM occurrence WHERE scan_id = $1`, gScan) != 1 {
		t.Fatal("inject issue scans")
	}

	// Active: untouched. Approved exception: untouched. Fixed: reopened.
	match.ScanID = scan
	if c, r := f.inject("", match); c != 0 || r != 0 {
		t.Fatal(c, r)
	}
	f.setStatus("false_positive")
	if c, r := f.inject("", match); c != 0 || r != 0 {
		t.Fatal(c, r)
	}
	if _, st := f.malFP(); st != "false_positive" {
		t.Fatal(st)
	}
	f.setStatus("fixed")
	if c, r := f.inject("", match); c != 0 || r != 1 {
		t.Fatal(c, r)
	}
	if _, st := f.malFP(); st != "reopened" {
		t.Fatal(st)
	}
	if f.count(`SELECT count(*) FROM outbox_event WHERE org_id = $1 AND type = 'component.malicious'`, f.org) != 2 ||
		f.count(`SELECT count(*) FROM outbox_event WHERE org_id = $1 AND type = 'issue.reopened'`, f.org) != 1 ||
		f.count(`SELECT count(*) FROM issue_event WHERE type = 'status_changed' AND to_value = 'reopened'
			AND note = 'found by malicious-package advisory MAL-2033-1 (no scan)'`) != 1 {
		t.Fatal("reopen events")
	}

	// Another target with a colliding fingerprint is left alone (issues are
	// scoped by target); an archived project gets nothing.
	if c, r := f.inject("ghcr.io/acme/api", match); c != 0 || r != 0 {
		t.Fatal(c, r)
	}
	ownerTx(t, g.org, func(tx pgx.Tx) error {
		_, err := tx.Exec(ctx, `UPDATE issue SET status = 'fixed' WHERE project_id = $1`, g.project)
		if err == nil {
			_, err = tx.Exec(ctx, `UPDATE project SET archived_at = now() WHERE id = $1`, g.project)
		}
		return err
	})
	if c, r := g.inject("", match); c != 0 || r != 0 {
		t.Fatal(c, r)
	}

	// The next scan of f sees the same fingerprint (no new issue), and one
	// without the package fixes it as usual.
	for i, pkgs := range [][]trivyjson.Package{packages, packages[1:]} {
		s := f.scan("trivy")
		if err := db.WithOrg(ctx, appPool, f.org, func(tx pgx.Tx) error {
			p, err := results.Process(ctx, tx, results.Input{OrgID: f.org, ProjectID: f.project, ScanID: s, Status: "completed",
				Runs: ok("trivy"), Packages: pkgs, GuardRatio: 1, Now: time.Now().UTC()})
			if err == nil && (p.Stats.New != 0 || p.Stats.Fixed != i) {
				t.Errorf("scan %d: %+v", i, p.Stats)
			}
			return err
		}); err != nil {
			t.Fatal(err)
		}
	}
	if _, st := f.malFP(); st != "fixed" {
		t.Fatal(st)
	}
}
