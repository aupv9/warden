//go:build integration

package results_test

import (
	"context"
	"strconv"
	"strings"
	"testing"
	"time"

	"github.com/google/uuid"
	"github.com/jackc/pgx/v5"

	"github.com/aupv9/warden/backend/internal/db"
	"github.com/aupv9/warden/backend/internal/domain/licensepolicy"
	"github.com/aupv9/warden/backend/internal/scan/results"
	"github.com/aupv9/warden/backend/internal/scan/sandbox"
	"github.com/aupv9/warden/backend/internal/scan/trivyjson"
)

func npm(name, version, path string, licenses ...string) trivyjson.Package {
	return trivyjson.Package{Ecosystem: "npm", Name: name, MatchName: strings.ToLower(name), Version: version, MatchVersion: version,
		FilePath: path, PURL: "pkg:npm/" + name + "@" + version, Licenses: licenses}
}

// processPackages runs a Trivy scan of target with packages at now.
func (f *fixture) processPackages(target string, runs []sandbox.ToolRun, status string, now time.Time, pkgs []trivyjson.Package) (uuid.UUID, results.Plan) {
	f.t.Helper()
	scan := f.scan("trivy")
	var plan results.Plan
	if err := db.WithOrg(context.Background(), appPool, f.org, func(tx pgx.Tx) error {
		var err error
		plan, err = results.Process(context.Background(), tx, results.Input{
			OrgID: f.org, ProjectID: f.project, ScanID: scan, Status: status, Target: target, Runs: runs,
			Packages: pkgs, GuardRatio: 1, Now: now,
		})
		return err
	}); err != nil {
		f.t.Fatal(err)
	}
	return scan, plan
}

type componentRow struct {
	Scan      uuid.UUID
	FirstSeen time.Time
	Licenses  []string
	PURL      *string
}

// components reads the (project, target)'s inventory by name@version|path.
func (f *fixture) components(target string) map[string]componentRow {
	out := map[string]componentRow{}
	ownerTx(f.t, f.org, func(tx pgx.Tx) error {
		rows, err := tx.Query(context.Background(), `SELECT name, version, path, scan_id, first_seen, licenses, purl FROM component
			WHERE project_id = $1 AND target = $2`, f.project, target)
		if err != nil {
			return err
		}
		defer rows.Close()
		for rows.Next() {
			var name, version, path string
			var r componentRow
			if err := rows.Scan(&name, &version, &path, &r.Scan, &r.FirstSeen, &r.Licenses, &r.PURL); err != nil {
				return err
			}
			out[name+"@"+version+"|"+path] = r
		}
		return rows.Err()
	})
	return out
}

// Each Trivy scan replaces its (project, target)'s inventory by a diff: rows
// that stay keep first_seen, new rows get the scan's time, gone rows go. A
// scan where Trivy failed keeps the inventory; targets don't touch each other.
func TestComponentInventoryReplace(t *testing.T) {
	f := newFixture(t)
	t1 := time.Now().UTC().Add(-time.Hour).Truncate(time.Microsecond)
	t2 := t1.Add(30 * time.Minute)

	s1, p := f.processPackages("", ok("trivy"), "completed", t1, []trivyjson.Package{
		npm("lodash", "4.17.15", "package-lock.json", "MIT"),
		npm("left-pad", "1.3.0", "package-lock.json"),
		npm("lodash", "4.17.15", "package-lock.json", "ISC"), // same key twice: one row
		{Ecosystem: "bad eco", Name: "x", MatchName: "x", Version: "1"},
	})
	if p.Components == nil || *p.Components != (results.ComponentStats{Added: 2, Skipped: 1}) {
		t.Fatalf("%+v", p.Components)
	}
	c := f.components("")
	if len(c) != 2 || c["lodash@4.17.15|package-lock.json"].Scan != s1 || !c["lodash@4.17.15|package-lock.json"].FirstSeen.Equal(t1) ||
		strings.Join(c["lodash@4.17.15|package-lock.json"].Licenses, ",") != "MIT,ISC" || c["left-pad@1.3.0|package-lock.json"].Licenses == nil {
		t.Fatalf("%+v", c)
	}
	f.processPackages("ghcr.io/acme/web", ok("trivy"), "completed", t1, []trivyjson.Package{npm("express", "4.0.0", "ghcr.io/acme/web::app/package-lock.json")})

	s2, p := f.processPackages("", ok("trivy"), "partial", t2, []trivyjson.Package{
		npm("lodash", "4.17.15", "package-lock.json", "MIT"),
		npm("lodash", "4.17.21", "package-lock.json", "MIT"),
	})
	if *p.Components != (results.ComponentStats{Added: 1, Kept: 1, Removed: 1}) {
		t.Fatalf("%+v", p.Components)
	}
	c = f.components("")
	kept, added := c["lodash@4.17.15|package-lock.json"], c["lodash@4.17.21|package-lock.json"]
	if len(c) != 2 || kept.Scan != s2 || !kept.FirstSeen.Equal(t1) || strings.Join(kept.Licenses, ",") != "MIT" ||
		added.Scan != s2 || !added.FirstSeen.Equal(t2) {
		t.Fatalf("%+v", c)
	}

	// Trivy failed (or wasn't run): Packages nil, the inventory stays.
	failed := []sandbox.ToolRun{{Tool: "trivy", Status: sandbox.Failed}, {Tool: "opengrep", Status: sandbox.Succeeded}}
	if _, p := f.processPackages("", failed, "partial", t2.Add(time.Minute), nil); p.Components != nil {
		t.Fatalf("%+v", p.Components)
	}
	// Even a stray package list from a failed Trivy run is ignored.
	f.processPackages("", failed, "partial", t2.Add(time.Minute), []trivyjson.Package{})
	if c := f.components(""); len(c) != 2 || c["lodash@4.17.15|package-lock.json"].Scan != s2 {
		t.Fatalf("%+v", c)
	}
	// The image target was never touched; an empty successful scan empties only its own target.
	if img := f.components("ghcr.io/acme/web"); len(img) != 1 {
		t.Fatalf("%+v", img)
	}
	if _, p := f.processPackages("ghcr.io/acme/web", ok("trivy"), "completed", t2, []trivyjson.Package{}); *p.Components != (results.ComponentStats{Removed: 1}) {
		t.Fatalf("%+v", p.Components)
	}
	if len(f.components("ghcr.io/acme/web")) != 0 || len(f.components("")) != 2 {
		t.Fatal("wrong target emptied")
	}
}

// The largest inventory a scan may have (200k packages) is replaced in one
// transaction, both when new and when it changes.
func TestComponentInventoryAtCap(t *testing.T) {
	if testing.Short() {
		t.Skip("large")
	}
	f := newFixture(t)
	pkgs := make([]trivyjson.Package, results.MaxComponents)
	for i := range pkgs {
		pkgs[i] = npm("pkg-"+strconv.Itoa(i%5000), "1.0."+strconv.Itoa(i/5000), "package-lock.json", "MIT")
	}
	start := time.Now()
	_, p := f.processPackages("", ok("trivy"), "completed", time.Now().UTC(), pkgs)
	first := time.Since(start)
	if p.Components.Added != results.MaxComponents {
		t.Fatalf("%+v", p.Components)
	}
	for i := range pkgs[:1000] {
		pkgs[i].Version = "2.0." + strconv.Itoa(i)
	}
	start = time.Now()
	_, p = f.processPackages("", ok("trivy"), "completed", time.Now().UTC(), pkgs)
	if *p.Components != (results.ComponentStats{Added: 1000, Kept: results.MaxComponents - 1000, Removed: 1000}) {
		t.Fatalf("%+v", p.Components)
	}
	t.Logf("200k components: first scan %v, rescan %v", first, time.Since(start))
	if n := f.count(`SELECT count(*) FROM component WHERE project_id = $1`, f.project); n != results.MaxComponents {
		t.Fatal(n)
	}
}

// License issues record their Trivy category when created and keep it in
// step on every sighting.
func TestLicenseCategoryWritten(t *testing.T) {
	f := newFixture(t)
	f.setLicensePolicy(`{"categories":{"restricted":"review"}}`)
	licenses := []trivyjson.License{{FilePath: "package-lock.json", PkgName: "gpl-thing", PkgVersion: "1.0.0", License: "GPL-3.0-only",
		Terms: [][]string{{"GPL-3.0-only"}}, Category: licensepolicy.Restricted, Declared: "GPL-3.0-only"}}
	f.processLicenses(licenses, nil)
	category := func() *string {
		var c *string
		ownerTx(t, f.org, func(tx pgx.Tx) error {
			return tx.QueryRow(context.Background(), `SELECT license_category FROM issue WHERE project_id = $1 AND rule_id = 'license:GPL-3.0-only'`,
				f.project).Scan(&c)
		})
		return c
	}
	if c := category(); c == nil || *c != "restricted" {
		t.Fatal(c)
	}
	ownerTx(t, f.org, func(tx pgx.Tx) error {
		_, err := tx.Exec(context.Background(), `UPDATE issue SET license_category = NULL WHERE project_id = $1`, f.project)
		return err
	})
	f.processLicenses(licenses, nil)
	if c := category(); c == nil || *c != "restricted" {
		t.Fatal(c)
	}
	// Other issues have none.
	if n := f.count(`SELECT count(*) FROM issue WHERE project_id = $1 AND license_category IS NOT NULL AND rule_id NOT LIKE 'license:%'`, f.project); n != 0 {
		t.Fatal(n)
	}
}
