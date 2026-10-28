//go:build integration

package results_test

import (
	"context"
	"strings"
	"testing"
	"time"

	"github.com/jackc/pgx/v5"

	"github.com/aupv9/warden/backend/internal/db"
	"github.com/aupv9/warden/backend/internal/domain/licensepolicy"
	"github.com/aupv9/warden/backend/internal/scan/results"
	"github.com/aupv9/warden/backend/internal/scan/trivyjson"
)

func (f *fixture) setLicensePolicy(policy string) {
	ownerTx(f.t, f.org, func(tx pgx.Tx) error {
		_, err := tx.Exec(context.Background(), `UPDATE organization SET license_policy = $2 WHERE id = $1`, f.org, []byte(policy))
		return err
	})
}

func (f *fixture) processLicenses(licenses []trivyjson.License, sbom *results.SBOM) results.Plan {
	f.t.Helper()
	scan := f.scan("trivy")
	var plan results.Plan
	if err := db.WithOrg(context.Background(), appPool, f.org, func(tx pgx.Tx) error {
		var err error
		plan, err = results.Process(context.Background(), tx, results.Input{
			OrgID: f.org, ProjectID: f.project, ScanID: scan, Status: "completed", Runs: ok("trivy"),
			Licenses: licenses, SBOM: sbom, GuardRatio: 1, Now: time.Now().UTC(),
		})
		return err
	}); err != nil {
		f.t.Fatal(err)
	}
	return plan
}

func TestLicenseIssuesFollowThePolicy(t *testing.T) {
	f := newFixture(t)
	licenses := []trivyjson.License{
		{FilePath: "package-lock.json", PkgName: "gpl-thing", PkgVersion: "1.0.0", License: "GPL-3.0-only",
			Terms: [][]string{{"GPL-3.0-only"}}, Category: licensepolicy.Restricted, Declared: "GPL-3.0-only"},
		{FilePath: "package-lock.json", PkgName: "lodash", PkgVersion: "4.17.21", License: "MIT",
			Terms: [][]string{{"MIT"}}, Category: licensepolicy.Notice, Declared: "MIT"},
	}
	// Off by default ('{}'): nothing.
	if p := f.processLicenses(licenses, nil); p.Stats.New != 0 {
		t.Fatalf("%+v", p.Stats)
	}
	f.setLicensePolicy(`{"categories":{"forbidden":"block","restricted":"review"}}`)
	expires := time.Now().Add(time.Hour).UTC().Truncate(time.Second)
	sbom := &results.SBOM{Key: "sboms/" + f.org.String() + "/x.cdx.json", Size: 42, SHA256: strings.Repeat("a", 64), Components: 7, ExpiresAt: expires}
	if p := f.processLicenses(licenses, sbom); p.Stats.New != 1 {
		t.Fatalf("%+v", p.Stats)
	}
	var sev, pkg, ver, path string
	ownerTx(t, f.org, func(tx pgx.Tx) error {
		return tx.QueryRow(context.Background(), `SELECT severity, package_name, package_version, file_path FROM issue
			WHERE project_id = $1 AND rule_id = 'license:GPL-3.0-only'`, f.project).Scan(&sev, &pkg, &ver, &path)
	})
	if sev != "medium" || pkg != "gpl-thing" || ver != "1.0.0" || path != "package-lock.json" {
		t.Fatal(sev, pkg, ver, path)
	}
	if n := f.count(`SELECT count(*) FROM scan WHERE sbom_key = $1 AND sbom_components = 7 AND sbom_size = 42 AND sbom_expires_at = $2`, sbom.Key, expires); n != 1 {
		t.Fatal("sbom not recorded")
	}

	// Blocking restricted licenses raises the severity of the same issue.
	f.setLicensePolicy(`{"categories":{"restricted":"block"}}`)
	if p := f.processLicenses(licenses, nil); p.Stats.New != 0 || p.Stats.Total != 1 {
		t.Fatalf("%+v", p.Stats)
	}
	if f.issues()["license:GPL-3.0-only"].Status != "open" ||
		f.count(`SELECT count(*) FROM issue WHERE rule_id = 'license:GPL-3.0-only' AND severity = 'high'`) != 1 {
		t.Fatal("severity not raised")
	}
	// Turning the policy off fixes the license issues like any finding that went away.
	f.setLicensePolicy(`{}`)
	if p := f.processLicenses(licenses, nil); p.Stats.Fixed != 1 {
		t.Fatalf("%+v", p.Stats)
	}
	if f.issues()["license:GPL-3.0-only"].Status != "fixed" {
		t.Fatal("not fixed")
	}
}

// The sbom_* columns are all set or all null.
func TestSBOMColumnsAllOrNone(t *testing.T) {
	f := newFixture(t)
	scan := f.scan("trivy")
	err := db.WithOrg(context.Background(), ownerPool, f.org, func(tx pgx.Tx) error {
		_, err := tx.Exec(context.Background(), `UPDATE scan SET sbom_key = 'k' WHERE id = $1`, scan)
		return err
	})
	if err == nil || !strings.Contains(err.Error(), "scan_sbom_all_or_none") {
		t.Fatal(err)
	}
}
