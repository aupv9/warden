package results

import (
	"context"
	"fmt"
	"strings"
	"testing"
	"time"

	"github.com/google/uuid"

	"github.com/aupv9/warden/backend/internal/domain/licensepolicy"
	"github.com/aupv9/warden/backend/internal/domain/severity"
	"github.com/aupv9/warden/backend/internal/scan/sandbox"
	"github.com/aupv9/warden/backend/internal/scan/sarif"
	"github.com/aupv9/warden/backend/internal/scan/trivyjson"
	"github.com/aupv9/warden/backend/internal/worker/dbtest"
)

func lic(pkg, version, license string, cat licensepolicy.Category, terms ...[]string) trivyjson.License {
	if terms == nil {
		terms = [][]string{{license}}
	}
	return trivyjson.License{Target: "app/package-lock.json", FilePath: "package-lock.json", Class: trivyjson.ClassLangPackages,
		PkgName: pkg, PkgVersion: version, License: license, Terms: terms, Category: cat, Declared: license}
}

var sampleLicenses = []trivyjson.License{
	lic("gpl-thing", "1.0.0", "GPL-3.0-only", licensepolicy.Restricted),
	lic("lodash", "4.17.15", "MIT", licensepolicy.Notice),
	lic("bad", "6.6.6", "BSD-3-Clause AND SSPL-1.0", licensepolicy.Notice, []string{"BSD-3-Clause", "SSPL-1.0"}),
	lic("weird", "2.0.0", trivyjson.UnknownID, licensepolicy.Unknown),
	lic("banned", "1.0", "WTFPL", licensepolicy.Forbidden),
}

func TestLicenseFindings(t *testing.T) {
	if fs := LicenseFindings(sampleLicenses, licensepolicy.Policy{}); fs != nil {
		t.Fatal("a policy that is off reports licenses")
	}
	p := licensepolicy.Recommended()
	p.Deny = []string{"SSPL-1.0"}
	fs := LicenseFindings(sampleLicenses, p)
	byRule := map[string]sarif.Finding{}
	for _, f := range fs {
		byRule[f.RuleID] = f
	}
	if len(fs) != 3 {
		t.Fatalf("%d findings: %+v", len(fs), fs)
	}
	g := byRule["license:GPL-3.0-only"]
	if g.Tool != "trivy" || g.Severity != severity.Medium || g.Title != "gpl-thing uses GPL-3.0-only (restricted)" ||
		g.PackageName != "gpl-thing" || g.PackageVersion != "1.0.0" || g.FixedVersion != "" || g.FilePath != "package-lock.json" ||
		g.ContentKey != "license:GPL-3.0-only|gpl-thing|1.0.0" || g.StartLine != nil || g.CVE != nil {
		t.Fatalf("%+v", g)
	}
	if !strings.Contains(g.Description, "sets restricted licenses to review") || g.Remediation == "" {
		t.Fatal(g.Description)
	}
	// The denied id names the rule, whatever else the expression holds.
	s := byRule["license:SSPL-1.0"]
	if s.Severity != severity.High || s.Title != "bad uses SSPL-1.0 (notice)" || !strings.Contains(s.Description, "denies SSPL-1.0") {
		t.Fatalf("%+v", s)
	}
	if b := byRule["license:WTFPL"]; b.Severity != severity.High {
		t.Fatalf("%+v", b)
	}
	// Unknown licenses only when the policy says so.
	p.Categories[licensepolicy.Unknown] = licensepolicy.Review
	u := LicenseFindings(sampleLicenses, p)
	if len(u) != 4 || u[2].RuleID != "license:LicenseRef-unknown" || !strings.Contains(u[2].Description, "not a valid SPDX") {
		t.Fatalf("%+v", u)
	}
}

// License issues share the trivy tool with vulnerabilities but never collide
// with them, and a vulnerability's fingerprint doesn't change when license
// findings are added.
func TestLicenseFindingsKeepVulnerabilityFingerprints(t *testing.T) {
	vuln := fTrivy
	vuln.FilePath, vuln.PackageName, vuln.PackageVersion = "package-lock.json", "gpl-thing", "1.0.0"
	before := Fingerprints(map[string][]sarif.Finding{"trivy": {vuln}}, map[string]bool{"trivy": true})
	lf := LicenseFindings(sampleLicenses, licensepolicy.Recommended())
	after := Fingerprints(map[string][]sarif.Finding{"trivy": append([]sarif.Finding{vuln}, lf...)}, map[string]bool{"trivy": true})
	if after[0].Fingerprint != before[0].Fingerprint || len(after) != 1+len(lf) || after[1].Fingerprint == after[0].Fingerprint {
		t.Fatalf("%+v", after)
	}
}

func licenseWorld(policy string, trivy sandbox.ToolStatus) (Input, []dbtest.Step) {
	in := Input{OrgID: uuid.New(), ProjectID: uuid.New(), ScanID: uuid.New(), Status: "completed", GuardRatio: 1, Now: time.Now(),
		Runs: []sandbox.ToolRun{{Tool: "trivy", Status: trivy}}, Licenses: sampleLicenses,
		SBOM: &SBOM{Key: "sboms/o/s.cdx.json", Size: 10, SHA256: strings.Repeat("a", 64), Components: 3, ExpiresAt: time.Now()}}
	steps := []dbtest.Step{
		{Prefix: "SELECT status FROM scan", Rows: row("running")},
		{Prefix: "SELECT issue_seq FROM project", Rows: row(0)},
		{Prefix: "SELECT sla_days, license_policy FROM organization", Rows: row([]byte(`{"high":30}`), []byte(policy))},
		{Prefix: "SELECT id, fingerprint"},
	}
	return in, steps
}

func TestProcessCreatesLicenseIssuesAndRecordsSBOM(t *testing.T) {
	in, steps := licenseWorld(`{"categories":{"forbidden":"block","restricted":"review"}}`, sandbox.Succeeded)
	db := dbtest.Loose(t, append(steps,
		dbtest.Step{Prefix: "SELECT assign_rules", Rows: row([]byte(`[]`))},
		dbtest.Step{Prefix: "UPDATE project SET issue_seq", Rows: row(2)},
		dbtest.Step{Prefix: "INSERT INTO", Affected: 1},
		dbtest.Step{Prefix: "UPDATE", Affected: 1},
	)...)
	p, err := Process(context.Background(), db, in)
	if err != nil {
		t.Fatal(err)
	}
	if p.Stats.New != 2 || p.ToolCounts["trivy"] != 2 {
		t.Fatalf("%+v", p)
	}
	issues := db.Calls("INSERT INTO issue (")
	if len(issues) != 2 || issues[0].Args[6] != "license:GPL-3.0-only" || issues[1].Args[6] != "license:WTFPL" {
		t.Fatalf("%v", issues)
	}
	sb := db.Calls("UPDATE scan SET sbom_key")
	if len(sb) != 1 || sb[0].Args[1] != "sboms/o/s.cdx.json" || sb[0].Args[4] != 3 {
		t.Fatalf("%v", sb)
	}
}

// Licenses count only when Trivy succeeded, and a policy that is off creates nothing.
func TestProcessLicensesNeedTrivyAndAPolicy(t *testing.T) {
	for _, c := range []struct {
		policy string
		trivy  sandbox.ToolStatus
	}{
		{`{}`, sandbox.Succeeded},
		{`{"categories":{"forbidden":"block"}}`, sandbox.Failed},
	} {
		in, steps := licenseWorld(c.policy, c.trivy)
		in.SBOM = nil
		db := dbtest.Loose(t, append(steps, dbtest.Step{Prefix: "UPDATE", Affected: 1}, dbtest.Step{Prefix: "INSERT INTO outbox_event", Affected: 1})...)
		if _, err := Process(context.Background(), db, in); err != nil {
			t.Fatal(err)
		}
		if n := len(db.Calls("INSERT INTO issue (")); n != 0 {
			t.Fatalf("%s/%s: %d issues", c.policy, c.trivy, n)
		}
		if len(db.Calls("UPDATE scan SET sbom_key")) != 0 {
			t.Fatal("sbom recorded without one")
		}
	}
}

func TestProcessRejectsCorruptLicensePolicy(t *testing.T) {
	for _, bad := range []string{`[]`, `{"categories":"x"}`, `not json`} {
		in, steps := licenseWorld(bad, sandbox.Succeeded)
		db := dbtest.New(t, steps[:3]...)
		if _, err := Process(context.Background(), db, in); err == nil || !strings.Contains(err.Error(), "license_policy") {
			t.Fatal(fmt.Sprint(bad, err))
		}
	}
}
