package results

import (
	"context"
	"strings"
	"testing"

	"github.com/google/uuid"

	"github.com/aupv9/warden/backend/internal/domain/ecosystem"
	"github.com/aupv9/warden/backend/internal/domain/fingerprint"
	"github.com/aupv9/warden/backend/internal/domain/severity"
	"github.com/aupv9/warden/backend/internal/scan/sarif"
	"github.com/aupv9/warden/backend/internal/scan/trivyjson"
	"github.com/aupv9/warden/backend/internal/worker/dbtest"
)

func malPkg(eco, name, version, path string) trivyjson.Package {
	return trivyjson.Package{Ecosystem: eco, Name: name, MatchName: ecosystem.MatchName(eco, name), Version: version,
		MatchVersion: ecosystem.MatchVersion(eco, version), FilePath: path}
}

func TestMaliciousFinding(t *testing.T) {
	f := MaliciousFinding(malPkg("npm", "Evil-Pkg", "1.0.0", "app/package-lock.json"), Advisory{ID: "MAL-2026-1", Summary: "Malicious code in evil-pkg (npm)"})
	if f.Tool != "trivy" || f.RuleID != "malicious:MAL-2026-1" || f.Severity != severity.Critical ||
		f.Title != "Evil-Pkg 1.0.0 is a malicious package (MAL-2026-1)" || f.FilePath != "app/package-lock.json" ||
		f.ContentKey != fingerprint.SCAContentKey("MAL-2026-1", "evil-pkg", "1.0.0") ||
		f.PackageName != "Evil-Pkg" || f.PackageVersion != "1.0.0" || len(f.CVE) != 0 || f.FixedVersion != "" ||
		!strings.Contains(f.Description, "Malicious code in evil-pkg (npm)") || f.Remediation == "" || !IsMalicious(f) {
		t.Fatalf("%+v", f)
	}
	if IsMalicious(sarif.Finding{Tool: "opengrep", RuleID: "malicious:x"}) || IsMalicious(sarif.Finding{Tool: "trivy", RuleID: "license:MIT"}) {
		t.Fatal("IsMalicious too broad")
	}
}

// The fingerprint Inject computes for a component is the one a scan computes
// for the same package, whatever else the scan found and however the
// inventory spells the version (Go's leading v).
func TestInjectFingerprintEqualsScan(t *testing.T) {
	adv := Advisory{ID: "MAL-2026-7", Summary: "s"}
	scanPkg := malPkg("Go", "github.com/Evil/mod", "v1.2.3", "go.mod")
	other := []sarif.Finding{
		{Tool: "trivy", RuleID: "CVE-2024-1", FilePath: "go.mod", ContentKey: "CVE-2024-1|x|1"},
		{Tool: "trivy", RuleID: "license:GPL-3.0-only", FilePath: "go.mod", ContentKey: "license:GPL-3.0-only|y|2"},
	}
	scanFindings := append(other, MaliciousFinding(scanPkg, adv))
	var scanFP string
	for _, fp := range Fingerprints(map[string][]sarif.Finding{"trivy": scanFindings, "opengrep": {fA}}, map[string]bool{"trivy": true, "opengrep": true}) {
		if IsMalicious(fp.Finding) {
			scanFP = fp.Fingerprint
		}
	}
	// The inventory row: same package, version stored without the v.
	inv := malPkg("Go", "github.com/evil/mod", "1.2.3", "go.mod")
	inj := injectFindings([]MaliciousMatch{{Package: inv, ScanID: uuid.New(), Advisory: adv},
		{Package: inv, ScanID: uuid.New(), Advisory: adv}}) // duplicates collapse
	if len(inj) != 1 || scanFP == "" || inj[0].fingerprint != scanFP {
		t.Fatalf("scan %s, inject %+v", scanFP, inj)
	}
	if want := fingerprint.Fingerprint("trivy", "malicious:MAL-2026-7", "go.mod", fingerprint.SCAContentKey("MAL-2026-7", "github.com/evil/mod", "1.2.3"), 0); scanFP != want {
		t.Fatal("unexpected fingerprint inputs")
	}
}

func TestMaliciousFindingsMatch(t *testing.T) {
	packages := []trivyjson.Package{
		malPkg("npm", "evil", "1.0.0", "package-lock.json"),
		malPkg("npm", "evil", "1.0.0", "web/package-lock.json"), // another lockfile: its own finding
		malPkg("npm", "typo", "2.0.0", "package-lock.json"),     // listed version
		malPkg("npm", "typo", "2.0.1", "package-lock.json"),     // not listed
		malPkg("PyPI", "Bad_Pkg", "1.0RC1", "requirements.txt"), // normalized name and version
		malPkg("alpine", "musl", "1.2.3", "image"),              // no OSV feed: never looked up
		malPkg("npm", "fine", "1.0.0", "package-lock.json"),
	}
	db := dbtest.New(t, dbtest.Step{Prefix: "SELECT m.id, m.summary, m.ecosystem, m.match_name", Args: func(args []any) error {
		ecos, names := args[0].([]string), args[1].([]string)
		if strings.Join(ecos, ",") != "npm,npm,PyPI,npm" || strings.Join(names, ",") != "evil,typo,bad-pkg,fine" {
			t.Errorf("lookup %v %v", ecos, names)
		}
		return nil
	}, Rows: [][]any{
		{"MAL-2026-1", "evil", "npm", "evil", true, []string{}},
		{"MAL-2026-2", "typo", "npm", "typo", false, []string{"1.9.0", "2.0.0"}},
		{"MAL-2026-3", "bad", "PyPI", "bad-pkg", false, []string{"1.0rc1"}},
	}})
	got, err := MaliciousFindings(context.Background(), db, packages)
	if err != nil {
		t.Fatal(err)
	}
	db.Done()
	var titles []string
	for _, f := range got {
		titles = append(titles, f.Title+" @ "+f.FilePath)
	}
	want := []string{
		"evil 1.0.0 is a malicious package (MAL-2026-1) @ package-lock.json",
		"evil 1.0.0 is a malicious package (MAL-2026-1) @ web/package-lock.json",
		"typo 2.0.0 is a malicious package (MAL-2026-2) @ package-lock.json",
		"Bad_Pkg 1.0RC1 is a malicious package (MAL-2026-3) @ requirements.txt",
	}
	if strings.Join(titles, "\n") != strings.Join(want, "\n") {
		t.Fatalf("got\n%s", strings.Join(titles, "\n"))
	}

	// Nothing to look up: no query at all.
	none, err := MaliciousFindings(context.Background(), dbtest.New(t), []trivyjson.Package{malPkg("alpine", "musl", "1", "x")})
	if err != nil || none != nil {
		t.Fatal(none, err)
	}
	if _, err := MaliciousFindings(context.Background(), dbtest.New(t, dbtest.Step{Prefix: "SELECT m.id", Err: errDB}), packages); err == nil {
		t.Fatal("db error swallowed")
	}
}
