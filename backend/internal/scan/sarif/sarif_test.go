package sarif_test

import (
	"encoding/json"
	"errors"
	"os"
	"path/filepath"
	"slices"
	"strings"
	"testing"

	"github.com/aupv9/warden/backend/internal/domain/severity"
	"github.com/aupv9/warden/backend/internal/scan/redact"
	"github.com/aupv9/warden/backend/internal/scan/sarif"
	st "github.com/aupv9/warden/backend/internal/scan/scantest"
)

func parse(t *testing.T, doc st.M, tool string, opts sarif.Options) []sarif.Finding {
	t.Helper()
	fs, err := sarif.Parse(st.RoundTrip(doc), tool, opts)
	if err != nil {
		t.Fatal(err)
	}
	return fs
}

func one(t *testing.T, fs []sarif.Finding) sarif.Finding {
	t.Helper()
	if len(fs) != 1 {
		t.Fatalf("want 1 finding, got %d", len(fs))
	}
	return fs[0]
}

func TestGitleaksWithoutRedactionIsRefused(t *testing.T) {
	if _, err := sarif.Parse(st.RoundTrip(st.GitleaksDoc()), "gitleaks", sarif.Options{}); !errors.Is(err, sarif.ErrSARIF) {
		t.Fatalf("got %v", err)
	}
}

func TestGitleaksParseAfterRedaction(t *testing.T) {
	doc, err := redact.Doc(st.RoundTrip(st.GitleaksDoc()), st.HMACKey)
	if err != nil {
		t.Fatal(err)
	}
	f := one(t, parse(t, doc, "gitleaks", sarif.Options{}))
	if f.Severity != severity.Critical || f.Snippet != "AKIA****" {
		t.Fatalf("%+v", f)
	}
	raw, _ := json.Marshal(f.Raw)
	if strings.Contains(string(raw), st.FakeSecret) {
		t.Fatal("secret in raw")
	}
}

func TestOpengrepParseReadsSourceLines(t *testing.T) {
	root := filepath.Join(t.TempDir(), "src")
	_ = os.MkdirAll(filepath.Join(root, "svc-main"), 0o755)
	_ = os.WriteFile(filepath.Join(root, "svc-main/db.py"), []byte("a\nb\ncur.execute('SELECT ' + q)\nc\n"), 0o644)
	rules := st.M{
		"id":               "python.sqli",
		"shortDescription": st.M{"text": "SQL injection"},
		"properties":       st.M{"tags": []any{"CWE-89: SQL Injection"}, "security-severity": "9.8"},
	}
	doc := st.Doc([]any{st.M{
		"ruleId": "python.sqli", "level": "error", "message": st.M{"text": "m"},
		"locations": []any{st.Loc("/src/svc-main/db.py", 3)},
	}}, rules)
	f := one(t, parse(t, doc, "opengrep", sarif.Options{RootDir: "svc-main", SourceRoot: root}))
	if f.FilePath != "db.py" || f.Severity != severity.Critical || !slices.Equal(f.CWE, []string{"CWE-89"}) {
		t.Fatalf("%+v", f)
	}
	if f.Snippet != "a\nb\ncur.execute('SELECT ' + q)\nc" {
		t.Fatalf("snippet %q", f.Snippet)
	}
}

func TestSourceReadCannotEscapeRoot(t *testing.T) {
	dir := t.TempDir()
	_ = os.WriteFile(filepath.Join(dir, "outside.txt"), []byte("host secret\n"), 0o644)
	root := filepath.Join(dir, "src")
	_ = os.Mkdir(root, 0o755)
	for _, uri := range []string{"../outside.txt", "/src/../../outside.txt", "file:///src/..%2F..%2Foutside.txt"} {
		doc := st.Doc([]any{st.M{"ruleId": "r", "message": st.M{"text": "m"}, "locations": []any{st.Loc(uri, 1)}}})
		if f := one(t, parse(t, doc, "opengrep", sarif.Options{SourceRoot: root})); f.Snippet != "" {
			t.Fatalf("%s: read %q", uri, f.Snippet)
		}
	}
}

func TestSourceReadDoesNotFollowSymlinkOut(t *testing.T) {
	dir := t.TempDir()
	_ = os.WriteFile(filepath.Join(dir, "outside.txt"), []byte("host secret\n"), 0o644)
	root := filepath.Join(dir, "src")
	_ = os.Mkdir(root, 0o755)
	_ = os.Symlink(filepath.Join(dir, "outside.txt"), filepath.Join(root, "link.py"))
	doc := st.Doc([]any{st.M{"ruleId": "r", "message": st.M{"text": "m"}, "locations": []any{st.Loc("link.py", 1)}}})
	if f := one(t, parse(t, doc, "opengrep", sarif.Options{SourceRoot: root})); f.Snippet != "" {
		t.Fatalf("read %q", f.Snippet)
	}
}

func TestSourceReadIsBoundedOnHugeLines(t *testing.T) {
	root := t.TempDir()
	_ = os.WriteFile(filepath.Join(root, "min.js"), []byte(strings.Repeat("x", 3<<20)+"\n"), 0o644)
	doc := st.Doc([]any{st.M{"ruleId": "r", "message": st.M{"text": "m"}, "locations": []any{st.Loc("min.js", 1)}}})
	f := one(t, parse(t, doc, "opengrep", sarif.Options{SourceRoot: root}))
	if len([]rune(f.Snippet)) != sarif.MaxSnippet {
		t.Fatalf("snippet len %d", len(f.Snippet))
	}
}

func TestUniversalNewlines(t *testing.T) {
	root := t.TempDir()
	_ = os.WriteFile(filepath.Join(root, "a.py"), []byte("l1\r\nl2\rl3\nl4"), 0o644)
	doc := st.Doc([]any{st.M{"ruleId": "r", "message": st.M{"text": "m"}, "locations": []any{st.Loc("a.py", 4)}}})
	f := one(t, parse(t, doc, "opengrep", sarif.Options{SourceRoot: root}))
	if f.Snippet != "l1\nl2\nl3\nl4" {
		t.Fatalf("%q", f.Snippet)
	}
}

func TestTrivyParse(t *testing.T) {
	msg := "Package: lodash\nInstalled Version: 4.17.20\nVulnerability CVE-2021-23337\n" +
		"Severity: HIGH\nFixed Version: 4.17.21\nLink: [CVE-2021-23337](https://x)"
	doc := st.Doc(
		[]any{st.M{"ruleId": "CVE-2021-23337", "message": st.M{"text": msg}, "locations": []any{st.Loc("app/package-lock.json", 1)}}},
		st.M{"id": "CVE-2021-23337", "properties": st.M{"tags": []any{"vulnerability", "HIGH"}}},
	)
	f := one(t, parse(t, doc, "trivy", sarif.Options{RootDir: "app"}))
	if f.PackageName != "lodash" || f.PackageVersion != "4.17.20" || f.FixedVersion != "4.17.21" ||
		!slices.Equal(f.CVE, []string{"CVE-2021-23337"}) || f.Severity != severity.High ||
		f.FilePath != "package-lock.json" || f.ContentKey != "CVE-2021-23337|lodash|4.17.20" || f.StartLine != nil {
		t.Fatalf("%+v", f)
	}
}

// Trivy's license results (rule "pkg:SPDX", tag "license") are dropped: the
// vulnerability findings, and so their fingerprints, are what they were
// before licenses were scanned.
func TestTrivyDropsLicenseResults(t *testing.T) {
	msg := "Package: lodash\nInstalled Version: 4.17.20\nVulnerability CVE-2021-23337\nSeverity: HIGH\nFixed Version: 4.17.21"
	vuln := st.M{"ruleId": "CVE-2021-23337", "message": st.M{"text": msg}, "locations": []any{st.Loc("app/package-lock.json", 1)}}
	vulnRule := st.M{"id": "CVE-2021-23337", "properties": st.M{"tags": []any{"vulnerability", "security", "HIGH"}}}
	license := st.M{"ruleId": "gpl-thing:GPL-3.0-only", "message": st.M{"text": "Artifact: app/package-lock.json\nLicense GPL-3.0-only\nPkgName: gpl-thing"},
		"locations": []any{st.Loc("app/package-lock.json", 1)}}
	licenseRule := st.M{"id": "gpl-thing:GPL-3.0-only", "properties": st.M{"tags": []any{"license", "security", "HIGH"}}}

	before := parse(t, st.Doc([]any{vuln}, vulnRule), "trivy", sarif.Options{RootDir: "app"})
	after := parse(t, st.Doc([]any{license, vuln, license}, licenseRule, vulnRule), "trivy", sarif.Options{RootDir: "app"})
	if len(after) != 1 || after[0].Key() != before[0].Key() || after[0].Severity != before[0].Severity {
		t.Fatalf("before %+v\nafter %+v", before, after)
	}
	// Other tools keep results whatever their tags.
	if fs := parse(t, st.Doc([]any{license}, licenseRule), "checkov", sarif.Options{}); len(fs) != 1 {
		t.Fatal(fs)
	}
}

// Image scans: Trivy reports OS packages against the tarball (/src/image.tar)
// and language packages at their path in the image (real Trivy 0.75 output).
func TestTrivyImagePaths(t *testing.T) {
	msg := "Package: busybox\nInstalled Version: 1.36.0-r9\nSeverity: HIGH\nFixed Version: 1.36.1-r1"
	rule := st.M{"id": "CVE-2023-42363", "properties": st.M{"tags": []any{"vulnerability", "HIGH"}}}
	doc := st.Doc([]any{
		st.M{"ruleId": "CVE-2023-42363", "message": st.M{"text": msg}, "locations": []any{st.Loc("/src/image.tar", 1)}},
		st.M{"ruleId": "CVE-2023-42363", "message": st.M{"text": msg}, "locations": []any{st.Loc("usr/local/bin/trivy", 1)}},
	}, rule)
	fs := parse(t, doc, "trivy", sarif.Options{ImageTarget: "ghcr.io/acme/api", OSLabel: "alpine"})
	if len(fs) != 2 || fs[0].FilePath != "ghcr.io/acme/api::alpine" || fs[1].FilePath != "ghcr.io/acme/api::usr/local/bin/trivy" {
		t.Fatalf("%+v", fs)
	}
	if sarif.ImagePath("x", "", "src/image.tar") != "x::os" {
		t.Fatal("no OS label")
	}
	// Source scans are untouched.
	if f := parse(t, doc, "trivy", sarif.Options{}); f[1].FilePath != "usr/local/bin/trivy" {
		t.Fatal(f[1].FilePath)
	}
}

func TestResultCap(t *testing.T) {
	results := make([]any, sarif.MaxResultsPerTool+1)
	for i := range results {
		results[i] = st.M{"ruleId": "r", "message": st.M{"text": "m"}}
	}
	if _, err := sarif.Parse(st.Doc(results), "checkov", sarif.Options{}); !errors.Is(err, sarif.ErrSARIF) {
		t.Fatalf("got %v", err)
	}
}

func TestGarbageFieldsAreIgnored(t *testing.T) {
	doc := st.Doc([]any{
		st.M{"ruleId": json.Number("5")},
		"junk",
		st.M{"ruleId": "ok", "locations": []any{st.M{"physicalLocation": st.M{"region": st.M{"startLine": json.Number("-1")}}}}},
		st.M{"ruleId": "float", "locations": []any{st.M{"physicalLocation": st.M{"region": st.M{"startLine": json.Number("2.5")}}}}},
		st.M{"ruleId": "badloc", "locations": []any{"x", 3}},
		st.M{"ruleId": "badloc2", "locations": "x", "message": []any{1}},
	})
	fs := parse(t, doc, "checkov", sarif.Options{})
	if len(fs) != 4 || fs[0].RuleID != "ok" || fs[0].StartLine != nil || fs[1].StartLine != nil {
		t.Fatalf("%+v", fs)
	}
}

// Malformed structure that crashed the Python parser (tool/driver/rules of the wrong type).
func TestWrongTypesInRunStructure(t *testing.T) {
	for _, run := range []any{
		st.M{"tool": "x", "results": []any{st.M{"ruleId": "r"}}},
		st.M{"tool": st.M{"driver": []any{}}, "results": []any{st.M{"ruleId": "r"}}},
		st.M{"tool": st.M{"driver": st.M{"rules": "x"}}, "results": []any{st.M{"ruleId": "r"}}},
		st.M{"tool": st.M{"driver": st.M{"rules": []any{st.M{"id": "r", "properties": "x", "shortDescription": 7}}}}, "results": []any{st.M{"ruleId": "r"}}},
	} {
		fs := parse(t, st.M{"runs": []any{run, "junk"}}, "opengrep", sarif.Options{})
		if len(fs) != 1 {
			t.Fatalf("%v: %+v", run, fs)
		}
	}
}

func TestLongFieldsAreTruncated(t *testing.T) {
	long := strings.Repeat("é", 10_000)
	doc := st.Doc([]any{st.M{"ruleId": "r", "message": st.M{"text": long}, "locations": []any{st.Loc("a.py", 1, long)}}})
	f := one(t, parse(t, doc, "checkov", sarif.Options{}))
	if n := len([]rune(f.Title)); n != sarif.MaxTitle {
		t.Fatalf("title %d", n)
	}
	if n := len([]rune(f.Snippet)); n != sarif.MaxSnippet {
		t.Fatalf("snippet %d", n)
	}
}

func TestOpengrepRulePrefixAndGenericTitleNormalized(t *testing.T) {
	rid := "data.rules.python.lang.security.audit.eval"
	doc := st.Doc(
		[]any{st.M{"ruleId": rid, "message": st.M{"text": "Detected eval() use"}, "locations": []any{st.Loc("a.py", 1)}}},
		st.M{"id": rid, "shortDescription": st.M{"text": "Opengrep Finding: " + rid}},
	)
	f := one(t, parse(t, doc, "opengrep", sarif.Options{}))
	if f.RuleID != "python.lang.security.audit.eval" || f.Title != "Detected eval() use" {
		t.Fatalf("%+v", f)
	}
}

func writeFile(t *testing.T, data string) string {
	t.Helper()
	p := filepath.Join(t.TempDir(), "x.sarif")
	_ = os.WriteFile(p, []byte(data), 0o644)
	return p
}

func TestLoadRejectsBadDocuments(t *testing.T) {
	for _, data := range []string{`not json`, `[]`, `{"runs": {}}`, `{"runs": []} trailing`, ``} {
		if _, err := sarif.Load(writeFile(t, data)); !errors.Is(err, sarif.ErrSARIF) {
			t.Errorf("%q: %v", data, err)
		}
	}
	if _, err := sarif.Load(writeFile(t, `{"runs": []}`)); err != nil {
		t.Fatal(err)
	}
}
