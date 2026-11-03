package sarif_test

import (
	"encoding/json"
	"errors"
	"os"
	"path/filepath"
	"slices"
	"strings"
	"testing"
	"time"

	"github.com/aupv9/warden/backend/internal/domain/fingerprint"
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

var (
	shaOld = strings.Repeat("0a", 20)
	shaNew = strings.Repeat("0b", 20)
)

func historyCommit(sha, date string) st.Commit {
	return st.Commit{SHA: sha, Date: date, Author: "A", Email: "a@x.test", Message: "m"}
}

func redacted(t *testing.T, results ...any) st.M {
	t.Helper()
	doc, err := redact.Doc(st.RoundTrip(st.Doc(results)), st.HMACKey)
	if err != nil {
		t.Fatal(err)
	}
	return doc
}

// Git mode: the path is the repository's (a top-level src/ kept), and the
// commit is read from what warden-redact left.
func TestGitleaksHistoryParse(t *testing.T) {
	doc := redacted(t, st.HistoryResult("aws-access-token", "src/config.py", 4, st.FakeSecret, historyCommit(shaOld, "2024-02-03T04:05:06+07:00")))
	f := one(t, parse(t, doc, "gitleaks", sarif.Options{History: true, RootDir: "src"}))
	if f.FilePath != "src/config.py" || f.Line() != 4 || f.Commit == nil || f.Commit.SHA != shaOld || f.Commit.Count != 1 ||
		f.Commit.Date == nil || !f.Commit.Date.Equal(time.Date(2024, 2, 2, 21, 5, 6, 0, time.UTC)) || f.Commit.Date.Location() != time.UTC {
		t.Fatalf("%+v %+v", f, f.Commit)
	}
	if k := f.Key(); k.FilePath != fingerprint.HistoryPath || k.ContentKey == "" {
		t.Fatal(k)
	}
	// Source scans ignore commit fields (dir mode writes empty ones).
	if f := one(t, parse(t, doc, "gitleaks", sarif.Options{})); f.Commit != nil || f.Key().FilePath != "config.py" {
		t.Fatalf("%+v", f)
	}
}

func TestGitleaksHistoryRejectsBadCommits(t *testing.T) {
	sha256 := strings.Repeat("c", 64)
	if f := one(t, parse(t, redacted(t, st.HistoryResult("r", "a", 1, "s3cr3t-value-1", historyCommit(sha256, "2020-01-01T00:00:00Z"))),
		"gitleaks", sarif.Options{History: true})); f.Commit.SHA != sha256 {
		t.Fatal(f.Commit)
	}
	for name, sha := range map[string]string{
		"missing": "", "short": shaOld[:39], "upper": strings.ToUpper(shaOld), "abbreviated": shaOld[:7],
		"injection": shaOld + "' OR 1=1 --", "newline": shaOld + "\n", "41 chars": shaOld + "a",
	} {
		doc := redacted(t, st.HistoryResult("r", "a", 1, "s3cr3t-value-1", historyCommit(sha, "2020-01-01T00:00:00Z")))
		if _, err := sarif.Parse(doc, "gitleaks", sarif.Options{History: true}); !errors.Is(err, sarif.ErrSARIF) {
			t.Errorf("%s: got %v", name, err)
		}
	}
	// A date that isn't a sane RFC 3339 time is dropped, not the finding.
	for _, date := range []string{"", "yesterday", "2020-01-01", "1969-12-31T23:59:59Z", "2020-13-01T00:00:00Z",
		"10000-01-01T00:00:00Z", "2020-01-01T00:00:00Z" + strings.Repeat(" ", 100), "2020-01-01 00:00:00"} {
		doc := redacted(t, st.HistoryResult("r", "a", 1, "s3cr3t-value-1", historyCommit(shaOld, date)))
		if f := one(t, parse(t, doc, "gitleaks", sarif.Options{History: true})); f.Commit == nil || f.Commit.Date != nil {
			t.Errorf("%q: %+v", date, f.Commit)
		}
	}
}

// One finding per rule and secret: the oldest commit's location, and how many
// commits added it. Another secret, or another rule, stays apart.
func TestCollapseHistory(t *testing.T) {
	other := "ghp_" + strings.Repeat("Q", 36)
	doc := redacted(t,
		st.HistoryResult("aws-access-token", "b/new.py", 9, st.FakeSecret, historyCommit(shaNew, "2025-06-01T00:00:00Z")),
		st.HistoryResult("aws-access-token", "a/old.py", 3, st.FakeSecret, historyCommit(shaOld, "2023-06-01T00:00:00Z")),
		st.HistoryResult("aws-access-token", "a/copy.py", 1, st.FakeSecret, historyCommit(shaOld, "2023-06-01T00:00:00Z")),
		st.HistoryResult("github-pat", "x.py", 2, other, historyCommit(shaNew, "2025-06-01T00:00:00Z")),
		st.HistoryResult("generic-api-key", "a/old.py", 3, st.FakeSecret, historyCommit(shaNew, "")),
	)
	fs := sarif.CollapseHistory(parse(t, doc, "gitleaks", sarif.Options{History: true}))
	if len(fs) != 3 {
		t.Fatalf("%d findings", len(fs))
	}
	aws := fs[0]
	// Same commit and date: the path decides, so the choice is stable.
	if aws.RuleID != "aws-access-token" || aws.FilePath != "a/copy.py" || aws.Line() != 1 || aws.Commit.SHA != shaOld || aws.Commit.Count != 2 {
		t.Fatalf("%+v %+v", aws, aws.Commit)
	}
	if fs[1].RuleID != "github-pat" || fs[1].Commit.Count != 1 || fs[2].RuleID != "generic-api-key" || fs[2].Commit.Date != nil {
		t.Fatalf("%+v %+v", fs[1], fs[2])
	}
	// Unknown dates sort after known ones.
	a := sarif.Finding{Tool: "gitleaks", RuleID: "r", ContentKey: "k", FilePath: "a", Commit: &sarif.Commit{SHA: shaOld}}
	when := time.Date(2030, 1, 1, 0, 0, 0, 0, time.UTC)
	b := sarif.Finding{Tool: "gitleaks", RuleID: "r", ContentKey: "k", FilePath: "b", Commit: &sarif.Commit{SHA: shaNew, Date: &when}}
	if got := sarif.CollapseHistory([]sarif.Finding{a, b}); len(got) != 1 || got[0].FilePath != "b" || got[0].Commit.Count != 2 {
		t.Fatalf("%+v", got)
	}
	// Findings without a commit (source scans) are left alone.
	plain := sarif.Finding{Tool: "gitleaks", RuleID: "r", ContentKey: "k", FilePath: "a"}
	if got := sarif.CollapseHistory([]sarif.Finding{plain, plain}); len(got) != 2 {
		t.Fatal(got)
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

// Org rules: Opengrep's "rules.org.<key>" (the /rules mount) becomes
// "org.<key>", and the finding takes the rule's stored severity whatever level
// the SARIF claims. The rule's text comes from its metadata, never from the
// result message (which Opengrep fills with matched code).
func TestOrgRuleIDAndSeverity(t *testing.T) {
	rid := "rules.org.no-eval"
	doc := st.Doc(
		[]any{st.M{"ruleId": rid, "level": "note", "message": st.M{"text": "Do not call eval here: secret_value"},
			"locations": []any{st.Loc("a.py", 2)}}},
		st.M{"id": rid, "shortDescription": st.M{"text": "Opengrep Finding: " + rid},
			"fullDescription":      st.M{"text": "Do not call $F here."},
			"defaultConfiguration": st.M{"level": "note"}, "properties": st.M{"security-severity": "9.8"}},
	)
	opts := sarif.Options{OrgRules: map[string]severity.Severity{"org.no-eval": severity.Low}}
	f := one(t, parse(t, doc, "opengrep", opts))
	if f.RuleID != "org.no-eval" || f.Severity != severity.Low || f.RuleDescription != "Do not call $F here." {
		t.Fatalf("%+v", f)
	}
	if !sarif.IsOrgRule("opengrep", f.RuleID) || !sarif.IsOrgRule("gitleaks", "org.x") ||
		sarif.IsOrgRule("trivy", "org.x") || sarif.IsOrgRule("opengrep", "python.org.x") {
		t.Fatal("IsOrgRule")
	}

	gl := st.GitleaksDoc()
	gl["runs"].([]any)[0].(st.M)["results"].([]any)[0].(st.M)["ruleId"] = "org.acme-token"
	gl["runs"].([]any)[0].(st.M)["tool"].(st.M)["driver"].(st.M)["rules"] = []any{
		st.M{"id": "org.acme-token", "shortDescription": st.M{"text": "Acme API token"}}}
	red, err := redact.Doc(st.RoundTrip(gl), st.HMACKey)
	if err != nil {
		t.Fatal(err)
	}
	g := one(t, parse(t, red, "gitleaks", sarif.Options{OrgRules: map[string]severity.Severity{"org.acme-token": severity.Medium}}))
	if g.RuleID != "org.acme-token" || g.Severity != severity.Medium || g.RuleDescription != "Acme API token" ||
		strings.Contains(g.RuleDescription+g.Title+g.Description+g.Snippet, st.FakeSecret) {
		t.Fatalf("%+v", g)
	}
}

// Attacks on the org namespace: a Warden rule whose id would strip to
// "org.…" keeps its full id (it can't stand in for an org rule's
// fingerprint), and an org rule id the scan didn't run is refused, not
// trusted with a severity.
func TestOrgRuleNamespace(t *testing.T) {
	builtin := "data.rules.org.no-eval"
	doc := st.Doc([]any{st.M{"ruleId": builtin, "level": "error", "message": st.M{"text": "m"}, "locations": []any{st.Loc("a.py", 1)}}})
	f := one(t, parse(t, doc, "opengrep", sarif.Options{OrgRules: map[string]severity.Severity{"org.no-eval": severity.Low}}))
	if f.RuleID != builtin || f.Severity != severity.High {
		t.Fatalf("%+v", f)
	}
	for _, c := range []struct {
		tool, id string
		opts     sarif.Options
	}{
		{"opengrep", "rules.org.other", sarif.Options{OrgRules: map[string]severity.Severity{"org.no-eval": severity.Low}}},
		{"opengrep", "rules.org.no-eval", sarif.Options{}},
		{"opengrep", "org.no-eval", sarif.Options{}},
		{"opengrep", "rules.org.bad-sev", sarif.Options{OrgRules: map[string]severity.Severity{"org.bad-sev": "urgent"}}},
		{"checkov", "CKV_1", sarif.Options{}}, // control: not an org rule
	} {
		doc := st.Doc([]any{st.M{"ruleId": c.id, "message": st.M{"text": "m"}, "locations": []any{st.Loc("a.py", 1)}}})
		_, err := sarif.Parse(st.RoundTrip(doc), c.tool, c.opts)
		if want := c.tool != "checkov"; errors.Is(err, sarif.ErrSARIF) != want {
			t.Errorf("%s %s: %v", c.tool, c.id, err)
		}
	}
	gl := st.GitleaksDoc()
	gl["runs"].([]any)[0].(st.M)["results"].([]any)[0].(st.M)["ruleId"] = "org.unknown"
	red, err := redact.Doc(st.RoundTrip(gl), st.HMACKey)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := sarif.Parse(red, "gitleaks", sarif.Options{}); !errors.Is(err, sarif.ErrSARIF) {
		t.Fatalf("got %v", err)
	}
}

// Only org rules the tool listed count as loaded; Warden's rules, other
// tools' namespaces and junk entries don't.
func TestLoadedOrgRules(t *testing.T) {
	doc := st.RoundTrip(st.Doc([]any{},
		st.M{"id": "rules.org.good"}, st.M{"id": "data.rules.org.sneaky"}, st.M{"id": "data.rules.python.x"},
		st.M{"id": 7}, "junk", st.M{"id": "rules.org." + strings.Repeat("a", 300)}))
	got := sarif.LoadedOrgRules(doc, "opengrep")
	if len(got) != 1 || !got["org.good"] {
		t.Fatal(got)
	}
	gl := st.RoundTrip(st.Doc([]any{}, st.M{"id": "org.acme"}, st.M{"id": "aws-access-token"}))
	if got := sarif.LoadedOrgRules(gl, "gitleaks"); len(got) != 1 || !got["org.acme"] {
		t.Fatal(got)
	}
	if got := sarif.LoadedOrgRules(gl, "trivy"); len(got) != 0 {
		t.Fatal(got)
	}
	if got := sarif.LoadedOrgRules(st.M{"runs": "x"}, "opengrep"); len(got) != 0 {
		t.Fatal(got)
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

// An org rule written to match credentials must not carry them out of the
// sandbox: Opengrep interpolates the matched code into the result message
// (and its region snippet), and nothing outside Gitleaks's sandbox redacts.
// Title and description come from the rule's own text; no snippet is kept.
func TestOrgOpengrepFindingCarriesNoMatchedCode(t *testing.T) {
	secret := st.FakeSecret
	root := filepath.Join(t.TempDir(), "src")
	_ = os.MkdirAll(root, 0o755)
	_ = os.WriteFile(filepath.Join(root, "conf.py"), []byte("x = 1\nkey = \""+secret+"\"\ny = 2\n"), 0o644)
	rid := "rules.org.hardcoded"
	loc := st.Loc("conf.py", 2)
	loc["physicalLocation"].(st.M)["region"].(st.M)["snippet"] = st.M{"text": "key = \"" + secret + "\""}
	doc := st.Doc(
		[]any{st.M{"ruleId": rid, "level": "error", "message": st.M{"text": "Hardcoded credential " + secret}, "locations": []any{loc}}},
		st.M{"id": rid, "shortDescription": st.M{"text": "Opengrep Finding: " + rid},
			"fullDescription": st.M{"text": "Hardcoded credential\nRotate it."}},
	)
	opts := sarif.Options{SourceRoot: root, OrgRules: map[string]severity.Severity{"org.hardcoded": severity.High}}
	f := one(t, parse(t, doc, "opengrep", opts))
	if strings.Contains(f.Title+f.Description+f.Snippet+f.RuleDescription, secret) {
		t.Fatalf("matched code left the sandbox: %+v", f)
	}
	if f.Title != "Hardcoded credential" || f.Snippet != "" || f.ContentKey == "" || *f.StartLine != 2 {
		t.Fatalf("%+v", f)
	}
}
