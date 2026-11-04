package importer_test

import (
	"encoding/json"
	"errors"
	"fmt"
	"os"
	"strings"
	"testing"
	"time"

	"github.com/aupv9/warden/backend/internal/domain/fingerprint"
	"github.com/aupv9/warden/backend/internal/domain/severity"
	"github.com/aupv9/warden/backend/internal/scan/importer"
	"github.com/aupv9/warden/backend/internal/scan/sarif"
	st "github.com/aupv9/warden/backend/internal/scan/scantest"
)

// The fixtures in testdata are real tool output, trimmed (scripts dropped
// unused rule texts, invocations and artifacts, long descriptions):
//
//   - codeql-cpp.sarif: CodeQL 2.15.0, C++ queries, rules in the driver and
//     results by ruleIndex; github.com/shellphish/artiphishell,
//     components/codeql/examples/sample-report.sarif.
//   - codeql-python-extensions.sarif: CodeQL 2.17.4, rules in a query pack
//     (tool.extensions) and results by rule.toolComponent, whose indexes are
//     out of range in the published file;
//     github.com/SecureCodeWarrior/github-action-add-sarif-contextual-training,
//     fixtures/codeql-extension-rules.sarif.
//   - gitlab-semgrep.json: GitLab's Semgrep analyzer, report schema 15.2.2;
//     gitlab.com/gitlab-org/security-products/analyzers/semgrep,
//     qa/expect/python/pip-flask/gl-sast-report.json.

func parse(t *testing.T, doc any, format string) *importer.Report {
	t.Helper()
	raw, err := json.Marshal(doc)
	if err != nil {
		t.Fatal(err)
	}
	rep, err := importer.Parse(raw, format)
	if err != nil {
		t.Fatalf("parse: %v", err)
	}
	checkReport(t, rep)
	return rep
}

func rejected(t *testing.T, raw []byte, format, code string) {
	t.Helper()
	_, err := importer.Parse(raw, format)
	var rej *importer.Rejected
	if !errors.As(err, &rej) || rej.Code != code {
		t.Fatalf("want %s, got %v", code, err)
	}
}

func mustJSON(v any) []byte {
	b, err := json.Marshal(v)
	if err != nil {
		panic(err)
	}
	return b
}

// sarifDoc is a SARIF 2.1.0 log with one run.
func sarifDoc(results []any, rules ...any) st.M {
	if rules == nil {
		rules = []any{}
	}
	return st.M{
		"$schema": "https://json.schemastore.org/sarif-2.1.0.json",
		"version": "2.1.0",
		"runs":    []any{st.M{"tool": st.M{"driver": st.M{"name": "CodeQL", "semanticVersion": "2.20.1", "rules": rules}}, "results": results}},
	}
}

func result(rule, uri string, line int) st.M {
	r := st.M{"ruleId": rule, "message": st.M{"text": "m " + rule}}
	if uri != "" {
		r["locations"] = []any{st.M{"physicalLocation": st.M{
			"artifactLocation": st.M{"uri": uri, "uriBaseId": "%SRCROOT%"},
			"region":           st.M{"startLine": line},
		}}}
	}
	return r
}

func TestRealCodeQL(t *testing.T) {
	raw, err := os.ReadFile("testdata/codeql-cpp.sarif")
	if err != nil {
		t.Fatal(err)
	}
	rep, err := importer.Parse(raw, importer.FormatSARIF)
	if err != nil {
		t.Fatal(err)
	}
	checkReport(t, rep)
	if rep.ToolVersion != "2.15.0" || rep.Read != 12 || len(rep.Results) != 12 || rep.Dropped != 0 {
		t.Fatalf("version %q, read %d, kept %d, dropped %d", rep.ToolVersion, rep.Read, len(rep.Results), rep.Dropped)
	}
	byRule := map[string]importer.Result{}
	for _, r := range rep.Results {
		byRule[r.RuleID] = r
		if !strings.HasPrefix(r.Path, "ruaronicola/codeql-codebases/garfield/challenge_src/src/") || r.StartLine == nil ||
			!strings.HasPrefix(r.Fingerprint, "pf:") {
			t.Fatalf("result %+v", r)
		}
	}
	// By ruleIndex into the driver's rules: title, description, CWEs from
	// the tags and the severity from security-severity (8.1: High).
	r := byRule["cpp/integer-multiplication-cast-to-long"]
	if r.Title != "Multiplication result converted to larger type" || r.Severity != severity.High ||
		strings.Join(r.CWE, ",") != "CWE-190,CWE-192,CWE-197,CWE-681" || !strings.HasPrefix(r.Description, "A multiplication result") {
		t.Fatalf("%+v", r)
	}
	if r := byRule["cpp/long-switch"]; *r.StartLine != 765 || *r.EndLine != 1085 {
		t.Fatalf("lines %+v", r)
	}
	// No security-severity: the level (note: Low; warning: Medium).
	if r := byRule["cpp/commented-out-code"]; r.Severity != severity.Low {
		t.Fatalf("%+v", r)
	}
	if r := byRule["cpp/use-of-goto"]; r.Severity != severity.Medium {
		t.Fatalf("%+v", r)
	}
}

func TestRealCodeQLExtensions(t *testing.T) {
	raw, err := os.ReadFile("testdata/codeql-python-extensions.sarif")
	if err != nil {
		t.Fatal(err)
	}
	rep, err := importer.Parse(raw, importer.FormatSARIF)
	if err != nil {
		t.Fatal(err)
	}
	checkReport(t, rep)
	if rep.ToolVersion != "2.17.4" || len(rep.Results) != 2 {
		t.Fatalf("%+v", rep)
	}
	// rule.toolComponent points at the query pack; the index is out of range
	// there, so the rule is found by id.
	r := rep.Results[1]
	if r.RuleID != "py/command-line-injection" || r.Title != "Uncontrolled command line" || r.Severity != severity.Critical ||
		strings.Join(r.CWE, ",") != "CWE-78,CWE-88" || r.Path != "dsvpwa/handlers.py" || *r.StartLine != 184 ||
		!strings.HasPrefix(r.Remediation, "# Uncontrolled command line") {
		t.Fatalf("%+v", r)
	}
	// Code flows and related locations are never read: nothing of them is kept.
	for _, r := range rep.Results {
		for _, s := range []string{r.Message, r.Description, r.Remediation} {
			if strings.Contains(s, "codeFlows") || strings.Contains(s, "threadFlows") {
				t.Fatalf("code flow kept: %q", s)
			}
		}
	}
}

func TestRealGitLab(t *testing.T) {
	raw, err := os.ReadFile("testdata/gitlab-semgrep.json")
	if err != nil {
		t.Fatal(err)
	}
	rep, err := importer.Parse(raw, importer.FormatGitLab)
	if err != nil {
		t.Fatal(err)
	}
	checkReport(t, rep)
	if rep.Read != 6 || len(rep.Results) != 6 {
		t.Fatalf("%+v", rep)
	}
	r := rep.Results[0]
	if r.RuleID != "bandit.B506" || r.Title != "Deserialization of untrusted data" || r.Severity != severity.High ||
		strings.Join(r.CWE, ",") != "CWE-502" || r.Path != "app/app.py" || *r.StartLine != 329 || *r.EndLine != 329 ||
		!strings.HasPrefix(r.Fingerprint, "pf:") || !strings.HasPrefix(r.Description, "The application was found") {
		t.Fatalf("%+v", r)
	}
	sev := map[severity.Severity]int{}
	for _, r := range rep.Results {
		sev[r.Severity]++
	}
	if sev[severity.High] != 2 || sev[severity.Medium] != 2 || sev[severity.Low] != 2 {
		t.Fatalf("severities %v", sev)
	}
}

// Every path that would leave the source root, or could be read as
// another path, drops its result; it is never repaired.
func TestPathAttacks(t *testing.T) {
	base := "file:///home/runner/work/app/app/"
	for _, c := range []struct {
		uri, uriBase string
		want         string // "" : dropped
	}{
		{"src/a.py", "%SRCROOT%", "src/a.py"},
		{"./src//a.py", "", "src/a.py"},
		{"src/a%20b.py", "%SRCROOT%", "src/a b.py"},
		{"file:///home/runner/work/app/app/src/a.py", "", "src/a.py"},
		{"/home/runner/work/app/app/src/a.py", "", "src/a.py"},
		{"file://localhost/home/runner/work/app/app/x.go", "", "x.go"},

		{"../etc/passwd", "%SRCROOT%", ""},
		{"src/../../etc/passwd", "", ""},
		{"%2e%2e/etc/passwd", "", ""},
		{"%2E%2E%2Fetc%2Fpasswd", "", ""},
		{"%252e%252e/etc/passwd", "", ""}, // decoded once: still encoded
		{"src%252fa.py", "", ""},
		{"..\\..\\windows\\win.ini", "", ""},
		{"src\\a.py", "", ""},
		{"C:/Windows/win.ini", "", ""},
		{"c:x", "", ""},
		{"/etc/passwd", "", ""},
		{"file:///etc/passwd", "", ""},
		{"file:///home/runner/work/app/app/../../../../etc/passwd", "", ""},
		{"file:///home/runner/work/app/appendix/x.py", "", ""}, // not under the root, only a prefix of its name
		{"file://evil.example/home/runner/work/app/app/a.py", "", ""},
		{"file:///home/runner/work/app/app/a.py?x=1", "", ""},
		{"//evil.example/share/a.py", "", ""},
		{"https://evil.example/a.py", "", ""},
		{"javascript:alert(1)", "", ""},
		{"src/a.py", "PROJECTROOT", ""},
		{"src/a\x00.py", "", ""},
		{"src/a%00.py", "", ""},
		{"src/\u202egnp.exe", "", ""},
		{"src/%E2%80%AEgnp.exe", "", ""},
		{"src/a\u200b.py", "", ""},
		{"src/a\nb.py", "", ""},
		{"src/%0a.py", "", ""},
		{"%", "", ""},
		{".", "", ""},
		{strings.Repeat("a/", 600) + "x.py", "", ""},
	} {
		res := result("r", "x", 1)
		al := res["locations"].([]any)[0].(st.M)["physicalLocation"].(st.M)["artifactLocation"].(st.M)
		al["uri"], al["uriBaseId"] = c.uri, c.uriBase
		if c.uriBase == "" {
			delete(al, "uriBaseId")
		}
		doc := sarifDoc([]any{res})
		doc["runs"].([]any)[0].(st.M)["originalUriBaseIds"] = st.M{"%SRCROOT%": st.M{"uri": base}}
		rep := parse(t, doc, importer.FormatSARIF)
		switch {
		case c.want == "" && (len(rep.Results) != 0 || rep.Dropped != 1):
			t.Errorf("%q kept as %+v", c.uri, rep.Results)
		case c.want != "" && (len(rep.Results) != 1 || rep.Results[0].Path != c.want):
			t.Errorf("%q: got %+v, want %q", c.uri, rep.Results, c.want)
		}
	}
}

// An absolute path is made relative only by the run's %SRCROOT%: without
// it, or with a %SRCROOT% that is itself relative, the result is dropped.
func TestAbsoluteWithoutSourceRoot(t *testing.T) {
	for _, base := range []any{nil, st.M{"uri": "src/"}, st.M{"uri": "file:///w/", "uriBaseId": "OTHER"}, "file:///w/"} {
		doc := sarifDoc([]any{result("r", "file:///w/a.py", 1)})
		if base != nil {
			doc["runs"].([]any)[0].(st.M)["originalUriBaseIds"] = st.M{"%SRCROOT%": base}
		}
		if rep := parse(t, doc, importer.FormatSARIF); len(rep.Results) != 0 || rep.Dropped != 1 {
			t.Fatalf("base %v: %+v", base, rep)
		}
	}
}

func TestResultWithoutLocationKeptWithoutPath(t *testing.T) {
	rep := parse(t, sarifDoc([]any{result("r", "", 0)}), importer.FormatSARIF)
	if len(rep.Results) != 1 || rep.Results[0].Path != "" || rep.Results[0].StartLine != nil {
		t.Fatalf("%+v", rep.Results)
	}
}

func TestVersionChecks(t *testing.T) {
	ok := sarifDoc([]any{})
	if _, err := importer.Parse(mustJSON(ok), importer.FormatSARIF); err != nil {
		t.Fatal(err)
	}
	for name, mutate := range map[string]func(st.M){
		"version 2.0.0":     func(d st.M) { d["version"] = "2.0.0" },
		"no version":        func(d st.M) { delete(d, "version") },
		"numeric version":   func(d st.M) { d["version"] = 2.1 },
		"schema 2.0":        func(d st.M) { d["$schema"] = "https://json.schemastore.org/sarif-2.0.0.json" },
		"schema not string": func(d st.M) { d["$schema"] = st.M{} },
		"no runs":           func(d st.M) { delete(d, "runs") },
		"runs an object":    func(d st.M) { d["runs"] = st.M{} },
		"results an object": func(d st.M) { d["runs"].([]any)[0].(st.M)["results"] = st.M{} },
	} {
		d := sarifDoc([]any{})
		mutate(d)
		t.Run(name, func(t *testing.T) { rejected(t, mustJSON(d), importer.FormatSARIF, importer.CodeInvalid) })
	}
	for name, raw := range map[string]string{
		"empty": "", "not JSON": "<sarif/>", "truncated": `{"version":"2.1.0","runs":[`,
		"trailing data": `{"version":"2.1.0","runs":[]} {}`, "array": `[]`, "null": `null`,
	} {
		t.Run(name, func(t *testing.T) { rejected(t, []byte(raw), importer.FormatSARIF, importer.CodeInvalid) })
	}
	rejected(t, mustJSON(ok), "xml", importer.CodeInvalid)
}

// A depth bomb is refused before it is decoded, also inside a field Warden
// never reads, and in no time.
func TestDepthBomb(t *testing.T) {
	deep := strings.Repeat("[", 5_000_000) + strings.Repeat("]", 5_000_000)
	start := time.Now()
	rejected(t, []byte(deep), importer.FormatSARIF, importer.CodeInvalid)
	inside := `{"version":"2.1.0","runs":[{"results":[{"ruleId":"r","codeFlows":` + strings.Repeat(`{"a":`, 100) + `1` +
		strings.Repeat("}", 100) + `}]}]}`
	rejected(t, []byte(inside), importer.FormatSARIF, importer.CodeInvalid)
	rejected(t, []byte(inside), importer.FormatGitLab, importer.CodeInvalid)
	// Brackets in strings don't count.
	quoted := `{"version":"2.1.0","runs":[{"results":[{"ruleId":"` + strings.Repeat("[{", 1000) + `\"\\"}]}]}`
	if _, err := importer.Parse([]byte(quoted), importer.FormatSARIF); err != nil {
		t.Fatal(err)
	}
	if d := time.Since(start); d > 5*time.Second {
		t.Fatalf("took %v", d)
	}
}

func TestCountLimits(t *testing.T) {
	rules := make([]any, importer.MaxRules+1)
	for i := range rules {
		rules[i] = st.M{"id": fmt.Sprint("r", i)}
	}
	rejected(t, mustJSON(sarifDoc([]any{}, rules...)), importer.FormatSARIF, importer.CodeTooLarge)
	// The rule limit is the file's, extensions included.
	half := sarifDoc([]any{}, rules[:importer.MaxRules/2+1]...)
	half["runs"].([]any)[0].(st.M)["tool"].(st.M)["extensions"] = []any{st.M{"name": "pack", "rules": rules[:importer.MaxRules/2+1]}}
	rejected(t, mustJSON(half), importer.FormatSARIF, importer.CodeTooLarge)
	if _, err := importer.Parse(mustJSON(sarifDoc([]any{}, rules[:importer.MaxRules]...)), importer.FormatSARIF); err != nil {
		t.Fatal(err)
	}

	exts := make([]any, importer.MaxComponents+1)
	for i := range exts {
		exts[i] = st.M{}
	}
	d := sarifDoc([]any{})
	d["runs"].([]any)[0].(st.M)["tool"].(st.M)["extensions"] = exts
	rejected(t, mustJSON(d), importer.FormatSARIF, importer.CodeTooLarge)

	runs := make([]any, importer.MaxRuns+1)
	for i := range runs {
		runs[i] = st.M{"results": []any{}}
	}
	rejected(t, mustJSON(st.M{"version": "2.1.0", "runs": runs}), importer.FormatSARIF, importer.CodeTooLarge)

	// Results count across runs: two runs of MaxResults/2+1 are too many.
	var sb strings.Builder
	sb.WriteString(`{"version":"2.1.0","runs":[`)
	for r := 0; r < 2; r++ {
		if r > 0 {
			sb.WriteByte(',')
		}
		sb.WriteString(`{"results":[`)
		for i := 0; i <= importer.MaxResults/2; i++ {
			if i > 0 {
				sb.WriteByte(',')
			}
			sb.WriteString(`{}`)
		}
		sb.WriteString(`]}`)
	}
	sb.WriteString(`]}`)
	rejected(t, []byte(sb.String()), importer.FormatSARIF, importer.CodeTooLarge)

	vulns := strings.Repeat(`{},`, importer.MaxResults) + `{}`
	rejected(t, []byte(`{"version":"15.0.7","vulnerabilities":[`+vulns+`]}`), importer.FormatGitLab, importer.CodeTooLarge)
}

func TestRuleLookup(t *testing.T) {
	rules := []any{
		st.M{"id": "a", "shortDescription": st.M{"text": "Rule A"}},
		st.M{"id": "b", "shortDescription": st.M{"text": "Rule B"}},
	}
	byIndex := st.M{"ruleIndex": 1, "message": st.M{"text": "m"}}                                // no id: the rule's
	outOfRange := st.M{"ruleId": "a", "ruleIndex": 99, "message": st.M{"text": "m"}}             // by id
	negative := st.M{"ruleId": "a", "ruleIndex": -1, "message": st.M{"text": "m"}}               // by id
	mismatch := st.M{"ruleId": "a", "ruleIndex": 1, "message": st.M{"text": "m"}}                // the id wins
	noRule := st.M{"ruleIndex": 99, "message": st.M{"text": "m"}}                                // dropped
	unknown := st.M{"ruleId": "zzz", "message": st.M{"text": "m"}}                               // kept, title = id
	badComponent := st.M{"rule": st.M{"id": "a", "index": 0, "toolComponent": st.M{"index": 7}}} // by id
	rep := parse(t, sarifDoc([]any{byIndex, outOfRange, negative, mismatch, noRule, unknown, badComponent}, rules...), importer.FormatSARIF)
	var got []string
	for _, r := range rep.Results {
		got = append(got, r.RuleID+"="+r.Title)
	}
	if strings.Join(got, ",") != "b=Rule B,a=Rule A,a=Rule A,a=Rule A,zzz=,a=Rule A" || rep.Dropped != 1 {
		t.Fatalf("%v, dropped %d", got, rep.Dropped)
	}
	fs := rep.Findings("(import) codeql")
	if fs[4].Title != "zzz" {
		t.Fatalf("title fallback %q", fs[4].Title)
	}
}

func TestSecuritySeverity(t *testing.T) {
	for _, c := range []struct {
		v    any
		want severity.Severity
	}{
		{"9.0", severity.Critical}, {"10.0", severity.Critical}, {9.8, severity.Critical}, {"8.9", severity.High}, {"7", severity.High},
		{"4.0", severity.Medium}, {"3.9", severity.Low}, {"0.0", severity.Low}, {" 7.5 ", severity.High},
		// Not a score: the level decides (warning: Medium).
		{"NaN", severity.Medium}, {"Infinity", severity.Medium}, {"-1", severity.Medium}, {-9.5, severity.Medium},
		{"1e1", severity.Medium}, {"0x1p3", severity.Medium}, {"11", severity.Medium}, {"10.5", severity.Medium},
		{"high", severity.Medium}, {true, severity.Medium}, {st.M{}, severity.Medium}, {"", severity.Medium},
		{"9" + strings.Repeat("0", 100), severity.Medium},
	} {
		rule := st.M{"id": "r", "properties": st.M{"security-severity": c.v}}
		rep := parse(t, sarifDoc([]any{result("r", "a.py", 1)}, rule), importer.FormatSARIF)
		if got := rep.Results[0].Severity; got != c.want {
			t.Errorf("%v: %s, want %s", c.v, got, c.want)
		}
	}
	// The result's own score wins over the rule's; then levels.
	res := result("r", "a.py", 1)
	res["properties"] = st.M{"security-severity": "9.1"}
	rule := st.M{"id": "r", "properties": st.M{"security-severity": "2.0"}}
	if rep := parse(t, sarifDoc([]any{res}, rule), importer.FormatSARIF); rep.Results[0].Severity != severity.Critical {
		t.Fatal(rep.Results[0].Severity)
	}
	for _, c := range []struct {
		result, rule string
		want         severity.Severity
	}{
		{"error", "", severity.High}, {"warning", "error", severity.Medium}, {"note", "", severity.Low}, {"none", "", severity.Low},
		{"", "error", severity.High}, {"", "", severity.Medium}, {"fatal", "note", severity.Low}, {"ERROR", "", severity.Medium},
	} {
		res := result("r", "a.py", 1)
		if c.result != "" {
			res["level"] = c.result
		}
		rule := st.M{"id": "r", "defaultConfiguration": st.M{"level": c.rule}}
		if rep := parse(t, sarifDoc([]any{res}, rule), importer.FormatSARIF); rep.Results[0].Severity != c.want {
			t.Errorf("level %q/%q: %s, want %s", c.result, c.rule, rep.Results[0].Severity, c.want)
		}
	}
}

// A report can name any rule id, a Warden scanner's or an org rule's: the
// findings are still tool external's, with the report's severity, and are
// no org rule's.
func TestSpoofedRuleIDs(t *testing.T) {
	res := []any{result("gitleaks", "a.py", 1), result("aws-access-token", "a.py", 2), result("org.payments-key", "a.py", 3),
		result("rules.org.x", "a.py", 4), result("CKV_AWS_20", "a.py", 5)}
	rep := parse(t, sarifDoc(res), importer.FormatSARIF)
	for _, f := range rep.Findings("(import) semgrep") {
		if f.Tool != sarif.ToolExternal || f.Severity != severity.Medium || sarif.IsOrgRule(f.Tool, f.RuleID) {
			t.Fatalf("%+v", f)
		}
	}
	if fs := rep.Findings("(import) semgrep"); fs[2].RuleID != "org.payments-key" {
		t.Fatalf("rule id rewritten: %q", fs[2].RuleID)
	}
}

func TestPartialFingerprints(t *testing.T) {
	withFP := func(line int, fps st.M) st.M {
		r := result("r", "a.py", line)
		r["partialFingerprints"] = fps
		return r
	}
	rep := parse(t, sarifDoc([]any{
		withFP(1, st.M{"primaryLocationLineHash": "abc:1", "primaryLocationStartColumnFingerprint": "4"}),
		withFP(9, st.M{"primaryLocationLineHash": "abc:1", "primaryLocationStartColumnFingerprint": "8"}), // reindented, moved
		withFP(1, st.M{"b": "2", "a": "1"}),
		withFP(1, st.M{"a": "1", "b": "2"}),
		withFP(1, st.M{"a": "1=b", "": "x"}),
		withFP(1, st.M{"a": 5}),
		result("r", "a.py", 3),
	}), importer.FormatSARIF)
	fp := func(i int) string { return rep.Results[i].Fingerprint }
	if fp(0) != fp(1) || fp(2) != fp(3) || fp(2) == fp(4) || fp(5) != "" || fp(6) != "" || len(fp(0)) != 67 {
		t.Fatalf("%q", []string{fp(0), fp(1), fp(2), fp(3), fp(4), fp(5), fp(6)})
	}

	// Huge: many keys (only the first are read) and huge values (hashed).
	many := st.M{}
	for i := range 100_000 {
		many[fmt.Sprintf("k%06d", i)] = strings.Repeat("v", 10)
	}
	many["primaryLocationLineHash"] = strings.Repeat("h", 1<<20)
	start := time.Now()
	rep = parse(t, sarifDoc([]any{withFP(1, many)}), importer.FormatSARIF)
	if f := rep.Results[0].Fingerprint; len(f) != 67 || time.Since(start) > 10*time.Second {
		t.Fatalf("fingerprint %q in %v", f, time.Since(start))
	}
}

// Without partial fingerprints the content key is a hash of the message, no
// line: a moved finding keeps its fingerprint; the target is in the key's
// path, so another tool or category never shares it.
func TestFindingsFingerprint(t *testing.T) {
	a := result("r", "src/a.py", 10)
	b := result("r", "src/a.py", 42)
	ra, rb := parse(t, sarifDoc([]any{a}), ""), parse(t, sarifDoc([]any{b}), "")
	fa, fb := ra.Findings("(import) codeql"), rb.Findings("(import) codeql")
	if fa[0].Key() != fb[0].Key() {
		t.Fatalf("moved finding: %+v vs %+v", fa[0].Key(), fb[0].Key())
	}
	k := fa[0].Key()
	if k.Tool != sarif.ToolExternal || k.FilePath != "(import) codeql::src/a.py" || !strings.HasPrefix(k.ContentKey, "msg:") ||
		fa[0].FilePath != "src/a.py" || fa[0].Snippet != "" {
		t.Fatalf("%+v %+v", k, fa[0])
	}
	other := ra.Findings("(import) codeql /language:go/")[0].Key()
	if fingerprint.Fingerprint(k.Tool, k.RuleID, k.FilePath, k.ContentKey, 0) ==
		fingerprint.Fingerprint(other.Tool, other.RuleID, other.FilePath, other.ContentKey, 0) {
		t.Fatal("two categories share a fingerprint")
	}
}

// Control, bidi and other format characters go from every string; texts
// keep their newlines and tabs, one-line strings don't; every string is
// capped.
func TestStringsCleanedAndCapped(t *testing.T) {
	rule := st.M{
		"id":               "r\u202e\x00x",
		"shortDescription": st.M{"text": "Title\u2066 with\nnewline\u200b", "markdown": "**md**"},
		"fullDescription":  st.M{"text": "line1\r\nline2\rline3\x1b[31m\u2028end\t" + strings.Repeat("d", 10_000)},
		"help":             st.M{"text": strings.Repeat("é", 5000), "markdown": "# md"},
	}
	res := st.M{"ruleId": "r\u202e\x00x", "message": st.M{"text": "msg \u202Eevil\u202C " + strings.Repeat("m", 5000), "markdown": "x"},
		"locations": []any{st.M{"physicalLocation": st.M{"artifactLocation": st.M{"uri": "a.py"}, "region": st.M{"startLine": 3, "endLine": 1}}}}}
	rep := parse(t, sarifDoc([]any{res}, rule), importer.FormatSARIF)
	r := rep.Results[0]
	if r.RuleID != "rx" || r.Title != "Title with newline" || !strings.HasPrefix(r.Description, "line1\nline2\nline3[31mend\t") ||
		len(r.Description) > importer.MaxRuleText || len(r.Remediation) > importer.MaxRuleText || len(r.Message) > importer.MaxMessage ||
		!strings.HasPrefix(r.Message, "msg evil m") || *r.StartLine != 3 || *r.EndLine != 3 {
		t.Fatalf("%+v", r)
	}
	long := st.M{"id": strings.Repeat("i", 1000), "shortDescription": st.M{"text": strings.Repeat("t", 1000)}}
	r = parse(t, sarifDoc([]any{st.M{"ruleId": strings.Repeat("i", 1000)}}, long), importer.FormatSARIF).Results[0]
	if len([]rune(r.RuleID)) != importer.MaxRuleID || len([]rune(r.Title)) != importer.MaxTitle {
		t.Fatalf("%d %d", len(r.RuleID), len(r.Title))
	}
	// The tool version: one line, capped for scan.import_tool_version.
	d := sarifDoc([]any{})
	d["runs"].([]any)[0].(st.M)["tool"].(st.M)["driver"].(st.M)["version"] = "1.2\u202e\n" + strings.Repeat("9", 500)
	if v := parse(t, d, "").ToolVersion; len([]rune(v)) != importer.MaxVersion || strings.ContainsAny(v, "\n\u202e") {
		t.Fatalf("version %q", v)
	}
}

func TestNotFindingsSkipped(t *testing.T) {
	mk := func(k, v any) st.M {
		r := result("r", "a.py", 1)
		r[k.(string)] = v
		return r
	}
	rep := parse(t, sarifDoc([]any{
		mk("kind", "pass"), mk("kind", "notApplicable"), mk("kind", "informational"), mk("kind", "fail"), mk("kind", "review"),
		mk("baselineState", "absent"), mk("baselineState", "new"),
		mk("suppressions", []any{st.M{"kind": "inSource"}}), mk("suppressions", []any{st.M{"status": "accepted"}}),
		mk("suppressions", []any{st.M{"status": "rejected"}}), mk("suppressions", []any{st.M{"status": "underReview"}}),
		mk("suppressions", []any{}),
	}), importer.FormatSARIF)
	if len(rep.Results) != 6 || rep.Skipped != 6 || rep.Read != 12 {
		t.Fatalf("kept %d, skipped %d, read %d", len(rep.Results), rep.Skipped, rep.Read)
	}
}

func TestWrongTypesIgnored(t *testing.T) {
	res := st.M{"ruleId": "r", "message": "not an object", "locations": st.M{}, "partialFingerprints": []any{1},
		"ruleIndex": "0", "level": 3, "properties": "x"}
	rule := st.M{"id": "r", "shortDescription": "s", "properties": st.M{"tags": "external/cwe/cwe-79"}}
	rep := parse(t, sarifDoc([]any{res, 5, "x", nil}, rule, 7), importer.FormatSARIF)
	if len(rep.Results) != 1 || rep.Results[0].RuleID != "r" || rep.Dropped != 3 {
		t.Fatalf("%+v", rep)
	}
}

func gitlabDoc(vulns ...any) st.M {
	return st.M{"version": "15.0.7", "vulnerabilities": vulns,
		"scan": st.M{"scanner": st.M{"id": "semgrep", "name": "Semgrep", "version": "1.86.0"}, "type": "sast"}}
}

func vuln(id, file string, sev string) st.M {
	return st.M{"id": "x", "name": "Name " + id, "description": "desc", "severity": sev,
		"identifiers": []any{st.M{"type": "semgrep_id", "name": id, "value": id}, st.M{"type": "cwe", "name": "CWE-79", "value": "79"}},
		"location":    st.M{"file": file, "start_line": 4, "end_line": 6}}
}

func TestGitLab(t *testing.T) {
	rep := parse(t, gitlabDoc(
		vuln("a", "src/a.py", "Critical"), vuln("b", "src/b.py", "High"), vuln("c", "c.py", "Medium"), vuln("d", "d.py", "Low"),
		vuln("e", "e.py", "Info"), vuln("f", "f.py", "Unknown"), vuln("g", "g.py", "Bogus"),
		vuln("h", "../etc/passwd", "High"), vuln("i", "/etc/passwd", "High"), vuln("j", "a\\b", "High"), vuln("k", "%2e%2e/x", "High"),
		st.M{"name": "no identifiers", "location": st.M{"file": "a.py"}},
		vuln("", "a.py", "High"),
	), importer.FormatGitLab)
	if rep.ToolVersion != "1.86.0" || rep.Read != 13 || rep.Dropped != 6 || len(rep.Results) != 7 {
		t.Fatalf("%+v", rep)
	}
	want := []severity.Severity{severity.Critical, severity.High, severity.Medium, severity.Low, severity.Low, severity.Low, severity.Low}
	for i, r := range rep.Results {
		if r.Severity != want[i] || strings.Join(r.CWE, ",") != "CWE-79" || *r.StartLine != 4 || *r.EndLine != 6 || r.Description != "desc" {
			t.Fatalf("%d: %+v", i, r)
		}
	}
	for _, v := range []string{"14.1.2", "15", "16.0.0", "15.0.x"} {
		d := gitlabDoc()
		d["version"] = v
		rejected(t, mustJSON(d), importer.FormatGitLab, importer.CodeInvalid)
	}
	rejected(t, mustJSON(st.M{"version": "15.0.0"}), importer.FormatGitLab, importer.CodeInvalid)
	// A SARIF file is no GitLab report, and the other way round.
	rejected(t, mustJSON(sarifDoc([]any{})), importer.FormatGitLab, importer.CodeInvalid)
	rejected(t, mustJSON(gitlabDoc()), importer.FormatSARIF, importer.CodeInvalid)
}

// GitLab's tracking signatures are its partial fingerprints: a moved
// vulnerability with the same signatures keeps its key.
func TestGitLabTracking(t *testing.T) {
	tracked := func(line int, sig string) st.M {
		v := vuln("a", "src/a.py", "High")
		v["location"].(st.M)["start_line"] = line
		v["tracking"] = st.M{"type": "source", "items": []any{st.M{"file": "src/a.py", "line_start": line,
			"signatures": []any{st.M{"algorithm": "scope_offset", "value": sig}}}}}
		return v
	}
	rep := parse(t, gitlabDoc(tracked(4, "src/a.py|f[0]:3"), tracked(40, "src/a.py|f[0]:3"), tracked(4, "src/a.py|g[0]:1"), vuln("a", "src/a.py", "High")),
		importer.FormatGitLab)
	r := rep.Results
	if r[0].Fingerprint == "" || r[0].Fingerprint != r[1].Fingerprint || r[0].Fingerprint == r[2].Fingerprint || r[3].Fingerprint != "" {
		t.Fatalf("%+v", r)
	}
}
