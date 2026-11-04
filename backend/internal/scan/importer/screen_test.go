package importer_test

import (
	"bytes"
	"encoding/json"
	"errors"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/aupv9/warden/backend/internal/scan/importer"
	"github.com/aupv9/warden/backend/internal/scan/redact"
	st "github.com/aupv9/warden/backend/internal/scan/scantest"
)

// fakeGitleaks stands in for Gitleaks in the sandbox: a finding for every
// line of the screening file that holds secret (the line of its start and
// its end, as Gitleaks reports them), redacted by the real warden-redact
// code, written where the sandbox would. Unit tests can't run the scanner
// image; the worker's integration test and the real-data check do.
func fakeGitleaks(t *testing.T, file []byte, secret string) string {
	t.Helper()
	var results []any
	for i, line := range strings.Split(string(file), "\n") {
		if strings.Contains(line, secret) {
			results = append(results, st.M{
				"ruleId":    "aws-access-token",
				"message":   st.M{"text": "aws-access-token has detected secret for file /src/strings.txt."},
				"locations": []any{st.Loc("/src/"+importer.ScreenFile, i+1, secret)},
			})
		}
	}
	if results == nil {
		results = []any{}
	}
	return writeRedacted(t, st.Doc(results))
}

func writeRedacted(t *testing.T, doc st.M) string {
	t.Helper()
	red, err := redact.Doc(st.RoundTrip(doc), st.HMACKey)
	if err != nil {
		t.Fatal(err)
	}
	b, err := json.Marshal(red)
	if err != nil {
		t.Fatal(err)
	}
	p := filepath.Join(t.TempDir(), "result.sarif")
	if err := os.WriteFile(p, b, 0o600); err != nil {
		t.Fatal(err)
	}
	return p
}

// screen runs the whole screening of a report against fakeGitleaks.
func screen(t *testing.T, rep *importer.Report, secret string) {
	t.Helper()
	s := rep.Screen()
	if bytes.Contains(s.Bytes(), []byte("\r")) {
		t.Fatal("screening file with a carriage return: Gitleaks would count other lines")
	}
	m, err := importer.Matches(fakeGitleaks(t, s.Bytes(), secret))
	if err != nil {
		t.Fatal(err)
	}
	rep.Apply(s, m)
	checkReport(t, rep)
}

// A secret anywhere in a kept string never reaches what is stored: the
// message, title, description and help are emptied (the title falls back to
// the rule id), a secret in a path or rule id drops the result.
func TestScreeningDropsSecrets(t *testing.T) {
	secret := st.FakeSecret
	rules := []any{
		st.M{"id": "in-title", "shortDescription": st.M{"text": "Leaked " + secret}},
		st.M{"id": "in-help", "shortDescription": st.M{"text": "Hard-coded key"},
			"fullDescription": st.M{"text": "Keys like these:\nkey = " + secret + "\nmust go."}, "help": st.M{"text": "Rotate " + secret}},
		st.M{"id": "clean", "shortDescription": st.M{"text": "Clean rule"}, "fullDescription": st.M{"text": "Nothing here."}},
	}
	msg := func(r st.M, text string) st.M { r["message"] = st.M{"text": text}; return r }
	results := []any{
		msg(result("in-title", "a.py", 1), "fine"),
		msg(result("in-help", "b.py", 2), "fine too"),
		msg(result("clean", "c.py", 3), "the key is "+secret+" here"),
		msg(result("clean", "config/"+secret+".env", 4), "path"),
		msg(result("clean-"+secret, "d.py", 5), "rule id"),
		msg(result("clean", "e.py", 6), "nothing"),
	}
	doc := sarifDoc(results, rules...)
	doc["runs"].([]any)[0].(st.M)["tool"].(st.M)["driver"].(st.M)["version"] = "1.0-" + secret
	rep := parse(t, doc, importer.FormatSARIF)
	screen(t, rep, secret)

	if rep.Read != 6 || len(rep.Results) != 4 || rep.Dropped != 2 || rep.ToolVersion != "" {
		t.Fatalf("read %d, kept %d, dropped %d, version %q", rep.Read, len(rep.Results), rep.Dropped, rep.ToolVersion)
	}
	// Title, description (multi-line), help, message, path, rule id, version.
	if rep.Screened != 7 {
		t.Fatalf("screened %d", rep.Screened)
	}
	fs := rep.Findings("(import) codeql")
	if fs[0].Title != "in-title" || fs[1].Description != "fine too" || fs[1].Remediation != "" || fs[1].Title != "Hard-coded key" ||
		fs[2].Description != "Nothing here." || fs[2].Title != "Clean rule" || fs[3].Description != "Nothing here." {
		t.Fatalf("%+v", fs)
	}
	if fs[2].ContentKey == fs[3].ContentKey {
		t.Fatal("the screened message and another share a content key")
	}
	raw, _ := json.Marshal(fs)
	if bytes.Contains(raw, []byte(secret)) || bytes.Contains(raw, []byte(secret[:12])) {
		t.Fatalf("secret stored: %s", raw)
	}
}

// A message whose secret Gitleaks finds on its second line: the lines a
// string spans are its own, whichever one matched.
func TestScreeningMultiLine(t *testing.T) {
	r := result("r", "a.py", 1)
	r["message"] = st.M{"text": "first line\r\nsecond " + st.FakeSecret + "\nthird"}
	rep := parse(t, sarifDoc([]any{r, result("q", "b.py", 1)}), importer.FormatSARIF)
	s := rep.Screen()
	lines := strings.Split(string(s.Bytes()), "\n")
	at := -1
	for i, l := range lines {
		if strings.Contains(l, st.FakeSecret) {
			at = i + 1
		}
	}
	if at < 2 || lines[at-2] != "first line" {
		t.Fatalf("screening file %q", s.Bytes())
	}
	rep.Apply(s, []importer.Lines{{Start: at, End: at}})
	if rep.Results[0].Message != "" || rep.Results[1].Message == "" || rep.Screened != 1 {
		t.Fatalf("%+v, screened %d", rep.Results, rep.Screened)
	}
}

// A secret that spans two strings (Gitleaks' match runs from one into the
// next) drops both; a match past the end, or covering everything, drops
// what it covers; reversed lines count as one.
func TestScreeningRanges(t *testing.T) {
	var res []any
	for _, id := range []string{"a", "b", "c", "d"} {
		res = append(res, result(id, id+".py", 1))
	}
	newRep := func() (*importer.Report, *importer.Screen) {
		rep := parse(t, sarifDoc(res), importer.FormatSARIF)
		return rep, rep.Screen()
	}
	// Lines: version, then per result: rule id, message, path (3 lines).
	rep, s := newRep()
	rep.Apply(s, []importer.Lines{{Start: 2, End: 2}})
	if len(rep.Results) != 3 || rep.Results[0].RuleID != "b" {
		t.Fatalf("%+v", rep.Results)
	}
	rep, s = newRep()
	rep.Apply(s, []importer.Lines{{Start: 3, End: 4}}) // a's message and path
	if len(rep.Results) != 3 || rep.Screened != 2 {
		t.Fatalf("%+v %d", rep.Results, rep.Screened)
	}
	rep, s = newRep()
	rep.Apply(s, []importer.Lines{{Start: 1, End: 1 << 30}})
	if len(rep.Results) != 0 || rep.Dropped != 4 || rep.ToolVersion != "" {
		t.Fatalf("%+v", rep)
	}
	rep, s = newRep()
	rep.Apply(s, []importer.Lines{{Start: 1 << 30, End: 1 << 30}, {Start: 6, End: 3}})
	if len(rep.Results) != 4 || rep.Results[1].Message != "" || rep.Screened != 1 {
		t.Fatalf("%+v %d", rep.Results, rep.Screened)
	}
	// Many overlapping wide matches stay cheap.
	rep, s = newRep()
	many := make([]importer.Lines, 200_000)
	for i := range many {
		many[i] = importer.Lines{Start: 1, End: 1 << 30}
	}
	rep.Apply(s, many)
	if len(rep.Results) != 0 {
		t.Fatal(rep.Results)
	}
}

// The same string in many results is screened once and dropped everywhere.
func TestScreeningDedupes(t *testing.T) {
	r := func(path string) st.M { x := result("r", path, 1); x["message"] = st.M{"text": "same"}; return x }
	rep := parse(t, sarifDoc([]any{r("a.py"), r("b.py"), r("c.py")}), importer.FormatSARIF)
	s := rep.Screen()
	if n := strings.Count(string(s.Bytes()), "same\n"); n != 1 {
		t.Fatalf("written %d times", n)
	}
	lines := strings.Split(string(s.Bytes()), "\n")
	for i, l := range lines {
		if l == "same" {
			rep.Apply(s, []importer.Lines{{Start: i + 1, End: i + 1}})
		}
	}
	for _, x := range rep.Results {
		if x.Message != "" {
			t.Fatal(rep.Results)
		}
	}
	if rep.Screened != 1 {
		t.Fatal(rep.Screened)
	}
}

// The screening fails closed: anything but a well-formed run with results
// whose lines are known is an error, never "no match".
func TestMatchesFailsClosed(t *testing.T) {
	write := func(body string) string {
		p := filepath.Join(t.TempDir(), "result.sarif")
		if err := os.WriteFile(p, []byte(body), 0o600); err != nil {
			t.Fatal(err)
		}
		return p
	}
	for name, body := range map[string]string{
		"missing file":          "",
		"not JSON":              "{",
		"no runs":               `{"version":"2.1.0"}`,
		"empty runs":            `{"version":"2.1.0","runs":[]}`,
		"run not an object":     `{"version":"2.1.0","runs":[1]}`,
		"no results":            `{"version":"2.1.0","runs":[{}]}`,
		"results an object":     `{"version":"2.1.0","runs":[{"results":{}}]}`,
		"result not an object":  `{"version":"2.1.0","runs":[{"results":[1]}]}`,
		"no location":           `{"version":"2.1.0","runs":[{"results":[{"ruleId":"x"}]}]}`,
		"no start line":         `{"version":"2.1.0","runs":[{"results":[{"locations":[{"physicalLocation":{"region":{}}}]}]}]}`,
		"start line 0":          `{"version":"2.1.0","runs":[{"results":[{"locations":[{"physicalLocation":{"region":{"startLine":0}}}]}]}]}`,
		"start line string":     `{"version":"2.1.0","runs":[{"results":[{"locations":[{"physicalLocation":{"region":{"startLine":"3"}}}]}]}]}`,
		"start line fractional": `{"version":"2.1.0","runs":[{"results":[{"locations":[{"physicalLocation":{"region":{"startLine":2.5}}}]}]}]}`,
	} {
		p := filepath.Join(t.TempDir(), "absent.sarif")
		if body != "" {
			p = write(body)
		}
		if _, err := importer.Matches(p); !errors.Is(err, importer.ErrScreen) {
			t.Errorf("%s: %v", name, err)
		}
	}
	m, err := importer.Matches(write(`{"version":"2.1.0","runs":[{"results":[]}]}`))
	if err != nil || len(m) != 0 {
		t.Fatal(m, err)
	}
	m, err = importer.Matches(write(`{"runs":[{"results":[{"locations":[{"physicalLocation":{"region":{"startLine":4,"endLine":2}}},
		{"physicalLocation":{"region":{"startLine":7,"endLine":9}}}]}]}]}`))
	if err != nil || len(m) != 2 || m[0] != (importer.Lines{Start: 4, End: 4}) || m[1] != (importer.Lines{Start: 7, End: 9}) {
		t.Fatal(m, err)
	}
}

func TestEmptyReportHasNothingToScreen(t *testing.T) {
	d := sarifDoc([]any{})
	d["runs"].([]any)[0].(st.M)["tool"].(st.M)["driver"].(st.M)["semanticVersion"] = ""
	if s := parse(t, d, "").Screen(); !s.Empty() || len(s.Bytes()) != 0 {
		t.Fatalf("%q", s.Bytes())
	}
}
