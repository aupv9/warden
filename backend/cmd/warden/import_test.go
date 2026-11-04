package main

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"io"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"unicode/utf8"
)

// sarifDoc is a SARIF file whose first run has automationDetails.id id (none
// when id is nil); the id comes after a results array, as CodeQL writes it.
func sarifDoc(id *string) []byte {
	run := map[string]any{"tool": map[string]any{"driver": map[string]any{"name": "CodeQL"}},
		"results": []any{map[string]any{"ruleId": "go/sql-injection", "message": map[string]any{"text": "automationDetails"}}}}
	if id != nil {
		run["automationDetails"] = map[string]any{"id": *id}
	}
	b, _ := json.Marshal(map[string]any{"version": "2.1.0", "runs": []any{run, map[string]any{"automationDetails": map[string]any{"id": "/second/"}}}})
	return b
}

func writeReport(t *testing.T, name string, data []byte) string {
	t.Helper()
	p := filepath.Join(t.TempDir(), name)
	if err := os.WriteFile(p, data, 0o600); err != nil {
		t.Fatal(err)
	}
	return p
}

func (f *fakeServer) runImport(t *testing.T, d deps, args ...string) result {
	t.Helper()
	all := append([]string{"import", "--url", f.srv.URL, "--org", f.org.String(), "--project", f.prj.String()}, args...)
	var out, errOut bytes.Buffer
	env := func(k string) string {
		if k == "WARDEN_TOKEN" {
			return f.token
		}
		return ""
	}
	code := run(context.Background(), all, env, &out, &errOut, d)
	r := result{code, out.String(), errOut.String()}
	if strings.Contains(r.stdout+r.stderr, f.token[strings.LastIndex(f.token, "_")+1:]) || strings.Contains(r.stdout+r.stderr, "presigned-signature") {
		t.Fatalf("secret printed:\n%s\n%s", r.stdout, r.stderr)
	}
	return r
}

// warden import: the report is uploaded as it is to POST …/scans/import,
// started, waited for and gated like a scan.
func TestImportPasses(t *testing.T) {
	f := newFakeServer(t)
	id := "/language:go/"
	doc := sarifDoc(&id)
	p := writeReport(t, "codeql results.SARIF", doc)
	r := f.runImport(t, testDeps(), "--tool", "codeql", "--fail-on", "critical", p)
	if r.code != exitPass || !strings.Contains(r.stdout, "PASS") || !strings.Contains(r.stdout, "==> category /language:go/") {
		t.Fatalf("%+v", r)
	}
	c := f.created
	if !strings.HasSuffix(f.createdPath, "/scans/import") || c["tool"] != "codeql" || c["format"] != "sarif" || c["category"] != id ||
		c["file_name"] != "codeql_results.sarif" || c["file_size"] != float64(len(doc)) || c["tools"] != nil || c["kind"] != nil {
		t.Fatalf("%s %v", f.createdPath, c)
	}
	if !bytes.Equal(f.uploaded, doc) || !f.started || f.failOn != "critical" || f.uploadHdr.Get("Authorization") != "" {
		t.Fatalf("uploaded=%q started=%v", f.uploaded, f.started)
	}

	// The gate fails an import like a scan.
	f = newFakeServer(t)
	f.gate = map[string]any{"status": "completed", "finished": true, "pass": false, "fail_on": "high", "counts": map[string]int{"high": 1},
		"blocking": []any{map[string]any{"id": "x", "key": "WEB-1", "title": "SQL injection", "severity": "high",
			"rule_id": "go/sql-injection", "external_tool": "codeql"}}}
	if r := f.runImport(t, testDeps(), "--tool", "codeql", "--category", "", p); r.code != exitGateFailed || !strings.Contains(r.stdout, "WEB-1") {
		t.Fatalf("%+v", r)
	}
	// --category "" is no category, whatever the file says.
	if f.created["category"] != "" || strings.Contains(f.created["file_name"].(string), "/") {
		t.Fatal(f.created)
	}

	// A failed import (the server refused the report) is an error.
	f = newFakeServer(t)
	code := "IMPORT_INVALID"
	f.statuses, f.errorCode = []string{"failed"}, &code
	if r := f.runImport(t, testDeps(), "--tool", "semgrep", p); r.code != exitError || !strings.Contains(r.stderr, "IMPORT_INVALID") {
		t.Fatalf("%+v", r)
	}

	// GitLab SAST reports: no category is read from them.
	f = newFakeServer(t)
	gl := writeReport(t, "gl-sast-report", []byte(`{"version":"15.0.0","vulnerabilities":[]}`))
	if r := f.runImport(t, testDeps(), "--tool", "gitlab-sast", "--format", "gitlab-sast", gl); r.code != exitPass ||
		f.created["format"] != "gitlab-sast" || f.created["category"] != "" || f.created["file_name"] != "gl-sast-report.json" {
		t.Fatalf("%+v %v", r, f.created)
	}
}

func TestImportArguments(t *testing.T) {
	f := newFakeServer(t)
	good := writeReport(t, "r.sarif", sarifDoc(nil))
	for name, c := range map[string]struct {
		args []string
		want string
	}{
		"no tool":         {[]string{good}, "--tool"},
		"warden scanner":  {[]string{"--tool", "gitleaks", good}, "--tool"},
		"bare external":   {[]string{"--tool", "external", good}, "--tool"},
		"format":          {[]string{"--tool", "codeql", "--format", "csv", good}, "--format"},
		"category":        {[]string{"--tool", "codeql", "--category", "a b", good}, "--category"},
		"no file":         {[]string{"--tool", "codeql"}, "FILE is missing"},
		"two files":       {[]string{"--tool", "codeql", good, good}, "one FILE"},
		"flag after file": {[]string{"--tool", "codeql", good, "--fail-on", "low"}, "one FILE"},
		"directory":       {[]string{"--tool", "codeql", t.TempDir()}, "non-empty file"},
		"missing":         {[]string{"--tool", "codeql", filepath.Join(t.TempDir(), "nope.sarif")}, "non-empty file"},
		"empty":           {[]string{"--tool", "codeql", writeReport(t, "e.sarif", nil)}, "non-empty file"},
		"scan flag":       {[]string{"--tool", "codeql", "--dir", ".", good}, "usage"},
		"not json":        {[]string{"--tool", "codeql", writeReport(t, "x.sarif", []byte("PK\x03\x04"))}, "pass --category"},
		"fail-on":         {[]string{"--tool", "codeql", "--fail-on", "info", good}, "--fail-on"},
	} {
		t.Run(name, func(t *testing.T) {
			r := f.runImport(t, testDeps(), c.args...)
			if r.code != exitError || !strings.Contains(r.stderr, c.want) {
				t.Fatalf("%+v", r)
			}
		})
	}
	if f.created != nil || f.uploaded != nil {
		t.Fatal("bad arguments reached the server")
	}
}

func TestImportFileName(t *testing.T) {
	for in, want := range map[string]string{
		"results.sarif":           "results.sarif",
		"dir/Results.JSON":        "Results.json",
		"gl-sast-report":          "gl-sast-report.sarif",
		"a b;rm -rf.sarif":        "a_b_rm_-rf.sarif",
		"../../etc/passwd":        "passwd.sarif",
		"\u202egnp.sarif":         "gnp.sarif",
		".sarif":                  "source.sarif",
		strings.Repeat("a", 300):  strings.Repeat("a", 100) + ".sarif",
		"x.sarif.exe":             "x.sarif.sarif",
		"report\x00.json":         "report.json",
		"r\n.sarif":               "r.sarif",
		"\xff\xfe.json":           "source.json",
		"report.Sarif.json":       "report.Sarif.json",
		"..":                      "source.sarif",
		"report.sarif/":           "report.sarif",
		"C:\\temp\\results.sarif": "C__temp_results.sarif",
	} {
		got := importFileName(in, importSARIF)
		if got != want {
			t.Errorf("%q: %q, want %q", in, got, want)
		}
		if !strings.HasSuffix(got, ".sarif") && !strings.HasSuffix(got, ".json") || strings.ContainsAny(got, `/\`) || len(got) > 255 {
			t.Errorf("%q: %q isn't a name the server accepts", in, got)
		}
	}
	if got := importFileName("gl-sast-report", importGitLabSAST); got != "gl-sast-report.json" {
		t.Fatal(got)
	}
}

func TestCategoryOf(t *testing.T) {
	for id, want := range map[string]string{
		"/language:go/":                 "/language:go/",
		"my-analysis/tool1/2022-01-02":  "my-analysis/tool1/",
		"my-analysis/tool1/":            "my-analysis/tool1/",
		"nightly":                       "nightly",
		"":                              "",
		"a b/":                          "",
		"(history)":                     "",
		"/x/" + strings.Repeat("a", 99): "/x/",
		strings.Repeat("a", 101):        "",
		"café/1":                        "",
		"a\n/1":                         "",
		"ok/\n":                         "ok/",
	} {
		if got := categoryOf(id); got != want {
			t.Errorf("%q: %q, want %q", id, got, want)
		}
	}
}

// sarifCategory reads one string from a hostile file: bounded, and never
// confused by look-alike keys elsewhere.
func TestSARIFCategoryAttacks(t *testing.T) {
	id := "/language:python/"
	for name, c := range map[string]struct {
		doc   string
		want  string
		found bool
		err   error
	}{
		"codeql":             {string(sarifDoc(&id)), id, true, nil},
		"none":               {string(sarifDoc(nil)), "", false, nil},
		"second run only":    {`{"runs":[{},{"automationDetails":{"id":"x"}}]}`, "", false, nil},
		"nested look-alike":  {`{"runs":[{"results":[{"automationDetails":{"id":"evil"}}],"properties":{"automationDetails":{"id":"evil"}}}]}`, "", false, nil},
		"top-level":          {`{"automationDetails":{"id":"evil"},"runs":[{}]}`, "", false, nil},
		"case":               {`{"RUNS":[{"automationDetails":{"id":"evil"}}],"runs":[{"AutomationDetails":{"id":"x"}}]}`, "", false, nil},
		"key in a string":    {`{"note":"\"runs\":[{\"automationDetails\":{\"id\":\"evil\"}}]","runs":[]}`, "", false, nil},
		"id not a string":    {`{"runs":[{"automationDetails":{"id":{"x":1}}}]}`, "", false, nil},
		"id number":          {`{"runs":[{"automationDetails":{"id":7}}]}`, "", false, nil},
		"runs object":        {`{"runs":{"automationDetails":{"id":"evil"}}}`, "", false, nil},
		"runs empty":         {`{"runs":[]}`, "", false, nil},
		"array document":     {`[{"runs":[{"automationDetails":{"id":"evil"}}]}]`, "", false, nil},
		"escaped id":         {`{"runs":[{"automationDetails":{"id":"\u002flanguage:go\u002f"}}]}`, "/language:go/", true, nil},
		"first wins":         {`{"runs":[{"automationDetails":{"id":"a/"}}],"runs":[{"automationDetails":{"id":"b/"}}]}`, "a/", true, nil},
		"truncated":          {`{"runs":[{"results":[`, "", false, errAny},
		"garbage":            {"\x00\x01", "", false, errAny},
		"bom":                {"\ufeff{}", "", false, errAny},
		"deep in results":    {`{"runs":[{"results":` + strings.Repeat("[", 200) + strings.Repeat("]", 200) + `}]}`, "", false, errCategoryJSON},
		"deep but in budget": {`{"runs":[{"results":` + strings.Repeat("[", 60) + strings.Repeat("]", 60) + `,"automationDetails":{"id":"ok/"}}]}`, "ok/", true, nil},
	} {
		got, found, err := sarifCategory(strings.NewReader(c.doc))
		switch {
		case c.err == errAny && err == nil, c.err != errAny && !errors.Is(err, c.err):
			t.Errorf("%s: err %v, want %v", name, err, c.err)
		case got != c.want || found != c.found:
			t.Errorf("%s: %q %v, want %q %v", name, got, found, c.want, c.found)
		}
	}

	// Past maxCategoryScan without the id: an error (pass --category), not a
	// silent "no category" that would move the issues to another target.
	big := io.MultiReader(strings.NewReader(`{"runs":[{"results":["`), infinite('a'))
	if _, _, err := sarifCategory(big); !errors.Is(err, errCategoryScan) {
		t.Fatal(err)
	}
	// Found within the budget, whatever follows.
	head := io.MultiReader(strings.NewReader(`{"runs":[{"automationDetails":{"id":"x/"},"results":["`), infinite('a'))
	if got, found, err := sarifCategory(head); got != "x/" || !found || err != nil {
		t.Fatal(got, found, err)
	}
}

// Each import (tool and category) keeps its own pull request comment, apart
// from the source, image and history scans'; the body carries the same
// marker comment() looks for.
func TestImportCommentMarkerAndRow(t *testing.T) {
	c := bodyClient()
	c.o.importFile, c.o.importTool, c.o.importCategory = "r.sarif", "codeql", "/language:go/"
	if got := c.o.commentTarget(); got != "(import) codeql /language:go/" {
		t.Fatal(got)
	}
	py := c.o
	py.importCategory = "/language:python/"
	hist := options{history: true}
	marks := map[string]bool{}
	for _, tg := range []string{c.o.commentTarget(), py.commentTarget(), hist.commentTarget(), "", "ghcr.io/acme/api"} {
		marks[commentMarker(c.o.project, tg)] = true
	}
	if len(marks) != 5 {
		t.Fatal(marks)
	}
	tool := "codeql"
	g := gate{Status: "completed", Finished: true, FailOn: "high", Counts: map[string]int{"high": 1},
		Blocking: []issue{{ID: "x", Key: "WEB-1", Title: "SQL injection", Severity: "high", RuleID: "go/sql-injection", ExternalTool: &tool}}}
	body := c.commentBody(g, "scan")
	checkBody(t, c, body)
	if !strings.HasPrefix(body, commentMarker(c.o.project, "(import) codeql /language:go/")+"\n") || !strings.Contains(body, "| `codeql: go/sql-injection` |") {
		t.Fatal(body)
	}
	// The history scan's body has the history marker (it had the source's).
	c.o = hist
	c.o.project, c.o.server = py.project, py.server
	if body := c.commentBody(gate{Status: "completed", Finished: true, Pass: true, FailOn: "high"}, "x"); !strings.HasPrefix(body, commentMarker(py.project, "(history)")+"\n") {
		t.Fatal(body)
	}
}

var errAny = errors.New("any error")

type infinite byte

func (b infinite) Read(p []byte) (int, error) {
	for i := range p {
		p[i] = byte(b)
	}
	return len(p), nil
}

// FuzzSARIFCategory: on any input, sarifCategory returns (no panic, bounded
// work) and the default category is a valid one or none; and any id written
// where CodeQL writes it is read back exactly as encoding/json reads it.
func FuzzSARIFCategory(f *testing.F) {
	id := "/language:go/"
	f.Add(sarifDoc(&id), id)
	f.Add([]byte(`{"runs":[{"automationDetails":{"id":"a/b/c"}}]}`), "a/b\u202e/c")
	f.Add([]byte(`{"runs":[[[[`), "\x00")
	f.Add([]byte(`{"runs":[{"automationDetails":{"id":"\ud800"}}]}`), "\xff/")
	f.Fuzz(func(t *testing.T, raw []byte, id string) {
		got, found, err := sarifCategory(bytes.NewReader(raw))
		if err == nil && found {
			if c := categoryOf(got); c != "" && (!importCategoryPattern.MatchString(c) || !utf8.ValidString(c) || len(c) > 100) {
				t.Fatalf("category %q from %q", c, got)
			}
		}
		if err != nil && (found || got != "") {
			t.Fatal("a value with an error", got, found, err)
		}
		doc := sarifDoc(&id)
		var want struct {
			Runs []struct {
				AutomationDetails struct{ ID string } `json:"automationDetails"`
			} `json:"runs"`
		}
		if err := json.Unmarshal(doc, &want); err != nil {
			t.Fatal(err)
		}
		got, found, err = sarifCategory(bytes.NewReader(doc))
		if err != nil || !found || got != want.Runs[0].AutomationDetails.ID {
			t.Fatalf("%q: %q %v %v", id, got, found, err)
		}
	})
}
