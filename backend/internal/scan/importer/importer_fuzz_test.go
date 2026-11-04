package importer_test

import (
	"encoding/json"
	"errors"
	"os"
	"strings"
	"testing"

	"github.com/aupv9/warden/backend/internal/scan/importer"
	st "github.com/aupv9/warden/backend/internal/scan/scantest"
)

// marker stands for a secret in the fuzz targets: the fake Gitleaks below
// matches every line of the screening file holding it.
const marker = "AKIAFUZZ"

// fuzzProperties: whatever the input, Parse returns a report that passes
// checkReport or a *Rejected with a known code; and after screening, no
// string the import stores holds what Gitleaks matched, and the counts
// still add up.
func fuzzProperties(t *testing.T, raw []byte, format string) {
	rep, err := importer.Parse(raw, format)
	if err != nil {
		var rej *importer.Rejected
		if !errors.As(err, &rej) || (rej.Code != importer.CodeInvalid && rej.Code != importer.CodeTooLarge) {
			t.Fatalf("error %v", err)
		}
		if strings.Contains(rej.Detail, marker) {
			t.Fatalf("rejection quotes the file: %q", rej.Detail)
		}
		return
	}
	checkReport(t, rep)
	s := rep.Screen()
	var matches []importer.Lines
	for i, line := range strings.Split(string(s.Bytes()), "\n") {
		if strings.Contains(line, marker) {
			matches = append(matches, importer.Lines{Start: i + 1, End: i + 1})
		}
	}
	rep.Apply(s, matches)
	checkReport(t, rep)
	out, err := json.Marshal(rep.Findings("(import) codeql"))
	if err != nil {
		t.Fatal(err)
	}
	if strings.Contains(string(out), marker) || strings.Contains(rep.ToolVersion, marker) {
		t.Fatalf("a screened string was kept: %s", out)
	}
}

func fuzzSeeds(f *testing.F, files ...string) {
	for _, p := range files {
		b, err := os.ReadFile(p)
		if err != nil {
			f.Fatal(err)
		}
		f.Add(b)
	}
}

func FuzzParseSARIF(f *testing.F) {
	fuzzSeeds(f, "testdata/codeql-cpp.sarif", "testdata/codeql-python-extensions.sarif")
	res := result("r", "src/a.py", 3)
	res["message"] = st.M{"text": "key " + marker + "\nnext"}
	res["partialFingerprints"] = st.M{"primaryLocationLineHash": "abc:1"}
	doc := sarifDoc([]any{res, result("../x", "%2e%2e/etc/passwd", 1), result("r", "file:///w/src/b.py", 2)},
		st.M{"id": "r", "shortDescription": st.M{"text": "T\u202e"}, "properties": st.M{"security-severity": "9.1", "tags": []any{"external/cwe/cwe-079"}}})
	doc["runs"].([]any)[0].(st.M)["originalUriBaseIds"] = st.M{"%SRCROOT%": st.M{"uri": "file:///w/"}}
	f.Add(mustJSON(doc))
	f.Add([]byte(`{"version":"2.1.0","runs":[{"tool":{"driver":{"rules":[{"id":"a"}]},"extensions":[{"rules":[{"id":"b"}]}]},` +
		`"results":[{"rule":{"id":"b","index":0,"toolComponent":{"index":0}},"locations":[{"physicalLocation":{"artifactLocation":{"uri":"a\\b"}}}]},` +
		`{"ruleIndex":0,"kind":"pass"},{"ruleIndex":5,"suppressions":[{}]}]}]}`))
	f.Add([]byte(`{"version":"2.1.0","runs":[{"results":[{"ruleId":"x","message":{"text":"\u0000\u001b\u2066\r\n"}}]}]}`))
	f.Add([]byte(`[[[[[[`))
	f.Fuzz(func(t *testing.T, raw []byte) { fuzzProperties(t, raw, importer.FormatSARIF) })
}

func FuzzParseGitLab(f *testing.F) {
	fuzzSeeds(f, "testdata/gitlab-semgrep.json")
	v := vuln("bandit.B105", "src/a.py", "High")
	v["description"] = "password = " + marker
	v["tracking"] = st.M{"items": []any{st.M{"signatures": []any{st.M{"algorithm": "scope_offset", "value": "src/a.py|f[0]:1"}}}}}
	f.Add(mustJSON(gitlabDoc(v, vuln("x", "../../x", "Critical"), vuln("y", "C:/x", "Info"))))
	f.Add([]byte(`{"version":"15.0.0","vulnerabilities":[{"identifiers":[{"type":"cwe","value":"0079"}],"location":{"file":"a","start_line":-1}}]}`))
	f.Fuzz(func(t *testing.T, raw []byte) { fuzzProperties(t, raw, importer.FormatGitLab) })
}
