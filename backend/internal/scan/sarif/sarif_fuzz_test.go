package sarif_test

import (
	"bytes"
	"encoding/json"
	"errors"
	"math"
	"regexp"
	"strings"
	"testing"
	"time"
	"unicode/utf8"

	"github.com/aupv9/warden/backend/internal/domain/severity"
	"github.com/aupv9/warden/backend/internal/scan/redact"
	"github.com/aupv9/warden/backend/internal/scan/sarif"
	st "github.com/aupv9/warden/backend/internal/scan/scantest"
)

var (
	fuzzTools = []string{"gitleaks", "trivy", "opengrep", "checkov"}
	shaRe     = regexp.MustCompile(`^(?:[0-9a-f]{40}|[0-9a-f]{64})$`)
)

func runes(s string) int { return utf8.RuneCountInString(s) }

// checkFinding: every string a parser keeps is capped, lines are sane, the
// severity is one Warden knows, and a history finding has a well-formed commit.
func checkFinding(t *testing.T, f sarif.Finding, history bool) {
	t.Helper()
	for _, c := range []struct {
		what string
		s    string
		max  int
	}{
		{"rule id", f.RuleID, 256}, {"title", f.Title, sarif.MaxTitle}, {"description", f.Description, sarif.MaxText},
		{"remediation", f.Remediation, sarif.MaxText}, {"snippet", f.Snippet, sarif.MaxSnippet},
		{"package", f.PackageName, 256}, {"version", f.PackageVersion, 128}, {"fixed version", f.FixedVersion, 256},
	} {
		if runes(c.s) > c.max {
			t.Fatalf("%s is %d runes (cap %d)", c.what, runes(c.s), c.max)
		}
	}
	if f.RuleID == "" || f.Title == "" {
		t.Fatalf("finding without rule id or title: %+v", f)
	}
	if severity.Rank(f.Severity) == len(severity.All) {
		t.Fatalf("severity %q", f.Severity)
	}
	for _, l := range []*int{f.StartLine, f.EndLine} {
		if l != nil && (*l < 0 || *l > math.MaxInt32) {
			t.Fatalf("line %d", *l)
		}
	}
	if f.Tool == "trivy" && (f.StartLine != nil || f.EndLine != nil) {
		t.Fatalf("trivy finding with lines")
	}
	if f.Commit != nil {
		if !history || f.Tool != "gitleaks" || !shaRe.MatchString(f.Commit.SHA) || f.Commit.Count != 1 {
			t.Fatalf("commit %+v", f.Commit)
		}
		if d := f.Commit.Date; d != nil && (d.Before(time.Unix(0, 0)) || d.Location() != time.UTC) {
			t.Fatalf("commit date %v", d)
		}
	} else if history && f.Tool == "gitleaks" {
		t.Fatalf("history finding without a commit")
	}
}

// olderRef is CollapseHistory's order, written out again as the oracle.
func olderRef(a, b sarif.Finding) bool {
	da, db := a.Commit.Date, b.Commit.Date
	switch {
	case da != nil && db == nil:
		return true
	case da == nil && db != nil:
		return false
	case da != nil && !da.Equal(*db):
		return da.Before(*db)
	}
	if a.Commit.SHA != b.Commit.SHA {
		return a.Commit.SHA < b.Commit.SHA
	}
	if a.FilePath != b.FilePath {
		return a.FilePath < b.FilePath
	}
	return a.Line() < b.Line()
}

// checkCollapse: one finding per key with a commit, the oldest of its group,
// Count the group's distinct commits; findings without a commit unchanged.
func checkCollapse(t *testing.T, in []sarif.Finding) {
	t.Helper()
	out := sarif.CollapseHistory(in)
	plain := 0
	groups := map[any][]sarif.Finding{}
	for _, f := range in {
		if f.Commit == nil {
			plain++
		} else {
			groups[f.Key()] = append(groups[f.Key()], f)
		}
	}
	if len(out) != plain+len(groups) {
		t.Fatalf("%d findings collapsed to %d (%d plain, %d groups)", len(in), len(out), plain, len(groups))
	}
	seen := map[any]bool{}
	for _, f := range out {
		if f.Commit == nil {
			continue
		}
		k := f.Key()
		if seen[k] {
			t.Fatalf("key %v twice", k)
		}
		seen[k] = true
		shas := map[string]bool{}
		for _, g := range groups[k] {
			shas[g.Commit.SHA] = true
			if olderRef(g, f) {
				t.Fatalf("kept %+v, but %+v is older", f.Commit, g.Commit)
			}
		}
		if f.Commit.Count != len(shas) || !shas[f.Commit.SHA] {
			t.Fatalf("count %d, %d commits", f.Commit.Count, len(shas))
		}
	}
	for _, f := range in {
		if f.Commit != nil && f.Commit.Count != 1 {
			t.Fatal("CollapseHistory changed its input")
		}
	}
}

// FuzzParse feeds arbitrary JSON to the parser as each tool, in source and
// history mode, and collapses the history findings.
func FuzzParse(f *testing.F) {
	seed := func(doc st.M) []byte {
		b, _ := json.Marshal(doc)
		return b
	}
	gl, _ := redact.Doc(st.RoundTrip(st.GitleaksDoc()), st.HMACKey)
	hist, _ := redact.Doc(st.RoundTrip(st.Doc([]any{
		st.HistoryResult("aws-access-token", "src/config.py", 4, st.FakeSecret, st.Commit{SHA: strings.Repeat("0a", 20), Date: "2024-02-03T04:05:06+07:00"}),
		st.HistoryResult("aws-access-token", "b.py", 9, st.FakeSecret, st.Commit{SHA: strings.Repeat("0b", 20), Date: "2023-02-03T04:05:06Z"}),
		st.HistoryResult("aws-access-token", "c.py", 1, st.FakeSecret, st.Commit{SHA: strings.Repeat("0b", 20), Date: ""}),
	})), st.HMACKey)
	trivy := st.Doc([]any{st.M{"ruleId": "CVE-2024-1234", "message": st.M{"text": "Package: lodash\nInstalled Version: 4.17.0\nFixed Version: 4.17.21\nSeverity: HIGH"},
		"locations": []any{st.Loc("src/package-lock.json", 1)}}},
		st.M{"id": "CVE-2024-1234", "shortDescription": st.M{"text": "proto pollution"}, "properties": st.M{"tags": []any{"security", "HIGH", "CWE-1321"}}})
	og := st.Doc([]any{st.M{"ruleId": "data.rules.sqli", "level": "error", "message": st.M{"text": "SQL\ninjection"}, "locations": []any{st.Loc("svc/db.py", 3, "cur.execute(q)")}}},
		st.M{"id": "data.rules.sqli", "shortDescription": st.M{"text": "Opengrep Finding"}, "properties": st.M{"security-severity": "9.1", "tags": []any{"CWE-89: x"}}})
	for i, doc := range []st.M{gl, hist, trivy, og} {
		f.Add(seed(doc), uint8(i), i == 1)
	}
	f.Add([]byte(`{"runs":[{"results":[{"ruleId":"x","locations":[{"physicalLocation":{"region":{"startLine":-1,"endLine":1e99}}}]}]}]}`), uint8(3), false)
	f.Add([]byte(`{"runs":[{"tool":{"driver":{"rules":"x"}},"results":[1,"x",null,{"ruleId":7}]}],"x":{}}`), uint8(2), false)
	f.Fuzz(func(t *testing.T, data []byte, which uint8, history bool) {
		if len(data) > 64<<10 {
			return
		}
		v, err := sarif.Decode(bytes.NewReader(data))
		if err != nil {
			return
		}
		doc, ok := v.(map[string]any)
		if !ok {
			return
		}
		tool := fuzzTools[int(which)%len(fuzzTools)]
		opts := sarif.Options{RootDir: "src", History: history}
		if which&4 != 0 {
			opts.ImageTarget, opts.OSLabel = "ghcr.io/acme/api", "alpine"
		}
		fs, err := sarif.Parse(doc, tool, opts)
		if err != nil {
			if !errors.Is(err, sarif.ErrSARIF) {
				t.Fatalf("error that isn't ErrSARIF: %v", err)
			}
			return
		}
		if len(fs) > sarif.MaxResultsPerTool {
			t.Fatalf("%d findings", len(fs))
		}
		for _, f := range fs {
			if f.Tool != tool {
				t.Fatalf("tool %q", f.Tool)
			}
			checkFinding(t, f, history)
		}
		checkCollapse(t, fs)
	})
}

// FuzzRedactedGitleaks is the path a secret takes: Gitleaks SARIF, the
// redactor in the sandbox, then the parser. No finding (raw result
// included) holds the secret, whatever surrounds it.
func FuzzRedactedGitleaks(f *testing.F) {
	f.Add(st.FakeSecret, "app/config.py", "aws-access-token has detected secret ", "oops", true)
	f.Add("ghp_"+strings.Repeat("Q", 36), "x.py", "", "", false)
	f.Add("s3cr3t-value-1", "src/a.env", "key=", "\n", true)
	f.Fuzz(func(t *testing.T, secret, uri, before, after string, history bool) {
		if len(secret)+len(uri)+len(before)+len(after) > 4096 || secret == "" || strings.Contains(secret, "*") {
			return
		}
		r := st.HistoryResult("generic-api-key", uri, 3, secret, st.Commit{SHA: strings.Repeat("0c", 20), Date: "2025-01-01T00:00:00Z",
			Message: before + secret + after})
		r["message"] = st.M{"text": before + secret + after}
		r["properties"] = st.M{"tags": []any{secret}, before: after + secret}
		rt := st.RoundTrip(st.Doc([]any{r}, st.M{"id": "generic-api-key", "shortDescription": st.M{"text": before + secret}, "help": st.M{"text": secret + after}}))
		// The secret as the redactor sees it, after the JSON round trip.
		secret = rt["runs"].([]any)[0].(st.M)["results"].([]any)[0].(st.M)["locations"].([]any)[0].(st.M)["physicalLocation"].(st.M)["region"].(st.M)["snippet"].(st.M)["text"].(string)
		red, err := redact.Doc(rt, st.HMACKey)
		if err != nil {
			return // refused: the scan fails, nothing leaves the sandbox
		}
		// warden-redact writes JSON; the worker loads it back.
		b, _ := json.Marshal(red)
		v, err := sarif.Decode(bytes.NewReader(b))
		if err != nil {
			t.Fatal(err)
		}
		fs, err := sarif.Parse(v.(map[string]any), "gitleaks", sarif.Options{History: history})
		if err != nil {
			return
		}
		for _, f := range fs {
			// The strings the parser took from the document. (Tool, severity
			// and content key are Warden's own.)
			fields := append([]string{f.RuleID, f.Title, f.Description, f.Remediation, f.Snippet, f.PackageName, f.PackageVersion,
				f.FixedVersion}, append(f.CWE, f.CVE...)...)
			// The path is percent-decoded and cleaned after redaction, which can
			// rebuild a secret that only ever appeared encoded or split in the
			// URI (a file named after a secret, in the secret's own commit).
			if !strings.ContainsAny(secret, `/.\`) && !strings.Contains(uri, "%") {
				fields = append(fields, f.FilePath)
			}
			if f.Commit != nil {
				fields = append(fields, f.Commit.SHA)
			}
			for _, s := range fields {
				if strings.Contains(s, secret) {
					t.Fatalf("secret %q in finding field %q", secret, s)
				}
			}
			// The raw result is stored as it is: re-encode it as the store would.
			b, _ := json.Marshal(f.Raw)
			var back any
			_ = json.Unmarshal(b, &back)
			if leakedString(back, secret) {
				t.Fatalf("secret %q in raw result %s", secret, b)
			}
		}
	})
}

// leakedString reports whether any string of v (keys included) holds secret,
// apart from the content key Warden adds (an HMAC in hex).
func leakedString(v any, secret string) bool {
	switch t := v.(type) {
	case string:
		return strings.Contains(t, secret)
	case []any:
		for _, e := range t {
			if leakedString(e, secret) {
				return true
			}
		}
	case map[string]any:
		for k, e := range t {
			if k == redact.ContentKeyProp || k == "content_key" {
				continue
			}
			if (k != "properties" && leakedString(k, secret)) || leakedString(e, secret) {
				return true
			}
		}
	}
	return false
}
