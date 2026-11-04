package importer_test

import (
	"regexp"
	"slices"
	"strings"
	"testing"
	"unicode"
	"unicode/utf8"

	"github.com/aupv9/warden/backend/internal/domain/severity"
	"github.com/aupv9/warden/backend/internal/scan/importer"
	"github.com/aupv9/warden/backend/internal/scan/sarif"
)

var (
	cweRe = regexp.MustCompile(`^CWE-[1-9][0-9]{0,5}$`)
	fpRe  = regexp.MustCompile(`^pf:[0-9a-f]{64}$`)
)

// clean: valid UTF-8, no control character (but newline and tab in a
// text), no format character (bidi controls, zero-width), no line or
// paragraph separator, no surrounding space (but in a path).
func clean(t *testing.T, what, s string, multiline bool) {
	t.Helper()
	// A path is a file name: a space at either end is its own.
	if !utf8.ValidString(s) || (what != "path" && s != strings.TrimSpace(s)) {
		t.Fatalf("%s %q: invalid UTF-8 or untrimmed", what, s)
	}
	for _, r := range s {
		if multiline && (r == '\n' || r == '\t') {
			continue
		}
		if unicode.IsControl(r) || unicode.Is(unicode.Cf, r) || r == '\u2028' || r == '\u2029' {
			t.Fatalf("%s %q holds %U", what, s, r)
		}
	}
}

// checkPath: relative to the source root, cleaned, and nothing that could
// be read as another path.
func checkPath(t *testing.T, p string) {
	t.Helper()
	if p == "" {
		return
	}
	clean(t, "path", p, false)
	if len(p) > importer.MaxPath || strings.HasPrefix(p, "/") || strings.ContainsAny(p, `\`) || strings.Contains(p, "\uFFFD") {
		t.Fatalf("path %q", p)
	}
	for i, seg := range strings.Split(p, "/") {
		if seg == "" || seg == "." || seg == ".." || (i == 0 && strings.Contains(seg, ":")) {
			t.Fatalf("path %q: segment %q", p, seg)
		}
	}
	low := strings.ToLower(p)
	for _, enc := range []string{"%2e", "%2f", "%5c", "%00"} {
		if strings.Contains(low, enc) {
			t.Fatalf("path %q still encoded", p)
		}
	}
}

// checkReport asserts the parser's properties on any report it returns.
func checkReport(t *testing.T, rep *importer.Report) {
	t.Helper()
	if rep.Read > importer.MaxResults || rep.Read != len(rep.Results)+rep.Dropped+rep.Skipped || rep.Dropped < 0 || rep.Skipped < 0 {
		t.Fatalf("counts: read %d, kept %d, dropped %d, skipped %d", rep.Read, len(rep.Results), rep.Dropped, rep.Skipped)
	}
	clean(t, "tool version", rep.ToolVersion, false)
	if utf8.RuneCountInString(rep.ToolVersion) > importer.MaxVersion {
		t.Fatalf("tool version %q", rep.ToolVersion)
	}
	for _, r := range rep.Results {
		if r.RuleID == "" || utf8.RuneCountInString(r.RuleID) > importer.MaxRuleID ||
			utf8.RuneCountInString(r.Title) > importer.MaxTitle || len(r.Message) > importer.MaxMessage ||
			len(r.Description) > importer.MaxRuleText || len(r.Remediation) > importer.MaxRuleText {
			t.Fatalf("caps: %+v", r)
		}
		clean(t, "rule id", r.RuleID, false)
		clean(t, "title", r.Title, false)
		clean(t, "message", r.Message, true)
		clean(t, "description", r.Description, true)
		clean(t, "remediation", r.Remediation, true)
		checkPath(t, r.Path)
		if !slices.Contains([]severity.Severity{severity.Critical, severity.High, severity.Medium, severity.Low}, r.Severity) {
			t.Fatalf("severity %q", r.Severity)
		}
		if len(r.CWE) > importer.MaxCWEs || !slices.IsSorted(r.CWE) || len(slices.Compact(slices.Clone(r.CWE))) != len(r.CWE) {
			t.Fatalf("cwe %v", r.CWE)
		}
		for _, c := range r.CWE {
			if !cweRe.MatchString(c) {
				t.Fatalf("cwe %q", c)
			}
		}
		if (r.StartLine == nil) != (r.EndLine == nil) || (r.StartLine != nil && (*r.StartLine < 1 || *r.EndLine < *r.StartLine)) {
			t.Fatalf("lines %v %v", r.StartLine, r.EndLine)
		}
		if r.Fingerprint != "" && !fpRe.MatchString(r.Fingerprint) {
			t.Fatalf("fingerprint %q", r.Fingerprint)
		}
	}
	const target = "(import) codeql"
	for _, f := range rep.Findings(target) {
		if f.Tool != sarif.ToolExternal || f.Title == "" || f.Snippet != "" || f.ImportTarget != target || f.ContentKey == "" ||
			f.Key().FilePath != target+"::"+f.FilePath {
			t.Fatalf("finding %+v", f)
		}
	}
}
