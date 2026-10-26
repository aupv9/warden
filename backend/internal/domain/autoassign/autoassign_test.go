package autoassign

import (
	"strings"
	"testing"
	"time"

	"github.com/google/uuid"
)

func s(v string) *string { return &v }

func TestGlob(t *testing.T) {
	for _, c := range []struct {
		pattern, path string
		want          bool
	}{
		{"*.go", "main.go", true},
		{"*.go", "cmd/main.go", false}, // * stays in one segment
		{"**/*.go", "main.go", true},   // ** may be zero segments
		{"**/*.go", "a/b/c/main.go", true},
		{"src/**", "src", true},
		{"src/**", "src/a/b.py", true},
		{"src/**", "srcx/a.py", false},
		{"src/**/test_*.py", "src/a/b/test_x.py", true},
		{"src/**/test_*.py", "src/test_x.py", true},
		{"src/**/test_*.py", "src/a/x_test.py", false},
		{"**", "anything/at/all", true},
		{"a?c", "abc", true},
		{"a?c", "a/c", false},
		{"a?c", "ac", false},
		{"**.go", "x.go", true}, // ** inside a segment is a plain *
		{"**.go", "d/x.go", false},
		{"docs/*", "docs/", true},
		{"vendor/**/*.js", "vendor/a/b.ts", false},
		{"ünï/*.go", "ünï/x.go", true},
		{"a/**/b/**/c", "a/x/b/y/z/c", true},
		{"a/**/b/**/c", "a/x/y/c", false},
		{"", "a", false},
		{"a", "", false},
		{"[a-z].go", "a.go", false}, // classes are rejected, never matched literally
	} {
		if got := Glob(c.pattern, c.path); got != c.want {
			t.Errorf("Glob(%q, %q) = %v, want %v", c.pattern, c.path, got, c.want)
		}
	}
}

// Patterns built to make backtracking matchers explode stay linear here.
func TestGlobResistsPathologicalPatterns(t *testing.T) {
	pattern := strings.Repeat("*a", 99) + "b"  // 199 chars, stars within one segment
	path := strings.Repeat("a", MaxPathLen-10) // never matches (no b)
	start := time.Now()
	if Glob(pattern, path) {
		t.Fatal("matched")
	}
	segs := strings.TrimSuffix(strings.Repeat("**/a/", 39), "/") + "/b" // segment-level stars
	deep := strings.TrimSuffix(strings.Repeat("a/", 2000), "/")
	if Glob(segs, deep) {
		t.Fatal("matched")
	}
	if d := time.Since(start); d > 2*time.Second {
		t.Fatalf("took %v", d)
	}
	if Glob(strings.Repeat("a", MaxGlobLen+1), strings.Repeat("a", MaxGlobLen+1)) {
		t.Fatal("over-long pattern matched")
	}
	if Glob("*", strings.Repeat("a", MaxPathLen+1)) {
		t.Fatal("over-long path matched")
	}
}

func TestValidate(t *testing.T) {
	id := uuid.New()
	if errs := Validate(Rule{AssigneeID: id}); errs["match"] == "" {
		t.Fatal(errs)
	}
	bad := Rule{Match: Match{PathGlob: s(strings.Repeat("a", 201)), Tool: s("semgrep"), SeverityAtLeast: s("urgent")}}
	errs := Validate(bad)
	for _, k := range []string{"match.path_glob", "match.tool", "match.severity_at_least", "assignee_id"} {
		if errs[k] == "" {
			t.Errorf("%s not reported: %v", k, errs)
		}
	}
	for _, p := range []string{"", "a{b,c}", `a\*`, "a[bc]", "a\x00b", "a\nb"} {
		if ValidateGlob(p) == "" {
			t.Errorf("%q accepted", p)
		}
	}
	if errs := Validate(Rule{Match: Match{PathGlob: s("src/**/*.py"), Tool: s("opengrep"), SeverityAtLeast: s("high")}, AssigneeID: id}); len(errs) != 0 {
		t.Fatal(errs)
	}
}

func TestMatchesAndFirst(t *testing.T) {
	a, b, gone := uuid.New(), uuid.New(), uuid.New()
	rules := []Rule{
		{Match: Match{PathGlob: s("src/**")}, AssigneeID: gone},
		{Match: Match{Tool: s("trivy"), SeverityAtLeast: s("high")}, AssigneeID: a},
		{Match: Match{PathGlob: s("src/**")}, AssigneeID: b},
		{AssigneeID: a}, // malformed: never matches
	}
	eligible := func(u uuid.UUID) bool { return u != gone }
	for _, c := range []struct {
		issue Issue
		want  int
	}{
		{Issue{FilePath: "src/a.py", Tool: "opengrep", Severity: "low"}, 2}, // rule 0 skipped: assignee gone
		{Issue{FilePath: "go.sum", Tool: "trivy", Severity: "critical"}, 1},
		{Issue{FilePath: "go.sum", Tool: "trivy", Severity: "medium"}, -1},
		{Issue{FilePath: "go.sum", Tool: "trivy", Severity: "bogus"}, -1},
		{Issue{FilePath: "web/x.js", Tool: "opengrep", Severity: "critical"}, -1},
	} {
		if got := First(rules, c.issue, eligible); got != c.want {
			t.Errorf("%+v: rule %d, want %d", c.issue, got, c.want)
		}
	}
}
