// Package autoassign holds project auto-assign rules: validation and matching.
// It is pure; the API validates rules with it and the result processor applies
// them to new issues.
//
// Path globs are doublestar-style: "*" and "?" stay inside one path segment,
// a "**" segment spans any number of segments. Matching is a linear-time
// two-pointer scan (backtracking only to the last star), never a regular
// expression, so a crafted pattern can't make it slow; patterns are capped at
// MaxGlobLen characters and paths at MaxPathLen bytes.
package autoassign

import (
	"slices"
	"strings"
	"unicode/utf8"

	"github.com/google/uuid"
)

const (
	MaxRules   = 50
	MaxGlobLen = 200
	// MaxPathLen: longer paths never match (the SARIF parser caps paths well below this).
	MaxPathLen = 4096
)

// Match is what a rule looks at. At least one field is set.
type Match struct {
	PathGlob        *string `json:"path_glob,omitempty"`
	Tool            *string `json:"tool,omitempty"`
	SeverityAtLeast *string `json:"severity_at_least,omitempty"`
}

// Rule assigns matching new issues to AssigneeID.
type Rule struct {
	Match      Match     `json:"match"`
	AssigneeID uuid.UUID `json:"assignee_id"`
}

// Issue is what rules are evaluated against.
type Issue struct {
	FilePath string
	Tool     string
	Severity string
}

var (
	Tools = []string{"gitleaks", "opengrep", "trivy", "checkov"}
	// Severities, most severe first.
	Severities = []string{"critical", "high", "medium", "low", "info"}
)

// ValidateGlob returns a message for an unacceptable pattern, or "".
func ValidateGlob(p string) string {
	switch {
	case p == "" || utf8.RuneCountInString(p) > MaxGlobLen:
		return "must be 1-200 characters"
	case !utf8.ValidString(p) || strings.ContainsFunc(p, func(r rune) bool { return r < 0x20 || r == 0x7f }):
		return "must be printable text"
	case strings.ContainsAny(p, `[]{}\`):
		// Classes, alternatives and escapes aren't supported; refusing them
		// beats silently matching them literally.
		return "only the wildcards *, ** and ? are supported"
	}
	return ""
}

// Validate checks one rule's matchers (not the assignee's membership). It
// returns field → message.
func Validate(r Rule) map[string]string {
	errs := map[string]string{}
	m := r.Match
	if m.PathGlob == nil && m.Tool == nil && m.SeverityAtLeast == nil {
		errs["match"] = "needs at least one of path_glob, tool, severity_at_least"
	}
	if m.PathGlob != nil {
		if msg := ValidateGlob(*m.PathGlob); msg != "" {
			errs["match.path_glob"] = msg
		}
	}
	if m.Tool != nil && !slices.Contains(Tools, *m.Tool) {
		errs["match.tool"] = "must be one of gitleaks, opengrep, trivy, checkov"
	}
	if m.SeverityAtLeast != nil && !slices.Contains(Severities, *m.SeverityAtLeast) {
		errs["match.severity_at_least"] = "must be one of critical, high, medium, low, info"
	}
	if r.AssigneeID == uuid.Nil {
		errs["assignee_id"] = "is required"
	}
	return errs
}

// Matches reports whether every matcher of the rule accepts the issue.
func (r Rule) Matches(i Issue) bool {
	m := r.Match
	if m.PathGlob == nil && m.Tool == nil && m.SeverityAtLeast == nil {
		return false // never assign everything because of a malformed rule
	}
	if m.Tool != nil && *m.Tool != i.Tool {
		return false
	}
	if m.SeverityAtLeast != nil {
		want, have := slices.Index(Severities, *m.SeverityAtLeast), slices.Index(Severities, i.Severity)
		if want < 0 || have < 0 || have > want {
			return false
		}
	}
	if m.PathGlob != nil && !Glob(*m.PathGlob, i.FilePath) {
		return false
	}
	return true
}

// First returns the index of the first rule that matches the issue and whose
// assignee is eligible, or -1.
func First(rules []Rule, i Issue, eligible func(uuid.UUID) bool) int {
	for n, r := range rules {
		if r.Matches(i) && eligible(r.AssigneeID) {
			return n
		}
	}
	return -1
}

// Glob matches a path against a doublestar-style pattern. Paths use "/".
func Glob(pattern, path string) bool {
	if pattern == "" || path == "" || len(pattern) > 4*MaxGlobLen || len(path) > MaxPathLen || ValidateGlob(pattern) != "" {
		return false
	}
	ps, ss := strings.Split(pattern, "/"), strings.Split(path, "/")
	// Two pointers over segments; "**" is a star over whole segments. On a
	// mismatch we resume after the last "**", consuming one more segment.
	pi, si := 0, 0
	star, mark := -1, 0
	for si < len(ss) {
		switch {
		case pi < len(ps) && ps[pi] == "**":
			star, mark = pi, si
			pi++
		case pi < len(ps) && segment(ps[pi], ss[si]):
			pi++
			si++
		case star >= 0:
			mark++
			pi, si = star+1, mark
		default:
			return false
		}
	}
	for pi < len(ps) && ps[pi] == "**" {
		pi++
	}
	return pi == len(ps)
}

// segment matches one path segment: "*" is any run of characters, "?" one
// character. Same linear two-pointer scan as Glob, over runes.
func segment(pattern, s string) bool {
	p, t := []rune(pattern), []rune(s)
	pi, ti := 0, 0
	star, mark := -1, 0
	for ti < len(t) {
		switch {
		case pi < len(p) && p[pi] == '*':
			star, mark = pi, ti
			pi++
		case pi < len(p) && (p[pi] == '?' || p[pi] == t[ti]):
			pi++
			ti++
		case star >= 0:
			mark++
			pi, ti = star+1, mark
		default:
			return false
		}
	}
	for pi < len(p) && p[pi] == '*' {
		pi++
	}
	return pi == len(p)
}
