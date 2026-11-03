// Package rules parses, validates and renders an org's own scanner rules:
// Opengrep (SAST, YAML) and Gitleaks (secrets, TOML). A rule body comes from
// an org admin or security lead through the API and is hostile input: it is
// decoded into a typed subset, checked, and rendered again from that struct.
// Nothing a user wrote reaches a scanner as written.
//
// Rules may only add findings. Allowlists, ignores, path exclusions, fixes and
// anything else that could silence a scan are refused, as are regular
// expressions Go's RE2 engine can't compile (no backreferences or lookaround,
// so no catastrophic backtracking). Rendered ids are Prefix + key, so an org
// rule can never collide with, or stand in for, a built-in rule's fingerprint.
package rules

import "errors"

// Tool is a scanner that takes org rules.
type Tool string

const (
	Opengrep Tool = "opengrep"
	Gitleaks Tool = "gitleaks"
)

const (
	// Prefix starts every org rule's id in findings and issues ("org.<key>").
	Prefix = "org."
	// MaxBodyBytes caps one rule's submitted body; MaxRulesPerTool and
	// MaxOrgBytes cap an org's rules.
	MaxBodyBytes    = 64 << 10
	MaxRulesPerTool = 200
	MaxOrgBytes     = 1 << 20
)

// Problem is one reason a body is refused, with its 1-based position in the
// submitted text when known (0 otherwise).
type Problem struct {
	Line, Column int
	Message      string
}

// Rule is a validated rule: Key is the id from the body (^[a-z0-9][a-z0-9._-]{0,63}$),
// Canonical the body rendered from the parsed rule (what is stored and shown),
// Severity Warden's severity for its findings (critical|high|medium|low|info).
type Rule struct {
	Tool      Tool
	Key       string
	Severity  string
	Canonical []byte
}

// ID is what the rule's findings carry: Prefix + Key.
func (r Rule) ID() string { return Prefix + r.Key }

var errNotImplemented = errors.New("rules: not implemented")

// Parse validates one rule body for tool. It returns the rule, or the
// problems that make the body unacceptable (never both).
func Parse(tool Tool, body []byte) (Rule, []Problem) {
	return Rule{}, []Problem{{Message: errNotImplemented.Error()}}
}

// Render writes the scanner configuration for rules (all of the same tool,
// already validated, in a stable order): an Opengrep YAML config with every
// rule's id set to ID(), or a Gitleaks TOML config of only these [[rules]].
// The Gitleaks config is used in addition to Warden's base config, never
// instead of it.
func Render(tool Tool, rules []Rule) ([]byte, error) {
	return nil, errNotImplemented
}
