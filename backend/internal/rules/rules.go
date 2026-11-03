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

import (
	"bytes"
	"fmt"
	"regexp"
	"regexp/syntax"
	"strings"
	"unicode"
	"unicode/utf8"
)

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

// Parse validates one rule body for tool. It returns the rule, or the
// problems that make the body unacceptable (never both).
func Parse(tool Tool, body []byte) (Rule, []Problem) {
	var p problems
	if len(body) > MaxBodyBytes {
		p.add(0, 0, "the rule is %d bytes; the limit is %d", len(body), MaxBodyBytes)
		return Rule{}, p.list
	}
	body = bytes.TrimPrefix(body, []byte{0xEF, 0xBB, 0xBF}) // a UTF-8 byte order mark
	if len(bytes.TrimSpace(body)) == 0 {
		p.add(0, 0, "the rule is empty")
		return Rule{}, p.list
	}
	if !checkBody(&p, body) {
		return Rule{}, p.list
	}
	switch tool {
	case Opengrep:
		r, ok := parseOpengrep(&p, body)
		if !ok || len(p.list) > 0 {
			return Rule{}, p.result()
		}
		return Rule{Tool: Opengrep, Key: r.ID, Severity: r.severity(), Canonical: r.canonical()}, nil
	case Gitleaks:
		r, ok := parseGitleaks(&p, body)
		if !ok || len(p.list) > 0 {
			return Rule{}, p.result()
		}
		// Gitleaks has no severity of its own; Warden's for an org rule is
		// what severity.Gitleaks gives an id starting with Prefix.
		return Rule{Tool: Gitleaks, Key: r.ID, Severity: "high", Canonical: r.canonical()}, nil
	default:
		p.add(0, 0, "unknown tool %q", tool)
		return Rule{}, p.list
	}
}

// Render writes the scanner configuration for rules (all of the same tool,
// already validated, in a stable order): an Opengrep YAML config with every
// rule's id set to ID(), or a Gitleaks TOML config of only these [[rules]].
// The Gitleaks config is used in addition to Warden's base config, never
// instead of it.
//
// Each rule's Canonical is parsed again and the config is rendered from that
// parse, never copied: a stored body changed behind Parse's back is refused
// here unless it is still acceptable, and Key must be its id. Byte equality
// with today's canonical form isn't required, so a later change of format
// doesn't break rules already stored.
func Render(tool Tool, rules []Rule) ([]byte, error) {
	if tool != Opengrep && tool != Gitleaks {
		return nil, fmt.Errorf("rules: unknown tool %q", tool)
	}
	if len(rules) > MaxRulesPerTool {
		return nil, fmt.Errorf("rules: %d %s rules; the limit is %d", len(rules), tool, MaxRulesPerTool)
	}
	seen := make(map[string]bool, len(rules))
	var og []opengrepRule
	var gl []gitleaksRule
	for i, r := range rules {
		if r.Tool != tool {
			return nil, fmt.Errorf("rules: rule %d (%q) is a %s rule, not %s", i, r.Key, r.Tool, tool)
		}
		if seen[r.Key] {
			return nil, fmt.Errorf("rules: duplicate key %q", r.Key)
		}
		seen[r.Key] = true
		var p problems
		ok := checkBody(&p, r.Canonical)
		if ok && len(r.Canonical) <= MaxBodyBytes {
			switch tool {
			case Opengrep:
				var x opengrepRule
				if x, ok = parseOpengrep(&p, r.Canonical); ok && len(p.list) == 0 && x.ID == r.Key {
					og = append(og, x)
					continue
				}
			case Gitleaks:
				var x gitleaksRule
				if x, ok = parseGitleaks(&p, r.Canonical); ok && len(p.list) == 0 && x.ID == r.Key {
					gl = append(gl, x)
					continue
				}
			}
		}
		return nil, fmt.Errorf("rules: rule %q is not a canonical %s rule", r.Key, tool)
	}
	if tool == Opengrep {
		return renderOpengrep(og)
	}
	return renderGitleaks(gl), nil
}

// problems collects what is wrong with a body, capped so a hostile body
// can't make the answer large.
type problems struct{ list []Problem }

const maxProblems = 50

func (p *problems) add(line, col int, format string, args ...any) {
	if len(p.list) < maxProblems {
		p.list = append(p.list, Problem{Line: line, Column: col, Message: fmt.Sprintf(format, args...)})
	}
}

func (p *problems) result() []Problem {
	if len(p.list) == 0 {
		return []Problem{{Message: "the rule is not valid"}}
	}
	return p.list
}

var keyRe = regexp.MustCompile(`^[a-z0-9][a-z0-9._-]{0,63}$`)

// checkKey: a rule's own id. Warden adds Prefix, so the body must not.
func checkKey(p *problems, line, col int, key string) bool {
	switch {
	case !keyRe.MatchString(key):
		p.add(line, col, "id must be 1-64 characters of a-z, 0-9, '.', '_' or '-', starting with a letter or digit")
	case strings.HasPrefix(key, Prefix):
		p.add(line, col, "id must not start with %q: Warden adds it", Prefix)
	default:
		return true
	}
	return false
}

// checkBody refuses what no rule needs anywhere in its text, comments
// included: invalid UTF-8, NUL and Unicode bidirectional controls (which can
// make a rule read differently from what it does).
func checkBody(p *problems, body []byte) bool {
	line, col := 1, 1
	for i := 0; i < len(body); {
		r, n := utf8.DecodeRune(body[i:])
		switch {
		case r == utf8.RuneError && n <= 1:
			p.add(line, col, "the rule is not valid UTF-8")
			return false
		case r == 0:
			p.add(line, col, "the rule contains a NUL character")
			return false
		case isBidi(r):
			p.add(line, col, "the rule contains a Unicode bidirectional control character (U+%04X)", r)
			return false
		}
		if r == '\n' {
			line, col = line+1, 1
		} else {
			col++
		}
		i += n
	}
	return true
}

func isBidi(r rune) bool {
	switch {
	case r == 0x061C, r == 0x200E, r == 0x200F,
		r >= 0x202A && r <= 0x202E,
		r >= 0x2066 && r <= 0x2069:
		return true
	}
	return false
}

// checkText checks one string value: a length cap in bytes, printable
// characters only (tab, and newline where multiline), no bidi controls.
func checkText(p *problems, line, col int, what, s string, maxBytes int, multiline bool) bool {
	if len(s) > maxBytes {
		p.add(line, col, "%s is %d bytes; the limit is %d", what, len(s), maxBytes)
		return false
	}
	if !utf8.ValidString(s) {
		p.add(line, col, "%s is not valid UTF-8", what)
		return false
	}
	for _, r := range s {
		switch {
		case r == '\t', r == '\n' && multiline:
		case isBidi(r):
			p.add(line, col, "%s contains a Unicode bidirectional control character (U+%04X)", what, r)
			return false
		// Format characters (zero-width spaces, tag characters) hide text;
		// only the zero-width joiner, which emoji need, is allowed.
		case r == utf8.RuneError, r == 0x2028, r == 0x2029,
			unicode.Is(unicode.Cf, r) && r != 0x200D,
			unicode.Is(unicode.Cc, r), unicode.Is(unicode.Co, r),
			!unicode.IsPrint(r) && !unicode.IsSpace(r) && r != 0x200D:
			p.add(line, col, "%s contains a control or unprintable character (U+%04X)", what, r)
			return false
		}
	}
	return true
}

// checkRegex: the expression must compile with Go's regexp (RE2: no
// backreferences or lookaround) and fit maxBytes. Opengrep runs regexes with
// PCRE, which backtracks, so for it (pcre) nested repetition such as (a+)* —
// exponential on a near-match — is refused as well; what's left is bounded by
// PCRE's match limit and the sandbox's timeout.
func checkRegex(p *problems, line, col int, what, re string, maxBytes int, pcre, nonEmpty bool) bool {
	if re == "" {
		p.add(line, col, "%s is empty", what)
		return false
	}
	if !checkText(p, line, col, what, re, maxBytes, false) {
		return false
	}
	c, err := regexp.Compile(re)
	if err != nil {
		p.add(line, col, "%s does not compile as an RE2 regular expression: %s", what, reErr(err))
		return false
	}
	if nonEmpty && c.MatchString("") {
		p.add(line, col, "%s matches empty text", what)
		return false
	}
	tree, err := syntax.Parse(re, syntax.Perl)
	if err != nil { // compiled above with the same flags
		p.add(line, col, "%s: %s", what, reErr(err))
		return false
	}
	// PCRE refuses more than 250 nested parentheses; Go allows 1000.
	if parenDepth(re) > maxRegexDepth {
		p.add(line, col, "%s nests more than %d levels deep", what, maxRegexDepth)
		return false
	}
	if pcre {
		if nestedRepeat(tree, false) {
			p.add(line, col, "%s repeats a repetition (like (a+)*), which can backtrack catastrophically; flatten it (e.g. [\\w.]+)", what)
			return false
		}
	}
	return true
}

// reErr is a regexp error without the expression it quotes back.
func reErr(err error) string {
	if e, ok := err.(*syntax.Error); ok {
		return e.Code.String()
	}
	return "invalid"
}

const maxRegexDepth = 100

// parenDepth is how deeply re nests parentheses, counting non-capturing
// groups (which Go's parse tree drops). Escapes, \Q...\E and character
// classes are skipped; anything it miscounts, it overcounts.
func parenDepth(re string) int {
	d, deepest, inClass := 0, 0, false
	for i := 0; i < len(re); i++ {
		switch c := re[i]; {
		case c == '\\' && i+1 < len(re) && re[i+1] == 'Q':
			end := strings.Index(re[i+2:], `\E`)
			if end < 0 {
				return deepest
			}
			i += end + 3
		case c == '\\':
			i++
		case inClass:
			inClass = c != ']'
		case c == '[':
			inClass = true
			if i+1 < len(re) && re[i+1] == '^' {
				i++
			}
			if i+1 < len(re) && re[i+1] == ']' {
				i++
			}
		case c == '(':
			d++
			deepest = max(deepest, d)
		case c == ')':
			d--
		}
	}
	return deepest
}

// nestedRepeat reports a variable-length repetition inside an unbounded one.
func nestedRepeat(re *syntax.Regexp, inUnbounded bool) bool {
	variable, unbounded := false, false
	switch re.Op {
	case syntax.OpStar, syntax.OpPlus:
		variable, unbounded = true, true
	case syntax.OpQuest:
		variable = true
	case syntax.OpRepeat:
		variable, unbounded = re.Max != re.Min, re.Max == -1
	}
	if variable && inUnbounded {
		return true
	}
	for _, s := range re.Sub {
		if nestedRepeat(s, inUnbounded || unbounded) {
			return true
		}
	}
	return false
}
