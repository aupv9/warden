package rules_test

import (
	"strings"
	"testing"

	"github.com/aupv9/warden/backend/internal/rules"
)

// ogRule builds a one-rule body around extra lines (already indented by 4).
func ogRule(id, extra string) string {
	return "rules:\n  - id: " + id + "\n    message: Found it\n    severity: ERROR\n    languages: [python]\n" + extra
}

var ogAccepted = []struct {
	name, body, key, severity string
}{
	{"pattern", ogRule("no-eval", "    pattern: eval($X)\n"), "no-eval", "high"},
	{"warning and info", strings.Replace(ogRule("w", "    pattern: f()\n"), "ERROR", "WARNING", 1), "w", "medium"},
	{"info", strings.Replace(ogRule("i", "    pattern: f()\n"), "ERROR", "INFO", 1), "i", "low"},
	{"patterns", ogRule("acme.sql_1", `    patterns:
      - pattern-inside: |
          def $F(...):
            ...
      - pattern: cursor.execute($Q)
      - pattern-not: cursor.execute("...")
      - pattern-not-inside: "if safe($Q): ..."
      - pattern-not-regex: ^\s*#
      - metavariable-regex:
          metavariable: $Q
          regex: ^(query|sql)_[a-z]+$
      - focus-metavariable: $Q
`), "acme.sql_1", "high"},
	{"pattern-either", ogRule("either", `    pattern-either:
      - pattern: os.system($X)
      - patterns:
          - pattern: subprocess.call($X, shell=True)
          - pattern-not: subprocess.call("...", shell=True)
      - pattern-regex: popen\(
      - pattern-either:
          - pattern: exec($X)
`), "either", "high"},
	{"pattern-regex generic", "rules:\n- id: acme-key\n  message: Acme key\n  severity: WARNING\n  languages: [generic]\n  pattern-regex: acme_[a-z0-9]{16}\n", "acme-key", "medium"},
	{"taint", ogRule("taint-1", `    mode: taint
    pattern-sources:
      - pattern: request.args.get(...)
    pattern-sanitizers:
      - pattern: escape(...)
    pattern-sinks:
      - patterns:
          - pattern: render($X)
          - focus-metavariable: [$X]
`), "taint-1", "high"},
	{"metavariable-pattern", ogRule("mvp", `    patterns:
      - pattern: query($X)
      - metavariable-pattern:
          metavariable: $X
          language: generic
          pattern-either:
            - pattern-regex: (?i)select
            - pattern: delete
`), "mvp", "high"},
	{"metadata", ogRule("meta", "    pattern: f()\n    metadata:\n      owasp: A03\n      cwe: 79\n      confidence: HIGH\n      verified: true\n      references: https://example.com/x\n"), "meta", "high"},
	{"mode search", ogRule("search", "    mode: search\n    pattern: f()\n"), "search", "high"},
	{"flow style", `{"rules": [{"id": "flow", "message": "m", "severity": "INFO", "languages": ["js", "ts"], "pattern": "eval(...)"}]}`, "flow", "low"},
	{"byte order mark", "\uFEFF" + ogRule("bom", "    pattern: f()\n"), "bom", "high"},
	{"unicode text", strings.Replace(ogRule("uni", "    pattern: f(\"héllo\")\n"), "Found it", "Trouvé 👩\u200d💻 \"quoted\" # not a comment: really", 1), "uni", "high"},
	{"comments", "# a rule\n" + ogRule("cmt", "    pattern: f() # trailing\n"), "cmt", "high"},
	{"multiline message", strings.Replace(ogRule("ml", "    pattern: f()\n"), "message: Found it", "message: |\n      Line one\n      Line two with trailing spaces   \n", 1), "ml", "high"},
	{"tricky scalars", ogRule("tricky", "    pattern: \"yes\"\n    metadata:\n      a: \"null\"\n      b: \"0x10\"\n      c: '- x'\n      d: \"@at\"\n"), "tricky", "high"},
}

func TestOpengrepAccepted(t *testing.T) {
	for _, c := range ogAccepted {
		t.Run(c.name, func(t *testing.T) {
			r, probs := rules.Parse(rules.Opengrep, []byte(c.body))
			if len(probs) > 0 {
				t.Fatalf("refused: %+v", probs)
			}
			if r.Tool != rules.Opengrep || r.Key != c.key || r.Severity != c.severity || r.ID() != "org."+c.key {
				t.Fatalf("got %+v", r)
			}
			checkCanonical(t, r)
			if strings.Contains(string(r.Canonical), "org."+c.key) {
				t.Fatalf("canonical carries the prefix:\n%s", r.Canonical)
			}
		})
	}
}

// checkCanonical: Canonical parses back to the same rule, and renders.
func checkCanonical(t *testing.T, r rules.Rule) {
	t.Helper()
	again, probs := rules.Parse(r.Tool, r.Canonical)
	if len(probs) > 0 {
		t.Fatalf("canonical refused: %+v\n%s", probs, r.Canonical)
	}
	if again.Tool != r.Tool || again.Key != r.Key || again.Severity != r.Severity || string(again.Canonical) != string(r.Canonical) {
		t.Fatalf("not idempotent:\n%s\n---\n%s", r.Canonical, again.Canonical)
	}
	out, err := rules.Render(r.Tool, []rules.Rule{r})
	if err != nil {
		t.Fatalf("render: %v", err)
	}
	checkRendered(t, r.Tool, out, []string{r.ID()})
}

func TestOpengrepCanonicalForm(t *testing.T) {
	body := `rules:
- metadata: {z: last, a: first}
  pattern: eval($X)
  languages: [python, go]
  severity: WARNING
  message: Don't eval
  id: order
`
	r, probs := rules.Parse(rules.Opengrep, []byte(body))
	if len(probs) > 0 {
		t.Fatal(probs)
	}
	want := `rules:
  - id: order
    message: Don't eval
    severity: WARNING
    languages: [python, go]
    pattern: eval($X)
    metadata:
      a: first
      z: last
`
	if string(r.Canonical) != want {
		t.Fatalf("canonical:\n%s", r.Canonical)
	}
}

// Every refusal is a reason the body names; the rule is never half-accepted.
var ogRefused = []struct {
	name, body, want string
}{
	// YAML features.
	{"billion laughs", "a: &a [x, x, x, x, x, x, x, x, x]\nb: &b [*a, *a, *a, *a, *a, *a, *a, *a, *a]\nc: &c [*b, *b, *b, *b, *b, *b, *b, *b, *b]\nd: [*c, *c, *c, *c, *c, *c, *c, *c, *c]\nrules: []\n", "anchors"},
	{"anchor", ogRule("a", "    pattern: &p eval($X)\n"), "anchors are not allowed"},
	{"alias", "x: &m eval($X)\n" + ogRule("a", "    pattern: *m\n"), "not allowed"},
	{"merge key", "base: &b {severity: ERROR}\n" + ogRule("a", "    <<: *b\n    pattern: f()\n"), "not allowed"},
	{"merge key alone", ogRule("a", "    pattern: f()\n    <<: {fix: x}\n"), "merge keys"},
	{"custom tag", ogRule("a", "    pattern: !python/object eval\n"), "tags are not allowed"},
	{"explicit str tag", ogRule("a", "    pattern: !!str eval\n"), "tags are not allowed"},
	{"binary tag", ogRule("a", "    pattern: !!binary ZXZhbA==\n"), "tags are not allowed"},
	{"two documents", ogRule("a", "    pattern: f()\n") + "---\n" + ogRule("b", "    pattern: g()\n"), "single YAML document"},
	{"two documents, second empty-ish", ogRule("a", "    pattern: f()\n") + "---\nx: 1\n", "single YAML document"},
	{"int key", ogRule("a", "    pattern: f()\n    1: x\n"), "keys must be plain strings"},
	{"complex key", ogRule("a", "    pattern: f()\n    ? [a, b]\n    : x\n"), "keys must be plain strings"},
	{"null key", ogRule("a", "    pattern: f()\n    ~: x\n"), "keys must be plain strings"},
	{"duplicate key", ogRule("a", "    pattern: f()\n    pattern: g()\n"), "duplicate key"},
	{"duplicate id", ogRule("a", "    pattern: f()\n    id: b\n"), "duplicate key"},
	{"deep nesting", ogRule("a", "    pattern-either:\n"+deepEither(20)), "nested more than"},
	{"flow nesting bomb", "rules: " + strings.Repeat("[", 5000) + strings.Repeat("]", 5000) + "\n", ""},
	{"too many nodes", ogRule("a", "    pattern: f()\n    languages2: ["+strings.Repeat("x, ", 6000)+"x]\n"), "more than 5000"},
	{"not yaml", "rules: [\n", "invalid YAML"},
	{"tab indentation", "rules:\n\t- id: a\n", "invalid YAML"},
	{"empty", "  \n", "empty"},
	{"only comments", "# nothing\n", "empty"},
	{"scalar", "eval\n", "mapping"},
	{"oversize", ogRule("a", "    pattern: f()\n    message2: "+strings.Repeat("x", rules.MaxBodyBytes)+"\n"), "limit"},

	// Structure.
	{"two rules", ogRule("a", "    pattern: f()\n") + "  - id: b\n    message: m\n    severity: ERROR\n    languages: [python]\n    pattern: g()\n", "exactly one rule"},
	{"no rules", "rules: []\n", "exactly one rule"},
	{"rules not a list", "rules: {id: a}\n", "exactly one rule"},
	{"top-level key", "imports: [x]\n" + ogRule("a", "    pattern: f()\n"), "not allowed at the top level"},
	{"missing rules", "foo: bar\n", "not allowed at the top level"},
	{"missing message", "rules:\n- id: a\n  severity: ERROR\n  languages: [python]\n  pattern: f()\n", `missing "message"`},
	{"missing pattern", ogRule("a", ""), "needs one of"},
	{"two formulas", ogRule("a", "    pattern: f()\n    pattern-regex: x\n"), "only one of"},

	// Keys that would change what's scanned, fixed or reported.
	{"fix", ogRule("a", "    pattern: f()\n    fix: g()\n"), "can't rewrite code"},
	{"fix-regex", ogRule("a", "    pattern: f()\n    fix-regex: {regex: f, replacement: g}\n"), "can't rewrite code"},
	{"paths", ogRule("a", "    pattern: f()\n    paths:\n      exclude: ['*']\n"), "can't include or exclude files"},
	{"options", ogRule("a", "    pattern: f()\n    options:\n      symbolic_propagation: true\n"), "options"},
	{"min-version", ogRule("a", "    pattern: f()\n    min-version: 1.0.0\n"), "version"},
	{"max-version", ogRule("a", "    pattern: f()\n    max-version: 1.0.0\n"), "version"},
	{"r2c-internal", ogRule("a", "    pattern: f()\n    r2c-internal-project-depends-on: {namespace: pypi}\n"), "internal scanner keys"},
	{"join", "rules:\n- id: a\n  message: m\n  severity: ERROR\n  languages: [python]\n  mode: join\n  join: {rules: []}\n", "not allowed"},
	{"extract", ogRule("a", "    mode: extract\n    extract: $X\n    pattern: f($X)\n"), "not allowed"},
	{"equivalences", ogRule("a", "    pattern: f()\n    equivalences:\n      - equivalence: a ==> b\n"), "equivalences"},
	{"unknown rule key", ogRule("a", "    pattern: f()\n    product: secrets\n"), `"product" is not allowed in a rule`},
	{"unknown key in patterns", ogRule("a", "    patterns:\n      - pattern: f()\n      - metavariable-comparison: {metavariable: $X, comparison: $X > 1}\n"), "evaluates expressions"},
	{"unknown key in either", ogRule("a", "    pattern-either:\n      - pattern: f()\n      - pattern-not: g()\n"), `"pattern-not" is not allowed in pattern-either`},
	{"two keys in a patterns item", ogRule("a", "    patterns:\n      - pattern: f()\n        pattern-not: g()\n"), "one operator"},
	{"unknown key in metavariable-regex", ogRule("a", "    patterns:\n      - pattern: f($X)\n      - metavariable-regex: {metavariable: $X, regex: a, constant-propagation: true}\n"), "not allowed in metavariable-regex"},
	{"source options", ogRule("a", "    mode: taint\n    pattern-sources:\n      - pattern: s()\n        by-side-effect: true\n    pattern-sinks:\n      - pattern: k()\n"), "one operator"},
	{"source label", ogRule("a", "    mode: taint\n    pattern-sources:\n      - label: X\n    pattern-sinks:\n      - pattern: k()\n"), `"label" is not allowed in pattern-sources`},
	{"propagators", ogRule("a", "    mode: taint\n    pattern-sources: [{pattern: s()}]\n    pattern-sinks: [{pattern: k()}]\n    pattern-propagators: [{pattern: p()}]\n"), "propagators"},
	{"taint without sinks", ogRule("a", "    mode: taint\n    pattern-sources: [{pattern: s()}]\n"), "pattern-sinks"},
	{"taint with pattern", ogRule("a", "    mode: taint\n    pattern: f()\n    pattern-sources: [{pattern: s()}]\n    pattern-sinks: [{pattern: k()}]\n"), "taint rule takes"},
	{"sources without taint", ogRule("a", "    pattern: f()\n    pattern-sources: [{pattern: s()}]\n"), "needs mode: taint"},
	{"other mode", ogRule("a", "    mode: steps\n    pattern: f()\n"), "mode must be"},
	{"no positive term", ogRule("a", "    patterns:\n      - pattern-not: f()\n"), "at least one of"},
	{"metadata nested", ogRule("a", "    pattern: f()\n    metadata:\n      cwe: [79, 80]\n"), "must be a string"},
	{"metadata security-severity", ogRule("a", "    pattern: f()\n    metadata:\n      security-severity: 9.8\n"), "reserved"},
	{"metadata too many", ogRule("a", "    pattern: f()\n    metadata:\n"+manyMeta(21)), "at most 20"},
	{"metadata long value", ogRule("a", "    pattern: f()\n    metadata:\n      x: "+strings.Repeat("v", 300)+"\n"), "limit is 256"},
	{"metadata bad name", ogRule("a", "    pattern: f()\n    metadata:\n      Bad Name: x\n"), "metadata name"},

	// Values.
	{"id with org prefix", ogRule("org.mine", "    pattern: f()\n"), "Warden adds it"},
	{"id uppercase", ogRule("Mine", "    pattern: f()\n"), "id must be"},
	{"id too long", ogRule(strings.Repeat("a", 65), "    pattern: f()\n"), "id must be"},
	{"id with slash", ogRule("a/b", "    pattern: f()\n"), "id must be"},
	{"id number", ogRule("123", "    pattern: f()\n"), "id must be a string"},
	{"severity lower", strings.Replace(ogRule("a", "    pattern: f()\n"), "ERROR", "error", 1), "severity must be"},
	{"severity critical", strings.Replace(ogRule("a", "    pattern: f()\n"), "ERROR", "CRITICAL", 1), "severity must be"},
	{"no languages", strings.Replace(ogRule("a", "    pattern: f()\n"), "[python]", "[]", 1), "non-empty list"},
	{"languages a string", strings.Replace(ogRule("a", "    pattern: f()\n"), "[python]", "python", 1), "non-empty list"},
	{"unknown language", strings.Replace(ogRule("a", "    pattern: f()\n"), "[python]", "[cobol]", 1), "unknown language"},
	{"language twice", strings.Replace(ogRule("a", "    pattern: f()\n"), "[python]", "[python, python]", 1), "twice"},
	{"empty pattern", ogRule("a", "    pattern: \"  \"\n"), "empty"},
	{"pattern a list", ogRule("a", "    pattern: [f]\n"), "must be a string"},
	{"pattern null", ogRule("a", "    pattern:\n"), "must be a string"},
	{"long pattern", ogRule("a", "    pattern: "+strings.Repeat("f", 4001)+"\n"), "limit is 4000"},
	{"long message", strings.Replace(ogRule("a", "    pattern: f()\n"), "Found it", strings.Repeat("m", 2001), 1), "limit is 2000"},
	{"bad metavariable", ogRule("a", "    patterns:\n      - pattern: f($X)\n      - focus-metavariable: X\n"), "metavariable like $X"},

	// Regular expressions.
	{"backreference", ogRule("a", "    pattern-regex: (a)\\1\n"), "RE2"},
	{"lookahead", ogRule("a", "    pattern-regex: foo(?=bar)\n"), "RE2"},
	{"lookbehind in metavariable-regex", ogRule("a", "    patterns:\n      - pattern: f($X)\n      - metavariable-regex: {metavariable: $X, regex: '(?<!x)y'}\n"), "RE2"},
	{"possessive", ogRule("a", "    pattern-regex: a*+\n"), "RE2"},
	{"nested repetition", ogRule("a", "    pattern-regex: (a+)+$\n"), "backtrack"},
	{"nested repetition in not-regex", ogRule("a", "    patterns:\n      - pattern: f()\n      - pattern-not-regex: (\\w*\\s?)*x\n"), "backtrack"},
	{"empty-matching regex", ogRule("a", "    pattern-regex: x*\n"), "matches empty text"},
	{"long regex", ogRule("a", "    pattern-regex: "+strings.Repeat("a", 1001)+"\n"), "limit is 1000"},
	{"huge repeat", ogRule("a", "    pattern-regex: a{1001}\n"), "RE2"},

	// Characters.
	{"bidi override", ogRule("a", "    pattern: f(\"\u202e\")\n"), "bidirectional"},
	{"bidi isolate in comment", "# \u2066hidden\u2069\n" + ogRule("a", "    pattern: f()\n"), "bidirectional"},
	{"escaped bidi", ogRule("a", "    pattern: \"f(\\u202E)\"\n"), "bidirectional"},
	{"escaped control", ogRule("a", "    pattern: \"f(\\x07)\"\n"), "control"},
	{"escaped NUL", ogRule("a", "    pattern: \"f(\\0)\"\n"), "control"},
	{"zero-width space", ogRule("a", "    pattern: \"f(\\u200B)\"\n"), "control"},
	{"NUL byte", ogRule("a", "    pattern: f()\x00\n"), "NUL"},
	{"invalid UTF-8", ogRule("a", "    pattern: f(\xff)\n"), "UTF-8"},
	{"newline in id", ogRule("\"a\\nb\"", "    pattern: f()\n"), "id must be"},
}

func deepEither(n int) string {
	var b strings.Builder
	ind := "      "
	for i := 0; i < n; i++ {
		b.WriteString(ind + "- pattern-either:\n")
		ind += "    "
	}
	b.WriteString(ind + "- pattern: f()\n")
	return b.String()
}

func manyMeta(n int) string {
	var b strings.Builder
	for i := 0; i < n; i++ {
		b.WriteString("      k" + strings.Repeat("x", i) + ": v\n")
	}
	return b.String()
}

func TestOpengrepRefused(t *testing.T) {
	for _, c := range ogRefused {
		t.Run(c.name, func(t *testing.T) {
			r, probs := rules.Parse(rules.Opengrep, []byte(c.body))
			checkRefused(t, r, probs, c.want)
		})
	}
}

func checkRefused(t *testing.T, r rules.Rule, probs []rules.Problem, want string) {
	t.Helper()
	if len(probs) == 0 {
		t.Fatalf("accepted:\n%s", r.Canonical)
	}
	if r.Key != "" || r.Canonical != nil || r.Tool != "" {
		t.Fatalf("refused but returned a rule: %+v", r)
	}
	var all []string
	for _, p := range probs {
		if p.Message == "" || p.Line < 0 || p.Column < 0 {
			t.Fatalf("bad problem %+v", p)
		}
		all = append(all, p.Message)
	}
	if !strings.Contains(strings.Join(all, "\n"), want) {
		t.Fatalf("want a problem containing %q, got %+v", want, probs)
	}
}

func TestOpengrepProblemPosition(t *testing.T) {
	_, probs := rules.Parse(rules.Opengrep, []byte(ogRule("a", "    pattern: f()\n    fix: g()\n")))
	if len(probs) != 1 || probs[0].Line != 7 || probs[0].Column != 5 {
		t.Fatalf("got %+v", probs)
	}
	_, probs = rules.Parse(rules.Opengrep, []byte(ogRule("a", "    pattern-regex: (a)\\1\n")))
	if len(probs) != 1 || probs[0].Line != 6 || probs[0].Column != 20 {
		t.Fatalf("got %+v", probs)
	}
	_, probs = rules.Parse(rules.Opengrep, []byte("rules:\n  - id: a\n   x: [\n"))
	if len(probs) != 1 || probs[0].Line == 0 {
		t.Fatalf("got %+v", probs)
	}
}
