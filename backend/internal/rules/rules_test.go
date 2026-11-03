package rules_test

import (
	"fmt"
	"slices"
	"strings"
	"testing"
	"time"

	"github.com/pelletier/go-toml/v2"
	"go.yaml.in/yaml/v3"

	"github.com/aupv9/warden/backend/internal/rules"
)

// checkRendered: the config holds exactly these rule ids, every one Prefix +
// key, and nothing but rules (no Gitleaks title, extend or allowlists).
func checkRendered(t testing.TB, tool rules.Tool, out []byte, ids []string) {
	t.Helper()
	var got []string
	switch tool {
	case rules.Opengrep:
		var doc map[string][]map[string]any
		if err := yaml.Unmarshal(out, &doc); err != nil {
			t.Fatalf("rendered YAML: %v\n%s", err, out)
		}
		if len(doc) != 1 || doc["rules"] == nil {
			t.Fatalf("rendered top level: %s", out)
		}
		for _, r := range doc["rules"] {
			id, _ := r["id"].(string)
			got = append(got, id)
		}
	case rules.Gitleaks:
		var doc map[string]any
		if err := toml.Unmarshal(out, &doc); err != nil {
			t.Fatalf("rendered TOML: %v\n%s", err, out)
		}
		list, _ := doc["rules"].([]any)
		if len(list) != len(ids) || len(doc) != min(len(ids), 1) {
			t.Fatalf("rendered top level: %s", out)
		}
		for _, x := range list {
			r, _ := x.(map[string]any)
			for k := range r {
				if !slices.Contains([]string{"id", "description", "regex", "secretGroup", "entropy", "keywords", "path", "tags"}, k) {
					t.Fatalf("rendered key %q", k)
				}
			}
			id, _ := r["id"].(string)
			got = append(got, id)
		}
	}
	if !slices.Equal(got, ids) {
		t.Fatalf("rendered ids %q, want %q", got, ids)
	}
	for _, id := range got {
		if !strings.HasPrefix(id, rules.Prefix) || strings.HasPrefix(id, rules.Prefix+rules.Prefix) {
			t.Fatalf("rendered id %q", id)
		}
	}
}

func mustParse(t *testing.T, tool rules.Tool, body string) rules.Rule {
	t.Helper()
	r, probs := rules.Parse(tool, []byte(body))
	if len(probs) > 0 {
		t.Fatalf("refused: %+v", probs)
	}
	return r
}

func TestRender(t *testing.T) {
	a := mustParse(t, rules.Opengrep, ogRule("a", "    pattern: f()\n"))
	b := mustParse(t, rules.Opengrep, ogAccepted[3].body)
	out, err := rules.Render(rules.Opengrep, []rules.Rule{a, b})
	if err != nil {
		t.Fatal(err)
	}
	checkRendered(t, rules.Opengrep, out, []string{"org.a", "org.acme.sql_1"})
	if !strings.HasPrefix(string(out), "rules:\n  - id: org.a\n") {
		t.Fatalf("rendered:\n%s", out)
	}

	g1 := mustParse(t, rules.Gitleaks, glRule("one", ""))
	g2 := mustParse(t, rules.Gitleaks, glAccepted[1].body)
	out, err = rules.Render(rules.Gitleaks, []rules.Rule{g1, g2})
	if err != nil {
		t.Fatal(err)
	}
	checkRendered(t, rules.Gitleaks, out, []string{"org.one", "org.acme.token_v2"})

	for _, tool := range []rules.Tool{rules.Opengrep, rules.Gitleaks} {
		out, err := rules.Render(tool, nil)
		if err != nil {
			t.Fatal(err)
		}
		checkRendered(t, tool, out, nil)
	}
}

func TestRenderRefuses(t *testing.T) {
	og := mustParse(t, rules.Opengrep, ogRule("a", "    pattern: f()\n"))
	gl := mustParse(t, rules.Gitleaks, glRule("a", ""))
	tampered := og
	tampered.Canonical = []byte(strings.Replace(string(og.Canonical), "pattern: f()", "pattern: f()\n    fix: g()", 1))
	renamed := og
	renamed.Key = "b"
	reordered := mustParse(t, rules.Opengrep, ogRule("a", "    pattern: f()\n    metadata: {x: y}\n"))
	reordered.Canonical = []byte("rules:\n  - metadata: {x: y}\n    id: a\n    message: Found it\n    severity: ERROR\n    languages: [python]\n    pattern: f()\n")
	glTampered := gl
	glTampered.Canonical = append(append([]byte{}, gl.Canonical...), "[allowlist]\npaths = ['.*']\n"...)
	big := make([]rules.Rule, rules.MaxRulesPerTool+1)
	for i := range big {
		big[i] = mustParse(t, rules.Gitleaks, glRule(fmt.Sprintf("r%d", i), ""))
	}
	for _, c := range []struct {
		name  string
		tool  rules.Tool
		rules []rules.Rule
	}{
		{"other tool", rules.Opengrep, []rules.Rule{og, gl}},
		{"unknown tool", "trivy", nil},
		{"duplicate key", rules.Opengrep, []rules.Rule{og, og}},
		{"tampered canonical", rules.Opengrep, []rules.Rule{tampered}},
		{"key not the body's id", rules.Opengrep, []rules.Rule{renamed}},
		{"gitleaks allowlist appended", rules.Gitleaks, []rules.Rule{glTampered}},
		{"zero rule", rules.Gitleaks, []rules.Rule{{Tool: rules.Gitleaks}}},
		{"too many", rules.Gitleaks, big},
	} {
		t.Run(c.name, func(t *testing.T) {
			if out, err := rules.Render(c.tool, c.rules); err == nil {
				t.Fatalf("rendered:\n%s", out)
			}
		})
	}
	if _, err := rules.Render(rules.Gitleaks, big[:rules.MaxRulesPerTool]); err != nil {
		t.Fatalf("%d rules: %v", rules.MaxRulesPerTool, err)
	}
	// A body stored in an older canonical form still renders, from its parse.
	out, err := rules.Render(rules.Opengrep, []rules.Rule{reordered})
	if err != nil {
		t.Fatal(err)
	}
	if !strings.HasPrefix(string(out), "rules:\n  - id: org.a\n") {
		t.Fatalf("rendered:\n%s", out)
	}
}

func TestRegexNesting(t *testing.T) {
	deep := strings.Repeat("(?:", 101) + "a" + strings.Repeat(")", 101)
	_, probs := rules.Parse(rules.Gitleaks, []byte("[[rules]]\nid = 'a'\nregex = '"+deep+"'\n"))
	checkRefused(t, rules.Rule{}, probs, "nests more than 100")
	// Parentheses that are escaped, quoted or in a class don't count.
	flat := strings.Repeat(`\(`, 150) + `\Q((((\E[(]` + strings.Repeat("(a)", 50)
	if _, probs := rules.Parse(rules.Gitleaks, []byte("[[rules]]\nid = 'a'\nregex = '"+flat+"'\n")); len(probs) > 0 {
		t.Fatal(probs)
	}
}

func TestParseUnknownTool(t *testing.T) {
	r, probs := rules.Parse("trivy", []byte(glRule("a", "")))
	checkRefused(t, r, probs, "unknown tool")
}

func FuzzParseOpengrep(f *testing.F) {
	for _, c := range ogAccepted {
		f.Add([]byte(c.body))
	}
	for _, c := range ogRefused {
		if len(c.body) < 8<<10 {
			f.Add([]byte(c.body))
		}
	}
	f.Fuzz(func(t *testing.T, body []byte) { fuzzParse(t, rules.Opengrep, body) })
}

func FuzzParseGitleaks(f *testing.F) {
	for _, c := range glAccepted {
		f.Add([]byte(c.body))
	}
	for _, c := range glRefused {
		if len(c.body) < 8<<10 {
			f.Add([]byte(c.body))
		}
	}
	f.Fuzz(func(t *testing.T, body []byte) { fuzzParse(t, rules.Gitleaks, body) })
}

// fuzzParse: Parse never panics and is quick; a refusal is only problems; an
// accepted rule is canonical (parses back to itself) and renders with only
// prefixed ids.
func fuzzParse(t *testing.T, tool rules.Tool, body []byte) {
	start := time.Now()
	r, probs := rules.Parse(tool, body)
	if d := time.Since(start); d > 2*time.Second {
		t.Fatalf("Parse took %v on %d bytes", d, len(body))
	}
	if len(probs) > 0 {
		if r.Key != "" || r.Canonical != nil {
			t.Fatalf("refused with a rule: %+v", r)
		}
		for _, p := range probs {
			if p.Message == "" || p.Line < 0 || p.Column < 0 {
				t.Fatalf("problem %+v", p)
			}
		}
		return
	}
	if r.Tool != tool || r.Key == "" || strings.HasPrefix(r.Key, rules.Prefix) || len(r.Canonical) == 0 {
		t.Fatalf("accepted %+v", r)
	}
	if !slices.Contains([]string{"high", "medium", "low"}, r.Severity) {
		t.Fatalf("severity %q", r.Severity)
	}
	again, probs := rules.Parse(tool, r.Canonical)
	if len(probs) > 0 {
		t.Fatalf("canonical refused: %+v\n%s", probs, r.Canonical)
	}
	if again.Key != r.Key || again.Severity != r.Severity || string(again.Canonical) != string(r.Canonical) {
		t.Fatalf("not idempotent:\n%q\n%q", r.Canonical, again.Canonical)
	}
	out, err := rules.Render(tool, []rules.Rule{r})
	if err != nil {
		t.Fatalf("render: %v\n%s", err, r.Canonical)
	}
	checkRendered(t, tool, out, []string{r.ID()})
}
