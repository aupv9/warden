package rules_test

import (
	"strings"
	"testing"

	"github.com/aupv9/warden/backend/internal/rules"
)

func glRule(id, extra string) string {
	return "[[rules]]\nid = \"" + id + "\"\nregex = '''acme_[a-z0-9]{16}'''\n" + extra
}

var glAccepted = []struct {
	name, body, key string
}{
	{"minimal", glRule("acme-token", ""), "acme-token"},
	{"full", `# Acme's tokens
[[rules]]
id = "acme.token_v2"
description = "Acme API token"
regex = '''(?i)acme[_-]?key\s*[:=]\s*['"]?([a-z0-9]{32})'''
secretGroup = 1
entropy = 3.5
keywords = ["acme", "acme_key"]
path = '''\.(env|ya?ml)$'''
tags = ["acme", "api"]
`, "acme.token_v2"},
	{"integer entropy", glRule("e", "entropy = 3\n"), "e"},
	{"zero secretGroup", glRule("z", "secretGroup = 0\n"), "z"},
	{"quoted keys", "[[rules]]\n\"id\" = 'q'\n'regex' = \"x{3}y\"\n", "q"},
	{"regex with quote and tab", "[[rules]]\nid = 'qt'\nregex = \"it's\\t[0-9]+\"\n", "qt"},
	{"inline arrays over lines", glRule("ml", "keywords = [\n  \"a\",\n  \"b\", # comment\n]\n"), "ml"},
	{"byte order mark", "\uFEFF" + glRule("bom", ""), "bom"},
}

func TestGitleaksAccepted(t *testing.T) {
	for _, c := range glAccepted {
		t.Run(c.name, func(t *testing.T) {
			r, probs := rules.Parse(rules.Gitleaks, []byte(c.body))
			if len(probs) > 0 {
				t.Fatalf("refused: %+v", probs)
			}
			if r.Tool != rules.Gitleaks || r.Key != c.key || r.Severity != "high" {
				t.Fatalf("got %+v", r)
			}
			checkCanonical(t, r)
		})
	}
}

func TestGitleaksCanonicalForm(t *testing.T) {
	body := `[[rules]]
tags = ["t"]
path = 'cfg'
keywords = ["k"]
entropy = 4
secretGroup = 1
regex = '''k=([a-z]+)'''
description = "D"
id = "order"
`
	r, probs := rules.Parse(rules.Gitleaks, []byte(body))
	if len(probs) > 0 {
		t.Fatal(probs)
	}
	want := `[[rules]]
id = 'order'
description = 'D'
regex = 'k=([a-z]+)'
secretGroup = 1
entropy = 4.0
keywords = ['k']
path = 'cfg'
tags = ['t']
`
	if string(r.Canonical) != want {
		t.Fatalf("canonical:\n%s", r.Canonical)
	}
}

var glRefused = []struct {
	name, body, want string
}{
	// Anything that could silence Gitleaks or swap its configuration.
	{"global allowlist", glRule("a", "") + "[allowlist]\npaths = ['''.*''']\n", "can't allow-list"},
	{"allowlists", glRule("a", "") + "[[allowlists]]\nregexes = ['''.*''']\n", "can't allow-list"},
	{"rule allowlists", glRule("a", "") + "[[rules.allowlists]]\nregexes = ['''.*''']\n", "can't allow-list"},
	{"rule allowlist table", glRule("a", "") + "[rules.allowlist]\nregexes = ['''.*''']\n", "can't allow-list"},
	{"rule allowlist dotted", glRule("a", "allowlist.regexes = ['''.*''']\n"), "can't allow-list"},
	{"extend", "[extend]\nuseDefault = false\n" + glRule("a", ""), "can't change which configuration"},
	{"extend path", glRule("a", "") + "[extend]\npath = '/etc/passwd'\n", "can't change which configuration"},
	{"extend disabledRules", glRule("a", "") + "[extend]\ndisabledRules = ['aws-access-token']\n", "can't"},
	{"useDefault at top", "useDefault = true\n" + glRule("a", ""), "can't change which configuration"},
	{"title", "title = 'mine'\n" + glRule("a", ""), "only its [[rules]] table"},
	{"minVersion", "minVersion = 'v8.0.0'\n" + glRule("a", ""), "version"},
	{"skipReport", glRule("a", "skipReport = true\n"), "must report"},
	{"required", glRule("a", "") + "[[rules.required]]\nid = 'aws-access-token'\n", "composite"},
	{"stopwords", glRule("a", "stopwords = ['x']\n"), `"stopwords" in [[rules]] is not allowed`},
	{"unknown key", glRule("a", "severity = 'low'\n"), "not allowed"},
	{"case variant key", glRule("a", "Keywords = ['x']\n"), "not allowed"},
	{"secretgroup lowercase", glRule("a", "secretgroup = 1\n"), "not allowed"},
	{"other table", glRule("a", "") + "[foo]\nx = 1\n", "not allowed"},

	// Structure.
	{"two rules", glRule("a", "") + glRule("b", ""), "exactly one [[rules]]"},
	{"no rules", "# nothing\nid = 'a'\n", "top level"},
	{"rules inline", "rules = [{id = 'a', regex = 'x'}]\n", "[[rules]] table"},
	{"rules as table", "[rules]\nid = 'a'\nregex = 'x'\n", "not allowed"},
	{"missing regex", "[[rules]]\nid = 'a'\npath = 'x'\n", `missing "regex"`},
	{"missing id", "[[rules]]\nregex = 'x'\n", `missing "id"`},
	{"duplicate key", glRule("a", "regex = 'y'\n"), "invalid TOML"},
	{"not toml", "[[rules]\nid = 'a'\n", "invalid TOML"},
	{"empty", "\n\n", "empty"},
	{"array nesting bomb", "x = " + strings.Repeat("[", 20000) + strings.Repeat("]", 20000) + "\n", ""},
	{"oversize", glRule("a", "description = '"+strings.Repeat("d", rules.MaxBodyBytes)+"'\n"), "limit"},

	// Values.
	{"id with org prefix", glRule("org.x", ""), "Warden adds it"},
	{"id bad", glRule("A B", ""), "id must be"},
	{"id integer", "[[rules]]\nid = 1\nregex = 'x'\n", "id must be a string"},
	{"regex integer", "[[rules]]\nid = 'a'\nregex = 1\n", "regex must be a string"},
	{"backreference", "[[rules]]\nid = 'a'\nregex = '''(a)\\1'''\n", "RE2"},
	{"lookahead", "[[rules]]\nid = 'a'\nregex = '''key(?=x)'''\n", "RE2"},
	{"empty-matching regex", "[[rules]]\nid = 'a'\nregex = '''[a-z]*'''\n", "matches empty text"},
	{"long regex", "[[rules]]\nid = 'a'\nregex = '" + strings.Repeat("a", 2001) + "'\n", "limit is 2000"},
	{"bad path regex", glRule("a", "path = '(?<=x)'\n"), "RE2"},
	{"secretGroup too big", glRule("a", "secretGroup = 1\n"), "between 0 and"},
	{"secretGroup negative", glRule("a", "secretGroup = -1\n"), "between 0 and"},
	{"secretGroup float", glRule("a", "secretGroup = 1.0\n"), "must be an integer"},
	{"entropy too high", glRule("a", "entropy = 8.5\n"), "between 0 and 8"},
	{"entropy negative", glRule("a", "entropy = -1\n"), "between 0 and 8"},
	{"entropy nan", glRule("a", "entropy = nan\n"), "between 0 and 8"},
	{"entropy inf", glRule("a", "entropy = inf\n"), "between 0 and 8"},
	{"entropy precision", glRule("a", "entropy = 3.14159\n"), "two decimals"},
	{"entropy string", glRule("a", "entropy = '3'\n"), "must be a number"},
	{"uppercase keyword", glRule("a", "keywords = ['Acme']\n"), "lowercase"},
	{"too many keywords", glRule("a", "keywords = ["+strings.Repeat("'k', ", 21)+"]\n"), "at most 20"},
	{"keyword twice", glRule("a", "keywords = ['k', 'k']\n"), "twice"},
	{"empty keyword", glRule("a", "keywords = ['']\n"), "empty entry"},
	{"keywords not strings", glRule("a", "keywords = [1]\n"), "list of strings"},
	{"keywords nested", glRule("a", "keywords = [['a']]\n"), "list of strings"},
	{"keywords inline table", glRule("a", "keywords = [{a = 'b'}]\n"), "list of strings"},
	{"too many tags", glRule("a", "tags = ["+strings.Repeat("'t', ", 11)+"]\n"), "at most 10"},
	{"long description", glRule("a", "description = '"+strings.Repeat("d", 501)+"'\n"), "limit is 500"},
	{"multiline description", glRule("a", "description = '''\nline\nline'''\n"), "control"},

	// Characters.
	{"bidi", glRule("a", "description = \"x\\u202Ey\"\n"), "bidirectional"},
	{"raw bidi in comment", "# \u2067\n" + glRule("a", ""), "bidirectional"},
	{"escaped control", glRule("a", "description = \"x\\u0007\"\n"), "control"},
	{"zero-width in keyword", glRule("a", "keywords = [\"ac\\u200Bme\"]\n"), "control"},
	{"invalid UTF-8", glRule("a", "description = 'x\xfe'\n"), "UTF-8"},
}

func TestGitleaksRefused(t *testing.T) {
	for _, c := range glRefused {
		t.Run(c.name, func(t *testing.T) {
			r, probs := rules.Parse(rules.Gitleaks, []byte(c.body))
			checkRefused(t, r, probs, c.want)
		})
	}
}

func TestGitleaksProblemPosition(t *testing.T) {
	_, probs := rules.Parse(rules.Gitleaks, []byte(glRule("a", "keywords = ['X']\n")))
	if len(probs) != 1 || probs[0].Line != 4 || probs[0].Column != 1 {
		t.Fatalf("got %+v", probs)
	}
	_, probs = rules.Parse(rules.Gitleaks, []byte(glRule("a", "")+"[allowlist]\n"))
	if len(probs) != 1 || probs[0].Line != 4 || probs[0].Column != 2 {
		t.Fatalf("got %+v", probs)
	}
	_, probs = rules.Parse(rules.Gitleaks, []byte(glRule("a", "x = = 1\n")))
	if len(probs) != 1 || probs[0].Line != 4 {
		t.Fatalf("got %+v", probs)
	}
}
