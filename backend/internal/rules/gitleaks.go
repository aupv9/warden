package rules

import (
	"errors"
	"math"
	"regexp"
	"slices"
	"strconv"
	"strings"

	"github.com/pelletier/go-toml/v2"
	"github.com/pelletier/go-toml/v2/unstable"
)

const (
	glMaxDescription = 500
	glMaxRegex       = 2000
	glMaxPathRegex   = 1000
	glMaxKeywords    = 20
	glMaxKeyword     = 64
	glMaxTags        = 10
	glMaxTag         = 64
)

// gitleaksRule is the accepted subset of a Gitleaks [[rules]] table. Severity
// is always high (severity.Gitleaks for an id starting with Prefix).
type gitleaksRule struct {
	ID, Description, Regex, Path string
	SecretGroup                  int
	Entropy                      float64
	Keywords, Tags               []string
}

var glKeys = []string{"id", "description", "regex", "secretGroup", "entropy", "keywords", "path", "tags"}

var glRefused = map[string]string{
	"allowlist":     "org rules can't allow-list findings",
	"allowlists":    "org rules can't allow-list findings",
	"extend":        "org rules can't change which configuration Gitleaks loads",
	"useDefault":    "org rules can't change which configuration Gitleaks loads",
	"title":         "an org rule is only its [[rules]] table",
	"minVersion":    "org rules can't depend on the scanner's version",
	"skipReport":    "org rules must report what they find",
	"required":      "composite rules read other rules' results",
	"disabledRules": "org rules can't disable rules",
}

// glPos is where a key was written, for problems about its value.
type glPos struct{ line, col int }

func parseGitleaks(p *problems, body []byte) (r gitleaksRule, ok bool) {
	defer func() {
		// The TOML parser is third-party code fed hostile input.
		if recover() != nil {
			p.add(0, 0, "the rule is not valid TOML")
			ok = false
		}
	}()
	// A full decode first: the TOML spec (duplicate keys, redefined tables,
	// bad escapes) is the library's job, with positions.
	var doc map[string]any
	if err := toml.Unmarshal(body, &doc); err != nil {
		var de *toml.DecodeError
		if errors.As(err, &de) {
			line, col := de.Position()
			p.add(line, col, "invalid TOML: %s", shorten(strings.TrimPrefix(de.Error(), "toml: ")))
		} else {
			p.add(0, 0, "the rule is not valid TOML")
		}
		return r, false
	}
	pos, ok := glStructure(p, body)
	if !ok {
		return r, false
	}
	var t map[string]any
	switch rs := doc["rules"].(type) {
	case []any:
		if len(rs) == 1 {
			t, _ = rs[0].(map[string]any)
		}
	case []map[string]any:
		if len(rs) == 1 {
			t = rs[0]
		}
	}
	if t == nil { // glStructure saw exactly one [[rules]]
		p.add(0, 0, "the rule must be exactly one [[rules]] table")
		return r, false
	}
	at := func(k string) (int, int) { return pos[k].line, pos[k].col }

	id, _ := t["id"].(string)
	if _, ok := t["id"]; !ok {
		p.add(0, 0, "missing \"id\"")
	} else if l, c := at("id"); checkKey(p, l, c, id) {
		r.ID = id
	}
	if d, ok := t["description"].(string); ok {
		l, c := at("description")
		if checkText(p, l, c, "description", d, glMaxDescription, false) {
			r.Description = d
		}
	}
	if re, ok := t["regex"].(string); !ok {
		p.add(0, 0, "missing \"regex\"")
	} else if l, c := at("regex"); checkRegex(p, l, c, "regex", re, glMaxRegex, false, true) {
		r.Regex = re
	}
	if v, ok := t["secretGroup"].(int64); ok {
		l, c := at("secretGroup")
		groups := -1
		if r.Regex != "" {
			groups = regexp.MustCompile(r.Regex).NumSubexp()
		}
		switch {
		case v < 0 || (groups >= 0 && v > int64(groups)):
			p.add(l, c, "secretGroup must be between 0 and the regex's %d groups", max(groups, 0))
		default:
			r.SecretGroup = int(v)
		}
	}
	if v, ok := t["entropy"]; ok {
		l, c := at("entropy")
		var e float64
		switch x := v.(type) {
		case int64:
			e = float64(x)
		case float64:
			e = x
		}
		switch {
		case !(e >= 0 && e <= 8):
			p.add(l, c, "entropy must be between 0 and 8")
		case math.Round(e*100)/100 != e:
			p.add(l, c, "entropy takes at most two decimals")
		default:
			r.Entropy = e
		}
	}
	r.Keywords = glStrings(p, t, pos, "keywords", glMaxKeywords, glMaxKeyword, true)
	if s, ok := t["path"].(string); ok {
		l, c := at("path")
		if checkRegex(p, l, c, "path", s, glMaxPathRegex, false, false) {
			r.Path = s
		}
	}
	r.Tags = glStrings(p, t, pos, "tags", glMaxTags, glMaxTag, false)
	return r, len(p.list) == 0
}

func glStrings(p *problems, t map[string]any, pos map[string]glPos, key string, maxN, maxLen int, lower bool) []string {
	v, ok := t[key].([]any)
	if !ok {
		return nil
	}
	l, c := pos[key].line, pos[key].col
	if len(v) > maxN {
		p.add(l, c, "at most %d %s", maxN, key)
		return nil
	}
	var out []string
	for _, e := range v {
		s, _ := e.(string) // glStructure checked the element kinds
		switch {
		case !checkText(p, l, c, key, s, maxLen, false):
		case strings.TrimSpace(s) == "":
			p.add(l, c, "%s has an empty entry", key)
		// Gitleaks compares keywords with lowercased text: an uppercase
		// keyword would never match, and the rule would never run.
		case lower && strings.ToLower(s) != s:
			p.add(l, c, "keywords must be lowercase")
		case slices.Contains(out, s):
			p.add(l, c, "%s lists %q twice", key, s)
		default:
			out = append(out, s)
		}
	}
	return out
}

// glStructure walks the document's expressions: one [[rules]] header, then
// only the accepted keys with values of the right kind. It returns where
// each key was written.
func glStructure(p *problems, body []byte) (map[string]glPos, bool) {
	var ps unstable.Parser
	ps.Reset(body)
	pos := map[string]glPos{}
	headers := 0
	where := func(n *unstable.Node) (int, int) {
		s := ps.Shape(n.Raw)
		return s.Start.Line, s.Start.Column
	}
	for ps.NextExpression() && len(p.list) < maxProblems {
		e := ps.Expression()
		var parts []string
		var first *unstable.Node
		for it := e.Key(); it.Next(); {
			if first == nil {
				first = it.Node()
			}
			parts = append(parts, string(it.Node().Data))
		}
		if first == nil {
			p.add(0, 0, "the rule is not valid TOML")
			return nil, false
		}
		line, col := where(first)
		name := strings.Join(parts, ".")
		switch e.Kind {
		case unstable.ArrayTable:
			if name != "rules" {
				glRefuse(p, line, col, parts, "["+"["+name+"]]")
				continue
			}
			if headers++; headers > 1 {
				p.add(line, col, "the rule must be exactly one [[rules]] table")
			}
			continue
		case unstable.Table:
			glRefuse(p, line, col, parts, "["+name+"]")
			continue
		case unstable.KeyValue:
		default:
			p.add(line, col, "the rule is not valid TOML")
			return nil, false
		}
		if headers == 0 {
			if name == "rules" {
				p.add(line, col, "write the rule as a [[rules]] table")
			} else {
				glRefuse(p, line, col, parts, qk(name)+" at the top level")
			}
			continue
		}
		if len(parts) != 1 || !slices.Contains(glKeys, parts[0]) {
			glRefuse(p, line, col, parts, qk(name)+" in [[rules]]")
			continue
		}
		pos[name] = glPos{line, col}
		v := e.Value()
		var want string
		switch name {
		case "secretGroup":
			if v.Kind != unstable.Integer {
				want = "an integer"
			}
		case "entropy":
			if v.Kind != unstable.Integer && v.Kind != unstable.Float {
				want = "a number"
			}
		case "keywords", "tags":
			if v.Kind != unstable.Array {
				want = "a list of strings"
				break
			}
			for it := v.Children(); it.Next(); {
				if it.Node().Kind != unstable.String {
					want = "a list of strings"
				}
			}
		default:
			if v.Kind != unstable.String {
				want = "a string"
			}
		}
		if want != "" {
			p.add(line, col, "%s must be %s", name, want)
		}
	}
	if err := ps.Error(); err != nil {
		p.add(0, 0, "the rule is not valid TOML")
		return nil, false
	}
	if headers == 0 && len(p.list) == 0 {
		p.add(1, 1, "the rule must be one [[rules]] table")
	}
	return pos, len(p.list) == 0
}

func glRefuse(p *problems, line, col int, parts []string, what string) {
	for _, part := range parts {
		if why, ok := glRefused[part]; ok {
			p.add(line, col, "%s is not allowed: %s", what, why)
			return
		}
	}
	p.add(line, col, "%s is not allowed", what)
}

func shorten(s string) string {
	if r := []rune(s); len(r) > 200 {
		return string(r[:200]) + "…"
	}
	return s
}

func (r gitleaksRule) canonical() []byte { return []byte(r.toml(r.ID)) }

func renderGitleaks(rules []gitleaksRule) []byte {
	var b strings.Builder
	for i, r := range rules {
		if i > 0 {
			b.WriteByte('\n')
		}
		b.WriteString(r.toml(Prefix + r.ID))
	}
	return []byte(b.String())
}

// toml writes the rule's table in a fixed key order, with id set to id.
func (r gitleaksRule) toml(id string) string {
	var b strings.Builder
	line := func(k, v string) { b.WriteString(k + " = " + v + "\n") }
	b.WriteString("[[rules]]\n")
	line("id", tomlString(id))
	if r.Description != "" {
		line("description", tomlString(r.Description))
	}
	line("regex", tomlString(r.Regex))
	if r.SecretGroup > 0 {
		line("secretGroup", strconv.Itoa(r.SecretGroup))
	}
	if r.Entropy > 0 {
		e := strconv.FormatFloat(r.Entropy, 'f', -1, 64)
		if !strings.Contains(e, ".") {
			e += ".0"
		}
		line("entropy", e)
	}
	if len(r.Keywords) > 0 {
		line("keywords", tomlList(r.Keywords))
	}
	if r.Path != "" {
		line("path", tomlString(r.Path))
	}
	if len(r.Tags) > 0 {
		line("tags", tomlList(r.Tags))
	}
	return b.String()
}

func tomlList(ss []string) string {
	q := make([]string, len(ss))
	for i, s := range ss {
		q[i] = tomlString(s)
	}
	return "[" + strings.Join(q, ", ") + "]"
}

// tomlString is a literal string ('...', no escapes: readable regexes) when
// it can be, else a basic string with every special character escaped.
func tomlString(s string) string {
	if !strings.ContainsAny(s, "'\t") {
		return "'" + s + "'"
	}
	var b strings.Builder
	b.WriteByte('"')
	for _, c := range s {
		switch c {
		case '"':
			b.WriteString(`\"`)
		case '\\':
			b.WriteString(`\\`)
		case '\t':
			b.WriteString(`\t`)
		default:
			b.WriteRune(c)
		}
	}
	b.WriteByte('"')
	return b.String()
}
