package rules

import (
	"bytes"
	"errors"
	"io"
	"regexp"
	"slices"
	"sort"
	"strconv"
	"strings"

	"go.yaml.in/yaml/v3"
)

// Limits of an Opengrep rule body. The YAML is walked as a yaml.Node tree, so
// anchors, aliases (billion laughs), merge keys and tags are seen and refused
// before anything is built from them.
const (
	ogMaxDepth     = 32
	ogMaxNodes     = 5000
	ogMaxMessage   = 2000
	ogMaxPattern   = 4000
	ogMaxRegex     = 1000
	ogMaxLanguages = 10
	ogMaxMetadata  = 20
	ogMaxMetaValue = 256
	ogMaxFocus     = 10
)

// ogLanguages are the language names Opengrep v1.30 accepts (`opengrep show
// supported-languages`), less "none".
var ogLanguages = []string{
	"apex", "bash", "c", "c#", "c++", "cairo", "circom", "clojure", "cpp", "crystal", "csharp",
	"dart", "docker", "dockerfile", "elixir", "ex", "generic", "go", "golang", "hack", "hcl",
	"html", "java", "javascript", "js", "json", "jsonnet", "julia", "kotlin", "kt", "lisp", "lua",
	"move_on_aptos", "move_on_sui", "ocaml", "php", "promql", "proto", "proto3", "protobuf", "py",
	"python", "python2", "python3", "ql", "r", "regex", "ruby", "rust", "scala", "scheme", "sh",
	"sol", "solidity", "swift", "terraform", "tf", "ts", "typescript", "vb", "vue", "xml", "yaml",
}

var ogSeverity = map[string]string{"ERROR": "high", "WARNING": "medium", "INFO": "low"}

// refusedKeys explains the keys people are most likely to try. Anything not
// accepted is refused; these just get a reason.
var refusedKeys = map[string]string{
	"fix":                     "org rules report findings; they can't rewrite code",
	"fix-regex":               "org rules report findings; they can't rewrite code",
	"paths":                   "org rules can't include or exclude files",
	"include":                 "org rules can't include or exclude files",
	"exclude":                 "org rules can't include or exclude files",
	"options":                 "org rules can't change the scanner's options",
	"min-version":             "org rules can't depend on the scanner's version",
	"max-version":             "org rules can't depend on the scanner's version",
	"join":                    "join rules read other rules' results",
	"extract":                 "extract rules change what other rules scan",
	"equivalences":            "equivalences change how patterns match",
	"metavariable-comparison": "metavariable-comparison evaluates expressions",
	"pattern-propagators":     "taint propagators are not supported in org rules",
}

var metavarRe = regexp.MustCompile(`^\$(\.\.\.)?[A-Z_][A-Z0-9_]{0,62}$`)

// opengrepRule is the accepted subset of an Opengrep rule.
type opengrepRule struct {
	ID, Message, Severity      string // Severity: ERROR, WARNING or INFO
	Languages                  []string
	Taint                      bool
	Formula                    *formula // search mode
	Sources, Sanitizers, Sinks []formula
	Metadata                   [][2]string // sorted by key
}

// formula is one pattern operator. Op says which fields are set.
type formula struct {
	Op       string
	Text     string    // pattern, pattern-not, pattern-inside, pattern-not-inside, pattern-regex, pattern-not-regex
	List     []formula // patterns, pattern-either
	Metavar  string    // metavariable-regex, metavariable-pattern
	Regex    string    // metavariable-regex
	Language string    // metavariable-pattern (optional)
	Sub      *formula  // metavariable-pattern
	Focus    []string  // focus-metavariable
}

func (r opengrepRule) severity() string { return ogSeverity[r.Severity] }

// Where each operator may appear. Negations, metavariable conditions and
// focus only narrow a conjunction (patterns:); they can't stand alone.
var (
	opsTop      = []string{"pattern", "patterns", "pattern-either", "pattern-regex"}
	opsEither   = opsTop
	opsTaint    = opsTop
	opsPatterns = []string{
		"pattern", "patterns", "pattern-either", "pattern-regex",
		"pattern-not", "pattern-inside", "pattern-not-inside", "pattern-not-regex",
		"metavariable-regex", "metavariable-pattern", "focus-metavariable",
	}
	opsPositive = []string{"pattern", "patterns", "pattern-either", "pattern-regex", "pattern-inside"}
)

func parseOpengrep(p *problems, body []byte) (r opengrepRule, ok bool) {
	root := decodeYAML(p, body)
	if root == nil || !checkTree(p, root) {
		return r, false
	}
	top := root.Content[0]
	if top.Kind != yaml.MappingNode {
		p.add(top.Line, top.Column, "the rule must be a mapping with a top-level \"rules\" list")
		return r, false
	}
	var list *yaml.Node
	for i := 0; i < len(top.Content); i += 2 {
		k, v := top.Content[i], top.Content[i+1]
		if k.Value != "rules" {
			p.add(k.Line, k.Column, "%s is not allowed at the top level; only \"rules\"", qk(k.Value))
			continue
		}
		list = v
	}
	if list == nil {
		if len(p.list) == 0 {
			p.add(top.Line, top.Column, "missing \"rules\"")
		}
		return r, false
	}
	if list.Kind != yaml.SequenceNode || len(list.Content) != 1 {
		p.add(list.Line, list.Column, "\"rules\" must be a list of exactly one rule")
		return r, false
	}
	return parseOgRule(p, list.Content[0])
}

func parseOgRule(p *problems, n *yaml.Node) (r opengrepRule, ok bool) {
	if n.Kind != yaml.MappingNode {
		p.add(n.Line, n.Column, "a rule must be a mapping")
		return r, false
	}
	fields := map[string]*yaml.Node{}
	var keys []*yaml.Node
	for i := 0; i < len(n.Content); i += 2 {
		k := n.Content[i]
		fields[k.Value] = n.Content[i+1]
		keys = append(keys, k)
	}
	for _, k := range keys {
		switch name := k.Value; {
		case slices.Contains([]string{"id", "message", "severity", "languages", "mode", "metadata",
			"pattern-sources", "pattern-sinks", "pattern-sanitizers"}, name), slices.Contains(opsTop, name):
		default:
			refuseKey(p, k, "in a rule")
		}
	}
	for _, req := range []string{"id", "message", "severity", "languages"} {
		if fields[req] == nil {
			p.add(n.Line, n.Column, "missing %q", req)
		}
	}
	if v := fields["id"]; v != nil {
		if s, ok := str(p, v, "id"); ok && checkKey(p, v.Line, v.Column, s) {
			r.ID = s
		}
	}
	if v := fields["message"]; v != nil {
		if s, ok := str(p, v, "message"); ok && checkText(p, v.Line, v.Column, "message", s, ogMaxMessage, true) {
			if strings.TrimSpace(s) == "" {
				p.add(v.Line, v.Column, "message is empty")
			}
			// Opengrep fills $X (and $1, $...X) in the message with the code it
			// matched, so a message could carry the very secret a rule finds
			// into issue titles, emails and webhooks. Gitleaks is the only
			// scanner whose output is redacted; org rules get no interpolation.
			if strings.Contains(s, "$") {
				p.add(v.Line, v.Column, "message can't contain $: Opengrep would fill metavariables with the matched code")
			}
			r.Message = s
		}
	}
	if v := fields["severity"]; v != nil {
		if s, ok := str(p, v, "severity"); ok {
			if ogSeverity[s] == "" {
				p.add(v.Line, v.Column, "severity must be ERROR, WARNING or INFO")
			}
			r.Severity = s
		}
	}
	if v := fields["languages"]; v != nil {
		r.Languages = parseLanguages(p, v)
	}
	if v := fields["mode"]; v != nil {
		if s, ok := str(p, v, "mode"); ok {
			switch s {
			case "search":
			case "taint":
				r.Taint = true
			default:
				p.add(v.Line, v.Column, "mode must be search or taint")
			}
		}
	}
	var formulaKeys []*yaml.Node
	for _, k := range keys {
		if slices.Contains(opsTop, k.Value) {
			formulaKeys = append(formulaKeys, k)
		}
	}
	if r.Taint {
		for _, k := range formulaKeys {
			p.add(k.Line, k.Column, "a taint rule takes pattern-sources and pattern-sinks, not %q", k.Value)
		}
		for _, x := range []struct {
			key      string
			dst      *[]formula
			required bool
		}{{"pattern-sources", &r.Sources, true}, {"pattern-sanitizers", &r.Sanitizers, false}, {"pattern-sinks", &r.Sinks, true}} {
			v := fields[x.key]
			if v == nil {
				if x.required {
					p.add(n.Line, n.Column, "a taint rule needs %q", x.key)
				}
				continue
			}
			*x.dst = parseFormulaList(p, v, x.key, opsTaint, 0)
		}
	} else {
		for _, key := range []string{"pattern-sources", "pattern-sinks", "pattern-sanitizers"} {
			if v := fields[key]; v != nil {
				p.add(v.Line, v.Column, "%q needs mode: taint", key)
			}
		}
		switch len(formulaKeys) {
		case 0:
			p.add(n.Line, n.Column, "a rule needs one of pattern, patterns, pattern-either or pattern-regex")
		case 1:
			k := formulaKeys[0]
			r.Formula = parseOp(p, k, fields[k.Value], 0)
		default:
			k := formulaKeys[1]
			p.add(k.Line, k.Column, "a rule takes only one of pattern, patterns, pattern-either or pattern-regex")
		}
	}
	if v := fields["metadata"]; v != nil {
		r.Metadata = parseMetadata(p, v)
	}
	return r, len(p.list) == 0
}

func parseLanguages(p *problems, v *yaml.Node) []string {
	if v.Kind != yaml.SequenceNode || len(v.Content) == 0 {
		p.add(v.Line, v.Column, "languages must be a non-empty list")
		return nil
	}
	if len(v.Content) > ogMaxLanguages {
		p.add(v.Line, v.Column, "at most %d languages", ogMaxLanguages)
		return nil
	}
	var out []string
	for _, e := range v.Content {
		s, ok := str(p, e, "a language")
		if !ok {
			continue
		}
		switch {
		case !slices.Contains(ogLanguages, s):
			p.add(e.Line, e.Column, "unknown language %s", qk(s))
		case slices.Contains(out, s):
			p.add(e.Line, e.Column, "language %q is listed twice", s)
		default:
			out = append(out, s)
		}
	}
	return out
}

func parseMetadata(p *problems, v *yaml.Node) [][2]string {
	if v.Kind != yaml.MappingNode {
		p.add(v.Line, v.Column, "metadata must be a mapping of names to strings")
		return nil
	}
	if len(v.Content)/2 > ogMaxMetadata {
		p.add(v.Line, v.Column, "at most %d metadata entries", ogMaxMetadata)
		return nil
	}
	var out [][2]string
	for i := 0; i < len(v.Content); i += 2 {
		k, val := v.Content[i], v.Content[i+1]
		switch {
		case !keyRe.MatchString(k.Value):
			p.add(k.Line, k.Column, "metadata name %s must be 1-64 characters of a-z, 0-9, '.', '_' or '-'", qk(k.Value))
			continue
		// Opengrep copies metadata into its SARIF, and Warden reads
		// security-severity from there: it would override the rule's severity.
		case k.Value == "security-severity", k.Value == "interfile",
			strings.HasPrefix(k.Value, "semgrep"), strings.HasPrefix(k.Value, "opengrep"),
			strings.HasPrefix(k.Value, "dev."), strings.HasPrefix(k.Value, "r2c"):
			p.add(k.Line, k.Column, "metadata %q is reserved", k.Value)
			continue
		}
		if val.Kind != yaml.ScalarNode || !slices.Contains([]string{"!!str", "!!int", "!!float", "!!bool"}, val.Tag) {
			p.add(val.Line, val.Column, "metadata %q must be a string", k.Value)
			continue
		}
		if !checkText(p, val.Line, val.Column, "metadata "+k.Value, val.Value, ogMaxMetaValue, false) {
			continue
		}
		out = append(out, [2]string{k.Value, val.Value})
	}
	sort.Slice(out, func(i, j int) bool { return out[i][0] < out[j][0] })
	return out
}

// parseFormulaList: a list of one-key mappings, each an operator from ops.
func parseFormulaList(p *problems, v *yaml.Node, what string, ops []string, depth int) []formula {
	if v.Kind != yaml.SequenceNode || len(v.Content) == 0 {
		p.add(v.Line, v.Column, "%s must be a non-empty list", what)
		return nil
	}
	var out []formula
	for _, e := range v.Content {
		if e.Kind != yaml.MappingNode || len(e.Content) != 2 {
			p.add(e.Line, e.Column, "each item of %s must be a mapping with one operator", what)
			continue
		}
		k := e.Content[0]
		if !slices.Contains(ops, k.Value) {
			refuseKey(p, k, "in "+what)
			continue
		}
		if f := parseOp(p, k, e.Content[1], depth+1); f != nil {
			out = append(out, *f)
		}
	}
	return out
}

func parseOp(p *problems, k, v *yaml.Node, depth int) *formula {
	f := &formula{Op: k.Value}
	switch k.Value {
	case "pattern", "pattern-not", "pattern-inside", "pattern-not-inside":
		s, ok := str(p, v, k.Value)
		if !ok || !checkText(p, v.Line, v.Column, k.Value, s, ogMaxPattern, true) {
			return nil
		}
		if strings.TrimSpace(s) == "" {
			p.add(v.Line, v.Column, "%s is empty", k.Value)
			return nil
		}
		f.Text = s
	case "pattern-regex", "pattern-not-regex":
		s, ok := str(p, v, k.Value)
		if !ok || !checkRegex(p, v.Line, v.Column, k.Value, s, ogMaxRegex, true, k.Value == "pattern-regex") {
			return nil
		}
		f.Text = s
	case "patterns":
		f.List = parseFormulaList(p, v, "patterns", opsPatterns, depth)
		if len(f.List) > 0 && !slices.ContainsFunc(f.List, func(x formula) bool { return slices.Contains(opsPositive, x.Op) }) {
			p.add(v.Line, v.Column, "patterns needs at least one of pattern, patterns, pattern-either, pattern-regex or pattern-inside")
		}
	case "pattern-either":
		f.List = parseFormulaList(p, v, "pattern-either", opsEither, depth)
	case "metavariable-regex", "metavariable-pattern":
		if !parseMetavarOp(p, f, v, depth) {
			return nil
		}
	case "focus-metavariable":
		items := []*yaml.Node{v}
		if v.Kind == yaml.SequenceNode {
			items = v.Content
			if len(items) == 0 || len(items) > ogMaxFocus {
				p.add(v.Line, v.Column, "focus-metavariable takes 1-%d metavariables", ogMaxFocus)
				return nil
			}
		}
		for _, e := range items {
			if m, ok := metavar(p, e, "focus-metavariable"); ok {
				f.Focus = append(f.Focus, m)
			}
		}
	default:
		refuseKey(p, k, "here")
		return nil
	}
	return f
}

func parseMetavarOp(p *problems, f *formula, v *yaml.Node, depth int) bool {
	if v.Kind != yaml.MappingNode {
		p.add(v.Line, v.Column, "%s must be a mapping", f.Op)
		return false
	}
	ok := true
	var sub []*yaml.Node
	for i := 0; i < len(v.Content); i += 2 {
		k, val := v.Content[i], v.Content[i+1]
		switch {
		case k.Value == "metavariable":
			m, good := metavar(p, val, "metavariable")
			ok = ok && good
			f.Metavar = m
		case k.Value == "regex" && f.Op == "metavariable-regex":
			s, good := str(p, val, "regex")
			if good && checkRegex(p, val.Line, val.Column, "regex", s, ogMaxRegex, true, false) {
				f.Regex = s
			} else {
				ok = false
			}
		case k.Value == "language" && f.Op == "metavariable-pattern":
			s, good := str(p, val, "language")
			if good && !slices.Contains(ogLanguages, s) {
				p.add(val.Line, val.Column, "unknown language %s", qk(s))
				good = false
			}
			ok = ok && good
			f.Language = s
		case f.Op == "metavariable-pattern" && slices.Contains(opsTop, k.Value):
			sub = append(sub, k, val)
		default:
			refuseKey(p, k, "in "+f.Op)
			ok = false
		}
	}
	if f.Metavar == "" && ok {
		p.add(v.Line, v.Column, "%s needs metavariable", f.Op)
		ok = false
	}
	switch f.Op {
	case "metavariable-regex":
		if f.Regex == "" && ok {
			p.add(v.Line, v.Column, "metavariable-regex needs regex")
			ok = false
		}
	case "metavariable-pattern":
		if len(sub) != 2 {
			p.add(v.Line, v.Column, "metavariable-pattern needs exactly one of pattern, patterns, pattern-either or pattern-regex")
			return false
		}
		f.Sub = parseOp(p, sub[0], sub[1], depth+1)
		ok = ok && f.Sub != nil
	}
	return ok
}

func metavar(p *problems, v *yaml.Node, what string) (string, bool) {
	s, ok := str(p, v, what)
	if ok && !metavarRe.MatchString(s) {
		p.add(v.Line, v.Column, "%s must be a metavariable like $X", what)
		return "", false
	}
	return s, ok
}

func str(p *problems, v *yaml.Node, what string) (string, bool) {
	if v.Kind != yaml.ScalarNode || v.Tag != "!!str" {
		p.add(v.Line, v.Column, "%s must be a string", what)
		return "", false
	}
	return v.Value, true
}

func refuseKey(p *problems, k *yaml.Node, where string) {
	if why, ok := refusedKeys[k.Value]; ok {
		p.add(k.Line, k.Column, "%q is not allowed: %s", k.Value, why)
		return
	}
	if strings.HasPrefix(k.Value, "r2c-internal") {
		p.add(k.Line, k.Column, "%s is not allowed: internal scanner keys are refused", qk(k.Value))
		return
	}
	p.add(k.Line, k.Column, "%s is not allowed %s", qk(k.Value), where)
}

// qk quotes a name from the body for a message, shortened.
func qk(s string) string {
	if r := []rune(s); len(r) > 64 {
		s = string(r[:64]) + "…"
	}
	return strconv.Quote(s)
}

var yamlLineRe = regexp.MustCompile(`^yaml: line (\d+): `)

// decodeYAML returns the single document's node, or nil with problems.
func decodeYAML(p *problems, body []byte) (doc *yaml.Node) {
	defer func() {
		// The decoder is third-party code fed hostile input; a panic there
		// is a refused body, not a crashed API.
		if recover() != nil {
			p.add(0, 0, "the rule is not valid YAML")
			doc = nil
		}
	}()
	dec := yaml.NewDecoder(bytes.NewReader(body))
	var n yaml.Node
	if err := dec.Decode(&n); err != nil {
		if errors.Is(err, io.EOF) {
			p.add(0, 0, "the rule is empty")
		} else {
			yamlProblem(p, err)
		}
		return nil
	}
	var extra yaml.Node
	if err := dec.Decode(&extra); !errors.Is(err, io.EOF) {
		line := extra.Line
		p.add(line, 0, "the rule must be a single YAML document")
		return nil
	}
	if n.Kind != yaml.DocumentNode || len(n.Content) != 1 {
		p.add(0, 0, "the rule is empty")
		return nil
	}
	return &n
}

func yamlProblem(p *problems, err error) {
	msg := err.Error()
	line := 0
	if m := yamlLineRe.FindStringSubmatch(msg); m != nil {
		for _, c := range m[1] {
			line = line*10 + int(c-'0')
			if line > 1<<20 {
				break
			}
		}
		msg = msg[len(m[0]):]
	} else {
		msg = strings.TrimPrefix(msg, "yaml: ")
	}
	if r := []rune(msg); len(r) > 200 {
		msg = string(r[:200]) + "…"
	}
	p.add(line, 0, "invalid YAML: %s", msg)
}

// checkTree refuses YAML features a rule doesn't need and that would make
// what's stored differ from what was read: anchors, aliases, merge keys, tags,
// keys that aren't plain strings, duplicate keys. It bounds depth and size,
// and checks every string for control and bidi characters.
func checkTree(p *problems, doc *yaml.Node) bool {
	type item struct {
		n     *yaml.Node
		depth int
	}
	stack := []item{{doc, 0}}
	count := 0
	before := len(p.list)
	for len(stack) > 0 && len(p.list) < maxProblems {
		it := stack[len(stack)-1]
		stack = stack[:len(stack)-1]
		n := it.n
		if count++; count > ogMaxNodes {
			p.add(0, 0, "the rule has more than %d YAML nodes", ogMaxNodes)
			return false
		}
		if it.depth > ogMaxDepth {
			p.add(n.Line, n.Column, "the rule is nested more than %d levels deep", ogMaxDepth)
			return false
		}
		switch {
		case n.Kind == yaml.AliasNode:
			p.add(n.Line, n.Column, "YAML aliases are not allowed")
			continue
		case n.Anchor != "":
			p.add(n.Line, n.Column, "YAML anchors are not allowed")
		case n.Style&yaml.TaggedStyle != 0:
			p.add(n.Line, n.Column, "YAML tags are not allowed")
		}
		switch n.Kind {
		case yaml.ScalarNode:
			checkText(p, n.Line, n.Column, "a value", n.Value, MaxBodyBytes, true)
		case yaml.MappingNode:
			seen := map[string]bool{}
			for i := 0; i+1 < len(n.Content); i += 2 {
				k := n.Content[i]
				switch {
				case k.Kind == yaml.ScalarNode && k.Tag == "!!merge":
					p.add(k.Line, k.Column, "YAML merge keys (<<) are not allowed")
					continue
				case k.Kind != yaml.ScalarNode || k.Tag != "!!str":
					p.add(k.Line, k.Column, "keys must be plain strings")
					continue
				case seen[k.Value]:
					p.add(k.Line, k.Column, "duplicate key %s", qk(k.Value))
				}
				seen[k.Value] = true
			}
		}
		for i := len(n.Content) - 1; i >= 0; i-- {
			stack = append(stack, item{n.Content[i], it.depth + 1})
		}
	}
	return len(p.list) == before
}

// canonical renders the rule as Warden stores and shows it, with its own id.
func (r opengrepRule) canonical() []byte {
	b, err := encodeYAML(mapping("rules", seq(r.node(r.ID))))
	if err != nil {
		// Every string was checked; the encoder has nothing to refuse.
		panic("rules: encoding a parsed Opengrep rule: " + err.Error())
	}
	return b
}

func renderOpengrep(rules []opengrepRule) ([]byte, error) {
	list := seq()
	for _, r := range rules {
		list.Content = append(list.Content, r.node(Prefix+r.ID))
	}
	return encodeYAML(mapping("rules", list))
}

func encodeYAML(n *yaml.Node) ([]byte, error) {
	var buf bytes.Buffer
	enc := yaml.NewEncoder(&buf)
	enc.SetIndent(2)
	if err := enc.Encode(n); err != nil {
		return nil, err
	}
	if err := enc.Close(); err != nil {
		return nil, err
	}
	return buf.Bytes(), nil
}

// node is the rule in a fixed key order, with id set to id.
func (r opengrepRule) node(id string) *yaml.Node {
	m := mapping("id", scalar(id), "message", scalar(r.Message), "severity", scalar(r.Severity))
	langs := seq()
	langs.Style = yaml.FlowStyle
	for _, l := range r.Languages {
		langs.Content = append(langs.Content, scalar(l))
	}
	add(m, "languages", langs)
	if r.Taint {
		add(m, "mode", scalar("taint"))
		add(m, "pattern-sources", formulaSeq(r.Sources))
		if len(r.Sanitizers) > 0 {
			add(m, "pattern-sanitizers", formulaSeq(r.Sanitizers))
		}
		add(m, "pattern-sinks", formulaSeq(r.Sinks))
	} else {
		add(m, r.Formula.Op, r.Formula.value())
	}
	if len(r.Metadata) > 0 {
		md := mapping()
		for _, kv := range r.Metadata {
			add(md, kv[0], scalar(kv[1]))
		}
		add(m, "metadata", md)
	}
	return m
}

func (f formula) value() *yaml.Node {
	switch f.Op {
	case "patterns", "pattern-either":
		return formulaSeq(f.List)
	case "metavariable-regex":
		return mapping("metavariable", scalar(f.Metavar), "regex", scalar(f.Regex))
	case "metavariable-pattern":
		m := mapping("metavariable", scalar(f.Metavar))
		if f.Language != "" {
			add(m, "language", scalar(f.Language))
		}
		add(m, f.Sub.Op, f.Sub.value())
		return m
	case "focus-metavariable":
		if len(f.Focus) == 1 {
			return scalar(f.Focus[0])
		}
		s := seq()
		for _, x := range f.Focus {
			s.Content = append(s.Content, scalar(x))
		}
		return s
	}
	return scalar(f.Text)
}

func formulaSeq(fs []formula) *yaml.Node {
	s := seq()
	for _, f := range fs {
		s.Content = append(s.Content, mapping(f.Op, f.value()))
	}
	return s
}

// scalar is a string node. The encoder quotes what YAML 1.2 would read as
// another type; Opengrep's YAML reader may follow YAML 1.1, so a string 1.1
// would read as a boolean, null or number (yes, off, ~, 1:30, .5) is
// double-quoted too.
func scalar(s string) *yaml.Node {
	n := &yaml.Node{Kind: yaml.ScalarNode, Tag: "!!str", Value: s}
	if yaml11Ambiguous(s) {
		n.Style = yaml.DoubleQuotedStyle
	}
	return n
}

var yaml11Words = []string{
	"y", "yes", "n", "no", "true", "false", "on", "off", "null", "~", "=", "<<",
	".inf", "-.inf", "+.inf", ".nan",
}

func yaml11Ambiguous(s string) bool {
	if s == "" || slices.Contains(yaml11Words, strings.ToLower(s)) {
		return true
	}
	switch s[0] {
	case '0', '1', '2', '3', '4', '5', '6', '7', '8', '9', '+', '-', '.':
		return true
	}
	return false
}

func seq(items ...*yaml.Node) *yaml.Node {
	return &yaml.Node{Kind: yaml.SequenceNode, Tag: "!!seq", Content: items}
}

// mapping takes alternating keys (string) and values (*yaml.Node).
func mapping(kv ...any) *yaml.Node {
	m := &yaml.Node{Kind: yaml.MappingNode, Tag: "!!map"}
	for i := 0; i+1 < len(kv); i += 2 {
		add(m, kv[i].(string), kv[i+1].(*yaml.Node))
	}
	return m
}

func add(m *yaml.Node, key string, v *yaml.Node) {
	m.Content = append(m.Content, scalar(key), v)
}
