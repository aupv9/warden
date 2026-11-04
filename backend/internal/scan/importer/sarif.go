package importer

import (
	"bytes"
	"encoding/json"
	"errors"
	"net/url"
	"regexp"
	"strconv"
	"strings"

	"github.com/aupv9/warden/backend/internal/domain/severity"
)

// srcRoot is the only uriBaseId a SARIF path may be relative to: the source
// root (CodeQL, GitHub). Any other base names a place Warden can't resolve.
const srcRoot = "%SRCROOT%"

type sarifLog struct {
	Schema  json.RawMessage `json:"$schema"`
	Version json.RawMessage `json:"version"`
	Runs    json.RawMessage `json:"runs"`
}

type sarifRun struct {
	Tool struct {
		Driver     json.RawMessage `json:"driver"`
		Extensions json.RawMessage `json:"extensions"`
	} `json:"tool"`
	Results            json.RawMessage `json:"results"`
	OriginalURIBaseIDs json.RawMessage `json:"originalUriBaseIds"`
}

type sarifComponent struct {
	Version         string          `json:"version"`
	SemanticVersion string          `json:"semanticVersion"`
	Rules           json.RawMessage `json:"rules"`
}

// sarifText is a SARIF message or multiformatMessageString: only the plain
// text is read, never markdown (it would be rendered).
type sarifText struct {
	Text string `json:"text"`
}

type sarifRule struct {
	ID                   string    `json:"id"`
	ShortDescription     sarifText `json:"shortDescription"`
	FullDescription      sarifText `json:"fullDescription"`
	Help                 sarifText `json:"help"`
	DefaultConfiguration struct {
		Level string `json:"level"`
	} `json:"defaultConfiguration"`
	Properties struct {
		Tags             json.RawMessage `json:"tags"`
		SecuritySeverity json.RawMessage `json:"security-severity"`
	} `json:"properties"`
}

type sarifResult struct {
	RuleID    string          `json:"ruleId"`
	RuleIndex json.RawMessage `json:"ruleIndex"`
	Rule      struct {
		ID            string          `json:"id"`
		Index         json.RawMessage `json:"index"`
		ToolComponent struct {
			Index json.RawMessage `json:"index"`
		} `json:"toolComponent"`
	} `json:"rule"`
	Kind                string          `json:"kind"`
	Level               string          `json:"level"`
	BaselineState       string          `json:"baselineState"`
	Suppressions        json.RawMessage `json:"suppressions"`
	Message             sarifText       `json:"message"`
	Locations           json.RawMessage `json:"locations"`
	PartialFingerprints json.RawMessage `json:"partialFingerprints"`
	Properties          struct {
		SecuritySeverity json.RawMessage `json:"security-severity"`
	} `json:"properties"`
}

type sarifArtifactLocation struct {
	URI       string `json:"uri"`
	URIBaseID string `json:"uriBaseId"`
}

type sarifLocation struct {
	PhysicalLocation struct {
		ArtifactLocation sarifArtifactLocation `json:"artifactLocation"`
		Region           struct {
			StartLine json.RawMessage `json:"startLine"`
			EndLine   json.RawMessage `json:"endLine"`
		} `json:"region"`
	} `json:"physicalLocation"`
}

// ruleInfo is what Warden keeps of a rule, cleaned and capped.
type ruleInfo struct {
	id, title, description, help, level string
	securitySeverity                    *float64
	cwe                                 []string
}

// runRules are a run's rules: the driver's and each extension's by index
// (results point at them with ruleIndex, rule.index and
// rule.toolComponent.index), and all of them by id (first wins).
type runRules struct {
	driver []*ruleInfo
	ext    [][]*ruleInfo
	byID   map[string]*ruleInfo
}

type sarifParser struct {
	rep   Report
	rules int // rules read so far, all runs
}

func parseSARIF(raw []byte) (*Report, error) {
	var doc sarifLog
	if err := decode(raw, &doc); err != nil {
		return nil, invalid("not JSON")
	}
	var version string
	if json.Unmarshal(doc.Version, &version) != nil || version != "2.1.0" {
		return nil, invalid("not SARIF 2.1.0 (version)")
	}
	if !absent(doc.Schema) {
		var schema string
		if json.Unmarshal(doc.Schema, &schema) != nil || !strings.Contains(schema, "2.1.0") {
			return nil, invalid("not SARIF 2.1.0 ($schema)")
		}
	}
	if absent(doc.Runs) {
		return nil, invalid("SARIF without runs")
	}
	p := &sarifParser{}
	err := elements(doc.Runs, MaxRuns, p.run)
	if err != nil {
		return nil, readError(err, "runs", MaxRuns)
	}
	return &p.rep, nil
}

// readError maps a reading error onto a rejection.
func readError(err error, what string, max int) error {
	var rej *Rejected
	switch {
	case errors.As(err, &rej):
		return rej
	case errors.Is(err, errTooMany):
		return tooLarge("more than %d %s", max, what)
	case errors.Is(err, errNotArray):
		return invalid("%s is not an array", what)
	}
	return invalid("malformed %s", what)
}

func (p *sarifParser) run(raw json.RawMessage) error {
	var run sarifRun
	if err := decode(raw, &run); err != nil {
		return err
	}
	rr := &runRules{byID: map[string]*ruleInfo{}}
	var driver sarifComponent
	if err := decode(run.Tool.Driver, &driver); err != nil {
		return err
	}
	if p.rep.ToolVersion == "" {
		v := driver.Version
		if cleanLine(v, MaxVersion) == "" {
			v = driver.SemanticVersion
		}
		p.rep.ToolVersion = cleanLine(v, MaxVersion)
	}
	var err error
	if rr.driver, err = p.componentRules(driver.Rules, rr); err != nil {
		return err
	}
	err = elements(run.Tool.Extensions, MaxComponents, func(el json.RawMessage) error {
		var c sarifComponent
		if err := decode(el, &c); err != nil {
			return err
		}
		rules, err := p.componentRules(c.Rules, rr)
		rr.ext = append(rr.ext, rules)
		return err
	})
	if err != nil {
		return readError(err, "extensions in a run", MaxComponents)
	}
	root := sourceRoot(run.OriginalURIBaseIDs)
	err = elements(run.Results, MaxResults-p.rep.Read, func(el json.RawMessage) error {
		return p.result(el, rr, root)
	})
	if err != nil {
		return readError(err, "results", MaxResults)
	}
	return nil
}

// componentRules reads a tool component's rules, counting them against
// MaxRules for the whole file.
func (p *sarifParser) componentRules(raw json.RawMessage, rr *runRules) ([]*ruleInfo, error) {
	var out []*ruleInfo
	err := elements(raw, MaxRules-p.rules, func(el json.RawMessage) error {
		p.rules++
		var r sarifRule
		if err := decode(el, &r); err != nil {
			return err
		}
		info := &ruleInfo{
			id:               cleanLine(r.ID, MaxRuleID),
			title:            cleanLine(r.ShortDescription.Text, MaxTitle),
			description:      cleanText(r.FullDescription.Text, MaxRuleText),
			help:             cleanText(r.Help.Text, MaxRuleText),
			level:            level(r.DefaultConfiguration.Level),
			securitySeverity: securitySeverity(r.Properties.SecuritySeverity),
			cwe:              tagCWEs(r.Properties.Tags),
		}
		out = append(out, info)
		if _, dup := rr.byID[info.id]; info.id != "" && !dup {
			rr.byID[info.id] = info
		}
		return nil
	})
	if err != nil {
		return nil, readError(err, "rules", MaxRules)
	}
	return out, nil
}

// sourceRoot is the absolute path %SRCROOT% stands for in a run
// (originalUriBaseIds), with a trailing slash, or "": then no absolute path
// of the run can be made relative.
func sourceRoot(raw json.RawMessage) string {
	root := ""
	members(raw, 64, func(key string, val json.RawMessage) {
		if key != srcRoot || root != "" {
			return
		}
		var base sarifArtifactLocation
		if decode(val, &base) != nil || base.URIBaseID != "" {
			return
		}
		if p, isAbs, ok := absolutePath(base.URI); isAbs && ok {
			if !strings.HasSuffix(p, "/") {
				p += "/"
			}
			root = p
		}
	})
	return root
}

func (p *sarifParser) result(raw json.RawMessage, rr *runRules, root string) error {
	p.rep.Read++
	var res sarifResult
	if err := decode(raw, &res); err != nil {
		return err
	}
	// Not a finding: a rule that passed or didn't apply, a note, a result
	// the tool's users suppressed, one that is gone since the baseline.
	switch {
	case res.Kind == "pass" || res.Kind == "notApplicable" || res.Kind == "informational",
		res.BaselineState == "absent", suppressed(res.Suppressions):
		p.rep.Skipped++
		return nil
	}
	id, rule := rr.lookup(&res)
	if rule == nil {
		rule = &ruleInfo{}
	}
	var loc sarifLocation
	firstElements(res.Locations, 1, func(el json.RawMessage) { _ = decode(el, &loc) })
	al := loc.PhysicalLocation.ArtifactLocation
	path, ok := sarifPath(al.URI, al.URIBaseID, root)
	if id == "" || !ok {
		p.rep.Dropped++
		return nil
	}
	start, end := lines(loc.PhysicalLocation.Region.StartLine, loc.PhysicalLocation.Region.EndLine)
	fps := map[string]string{}
	members(res.PartialFingerprints, maxFingerprints, func(key string, val json.RawMessage) {
		var s string
		if key != "" && json.Unmarshal(val, &s) == nil && s != "" {
			fps[key] = s
		}
	})
	lvl := level(res.Level)
	if lvl == "" {
		lvl = rule.level
	}
	sec := securitySeverity(res.Properties.SecuritySeverity)
	if sec == nil {
		sec = rule.securitySeverity
	}
	p.rep.Results = append(p.rep.Results, Result{
		RuleID: id, Title: rule.title, Message: cleanText(res.Message.Text, MaxMessage),
		Description: rule.description, Remediation: rule.help, Severity: sarifSeverity(sec, lvl),
		CWE: rule.cwe, Path: path, StartLine: start, EndLine: end, Fingerprint: fingerprintKey(fps),
	})
	return nil
}

// lookup finds a result's rule id and rule: by index into the driver's
// rules or, with rule.toolComponent.index, an extension's, when the rule
// there has the result's id; else by id. A result without an id takes its
// rule's. An index out of range or at a rule of another id is ignored: the
// id the result reports wins.
func (rr *runRules) lookup(res *sarifResult) (string, *ruleInfo) {
	id := cleanLine(res.RuleID, MaxRuleID)
	if id == "" {
		id = cleanLine(res.Rule.ID, MaxRuleID)
	}
	comp := rr.driver
	if !absent(res.Rule.ToolComponent.Index) {
		comp = nil
		if i := index(res.Rule.ToolComponent.Index); i >= 0 && i < len(rr.ext) {
			comp = rr.ext[i]
		}
	}
	idx := res.RuleIndex
	if absent(idx) {
		idx = res.Rule.Index
	}
	var rule *ruleInfo
	if i := index(idx); i >= 0 && i < len(comp) && (id == "" || comp[i].id == id) {
		rule = comp[i]
	}
	if rule == nil && id != "" {
		rule = rr.byID[id]
	}
	if id == "" && rule != nil {
		id = rule.id
	}
	return id, rule
}

// index reads an array index (a non-negative JSON integer), or -1.
func index(raw json.RawMessage) int {
	n, err := strconv.ParseInt(string(bytes.TrimSpace(raw)), 10, 32)
	if err != nil || n < 0 {
		return -1
	}
	return int(n)
}

// suppressed: a result with a suppression in effect (status accepted, or
// none given). One under review or rejected doesn't hide it.
func suppressed(raw json.RawMessage) bool {
	out := false
	firstElements(raw, 64, func(el json.RawMessage) {
		var s struct {
			Status string `json:"status"`
		}
		if decode(el, &s) == nil && (s.Status == "" || s.Status == "accepted") {
			out = true
		}
	})
	return out
}

func level(s string) string {
	switch s {
	case "none", "note", "warning", "error":
		return s
	}
	return ""
}

// securityScore: GitHub's security-severity is a CVSS-like score, "0.0" to
// "10.0", written as a string (some tools write a number). Anything else
// (NaN, Inf, a negative, a hex float, an exponent) is ignored: the level
// decides.
var securityScore = regexp.MustCompile(`^[0-9]{1,2}(\.[0-9]{1,6})?$`)

func securitySeverity(raw json.RawMessage) *float64 {
	raw = bytes.TrimSpace(raw)
	s := string(raw)
	if strings.HasPrefix(s, `"`) {
		if json.Unmarshal(raw, &s) != nil {
			return nil
		}
		s = strings.TrimSpace(s)
	}
	if !securityScore.MatchString(s) {
		return nil
	}
	f, err := strconv.ParseFloat(s, 64)
	if err != nil || f > 10 {
		return nil
	}
	return &f
}

// sarifSeverity: the security-severity score (>= 9 Critical, >= 7 High,
// >= 4 Medium, else Low), else the level (error High, warning Medium,
// note and none Low; SARIF's default level is warning).
func sarifSeverity(score *float64, lvl string) severity.Severity {
	if score != nil {
		switch s := *score; {
		case s >= 9:
			return severity.Critical
		case s >= 7:
			return severity.High
		case s >= 4:
			return severity.Medium
		}
		return severity.Low
	}
	switch lvl {
	case "error":
		return severity.High
	case "note", "none":
		return severity.Low
	}
	return severity.Medium
}

var cweTag = regexp.MustCompile(`(?i)^external/cwe/cwe-([0-9]{1,7})$`)

// tagCWEs reads the CWEs of a rule's tags (CodeQL: external/cwe/cwe-079).
func tagCWEs(raw json.RawMessage) []string {
	var out []string
	firstElements(raw, maxTags, func(el json.RawMessage) {
		var tag string
		if json.Unmarshal(el, &tag) != nil {
			return
		}
		if m := cweTag.FindStringSubmatch(tag); m != nil {
			if c := cwe(m[1]); c != "" {
				out = append(out, c)
			}
		}
	})
	return sortedCWEs(out)
}

var uriScheme = regexp.MustCompile(`^[A-Za-z][A-Za-z0-9+.-]*:`)

// sarifPath turns a result's artifact location into a path relative to the
// source root (ok false: drop the result). The URI is percent-decoded once.
// A relative URI must be relative to %SRCROOT% (or to nothing); an absolute
// one (file:///…, /…) must lie under the run's %SRCROOT% (sourceRoot), whose
// prefix is removed. Any other scheme is refused. No location is no path.
func sarifPath(uri, base, root string) (string, bool) {
	if uri == "" {
		return "", true
	}
	if base != "" && base != srcRoot {
		return "", false
	}
	if p, isAbs, ok := absolutePath(uri); isAbs {
		if !ok || root == "" || !strings.HasPrefix(p, root) {
			return "", false
		}
		return cleanPath(p[len(root):])
	}
	if uriScheme.MatchString(uri) {
		return "", false
	}
	p, err := url.PathUnescape(uri)
	if err != nil {
		return "", false
	}
	return cleanPath(p)
}

// absolutePath reads an absolute file: URI (no host but localhost, no
// query or fragment) or an absolute path, decoded once. isAbs: the URI is
// one of these (or tried to be: "//host/…"); ok: it was read.
func absolutePath(uri string) (path string, isAbs, ok bool) {
	switch {
	case strings.HasPrefix(uri, "//"):
		return "", true, false
	case strings.HasPrefix(uri, "/"):
		p, err := url.PathUnescape(uri)
		return p, true, err == nil
	case len(uri) >= 5 && strings.EqualFold(uri[:5], "file:"):
		u, err := url.Parse(uri)
		if err != nil || u.Opaque != "" || u.User != nil || (u.Host != "" && !strings.EqualFold(u.Host, "localhost")) ||
			u.RawQuery != "" || u.Fragment != "" || !strings.HasPrefix(u.Path, "/") {
			return "", true, false
		}
		return u.Path, true, true
	}
	return "", false, false
}
