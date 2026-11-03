// Package sarif normalizes scanner SARIF into Warden findings. SARIF is
// produced from attacker-controlled code, so every field is treated as hostile:
// wrong types are ignored, sizes are capped, and source reads stay inside the
// extracted upload.
package sarif

import (
	"bufio"
	"bytes"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"math"
	"os"
	"path/filepath"
	"regexp"
	"slices"
	"strconv"
	"strings"
	"time"
	"unicode/utf8"

	"github.com/aupv9/warden/backend/internal/domain/fingerprint"
	"github.com/aupv9/warden/backend/internal/domain/severity"
)

const (
	MaxResultsPerTool = 50_000
	MaxSnippet        = 4096
	MaxText           = 8192
	MaxTitle          = 500
	MaxFileBytes      = 256 << 20
	SnippetContext    = 3
	RedactedKeyProp   = "warden.contentKey"
	opengrepRulePref  = "data.rules."
	// opengrepOrgPref: Opengrep names a rule after its config's directory,
	// and the org's rules are mounted at /rules/opengrep.yml
	// (sandbox.WithOrgRules), so "org.<key>" comes out as "rules.org.<key>".
	opengrepOrgPref = "rules."
	// OrgRulePrefix starts the id of every org rule (rules.Prefix; the worker's
	// tests keep them equal). The namespace is the org's alone: a Warden rule
	// that would land in it keeps its unstripped id.
	OrgRulePrefix = "org."
)

// orgRuleTools take org rules (sandbox.OrgRulesFile).
var orgRuleTools = []string{"opengrep", "gitleaks"}

// IsOrgRule reports whether tool's ruleID is an org rule's.
func IsOrgRule(tool, ruleID string) bool {
	return strings.HasPrefix(ruleID, OrgRulePrefix) && slices.Contains(orgRuleTools, tool)
}

// normalizeRuleID maps the id a tool reports onto Warden's: Opengrep's
// directory prefixes go ("data.rules." for Warden's rules, "rules." for the
// org's), except that a Warden rule never enters the org namespace.
func normalizeRuleID(tool, id string) string {
	if tool != "opengrep" {
		return id
	}
	switch {
	case strings.HasPrefix(id, opengrepRulePref):
		// An id that is only the prefix keeps it: an empty rule id would make
		// a finding with neither id nor title (found by FuzzParse).
		if s := strings.TrimPrefix(id, opengrepRulePref); s != "" && !strings.HasPrefix(s, OrgRulePrefix) {
			return s
		}
	case strings.HasPrefix(id, opengrepOrgPref+OrgRulePrefix):
		return strings.TrimPrefix(id, opengrepOrgPref)
	}
	return id
}

// LoadedOrgRules returns the org rule ids (normalized) that tool lists in
// its SARIF rule metadata: the rules it loaded. Opengrep skips an org rule it
// can't parse with only a notification, and still runs the others, so a rule
// missing here didn't run, findings or not.
func LoadedOrgRules(doc map[string]any, tool string) map[string]bool {
	out := map[string]bool{}
	for _, r := range arr(doc["runs"]) {
		for _, rv := range arr(at(r, "tool", "driver", "rules")) {
			id, _ := obj(rv)["id"].(string)
			if id = normalizeRuleID(tool, id); IsOrgRule(tool, id) && len(id) <= 256 {
				out[id] = true
			}
		}
	}
	return out
}

// Tools whose URIs are relative to the scan target rather than under /src.
var targetRelativeTools = []string{"trivy"}

var (
	cweRe        = regexp.MustCompile(`CWE-\d+`)
	cveRe        = regexp.MustCompile(`\b(?:CVE-\d{4}-\d{4,}|GHSA(?:-[23456789cfghjmpqrvwx]{4}){3})\b`)
	trivyFieldRe = regexp.MustCompile(`(?m)^(Package|Installed Version|Fixed Version|Severity):\s*(.*)$`)
)

var ErrSARIF = errors.New("SARIF")

func sarifErr(format string, args ...any) error {
	return fmt.Errorf("%w: %s", ErrSARIF, fmt.Sprintf(format, args...))
}

type Finding struct {
	Tool           string            `json:"tool"`
	RuleID         string            `json:"rule_id"`
	Title          string            `json:"title"`
	Severity       severity.Severity `json:"severity"`
	FilePath       string            `json:"file_path"`
	ContentKey     string            `json:"content_key"`
	StartLine      *int              `json:"start_line,omitempty"`
	EndLine        *int              `json:"end_line,omitempty"`
	Description    string            `json:"description,omitempty"`
	Remediation    string            `json:"remediation,omitempty"`
	Snippet        string            `json:"snippet,omitempty"`
	CWE            []string          `json:"cwe,omitempty"`
	CVE            []string          `json:"cve,omitempty"`
	PackageName    string            `json:"package_name,omitempty"`
	PackageVersion string            `json:"package_version,omitempty"`
	FixedVersion   string            `json:"fixed_version,omitempty"`
	// LicenseCategory is the Trivy category of a license-policy finding
	// (results.LicenseFindings); never set from SARIF.
	LicenseCategory string `json:"license_category,omitempty"`
	// Commit is set on Gitleaks findings of history scans (Options.History).
	Commit *Commit `json:"commit,omitempty"`
	// RuleDescription is the rule's own text from the SARIF rule metadata
	// (full description, else a non-generic short one), never the result's
	// message, which Opengrep fills with matched code ($X). Rule tests show it.
	RuleDescription string         `json:"-"`
	Raw             map[string]any `json:"-"`
}

// Commit is the commit a secret was found in. After CollapseHistory it is the
// oldest commit that added the secret, and Count how many commits did.
type Commit struct {
	SHA   string     `json:"sha"`
	Date  *time.Time `json:"date,omitempty"`
	Count int        `json:"count"`
}

var (
	commitSHA = regexp.MustCompile(`^(?:[0-9a-f]{40}|[0-9a-f]{64})$`)
	// minCommitDate: git's dates start at the epoch (older ones are forged
	// or broken); Postgres would take them, but they mean nothing.
	minCommitDate = time.Unix(0, 0)
)

// parseCommit reads the commit Gitleaks reports in git mode. warden-redact
// left only commitSha and date; the sha must be well formed (Gitleaks always
// writes one, so anything else is refused), a date that isn't RFC 3339 within
// 1970..9999 is dropped.
func parseCommit(result map[string]any) (*Commit, error) {
	pf := obj(result["partialFingerprints"])
	sha, _ := pf["commitSha"].(string)
	if !commitSHA.MatchString(sha) {
		return nil, sarifErr("gitleaks history result without a valid commit sha")
	}
	c := &Commit{SHA: sha, Count: 1}
	if s, ok := pf["date"].(string); ok && len(s) <= 64 {
		if t, err := time.Parse(time.RFC3339, s); err == nil && !t.Before(minCommitDate) {
			t = t.UTC()
			c.Date = &t
		}
	}
	return c, nil
}

// CollapseHistory turns a history scan's findings into one per Key (rule and
// secret: the key's path is fingerprint.HistoryPath), however many commits
// and files added the secret. The one kept is the oldest commit's (by date,
// then sha, path and line, so the choice is stable), with Commit.Count the
// number of distinct commits. Unlike repeated findings in one file, these are
// not told apart by order: a secret added again is the same secret. Findings
// without a commit pass through.
func CollapseHistory(fs []Finding) []Finding {
	type group struct {
		oldest Finding
		shas   map[string]bool
	}
	groups := map[fingerprint.Key]*group{}
	var order []fingerprint.Key
	var out []Finding
	for _, f := range fs {
		if f.Commit == nil {
			out = append(out, f)
			continue
		}
		k := f.Key()
		g, ok := groups[k]
		if !ok {
			g = &group{oldest: f, shas: map[string]bool{}}
			groups[k] = g
			order = append(order, k)
		} else if older(f, g.oldest) {
			g.oldest = f
		}
		g.shas[f.Commit.SHA] = true
	}
	for _, k := range order {
		g := groups[k]
		f := g.oldest
		c := *f.Commit
		c.Count = len(g.shas)
		f.Commit = &c
		out = append(out, f)
	}
	return out
}

// older orders history findings by commit date (unknown dates last), sha,
// file and line.
func older(a, b Finding) bool {
	da, db := a.Commit.Date, b.Commit.Date
	switch {
	case da != nil && db == nil:
		return true
	case da == nil && db != nil:
		return false
	case da != nil && !da.Equal(*db):
		return da.Before(*db)
	}
	if a.Commit.SHA != b.Commit.SHA {
		return a.Commit.SHA < b.Commit.SHA
	}
	if a.FilePath != b.FilePath {
		return a.FilePath < b.FilePath
	}
	return a.Line() < b.Line()
}

// Line returns the start line, or 0 when unknown (used for fingerprint ordering).
func (f Finding) Line() int {
	if f.StartLine == nil {
		return 0
	}
	return *f.StartLine
}

// Key is the finding's identity. A secret in git history is keyed by rule and
// secret only (fingerprint.HistoryPath): the file it was added in doesn't
// make it another secret to rotate.
func (f Finding) Key() fingerprint.Key {
	path := f.FilePath
	if f.Commit != nil {
		path = fingerprint.HistoryPath
	}
	return fingerprint.Key{Tool: f.Tool, RuleID: f.RuleID, FilePath: path, ContentKey: f.ContentKey}
}

// Decode parses JSON keeping numbers exact (json.Number), as Load and the redactor need.
func Decode(r io.Reader) (any, error) {
	dec := json.NewDecoder(r)
	dec.UseNumber()
	var v any
	if err := dec.Decode(&v); err != nil {
		return nil, err
	}
	if _, err := dec.Token(); err != io.EOF {
		return nil, errors.New("trailing data after JSON document")
	}
	return v, nil
}

// Load reads a SARIF file of at most MaxFileBytes and checks it has runs[].
func Load(path string) (map[string]any, error) {
	st, err := os.Stat(path)
	if err != nil {
		return nil, err
	}
	if st.Size() > MaxFileBytes {
		return nil, sarifErr("SARIF %s too large", filepath.Base(path))
	}
	f, err := os.Open(path)
	if err != nil {
		return nil, err
	}
	defer f.Close()
	v, err := Decode(io.LimitReader(f, MaxFileBytes+1))
	if err != nil {
		return nil, sarifErr("invalid SARIF JSON: %v", err)
	}
	doc, ok := v.(map[string]any)
	if !ok {
		return nil, sarifErr("SARIF has no runs[]")
	}
	if _, ok := doc["runs"].([]any); !ok {
		return nil, sarifErr("SARIF has no runs[]")
	}
	return doc, nil
}

// Typed accessors: anything of the wrong type reads as the zero value.

func obj(v any) map[string]any {
	m, _ := v.(map[string]any)
	return m
}

func arr(v any) []any {
	a, _ := v.([]any)
	return a
}

func at(v any, keys ...string) any {
	for _, k := range keys {
		v = obj(v)[k]
	}
	return v
}

// str returns a non-empty string truncated to limit runes, or "".
func str(v any, limit int) string {
	s, _ := v.(string)
	return truncRunes(s, limit)
}

func truncRunes(s string, limit int) string {
	if len(s) <= limit {
		return s
	}
	i := 0
	for pos := range s {
		if i == limit {
			return s[:pos]
		}
		i++
	}
	return s
}

func nonNegInt(v any) *int {
	n, ok := v.(json.Number)
	if !ok {
		return nil
	}
	i, err := strconv.ParseInt(string(n), 10, 64)
	if err != nil || i < 0 || i > math.MaxInt32 {
		return nil
	}
	x := int(i)
	return &x
}

func number(v any) *float64 {
	var s string
	switch t := v.(type) {
	case json.Number:
		s = string(t)
	case string:
		s = strings.TrimSpace(t)
	default:
		return nil
	}
	f, err := strconv.ParseFloat(s, 64)
	if err != nil {
		return nil
	}
	return &f
}

func text(v any) string {
	if s := str(at(v, "markdown"), MaxText); s != "" {
		return s
	}
	return str(at(v, "text"), MaxText)
}

type Options struct {
	RootDir      string // single top-level dir of the upload, stripped from paths
	SourceRoot   string // extracted upload, used to read the flagged lines
	CheckovTable map[string]severity.Severity
	// ImageTarget is set for image scans (the image repository): Trivy paths
	// become "<target>::<path in the image>", and OSLabel names the OS packages.
	ImageTarget string
	OSLabel     string
	// History is set for history scans: Gitleaks ran in git mode, so paths
	// are relative to the repository (no /src mount, no zip root dir to strip)
	// and every result names its commit.
	History bool
	// OrgRules are the org rules the tool ran, by id ("org.<key>"), with the
	// severity each rule's findings get whatever level the SARIF claims. A
	// result of any other org rule id is refused: the scan didn't run it.
	OrgRules map[string]severity.Severity
}

// ImageArtifact is where an image scan's tarball is mounted (sandbox.ImageTools);
// Trivy reports OS package findings against it.
const ImageArtifact = "src/image.tar"

// ImagePath is the file path of a Trivy finding in an image scan: the image
// target, then the OS ("alpine") for OS packages or the path in the image
// (usr/local/bin/app) for language packages. The OS version is left out so
// that a base image update keeps the issues of the packages it didn't fix.
func ImagePath(target, osLabel, p string) string {
	if p == ImageArtifact || p == "" {
		p = osLabel
		if p == "" {
			p = "os"
		}
	}
	return target + "::" + p
}

func Parse(doc map[string]any, tool string, opts Options) ([]Finding, error) {
	var findings []Finding
	for _, r := range arr(doc["runs"]) {
		run := obj(r)
		if run == nil {
			continue
		}
		rules := map[string]map[string]any{}
		for _, rv := range arr(at(run, "tool", "driver", "rules")) {
			if rule := obj(rv); rule != nil {
				if id, ok := rule["id"].(string); ok {
					rules[id] = rule
				}
			}
		}
		for _, res := range arr(run["results"]) {
			if len(findings) >= MaxResultsPerTool {
				return nil, sarifErr("%s produced more than %d results", tool, MaxResultsPerTool)
			}
			result := obj(res)
			if result == nil {
				continue
			}
			f, err := parseResult(result, rules, tool, opts)
			if err != nil {
				return nil, err
			}
			if f != nil {
				findings = append(findings, *f)
			}
		}
	}
	return findings, nil
}

func parseResult(result map[string]any, rules map[string]map[string]any, tool string, opts Options) (*Finding, error) {
	ruleID := str(result["ruleId"], 256)
	if ruleID == "" {
		return nil, nil
	}
	rule := rules[ruleID]
	ruleID = normalizeRuleID(tool, ruleID)
	var orgSeverity severity.Severity
	if IsOrgRule(tool, ruleID) {
		sev, ok := opts.OrgRules[ruleID]
		if !ok || severity.Rank(sev) == len(severity.All) {
			return nil, sarifErr("%s reported org rule %q, which this scan didn't run", tool, truncRunes(ruleID, 80))
		}
		orgSeverity = sev
	}
	props := obj(rule["properties"])
	var tags []string
	for _, t := range arr(props["tags"]) {
		if s, ok := t.(string); ok {
			tags = append(tags, s)
		}
	}
	// Trivy's SARIF also lists every package license (tag "license"). License
	// issues come from its JSON report under the org's policy (trivyjson,
	// licensepolicy), so here Trivy yields vulnerabilities only, as before.
	if tool == "trivy" && slices.Contains(tags, "license") {
		return nil, nil
	}

	var loc map[string]any
	if locs := arr(result["locations"]); len(locs) > 0 {
		loc = obj(at(locs[0], "physicalLocation"))
	}
	uri := str(at(loc, "artifactLocation", "uri"), 2048)
	region := obj(loc["region"])
	start, end := nonNegInt(region["startLine"]), nonNegInt(region["endLine"])
	if end == nil || *end == 0 {
		end = start
	}
	filePath := fingerprint.NormPath(uri, opts.RootDir, !slices.Contains(targetRelativeTools, tool))
	if tool == "trivy" && opts.ImageTarget != "" {
		filePath = ImagePath(opts.ImageTarget, opts.OSLabel, filePath)
	}
	snippet := str(at(region, "snippet", "text"), MaxSnippet)
	if snippet == "requires login" {
		snippet = ""
	}

	message := text(result["message"])
	short := text(rule["shortDescription"])
	if strings.HasPrefix(short, "Opengrep Finding") || strings.HasPrefix(short, "Semgrep Finding") {
		short = ""
	}
	title := short
	if title == "" {
		title, _, _ = strings.Cut(message, "\n")
	}
	if title == "" {
		title = ruleID
	}
	description := text(rule["fullDescription"])
	ruleText := description
	if ruleText == "" {
		ruleText = short
	}
	if description == "" {
		description = message
	}
	if IsOrgRule(tool, ruleID) {
		// An org rule's text is its author's, and Opengrep interpolates the
		// matched code into the result message; nothing outside Gitleaks's
		// sandbox redacts it. Title and description come from the rule alone.
		title, description = ruleID, ruleText
		if first, _, _ := strings.Cut(strings.TrimSpace(ruleText), "\n"); first != "" {
			title = first
		}
		snippet = ""
	}

	f := &Finding{
		Tool:        tool,
		RuleID:      ruleID,
		Title:       truncRunes(title, MaxTitle),
		Severity:    severity.Medium,
		FilePath:    filePath,
		StartLine:   start,
		EndLine:     end,
		Description: description,
		Remediation: text(rule["help"]),
		Snippet:     snippet,
		CWE:         cwes(tags),
		Raw:         result,

		RuleDescription: ruleText,
	}

	switch tool {
	case "gitleaks":
		key, ok := at(result, "properties", RedactedKeyProp).(string)
		if !ok {
			return nil, sarifErr("gitleaks result missing redaction content key")
		}
		f.ContentKey = key
		f.Severity = severity.Gitleaks(ruleID)
		if opts.History {
			// A repository may well have a top-level src/: keep it.
			f.FilePath = fingerprint.NormPath(uri, "", false)
			var err error
			if f.Commit, err = parseCommit(result); err != nil {
				return nil, err
			}
		}
	case "trivy":
		fields := map[string]string{}
		for _, m := range trivyFieldRe.FindAllStringSubmatch(message, -1) {
			fields[m[1]] = m[2]
		}
		f.PackageName = truncRunes(fields["Package"], 256)
		f.PackageVersion = truncRunes(fields["Installed Version"], 128)
		f.FixedVersion = truncRunes(fields["Fixed Version"], 256)
		f.CVE = sortedUnique(cveRe.FindAllString(ruleID, -1))
		label := fields["Severity"]
		if label == "" {
			for _, t := range tags {
				if slices.Contains([]string{"CRITICAL", "HIGH", "MEDIUM", "LOW", "UNKNOWN"}, strings.ToUpper(t)) {
					label = t
					break
				}
			}
		}
		f.Severity = severity.Trivy(label)
		f.ContentKey = fingerprint.SCAContentKey(ruleID, f.PackageName, f.PackageVersion)
		f.StartLine, f.EndLine = nil, nil
	default:
		flagged := f.Snippet
		if opts.SourceRoot != "" && start != nil && *start > 0 {
			inSrc := fingerprint.NormPath(uri, "", true)
			if lines := readLines(opts.SourceRoot, inSrc, *start, *end, 0); lines != "" {
				flagged = lines
			}
			// No source snippet for an org rule's finding: a rule written to
			// match credentials would store them in the issue unredacted.
			// The content key below is a hash of the flagged lines.
			if f.Snippet == "" && !IsOrgRule(tool, ruleID) {
				f.Snippet = readLines(opts.SourceRoot, inSrc, *start, *end, SnippetContext)
			}
		}
		f.ContentKey = fingerprint.CodeContentKey(fingerprint.SplitLines(flagged))
		if tool == "opengrep" {
			level := result["level"]
			if s, _ := level.(string); s == "" {
				level = at(rule, "defaultConfiguration", "level")
			}
			f.Severity = severity.Opengrep(str(level, 16), number(props["security-severity"]))
		} else {
			f.Severity = severity.Checkov(ruleID, opts.CheckovTable)
		}
	}
	if orgSeverity != "" {
		f.Severity = orgSeverity
	}
	return f, nil
}

func cwes(tags []string) []string {
	var out []string
	for _, t := range tags {
		out = append(out, cweRe.FindAllString(t, -1)...)
	}
	return sortedUnique(out)
}

func sortedUnique(s []string) []string {
	if len(s) == 0 {
		return nil
	}
	slices.Sort(s)
	return slices.Compact(s)
}

// readLines returns lines start-ctx..end+ctx of root/rel, or "" if the file is
// missing or resolves outside root (e.g. via "../" or a symlink in the URI).
func readLines(root, rel string, start, end, ctx int) string {
	if root == "" || rel == "" {
		return ""
	}
	base, err := filepath.EvalSymlinks(root)
	if err != nil {
		return ""
	}
	base, _ = filepath.Abs(base)
	target, err := filepath.EvalSymlinks(filepath.Join(base, filepath.FromSlash(rel)))
	if err != nil || !strings.HasPrefix(target, base+string(filepath.Separator)) {
		return ""
	}
	st, err := os.Stat(target)
	if err != nil || !st.Mode().IsRegular() {
		return ""
	}
	fh, err := os.Open(target)
	if err != nil {
		return ""
	}
	defer fh.Close()

	lo, hi := max(1, start-ctx), end+ctx
	// Universal newlines (\n, \r\n, \r) like Python's text mode. Only bytes of
	// wanted lines are kept, and at most enough for MaxSnippet runes.
	const keepMax = MaxSnippet * utf8.UTFMax
	var lines []string
	var cur bytes.Buffer
	kept, pending := 0, false
	line := 1
	br := bufio.NewReader(fh)
	for line <= hi {
		b, err := br.ReadByte()
		if err != nil {
			break
		}
		if b != '\r' && b != '\n' {
			pending = true
			if line >= lo && kept < keepMax {
				cur.WriteByte(b)
				kept++
			}
			continue
		}
		if b == '\r' {
			if nb, err := br.ReadByte(); err == nil && nb != '\n' {
				_ = br.UnreadByte()
			}
		}
		if line >= lo {
			lines = append(lines, cur.String())
		}
		cur.Reset()
		pending = false
		line++
	}
	if pending && line >= lo && line <= hi {
		lines = append(lines, cur.String())
	}
	return truncRunes(replaceInvalidUTF8([]byte(strings.Join(lines, "\n"))), MaxSnippet)
}

// replaceInvalidUTF8 maps each invalid byte to U+FFFD, like Python's errors="replace".
func replaceInvalidUTF8(b []byte) string {
	if utf8.Valid(b) {
		return string(b)
	}
	var sb strings.Builder
	for len(b) > 0 {
		r, size := utf8.DecodeRune(b)
		sb.WriteRune(r) // RuneError for an invalid byte
		b = b[size:]
	}
	return sb.String()
}
