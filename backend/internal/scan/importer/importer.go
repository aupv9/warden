// Package importer reads another tool's results for an import scan (scan
// kind import): a SARIF 2.1.0 file (CodeQL, Semgrep, Snyk Code, …) or a
// GitLab SAST report. The file is hostile input: whoever uploads it chooses
// every byte, so
//
//   - nothing in it is run, unpacked or followed: it is only decoded, and
//     the depth, the counts and every string are capped first;
//   - only what Warden stores is kept (rule ids, messages, rule texts, paths,
//     lines, levels, CWEs, partial fingerprints, the tool's version); code
//     snippets, code flows, related locations, fixes, attachments and
//     markdown are never read;
//   - paths must stay relative to the source root; a result whose path
//     doesn't is dropped (Report.Dropped), never rewritten into another path;
//   - control, format (bidi, zero-width) and line separator characters are
//     removed from every string;
//   - every kept string is screened by Gitleaks before anything is stored
//     (Screen, Matches, Report.Apply): another tool's message can quote a
//     secret, and nothing else redacts it.
//
// The findings come out with tool sarif.ToolExternal: an import can't set,
// fix or reopen an issue of a Warden scanner.
package importer

import (
	"bytes"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"slices"
	"strconv"
	"strings"
	"unicode"
	"unicode/utf8"

	"github.com/aupv9/warden/backend/internal/domain/severity"
	"github.com/aupv9/warden/backend/internal/scan/sarif"
)

// Error codes (scan.error_code).
const (
	CodeInvalid      = "IMPORT_INVALID"       // not a SARIF 2.1.0 file / GitLab SAST 15.x report, or malformed
	CodeTooLarge     = "IMPORT_TOO_LARGE"     // over a size or count limit
	CodeScreenFailed = "IMPORT_SCREEN_FAILED" // Gitleaks couldn't screen the strings: nothing is stored
)

// Formats (scan.import_format).
const (
	FormatSARIF  = "sarif"
	FormatGitLab = "gitlab-sast"
)

// Limits. A file over one is refused whole (IMPORT_TOO_LARGE) rather than
// cut: a truncated report would auto-fix the issues it left out.
const (
	MaxRuns    = 10
	MaxResults = 50_000 // results (vulnerabilities) in the whole file
	MaxRules   = 5_000  // rules in the whole file, extensions included
	// MaxComponents bounds tool.extensions per run (CodeQL lists its query
	// packs there); an extension costs a slice even without rules.
	MaxComponents = 256
	// MaxDepth: no SARIF or GitLab field Warden reads is nested deeper than
	// about 12; a deeper file is refused before it is decoded.
	MaxDepth = 64
)

// String caps. Bytes for texts (cut on a rune boundary), runes for the short
// ones, as the SARIF parser of Warden's own scanners.
const (
	MaxMessage  = 2 << 10 // a result's message
	MaxRuleText = 4 << 10 // a rule's description and help
	MaxTitle    = sarif.MaxTitle
	MaxRuleID   = 256
	MaxPath     = 1024
	// MaxVersion is scan.import_tool_version's limit.
	MaxVersion = 100
	MaxCWEs    = 16
	// Only so many tags, identifiers, signatures and partial fingerprints of
	// one result or rule are read; the rest is skipped, not refused.
	maxTags         = 64
	maxIdentifiers  = 64
	maxFingerprints = 32
)

// Rejected is a file Warden refuses, with its error code (CodeInvalid,
// CodeTooLarge). Detail is Warden's own text: it never quotes the file.
type Rejected struct {
	Code   string
	Detail string
}

func (e *Rejected) Error() string { return e.Code + ": " + e.Detail }

func invalid(format string, args ...any) *Rejected {
	return &Rejected{Code: CodeInvalid, Detail: fmt.Sprintf(format, args...)}
}

func tooLarge(format string, args ...any) *Rejected {
	return &Rejected{Code: CodeTooLarge, Detail: fmt.Sprintf(format, args...)}
}

// Result is one finding of the report, as Warden keeps it.
type Result struct {
	RuleID string
	// Title: the rule's short description (SARIF) or the vulnerability's
	// name (GitLab); "" falls back to RuleID.
	Title       string
	Message     string
	Description string
	Remediation string
	Severity    severity.Severity
	CWE         []string
	// Path is relative to the source root, cleaned; "" when the result has
	// no location.
	Path               string
	StartLine, EndLine *int
	// Fingerprint is a hash of the result's partial fingerprints (SARIF
	// partialFingerprints, GitLab tracking signatures); "" without any.
	Fingerprint string
}

// Report is a parsed file.
type Report struct {
	// ToolVersion is the reporting tool's version (SARIF tool.driver.version
	// or semanticVersion; GitLab scan.scanner.version).
	ToolVersion string
	Results     []Result
	// Read counts every result (vulnerability) in the file; Dropped those
	// refused (path outside the source root, no rule id, a string Gitleaks
	// matched in a rule id or path); Skipped those that aren't findings
	// (SARIF kind pass, notApplicable or informational, suppressed, or
	// baselineState absent). Read = len(Results) + Dropped + Skipped.
	Read, Dropped, Skipped int
	// Screened counts the distinct strings Gitleaks matched (Apply).
	Screened int
}

// Parse reads a whole file of the given format (FormatSARIF, FormatGitLab).
// Its errors are *Rejected.
func Parse(raw []byte, format string) (*Report, error) {
	if err := checkDepth(raw, MaxDepth); err != nil {
		return nil, err
	}
	switch format {
	case FormatSARIF, "":
		return parseSARIF(raw)
	case FormatGitLab:
		return parseGitLab(raw)
	}
	return nil, invalid("unknown format")
}

// checkDepth refuses JSON nested deeper than max, in one pass over the
// bytes and before anything is decoded or allocated. Malformed JSON passes
// here and fails to decode.
func checkDepth(raw []byte, max int) error {
	depth := 0
	inString, escaped := false, false
	for _, b := range raw {
		if inString {
			switch {
			case escaped:
				escaped = false
			case b == '\\':
				escaped = true
			case b == '"':
				inString = false
			}
			continue
		}
		switch b {
		case '"':
			inString = true
		case '{', '[':
			if depth++; depth > max {
				return invalid("JSON nested deeper than %d levels", max)
			}
		case '}', ']':
			depth--
		}
	}
	return nil
}

// decode unmarshals one JSON value into v. A field of the wrong type is left
// zero (producers differ: a number where a string is expected); malformed
// JSON is an error. Fields that hold lists or maps are json.RawMessage in
// the target types and read with elements and members, so nothing is
// allocated per element before the counts are checked.
func decode(raw []byte, v any) error {
	if len(raw) == 0 {
		return nil // an absent field: v stays zero
	}
	err := json.Unmarshal(raw, v)
	var te *json.UnmarshalTypeError
	if errors.As(err, &te) {
		return nil
	}
	return err
}

// lineNumber reads a line number: a JSON integer in 1..MaxInt32, else nil.
func lineNumber(raw json.RawMessage) *int {
	n, err := strconv.ParseInt(string(bytes.TrimSpace(raw)), 10, 32)
	if err != nil || n < 1 {
		return nil
	}
	i := int(n)
	return &i
}

// lines returns a result's start and end line: none without a valid start,
// and an end before the start (or none) becomes the start.
func lines(start, end json.RawMessage) (*int, *int) {
	s := lineNumber(start)
	if s == nil {
		return nil, nil
	}
	e := lineNumber(end)
	if e == nil || *e < *s {
		e = s
	}
	return s, e
}

// dropped reports whether r is removed from a string: control characters
// (but, in a multi-line text, newline and tab), format characters (Cf: the
// bidi controls, zero-width characters, the BOM, tag characters) and the
// line and paragraph separators. A bidi control can make a string display
// as another (Trojan Source); a line separator would make the screening
// file's lines disagree with Gitleaks'.
func dropped(r rune, multiline bool) bool {
	switch {
	case multiline && (r == '\n' || r == '\t'):
		return false
	case unicode.IsControl(r), unicode.Is(unicode.Cf, r), r == '\u2028', r == '\u2029':
		return true
	}
	return false
}

// cleanText returns s without the characters dropped removes (\r\n and a
// lone \r become \n first), trimmed, cut to max bytes on a rune boundary.
func cleanText(s string, max int) string {
	s = strings.ReplaceAll(s, "\r\n", "\n")
	s = strings.ReplaceAll(s, "\r", "\n")
	s = strings.Map(func(r rune) rune {
		if dropped(r, true) {
			return -1
		}
		return r
	}, s)
	return strings.TrimSpace(capBytes(strings.TrimSpace(s), max))
}

// cleanLine is cleanText for one-line strings (titles, rule ids, versions):
// whitespace runs, newlines included, become one space; cut to max runes.
func cleanLine(s string, max int) string {
	s = strings.Map(func(r rune) rune {
		if dropped(r, false) && r != '\n' && r != '\r' && r != '\t' {
			return -1
		}
		return r
	}, s)
	return strings.TrimSpace(capRunes(strings.Join(strings.Fields(s), " "), max))
}

func capBytes(s string, max int) string {
	if len(s) <= max {
		return s
	}
	s = s[:max]
	for len(s) > 0 {
		r, size := utf8.DecodeLastRuneInString(s)
		if r != utf8.RuneError || size > 1 {
			break
		}
		s = s[:len(s)-1]
	}
	return s
}

func capRunes(s string, max int) string {
	if len(s) <= max {
		return s
	}
	n := 0
	for i := range s {
		if n == max {
			return s[:i]
		}
		n++
	}
	return s
}

// cleanPath turns a reported path (already percent-decoded once, for a SARIF
// URI) into a path relative to the source root, or ok false: the result is
// then dropped. Refused rather than repaired: an absolute path, "..", a
// backslash (a Windows separator or an escape), a colon in the first
// segment (a scheme, a drive), a percent-encoded dot, slash, backslash or
// NUL left after the one decoding (double encoding), and any character
// cleanText would remove. "." and empty segments go.
func cleanPath(p string) (string, bool) {
	if p == "" || len(p) > 4*MaxPath || strings.HasPrefix(p, "/") || strings.ContainsRune(p, '\\') ||
		!utf8.ValidString(p) || strings.ContainsRune(p, utf8.RuneError) {
		return "", false
	}
	for _, r := range p {
		if dropped(r, false) {
			return "", false
		}
	}
	low := strings.ToLower(p)
	for _, enc := range []string{"%2e", "%2f", "%5c", "%00"} {
		if strings.Contains(low, enc) {
			return "", false
		}
	}
	var parts []string
	for _, seg := range strings.Split(p, "/") {
		switch seg {
		case "", ".":
			continue
		case "..":
			return "", false
		}
		parts = append(parts, seg)
	}
	if len(parts) == 0 || strings.ContainsRune(parts[0], ':') {
		return "", false
	}
	out := strings.Join(parts, "/")
	if len(out) > MaxPath {
		return "", false
	}
	return out, true
}

// cwe turns a CWE number ("079", "79") into "CWE-79", or "".
func cwe(digits string) string {
	if digits == "" || len(digits) > 7 {
		return ""
	}
	n, err := strconv.Atoi(digits)
	if err != nil || n < 1 || n > 999_999 {
		return ""
	}
	return "CWE-" + strconv.Itoa(n)
}

func sortedCWEs(s []string) []string {
	if len(s) == 0 {
		return nil
	}
	slices.Sort(s)
	s = slices.Compact(s)
	if len(s) > MaxCWEs {
		s = s[:MaxCWEs]
	}
	return s
}

// fingerprintKey hashes a result's partial fingerprints into one key:
// primaryLocationLineHash alone when there is one (CodeQL's, GitHub's: it
// survives a moved line, where the column fingerprint doesn't), else every
// one in sorted key order. The values are hashed, never stored. "" without
// any.
func fingerprintKey(fps map[string]string) string {
	if len(fps) == 0 {
		return ""
	}
	if v, ok := fps["primaryLocationLineHash"]; ok {
		fps = map[string]string{"primaryLocationLineHash": v}
	}
	keys := make([]string, 0, len(fps))
	for k := range fps {
		keys = append(keys, k)
	}
	slices.Sort(keys)
	h := sha256.New()
	for _, k := range keys {
		// Length-prefixed: no two maps hash alike by moving a separator.
		fmt.Fprintf(h, "%d:%s=%d:%s\n", len(k), k, len(fps[k]), fps[k])
	}
	return "pf:" + hex.EncodeToString(h.Sum(nil))
}

// messageKey is the content key of a result without partial fingerprints:
// a hash of its screened message. No line number: a moved finding keeps its
// issue (repeated ones are told apart by order, fingerprint.Assign).
func messageKey(message string) string {
	sum := sha256.Sum256([]byte(message))
	return "msg:" + hex.EncodeToString(sum[:])
}

// Findings returns the report's results as Warden findings of an import
// scan's target (scan.target). Call it after Apply: it stores what was
// screened, and nothing else.
func (r *Report) Findings(target string) []sarif.Finding {
	out := make([]sarif.Finding, 0, len(r.Results))
	for _, res := range r.Results {
		title := res.Title
		if title == "" {
			title = res.RuleID
		}
		desc := res.Description
		if desc == "" {
			desc = res.Message
		}
		key := res.Fingerprint
		if key == "" {
			key = messageKey(res.Message)
		}
		out = append(out, sarif.Finding{
			Tool: sarif.ToolExternal, RuleID: res.RuleID, Title: title, Severity: res.Severity,
			FilePath: res.Path, ContentKey: key, StartLine: res.StartLine, EndLine: res.EndLine,
			Description: desc, Remediation: res.Remediation, CWE: res.CWE, ImportTarget: target,
		})
	}
	return out
}
