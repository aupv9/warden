package importer

import (
	"bytes"
	"encoding/json"
	"errors"
	"sort"
	"strconv"
	"strings"

	"github.com/aupv9/warden/backend/internal/scan/sarif"
)

// Screening: another tool's message, rule text or path can quote a secret
// (a hard-coded password a rule flagged, a token in a file name), and
// nothing else in Warden redacts what an import stores. So every string
// Warden would keep is written to one file, which the normal Gitleaks tool
// scans in the sandbox (Warden's rules and the org's, through warden-redact:
// only line numbers come back). A string on a line Gitleaks matched is
// dropped. Strings are written whole, one after another; a multi-line text
// takes as many lines, and Warden keeps the lines each one spans, so a
// secret split across lines still drops its string. Warden's strings have
// no other line breaks (cleanText): Gitleaks and Warden count the same lines.

// ScreenFile is the screening file's name under the scan's src/.
const ScreenFile = "strings.txt"

// Screen is a report's screening file.
type Screen struct {
	data  bytes.Buffer
	spans []span         // by string, in file order
	ids   map[string]int // string -> its span
}

// span is the lines a string takes in the file (1-based, inclusive).
type span struct{ first, last int }

// Screen lists every distinct non-empty string of the report that Warden
// would store: the tool's version and each result's rule id, title,
// message, rule description and help, and path.
func (r *Report) Screen() *Screen {
	s := &Screen{ids: map[string]int{}}
	line := 1
	add := func(str string) {
		if str == "" {
			return
		}
		if _, dup := s.ids[str]; dup {
			return
		}
		n := strings.Count(str, "\n")
		s.ids[str] = len(s.spans)
		s.spans = append(s.spans, span{line, line + n})
		line += n + 1
		s.data.WriteString(str)
		s.data.WriteByte('\n')
	}
	add(r.ToolVersion)
	for _, res := range r.Results {
		for _, str := range []string{res.RuleID, res.Title, res.Message, res.Description, res.Remediation, res.Path} {
			add(str)
		}
	}
	return s
}

// Bytes is the file's content.
func (s *Screen) Bytes() []byte { return s.data.Bytes() }

// Empty: the report keeps no string, so there is nothing to screen.
func (s *Screen) Empty() bool { return len(s.spans) == 0 }

// Lines are the lines of one Gitleaks finding (1-based, inclusive).
type Lines struct{ Start, End int }

// Apply drops every string of the report on a line in matches: a matched
// rule id or path drops its result (counted in Dropped), a matched title,
// message, description, help or tool version becomes "" (the title then
// falls back to the rule id). Screened counts the distinct strings matched.
// A string missing from s counts as matched: nothing unscreened is kept.
func (r *Report) Apply(s *Screen, matches []Lines) {
	// Which spans a match covers: the first whose last line is at or after
	// its start, through the last whose first line is at or before its end.
	// Counted with a difference array, so many wide matches stay linear.
	diff := make([]int, len(s.spans)+1)
	for _, m := range matches {
		if m.End < m.Start {
			m.End = m.Start
		}
		lo := sort.Search(len(s.spans), func(i int) bool { return s.spans[i].last >= m.Start })
		hi := sort.Search(len(s.spans), func(i int) bool { return s.spans[i].first > m.End })
		if lo < hi {
			diff[lo]++
			diff[hi]--
		}
	}
	hit := make([]bool, len(s.spans))
	r.Screened = 0
	for i, n := 0, 0; i < len(s.spans); i++ {
		n += diff[i]
		if hit[i] = n > 0; hit[i] {
			r.Screened++
		}
	}
	matched := func(str string) bool {
		if str == "" {
			return false
		}
		i, ok := s.ids[str]
		return !ok || hit[i]
	}
	kept := r.Results[:0]
	for _, res := range r.Results {
		if matched(res.RuleID) || matched(res.Path) {
			r.Dropped++
			continue
		}
		for _, p := range []*string{&res.Title, &res.Message, &res.Description, &res.Remediation} {
			if matched(*p) {
				*p = ""
			}
		}
		kept = append(kept, res)
	}
	clear(r.Results[len(kept):])
	r.Results = kept
	if matched(r.ToolVersion) {
		r.ToolVersion = ""
	}
}

// ErrScreen: the screening run's SARIF can't be mapped back to the strings.
var ErrScreen = errors.New("import screening")

// Matches reads the lines of every result of the screening run's SARIF
// (Gitleaks after warden-redact: never a secret, only where it was). It is
// strict, as the screening fails closed: a SARIF without a run or results
// array, or a result without a start line, is an error, never "no match".
func Matches(path string) ([]Lines, error) {
	doc, err := sarif.Load(path)
	if err != nil {
		return nil, errors.Join(ErrScreen, err)
	}
	runs, _ := doc["runs"].([]any)
	if len(runs) == 0 {
		return nil, errors.Join(ErrScreen, errors.New("no run"))
	}
	var out []Lines
	for _, r := range runs {
		run, _ := r.(map[string]any)
		results, ok := run["results"].([]any)
		if !ok {
			return nil, errors.Join(ErrScreen, errors.New("a run without results"))
		}
		for _, res := range results {
			result, _ := res.(map[string]any)
			locs, _ := result["locations"].([]any)
			found := false
			for _, l := range locs {
				loc, _ := l.(map[string]any)
				pl, _ := loc["physicalLocation"].(map[string]any)
				region, _ := pl["region"].(map[string]any)
				start := lineOf(region["startLine"])
				if start < 1 {
					continue
				}
				end := lineOf(region["endLine"])
				if end < start {
					end = start
				}
				out = append(out, Lines{start, end})
				found = true
			}
			if !found {
				return nil, errors.Join(ErrScreen, errors.New("a result without a line"))
			}
		}
	}
	return out, nil
}

func lineOf(v any) int {
	n, ok := v.(json.Number)
	if !ok {
		return 0
	}
	i, err := strconv.ParseInt(string(n), 10, 32)
	if err != nil || i < 1 {
		return 0
	}
	return int(i)
}
