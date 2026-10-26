// Package gate is the self-scan release gate: it fails when a finding at or
// above the threshold isn't covered by a valid baseline entry. Baseline entries
// follow the risk-acceptance rules: a reason of at least 20 characters and an
// expiry no more than 180 days out; expired entries stop counting.
package gate

import (
	"cmp"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"io/fs"
	"os"
	"slices"
	"strings"
	"time"

	"github.com/aupv9/warden/backend/internal/domain/fingerprint"
	"github.com/aupv9/warden/backend/internal/domain/issuestate"
	"github.com/aupv9/warden/backend/internal/domain/severity"
	"github.com/aupv9/warden/backend/internal/scan/sarif"
)

const minReasonLen = 20

type baselineEntry struct {
	Reason  *string `json:"reason"`
	Expires *string `json:"expires"`
}

// LoadBaseline returns the accepted fingerprints and a message for every entry
// that doesn't count (missing fields, short reason, expired, too far out).
func LoadBaseline(path string, today time.Time) (map[string]bool, []string, error) {
	accepted := map[string]bool{}
	if path == "" {
		return accepted, nil, nil
	}
	data, err := os.ReadFile(path)
	if errors.Is(err, fs.ErrNotExist) {
		return accepted, nil, nil
	}
	if err != nil {
		return nil, nil, err
	}
	var raw map[string]json.RawMessage
	if err := json.Unmarshal(data, &raw); err != nil {
		return nil, nil, fmt.Errorf("baseline %s: %w", path, err)
	}
	fps := make([]string, 0, len(raw))
	for fp := range raw {
		fps = append(fps, fp)
	}
	slices.Sort(fps)

	var problems []string
	for _, fp := range fps {
		short := fp[:min(12, len(fp))] + "…"
		var e baselineEntry
		var expires time.Time
		err := json.Unmarshal(raw[fp], &e)
		if err == nil && e.Reason != nil && e.Expires != nil {
			expires, err = time.Parse(time.DateOnly, *e.Expires)
		}
		switch {
		case err != nil || e.Reason == nil || e.Expires == nil:
			problems = append(problems, fmt.Sprintf("baseline entry %s needs 'reason' and ISO 'expires'", short))
		case len([]rune(*e.Reason)) < minReasonLen:
			problems = append(problems, fmt.Sprintf("baseline entry %s reason shorter than %d chars", short, minReasonLen))
		case expires.Before(today):
			problems = append(problems, fmt.Sprintf("baseline entry %s expired on %s", short, *e.Expires))
		case expires.Sub(today) > issuestate.RiskAcceptedMaxDays*24*time.Hour:
			problems = append(problems, fmt.Sprintf("baseline entry %s expires more than %d days out", short, issuestate.RiskAcceptedMaxDays))
		default:
			accepted[fp] = true
		}
	}
	return accepted, problems, nil
}

type Input struct {
	Tool, File string
}

type Options struct {
	Inputs     []Input
	FailOn     severity.Severity
	Baseline   string
	SourceRoot string
	JSONOut    string
	Today      time.Time // zero = now (UTC)
}

type Row struct {
	Fingerprint string `json:"fingerprint"`
	Tool        string `json:"tool"`
	Rule        string `json:"rule"`
	Severity    string `json:"severity"`
	Location    string `json:"location"`
	Title       string `json:"title"`
	Accepted    bool   `json:"accepted"`
}

// Run prints the summary to w and returns the exit code (0 pass, 1 fail).
func Run(opts Options, w io.Writer) (int, error) {
	today := opts.Today
	if today.IsZero() {
		today = time.Now().UTC()
	}
	today = time.Date(today.Year(), today.Month(), today.Day(), 0, 0, 0, 0, time.UTC)
	accepted, problems, err := LoadBaseline(opts.Baseline, today)
	if err != nil {
		return 2, err
	}
	failOn := opts.FailOn
	if failOn == "" {
		failOn = severity.Critical
	}
	threshold := severity.Rank(failOn)

	counts := map[severity.Severity]int{}
	report := []Row{}
	blocking := 0
	for _, in := range opts.Inputs {
		doc, err := sarif.Load(in.File)
		if err != nil {
			return 2, err
		}
		findings, err := sarif.Parse(doc, in.Tool, sarif.Options{SourceRoot: opts.SourceRoot})
		if err != nil {
			return 2, err
		}
		for _, item := range fingerprint.Assign(findings, sarif.Finding.Key, sarif.Finding.Line) {
			f := item.Finding
			counts[f.Severity]++
			loc := f.FilePath + ":"
			if f.StartLine != nil {
				loc += fmt.Sprint(*f.StartLine)
			}
			row := Row{
				Fingerprint: item.Fingerprint, Tool: in.Tool, Rule: f.RuleID, Severity: string(f.Severity),
				Location: loc, Title: f.Title, Accepted: accepted[item.Fingerprint],
			}
			report = append(report, row)
			if severity.Rank(f.Severity) <= threshold && !row.Accepted {
				blocking++
			}
		}
	}

	parts := make([]string, len(severity.All))
	for i, s := range severity.All {
		parts[i] = fmt.Sprintf("%s=%d", s, counts[s])
	}
	fmt.Fprintln(w, "Warden self-scan: "+strings.Join(parts, ", "))
	slices.SortStableFunc(report, func(a, b Row) int {
		return cmp.Compare(severity.Rank(severity.Severity(a.Severity)), severity.Rank(severity.Severity(b.Severity)))
	})
	for _, r := range report {
		if severity.Rank(severity.Severity(r.Severity)) > severity.Rank(severity.High) {
			continue
		}
		mark := strings.ToUpper(r.Severity)
		if r.Accepted {
			mark = "accepted"
		}
		fmt.Fprintf(w, "  [%s] %s:%s %s — %s\n", mark, r.Tool, r.Rule, r.Location, r.Title)
		fmt.Fprintf(w, "           fingerprint %s\n", r.Fingerprint)
	}
	for _, p := range problems {
		fmt.Fprintf(w, "  baseline: %s\n", p)
	}
	if opts.JSONOut != "" {
		b, err := json.MarshalIndent(report, "", "  ")
		if err != nil {
			return 2, err
		}
		if err := os.WriteFile(opts.JSONOut, b, 0o644); err != nil {
			return 2, err
		}
	}
	if blocking > 0 {
		fmt.Fprintf(w, "FAIL: %d finding(s) at or above %s not in baseline\n", blocking, failOn)
		return 1, nil
	}
	fmt.Fprintln(w, "PASS")
	return 0, nil
}
