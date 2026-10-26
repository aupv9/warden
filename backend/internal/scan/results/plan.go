// Package results turns a scan's findings into tracked issues: dedupe by
// fingerprint, open new issues, reopen regressions, auto-fix what disappeared.
// The decisions are pure (BuildPlan); Process loads state and applies the plan
// in the caller's transaction.
package results

import (
	"fmt"
	"slices"

	"github.com/google/uuid"

	"github.com/aupv9/warden/backend/internal/domain/fingerprint"
	"github.com/aupv9/warden/backend/internal/domain/issuestate"
	"github.com/aupv9/warden/backend/internal/domain/severity"
	"github.com/aupv9/warden/backend/internal/scan/sandbox"
	"github.com/aupv9/warden/backend/internal/scan/sarif"
)

// ExistingIssue is the part of an issue row the plan needs.
type ExistingIssue struct {
	ID                 uuid.UUID
	Fingerprint        string
	Tool               string
	Status             issuestate.Status
	Severity           severity.Severity
	SeverityOverridden bool
	LastSeenScanID     uuid.UUID
}

func (e ExistingIssue) active() bool { return slices.Contains(issuestate.Active, e.Status) }

type PlanInput struct {
	ScanID     uuid.UUID
	Runs       []sandbox.ToolRun // final tool statuses of this scan
	Findings   map[string][]sarif.Finding
	Existing   []ExistingIssue // every issue of the project, any status
	GuardRatio float64         // max fraction of active issues one scan may auto-fix
}

type NewIssue struct {
	Fingerprint string
	Finding     sarif.Finding
}

// Sighting is an existing issue found again by this scan.
type Sighting struct {
	Issue       ExistingIssue
	Finding     sarif.Finding
	Reopen      bool              // fixed/verified → reopened
	SeenAgain   bool              // first sighting of an active issue in this scan: one seen_again event
	NewSeverity severity.Severity // set when the scanner's severity changed and nobody overrode it
}

type Stats struct {
	New      int `json:"new"`
	Fixed    int `json:"fixed"`
	Reopened int `json:"reopened"`
	Total    int `json:"total"`
}

type Plan struct {
	New  []NewIssue
	Seen []Sighting
	Fix  []ExistingIssue
	// NeedsConfirmation: the auto-fix guard tripped, so nothing was fixed.
	NeedsConfirmation bool
	ToolCounts        map[string]int // findings per succeeded tool
	Stats             Stats
}

// SucceededTools are the tools whose results are complete for this scan. Only
// their issues may be auto-fixed: a tool that failed or timed out didn't look.
func SucceededTools(runs []sandbox.ToolRun) map[string]bool {
	ok := map[string]bool{}
	for _, r := range runs {
		if r.Status == sandbox.Succeeded {
			ok[r.Tool] = true
		}
	}
	return ok
}

// Fingerprints assigns fingerprints tool by tool (in a stable order).
func Fingerprints(findings map[string][]sarif.Finding, tools map[string]bool) []fingerprint.Fingerprinted[sarif.Finding] {
	names := make([]string, 0, len(findings))
	for t := range findings {
		if tools[t] {
			names = append(names, t)
		}
	}
	slices.Sort(names)
	var out []fingerprint.Fingerprinted[sarif.Finding]
	for _, t := range names {
		out = append(out, fingerprint.Assign(findings[t], sarif.Finding.Key, sarif.Finding.Line)...)
	}
	return out
}

// AutoFixGuardMin: a scan may always fix fewer issues than this. Below it the
// ratio would block the common case of a small project fixing its only finding,
// and a wrong upload can't close much anyway.
const AutoFixGuardMin = 5

// AutoFixAllowed is the guard against a truncated or wrong upload closing
// everything: a scan that would fix AutoFixGuardMin or more issues may fix at
// most ratio of the project's active issues.
func AutoFixAllowed(candidates, active int, ratio float64) bool {
	return candidates < AutoFixGuardMin || float64(candidates) <= ratio*float64(active)
}

// BuildPlan decides what this scan does to the project's issues. Replaying it
// against the state it produced yields no new issues, events or fixes.
func BuildPlan(in PlanInput) (Plan, error) {
	succeeded := SucceededTools(in.Runs)
	byFP := make(map[string]ExistingIssue, len(in.Existing))
	active := 0
	for _, e := range in.Existing {
		byFP[e.Fingerprint] = e
		if e.active() {
			active++
		}
	}

	p := Plan{ToolCounts: map[string]int{}}
	for t := range succeeded {
		p.ToolCounts[t] = 0
	}
	seen := map[string]bool{}
	for _, fp := range Fingerprints(in.Findings, succeeded) {
		if seen[fp.Fingerprint] {
			continue
		}
		seen[fp.Fingerprint] = true
		p.ToolCounts[fp.Finding.Tool]++
		p.Stats.Total++

		e, ok := byFP[fp.Fingerprint]
		if !ok {
			p.New = append(p.New, NewIssue{Fingerprint: fp.Fingerprint, Finding: fp.Finding})
			continue
		}
		s := Sighting{Issue: e, Finding: fp.Finding}
		if !e.SeverityOverridden && fp.Finding.Severity != e.Severity {
			s.NewSeverity = fp.Finding.Severity
		}
		switch {
		case e.active():
			s.SeenAgain = e.LastSeenScanID != in.ScanID
		case e.Status == issuestate.Fixed || e.Status == issuestate.Verified:
			if _, err := issuestate.Check(e.Status, issuestate.Reopened, issuestate.System); err != nil {
				return Plan{}, fmt.Errorf("reopen %s: %w", e.ID, err)
			}
			s.Reopen = true
			p.Stats.Reopened++
		default:
			// false_positive / risk_accepted: an approved exception keeps the
			// status; the occurrence is still recorded.
		}
		p.Seen = append(p.Seen, s)
	}

	var candidates []ExistingIssue
	for _, e := range in.Existing {
		if !e.active() || seen[e.Fingerprint] || !succeeded[e.Tool] {
			continue
		}
		if _, err := issuestate.Check(e.Status, issuestate.Fixed, issuestate.System); err != nil {
			continue
		}
		candidates = append(candidates, e)
	}
	if AutoFixAllowed(len(candidates), active, in.GuardRatio) {
		p.Fix = candidates
	} else {
		p.NeedsConfirmation = true
	}
	p.Stats.New = len(p.New)
	p.Stats.Fixed = len(p.Fix)
	return p, nil
}
