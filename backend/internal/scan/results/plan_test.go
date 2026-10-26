package results

import (
	"testing"

	"github.com/google/uuid"

	"github.com/aupv9/warden/backend/internal/domain/fingerprint"
	"github.com/aupv9/warden/backend/internal/domain/issuestate"
	"github.com/aupv9/warden/backend/internal/domain/severity"
	"github.com/aupv9/warden/backend/internal/scan/sandbox"
	"github.com/aupv9/warden/backend/internal/scan/sarif"
)

func line(n int) *int { return &n }

func finding(tool, rule, path string, ln int) sarif.Finding {
	return sarif.Finding{Tool: tool, RuleID: rule, Title: rule, Severity: severity.High, FilePath: path,
		ContentKey: fingerprint.CodeContentKey([]string{rule + path}), StartLine: line(ln), EndLine: line(ln)}
}

func fpOf(f sarif.Finding) string {
	return fingerprint.Fingerprint(f.Tool, f.RuleID, f.FilePath, f.ContentKey, 0)
}

func runs(st map[string]sandbox.ToolStatus) []sandbox.ToolRun {
	var out []sandbox.ToolRun
	for t, s := range st {
		out = append(out, sandbox.ToolRun{Tool: t, Status: s})
	}
	return out
}

func existing(f sarif.Finding, st issuestate.Status, lastSeen uuid.UUID) ExistingIssue {
	return ExistingIssue{ID: uuid.New(), Fingerprint: fpOf(f), Tool: f.Tool, Status: st, Severity: f.Severity, LastSeenScanID: lastSeen}
}

var (
	scanA  = uuid.New()
	scanB  = uuid.New()
	allOK  = runs(map[string]sandbox.ToolStatus{"opengrep": sandbox.Succeeded, "trivy": sandbox.Succeeded})
	fA     = finding("opengrep", "sqli", "a.py", 3)
	fB     = finding("opengrep", "xss", "b.py", 9)
	fTrivy = finding("trivy", "CVE-2026-1", "go.mod", 0)
)

func TestNewFindingsOpenIssues(t *testing.T) {
	p, err := BuildPlan(PlanInput{ScanID: scanA, Runs: allOK, GuardRatio: 0.5,
		Findings: map[string][]sarif.Finding{"opengrep": {fA, fB}, "trivy": {fTrivy}}})
	if err != nil {
		t.Fatal(err)
	}
	if len(p.New) != 3 || p.Stats != (Stats{New: 3, Total: 3}) || len(p.Seen)+len(p.Fix) != 0 {
		t.Fatalf("%+v", p)
	}
	if p.ToolCounts["opengrep"] != 2 || p.ToolCounts["trivy"] != 1 {
		t.Fatalf("%v", p.ToolCounts)
	}
}

func TestIdenticalFindingsInOneFileGetDistinctIssues(t *testing.T) {
	a, b := fA, fA
	b.StartLine = line(40)
	p, _ := BuildPlan(PlanInput{ScanID: scanA, Runs: allOK, Findings: map[string][]sarif.Finding{"opengrep": {a, b}}})
	if len(p.New) != 2 || p.New[0].Fingerprint == p.New[1].Fingerprint {
		t.Fatalf("%+v", p.New)
	}
}

func TestSeenAgainOncePerScan(t *testing.T) {
	e := existing(fA, issuestate.Assigned, scanA)
	p, _ := BuildPlan(PlanInput{ScanID: scanB, Runs: allOK, Existing: []ExistingIssue{e},
		Findings: map[string][]sarif.Finding{"opengrep": {fA}}})
	if len(p.Seen) != 1 || !p.Seen[0].SeenAgain || p.Seen[0].Reopen || len(p.New) != 0 {
		t.Fatalf("%+v", p)
	}
	// Already recorded for scanB (e.g. replay): no second event.
	e.LastSeenScanID = scanB
	p, _ = BuildPlan(PlanInput{ScanID: scanB, Runs: allOK, Existing: []ExistingIssue{e},
		Findings: map[string][]sarif.Finding{"opengrep": {fA}}})
	if p.Seen[0].SeenAgain {
		t.Fatal("seen_again twice in one scan")
	}
}

func TestFixedOrVerifiedIssueReopens(t *testing.T) {
	for _, st := range []issuestate.Status{issuestate.Fixed, issuestate.Verified} {
		e := existing(fA, st, scanA)
		p, err := BuildPlan(PlanInput{ScanID: scanB, Runs: allOK, Existing: []ExistingIssue{e},
			Findings: map[string][]sarif.Finding{"opengrep": {fA}}})
		if err != nil {
			t.Fatal(err)
		}
		if len(p.Seen) != 1 || !p.Seen[0].Reopen || p.Seen[0].SeenAgain || p.Stats.Reopened != 1 {
			t.Fatalf("%s: %+v", st, p)
		}
	}
}

func TestExceptionsKeepStatusButRecordOccurrence(t *testing.T) {
	for _, st := range []issuestate.Status{issuestate.FalsePositive, issuestate.RiskAccepted} {
		e := existing(fA, st, scanA)
		p, _ := BuildPlan(PlanInput{ScanID: scanB, Runs: allOK, Existing: []ExistingIssue{e},
			Findings: map[string][]sarif.Finding{"opengrep": {fA}}})
		if len(p.Seen) != 1 || p.Seen[0].Reopen || p.Seen[0].SeenAgain || len(p.New) != 0 || p.Stats.Total != 1 {
			t.Fatalf("%s: %+v", st, p)
		}
	}
	// ...and they are never auto-fixed when they disappear.
	e := existing(fA, issuestate.RiskAccepted, scanA)
	p, _ := BuildPlan(PlanInput{ScanID: scanB, Runs: allOK, Existing: []ExistingIssue{e}, GuardRatio: 1})
	if len(p.Fix) != 0 || p.NeedsConfirmation {
		t.Fatalf("%+v", p)
	}
}

func TestSeverityChangeUnlessOverridden(t *testing.T) {
	e := existing(fA, issuestate.Open, scanA)
	e.Severity = severity.Low
	p, _ := BuildPlan(PlanInput{ScanID: scanB, Runs: allOK, Existing: []ExistingIssue{e},
		Findings: map[string][]sarif.Finding{"opengrep": {fA}}})
	if p.Seen[0].NewSeverity != severity.High {
		t.Fatalf("%+v", p.Seen[0])
	}
	e.SeverityOverridden = true
	p, _ = BuildPlan(PlanInput{ScanID: scanB, Runs: allOK, Existing: []ExistingIssue{e},
		Findings: map[string][]sarif.Finding{"opengrep": {fA}}})
	if p.Seen[0].NewSeverity != "" {
		t.Fatal("overridden severity changed")
	}
}

func TestMissingActiveIssuesAreFixed(t *testing.T) {
	gone := existing(fB, issuestate.InProgress, scanA)
	kept := existing(fA, issuestate.Open, scanA)
	p, _ := BuildPlan(PlanInput{ScanID: scanB, Runs: allOK, Existing: []ExistingIssue{gone, kept}, GuardRatio: 0.5,
		Findings: map[string][]sarif.Finding{"opengrep": {fA}}})
	if len(p.Fix) != 1 || p.Fix[0].ID != gone.ID || p.Stats.Fixed != 1 || p.NeedsConfirmation {
		t.Fatalf("%+v", p)
	}
}

// A tool that failed or timed out didn't look, so its issues stay open.
func TestFailedToolIssuesAreNotFixed(t *testing.T) {
	trivyIssue := existing(fTrivy, issuestate.Open, scanA)
	keep := []ExistingIssue{trivyIssue, existing(fA, issuestate.Open, scanA), existing(fB, issuestate.Open, scanA)}
	for _, st := range []sandbox.ToolStatus{sandbox.Failed, sandbox.Timeout, sandbox.Skipped} {
		r := runs(map[string]sandbox.ToolStatus{"opengrep": sandbox.Succeeded, "trivy": st})
		p, _ := BuildPlan(PlanInput{ScanID: scanB, Runs: r, Existing: keep, GuardRatio: 1,
			Findings: map[string][]sarif.Finding{"opengrep": {fA, fB}, "trivy": {fTrivy}}})
		if len(p.Fix) != 0 || len(p.New) != 0 {
			t.Fatalf("%s: %+v", st, p)
		}
		if _, ok := p.ToolCounts["trivy"]; ok || p.Stats.Total != 2 {
			t.Fatalf("%s: findings of a failed tool counted: %+v", st, p)
		}
	}
	// A tool that wasn't selected for this scan doesn't fix anything either.
	p, _ := BuildPlan(PlanInput{ScanID: scanB, Runs: runs(map[string]sandbox.ToolStatus{"opengrep": sandbox.Succeeded}),
		Existing: keep, GuardRatio: 1, Findings: map[string][]sarif.Finding{"opengrep": {fA, fB}}})
	if len(p.Fix) != 0 {
		t.Fatalf("%+v", p.Fix)
	}
}

func TestAutoFixGuard(t *testing.T) {
	var ex []ExistingIssue
	for i := range 10 {
		ex = append(ex, existing(finding("opengrep", "r", "f.py", i+1), issuestate.Open, scanA))
		ex[i].Fingerprint = uuid.NewString() // distinct identities
	}
	// All 10 vanish: 10 > 0.5*10 → nothing fixed, flag for confirmation.
	p, _ := BuildPlan(PlanInput{ScanID: scanB, Runs: allOK, Existing: ex, GuardRatio: 0.5})
	if len(p.Fix) != 0 || !p.NeedsConfirmation || p.Stats.Fixed != 0 {
		t.Fatalf("%+v", p)
	}
	// Exactly half vanish: allowed.
	keep := map[string][]sarif.Finding{}
	for i := range 5 {
		f := finding("opengrep", "r", "f.py", i+1)
		ex[i].Fingerprint = fpOf(f)
		keep["opengrep"] = append(keep["opengrep"], f)
	}
	p, _ = BuildPlan(PlanInput{ScanID: scanB, Runs: allOK, Existing: ex, GuardRatio: 0.5, Findings: keep})
	if len(p.Fix) != 5 || p.NeedsConfirmation {
		t.Fatalf("fix %d needs %v", len(p.Fix), p.NeedsConfirmation)
	}
	for _, c := range []struct {
		cand, active int
		ratio        float64
		want         bool
	}{{0, 0, 0, true}, {1, 1, 0.5, false}, {1, 2, 0.5, true}, {3, 3, 1, true}, {1, 10, 0, false}} {
		if AutoFixAllowed(c.cand, c.active, c.ratio) != c.want {
			t.Errorf("%+v", c)
		}
	}
}

// A retried attempt replays the plan against the state the first one wrote.
func TestReplayIsIdempotent(t *testing.T) {
	gone := existing(fB, issuestate.Open, scanA)
	reg := existing(fTrivy, issuestate.Fixed, scanA)
	in := PlanInput{ScanID: scanB, Runs: allOK, GuardRatio: 1, Existing: []ExistingIssue{gone, reg},
		Findings: map[string][]sarif.Finding{"opengrep": {fA}, "trivy": {fTrivy}}}
	first, _ := BuildPlan(in)
	if len(first.New) != 1 || len(first.Fix) != 1 || first.Stats.Reopened != 1 {
		t.Fatalf("%+v", first)
	}
	// State after applying the first plan.
	gone.Status, reg.Status, reg.LastSeenScanID = issuestate.Fixed, issuestate.Reopened, scanB
	created := existing(fA, issuestate.Open, scanB)
	in.Existing = []ExistingIssue{gone, reg, created}
	second, _ := BuildPlan(in)
	if len(second.New)+len(second.Fix)+second.Stats.Reopened != 0 {
		t.Fatalf("replay changed state: %+v", second)
	}
	for _, s := range second.Seen {
		if s.SeenAgain || s.Reopen || s.NewSeverity != "" {
			t.Fatalf("replay emitted an event: %+v", s)
		}
	}
}

func TestDuplicateFingerprintsCountOnce(t *testing.T) {
	p, _ := BuildPlan(PlanInput{ScanID: scanA, Runs: allOK, Findings: map[string][]sarif.Finding{"opengrep": {fA}}})
	if p.Stats.Total != 1 {
		t.Fatal(p.Stats)
	}
	// Fingerprints skips tools that didn't succeed.
	if got := Fingerprints(map[string][]sarif.Finding{"trivy": {fTrivy}}, map[string]bool{}); len(got) != 0 {
		t.Fatal(got)
	}
}
