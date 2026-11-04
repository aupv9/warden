package results

import (
	"strings"
	"testing"

	"github.com/google/uuid"

	"github.com/aupv9/warden/backend/internal/domain/issuestate"
	"github.com/aupv9/warden/backend/internal/scan/sandbox"
	"github.com/aupv9/warden/backend/internal/scan/sarif"
)

var importOK = []sandbox.ToolRun{{Tool: sarif.ToolExternal, Status: sandbox.Succeeded}}

func external(rule, path string) sarif.Finding {
	f := finding(sarif.ToolExternal, rule, path, 1)
	f.ImportTarget = "(import) codeql"
	return f
}

func fpKey(f sarif.Finding) string {
	k := f.Key()
	return fpOf(sarif.Finding{Tool: k.Tool, RuleID: k.RuleID, FilePath: k.FilePath, ContentKey: k.ContentKey})
}

// An import fixes its own issues that are gone, and never an issue of a
// Warden scanner, even one the plan is handed (Process loads only external
// issues of the import's tool and target; the plan makes sure).
func TestImportNeverTouchesWardenIssues(t *testing.T) {
	kept, gone := external("js/xss", "a.js"), external("js/sqli", "b.js")
	warden := existing(fA, issuestate.Open, scanA)
	wardenFixed := existing(fB, issuestate.Fixed, scanA)
	ex := []ExistingIssue{
		{ID: uuid.New(), Fingerprint: fpKey(kept), Tool: sarif.ToolExternal, Status: issuestate.Open, Severity: kept.Severity, LastSeenScanID: scanA},
		{ID: uuid.New(), Fingerprint: fpKey(gone), Tool: sarif.ToolExternal, Status: issuestate.Open, Severity: gone.Severity, LastSeenScanID: scanA},
		warden, wardenFixed,
	}
	// Even a forged run and finding of a Warden tool are ignored by an import.
	runs := append([]sandbox.ToolRun{{Tool: "opengrep", Status: sandbox.Succeeded}}, importOK...)
	p, err := BuildPlan(PlanInput{ScanID: scanB, Runs: runs, GuardRatio: 1, Import: true, Existing: ex,
		Findings: map[string][]sarif.Finding{sarif.ToolExternal: {kept}, "opengrep": {fB}}})
	if err != nil {
		t.Fatal(err)
	}
	if len(p.Fix) != 1 || p.Fix[0].Fingerprint != fpKey(gone) || len(p.New) != 0 || len(p.Seen) != 1 || p.Stats.Reopened != 0 {
		t.Fatalf("%+v", p)
	}
	if _, ok := p.ToolCounts["opengrep"]; ok {
		t.Fatalf("tool counts %v", p.ToolCounts)
	}
}

// A Warden scan never fixes (or matches) an external issue, even one at its
// target and with a run that claims tool external succeeded.
func TestWardenScanNeverTouchesExternalIssues(t *testing.T) {
	ext := external("js/xss", "a.js")
	ex := []ExistingIssue{{ID: uuid.New(), Fingerprint: fpKey(ext), Tool: sarif.ToolExternal, Status: issuestate.Open, LastSeenScanID: scanA}}
	runs := append([]sandbox.ToolRun{{Tool: "opengrep", Status: sandbox.Succeeded}}, importOK...)
	p, err := BuildPlan(PlanInput{ScanID: scanB, Runs: runs, GuardRatio: 1, Existing: ex,
		Findings: map[string][]sarif.Finding{"opengrep": {}, sarif.ToolExternal: {ext}}})
	if err != nil {
		t.Fatal(err)
	}
	if len(p.Fix)+len(p.New)+len(p.Seen) != 0 {
		t.Fatalf("%+v", p)
	}
}

// The org rule logic is Opengrep's and Gitleaks': an imported "org.x" rule
// is an ordinary rule, fixed when it is gone.
func TestImportedOrgRuleIDIsNoOrgRule(t *testing.T) {
	f := external("org.payments", "a.js")
	ex := []ExistingIssue{{ID: uuid.New(), Fingerprint: fpKey(f), Tool: sarif.ToolExternal, RuleID: "org.payments",
		Status: issuestate.Open, LastSeenScanID: scanA}}
	p, err := BuildPlan(PlanInput{ScanID: scanB, Runs: importOK, GuardRatio: 1, Import: true, Existing: ex,
		Findings: map[string][]sarif.Finding{sarif.ToolExternal: {}}})
	if err != nil || len(p.Fix) != 1 {
		t.Fatalf("%+v %v", p, err)
	}
}

func TestCheckImport(t *testing.T) {
	imp := &Import{Tool: "codeql"}
	ext := external("r", "a.js")
	for name, c := range map[string]struct {
		in Input
		ok bool
	}{
		"import":                {Input{Import: imp, Runs: importOK, Findings: map[string][]sarif.Finding{sarif.ToolExternal: {ext}}}, true},
		"source":                {Input{Runs: allOK, Findings: map[string][]sarif.Finding{"opengrep": {fA}}}, true},
		"import without tool":   {Input{Import: &Import{}, Runs: importOK}, false},
		"import with opengrep":  {Input{Import: imp, Runs: allOK}, false},
		"import with its issue": {Input{Import: imp, Runs: importOK, Findings: map[string][]sarif.Finding{"opengrep": {fA}}}, false},
		"mislabelled finding":   {Input{Import: imp, Runs: importOK, Findings: map[string][]sarif.Finding{sarif.ToolExternal: {fA}}}, false},
		"source with external":  {Input{Runs: importOK}, false},
		"source with findings":  {Input{Runs: allOK, Findings: map[string][]sarif.Finding{sarif.ToolExternal: {ext}}}, false},
	} {
		if err := checkImport(c.in); (err == nil) != c.ok {
			t.Errorf("%s: %v", name, err)
		}
	}
}

// The guard ratio holds for imports as for scans: an import that would fix
// most of its target's issues fixes none.
func TestImportAutoFixGuard(t *testing.T) {
	var ex []ExistingIssue
	for _, r := range strings.Split("a b c d e f", " ") {
		f := external(r, r+".js")
		ex = append(ex, ExistingIssue{ID: uuid.New(), Fingerprint: fpKey(f), Tool: sarif.ToolExternal, Status: issuestate.Open, LastSeenScanID: scanA})
	}
	p, err := BuildPlan(PlanInput{ScanID: scanB, Runs: importOK, GuardRatio: 0.5, Import: true, Existing: ex,
		Findings: map[string][]sarif.Finding{sarif.ToolExternal: {}}})
	if err != nil || len(p.Fix) != 0 || !p.NeedsConfirmation {
		t.Fatalf("%+v %v", p, err)
	}
}
