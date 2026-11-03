package worker

import (
	"encoding/json"
	"errors"
	"slices"
	"strings"
	"testing"

	"github.com/google/uuid"

	"github.com/aupv9/warden/backend/internal/rules"
	"github.com/aupv9/warden/backend/internal/scan/results"
	"github.com/aupv9/warden/backend/internal/scan/sarif"
	st "github.com/aupv9/warden/backend/internal/scan/scantest"
	"github.com/aupv9/warden/backend/internal/worker/dbtest"
)

// fakeRules replaces rules.Parse and rules.Render (stubs until the rules
// branch lands, and beside the point here): a body "key:severity" parses
// unless it starts with "bad", and renders as the keys, one per line.
func fakeRules(t *testing.T) {
	t.Helper()
	p, r := parseRule, renderRules
	t.Cleanup(func() { parseRule, renderRules = p, r })
	parseRule = func(tool rules.Tool, body []byte) (rules.Rule, []rules.Problem) {
		key, sev, _ := strings.Cut(string(body), ":")
		if strings.HasPrefix(key, "bad") {
			return rules.Rule{}, []rules.Problem{{Message: "invalid"}}
		}
		return rules.Rule{Tool: tool, Key: key, Severity: sev, Canonical: body}, nil
	}
	renderRules = func(tool rules.Tool, rs []rules.Rule) ([]byte, error) {
		var b strings.Builder
		for _, r := range rs {
			if r.Tool != tool {
				return nil, errors.New("mixed tools")
			}
			b.WriteString(string(tool) + " " + r.ID() + "\n")
		}
		return []byte(b.String()), nil
	}
}

func TestOrgRulePrefixMatchesSARIF(t *testing.T) {
	if rules.Prefix != sarif.OrgRulePrefix {
		t.Fatal("rules.Prefix and sarif.OrgRulePrefix differ")
	}
}

// A scan runs the org's enabled rules for its tools: rendered into a
// read-only file the tool's sandbox mounts, the tool's command extended
// (never replaced), findings at the rule's severity, and the rules that ran
// recorded on the scan. A rule that no longer parses is skipped, not run and
// not recorded; the scan goes on.
func TestRunScanWithOrgRules(t *testing.T) {
	fakeRules(t)
	h := newHarness(t, "queued")
	ruleRows := [][]any{
		{uuid.New(), "opengrep", "bad-one", []byte("bad-one:high"), "high", 1, "h0"},
		{uuid.New(), "opengrep", "no-eval", []byte("no-eval:low"), "low", 3, "h1"},
		{uuid.New(), "opengrep", "mismatch", []byte("other:low"), "low", 1, "h2"},
	}
	h.db = dbtest.Loose(t, h.scanSteps("queued", dbtest.Step{Prefix: orgRulesQuery, Rows: ruleRows})...)
	h.sb.docs = map[string]st.M{"opengrep": st.Doc([]any{
		st.M{"ruleId": "rules.org.no-eval", "level": "error", "message": st.M{"text": "m"}, "locations": []any{st.Loc("/src/app/a.py", 1)}},
	})}
	if err := h.run(1); err != nil {
		t.Fatal(err)
	}
	q := h.db.Calls(orgRulesQuery)
	if len(q) != 1 || q[0].Args[0] != h.org || !slices.Equal(q[0].Args[1].([]string), []string{"opengrep"}) || q[0].Args[2] != h.project {
		t.Fatalf("%v", q)
	}
	if len(h.sb.specs) != 1 || !slices.Contains(h.sb.specs[0].Command, "/rules/opengrep.yml") ||
		!slices.Contains(h.sb.specs[0].Command, "/data/rules") {
		t.Fatalf("%+v", h.sb.specs)
	}
	m := h.sb.mounted["rules/opengrep.yml"]
	if string(m.data) != "opengrep org.no-eval\n" || m.mode != 0o444 {
		t.Fatalf("%q %v", m.data, m.mode)
	}
	created := h.db.Calls("INSERT INTO issue (")
	if len(created) != 1 || created[0].Args[6] != "org.no-eval" || created[0].Args[10] != "low" {
		t.Fatalf("%v", created)
	}
	fin := h.db.Calls("UPDATE scan SET status = $2, error_code = NULL")
	var refs []results.OrgRuleRef
	if len(fin) != 1 || json.Unmarshal(fin[0].Args[5].([]byte), &refs) != nil ||
		!slices.Equal(refs, []results.OrgRuleRef{{RuleID: "org.no-eval", Tool: "opengrep", Version: 3, SHA256: "h1"}}) {
		t.Fatalf("%v", fin)
	}
	h.assertCleaned()
	h.assertScoped()
}

// The rules of a tool that failed are not recorded (and fix nothing).
func TestRunScanOrgRulesOfFailedTool(t *testing.T) {
	fakeRules(t)
	h := newHarness(t, "queued")
	h.db = dbtest.Loose(t, h.scanSteps("queued",
		dbtest.Step{Prefix: "SELECT status, project_id", Rows: row("queued", h.project, objectKey, h.sha, []string{"opengrep", "checkov"}, false, "WEB", "source", "")},
		dbtest.Step{Prefix: orgRulesQuery, Rows: [][]any{{uuid.New(), "opengrep", "k", []byte("k:high"), "high", 1, "h"}}})...)
	h.env.Images = map[string]string{"opengrep": testImages["opengrep"], "checkov": testImages["opengrep"]}
	h.sb.status["opengrep"] = "failed"
	if err := h.run(1); err != nil {
		t.Fatal(err)
	}
	fin := h.db.Calls("UPDATE scan SET status = $2, error_code = NULL")
	if len(fin) != 1 || fin[0].Args[1] != "partial" || string(fin[0].Args[5].([]byte)) != "[]" {
		t.Fatalf("%v", fin)
	}
}

// No rules: the tools run exactly as before, nothing is mounted at /rules.
func TestRunScanWithoutOrgRules(t *testing.T) {
	fakeRules(t)
	h := newHarness(t, "queued")
	if err := h.run(1); err != nil {
		t.Fatal(err)
	}
	if len(h.sb.specs) != 1 || h.sb.specs[0].OrgRules != "" || slices.Contains(h.sb.specs[0].Command, "/rules/opengrep.yml") {
		t.Fatalf("%+v", h.sb.specs)
	}
	for p := range h.sb.mounted {
		if strings.HasPrefix(p, "rules") {
			t.Fatal(p)
		}
	}
	if fin := h.db.Calls("UPDATE scan SET status = $2, error_code = NULL"); string(fin[0].Args[5].([]byte)) != "[]" {
		t.Fatal(fin)
	}
}

// A tool whose rules can't be rendered runs Warden's rules only.
func TestRenderFailureRunsWardenRulesOnly(t *testing.T) {
	fakeRules(t)
	renderRules = func(rules.Tool, []rules.Rule) ([]byte, error) { return nil, errors.New("boom") }
	h := newHarness(t, "queued", dbtest.Step{Prefix: orgRulesQuery, Rows: [][]any{{uuid.New(), "opengrep", "k", []byte("k:high"), "high", 1, "h"}}})
	if err := h.run(1); err != nil {
		t.Fatal(err)
	}
	if h.sb.specs[0].OrgRules != "" {
		t.Fatalf("%+v", h.sb.specs[0])
	}
	if fin := h.db.Calls("UPDATE scan SET status = $2, error_code = NULL"); fin[0].Args[1] != "completed" || string(fin[0].Args[5].([]byte)) != "[]" {
		t.Fatal(fin)
	}
}

// Image scans don't query org rules at all.
func TestImageScanLoadsNoOrgRules(t *testing.T) {
	h := newHarness(t, "queued")
	rs, err := loadOrgRules(t.Context(), h.db, h.org, h.project, []string{"trivy"}, quietLog())
	if err != nil || rs != nil || len(h.db.Calls(orgRulesQuery)) != 0 {
		t.Fatal(rs, err)
	}
}
