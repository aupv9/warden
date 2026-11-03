package servicetest

import (
	"context"
	"errors"
	"maps"
	"slices"
	"strings"
	"time"

	"github.com/google/uuid"

	"github.com/aupv9/warden/backend/internal/domain/rbac"
	"github.com/aupv9/warden/backend/internal/rules"
	"github.com/aupv9/warden/backend/internal/service"
	"github.com/aupv9/warden/backend/internal/worker"
)

var errRLS = errors.New("new row violates row-level security policy")

// RuleRow is a stored scan_rule.
type RuleRow struct {
	service.ScanRule
	CreatedByID, UpdatedByID uuid.UUID
	DeletedAt                *time.Time
}

// RuleVersionRow is a stored scan_rule_version.
type RuleVersionRow struct {
	service.ScanRuleVersion
	OrgID, RuleID, CreatedByID uuid.UUID
	Severity                   string
}

// RuleTestRow is a stored scan_rule_test.
type RuleTestRow struct {
	service.NewRuleTest
	State      string
	Findings   []service.RuleTestFinding
	Error      *string
	FinishedAt *time.Time
}

// ruleState holds the scan-rule tables (v0.6) and the test_rules jobs.
type ruleState struct {
	Rules    map[uuid.UUID]RuleRow
	Versions []RuleVersionRow
	Tests    map[uuid.UUID]RuleTestRow
	TestJobs []worker.TestRulesArgs
}

func (s ruleState) clone() ruleState {
	return ruleState{Rules: maps.Clone(s.Rules), Versions: slices.Clone(s.Versions), Tests: maps.Clone(s.Tests),
		TestJobs: slices.Clone(s.TestJobs)}
}

// StoredRule returns a scan_rule row as stored (any org, deleted or not).
func (f *Fake) StoredRule(id uuid.UUID) (RuleRow, bool) {
	r, ok := f.st.rules.Rules[id]
	return r, ok
}

// RuleVersions returns a rule's stored versions, oldest first.
func (f *Fake) RuleVersions(id uuid.UUID) []RuleVersionRow {
	var out []RuleVersionRow
	for _, v := range f.st.rules.Versions {
		if v.RuleID == id {
			out = append(out, v)
		}
	}
	return out
}

// StoredRuleTest returns a scan_rule_test row as stored.
func (f *Fake) StoredRuleTest(id uuid.UUID) (RuleTestRow, bool) {
	t, ok := f.st.rules.Tests[id]
	return t, ok
}

// SetRuleTest changes a stored test (as the worker would).
func (f *Fake) SetRuleTest(id uuid.UUID, fn func(*RuleTestRow)) {
	t := f.st.rules.Tests[id]
	fn(&t)
	f.st.rules.Tests[id] = t
}

// TestJobs returns the enqueued test_rules jobs.
func (f *Fake) TestJobs() []worker.TestRulesArgs { return slices.Clone(f.st.rules.TestJobs) }

func (f *Fake) rule(id uuid.UUID) (RuleRow, bool) {
	r, ok := f.st.rules.Rules[id]
	return r, ok && r.OrgID == f.org && r.DeletedAt == nil
}

func (f *Fake) ruleOut(r RuleRow) service.ScanRule {
	out := r.ScanRule
	out.RuleID = rules.Prefix + out.Key
	out.ProjectIDs = slices.Clone(out.ProjectIDs)
	out.CreatedBy, out.UpdatedBy = f.refp(&r.CreatedByID), f.refp(&r.UpdatedByID)
	return out
}

func (f *Fake) LockScanRules(context.Context, uuid.UUID) error { return f.fail("LockScanRules") }

func (f *Fake) ScanRules(_ context.Context, tool string) ([]service.ScanRule, error) {
	if err := f.fail("ScanRules"); err != nil {
		return nil, err
	}
	var out []service.ScanRule
	for id := range f.st.rules.Rules {
		if r, ok := f.rule(id); ok && (tool == "" || r.Tool == tool) {
			out = append(out, f.ruleOut(r))
		}
	}
	slices.SortFunc(out, func(a, b service.ScanRule) int {
		if c := strings.Compare(a.Tool, b.Tool); c != 0 {
			return c
		}
		return strings.Compare(a.Key, b.Key)
	})
	return out, nil
}

func (f *Fake) ScanRule(_ context.Context, id uuid.UUID, _ bool) (service.ScanRule, error) {
	if err := f.fail("ScanRule"); err != nil {
		return service.ScanRule{}, err
	}
	r, ok := f.rule(id)
	if !ok {
		return service.ScanRule{}, service.ErrNotFound
	}
	return f.ruleOut(r), nil
}

func (f *Fake) ScanRuleUsage(_ context.Context, tool string) (int, int64, error) {
	n, bytes := 0, int64(0)
	for id := range f.st.rules.Rules {
		if r, ok := f.rule(id); ok {
			bytes += int64(len(r.Body))
			if r.Tool == tool {
				n++
			}
		}
	}
	return n, bytes, f.fail("ScanRuleUsage")
}

func (f *Fake) appendVersion(r service.ScanRule, by uuid.UUID, at service.Time) {
	f.st.rules.Versions = append(f.st.rules.Versions, RuleVersionRow{OrgID: r.OrgID, RuleID: r.ID, CreatedByID: by,
		Severity: r.Severity, ScanRuleVersion: service.ScanRuleVersion{Version: r.Version, Body: r.Body, SHA256: r.SHA256,
			Name: r.Name, Enabled: r.Enabled, ProjectIDs: slices.Clone(r.ProjectIDs), CreatedAt: at}})
}

func (f *Fake) InsertScanRule(_ context.Context, r service.ScanRule) error {
	if err := f.fail("InsertScanRule"); err != nil {
		return err
	}
	if r.OrgID != f.org {
		return errRLS
	}
	for id := range f.st.rules.Rules {
		if x, ok := f.rule(id); ok && x.Tool == r.Tool && x.Key == r.Key {
			return service.ErrConflict
		}
	}
	if f.st.rules.Rules == nil {
		f.st.rules.Rules = map[uuid.UUID]RuleRow{}
	}
	r.ProjectIDs = slices.Clone(r.ProjectIDs)
	f.st.rules.Rules[r.ID] = RuleRow{ScanRule: r, CreatedByID: r.CreatedBy.ID, UpdatedByID: r.CreatedBy.ID}
	f.appendVersion(r, r.CreatedBy.ID, r.CreatedAt)
	return nil
}

func (f *Fake) UpdateScanRule(_ context.Context, r service.ScanRule) error {
	if err := f.fail("UpdateScanRule"); err != nil {
		return err
	}
	old, ok := f.rule(r.ID)
	if !ok {
		return nil
	}
	old.Name, old.Body, old.SHA256, old.Severity, old.Enabled = r.Name, r.Body, r.SHA256, r.Severity, r.Enabled
	old.ProjectIDs, old.Version, old.UpdatedByID, old.UpdatedAt = slices.Clone(r.ProjectIDs), r.Version, r.UpdatedBy.ID, r.UpdatedAt
	f.st.rules.Rules[r.ID] = old
	f.appendVersion(old.ScanRule, r.UpdatedBy.ID, r.UpdatedAt)
	return nil
}

func (f *Fake) DeleteScanRule(_ context.Context, id, by uuid.UUID, at time.Time) error {
	if err := f.fail("DeleteScanRule"); err != nil {
		return err
	}
	r, ok := f.rule(id)
	if !ok {
		return nil
	}
	r.DeletedAt, r.UpdatedByID, r.UpdatedAt = &at, by, service.Time(at)
	f.st.rules.Rules[id] = r
	return nil
}

func (f *Fake) ScanRuleVersions(_ context.Context, id uuid.UUID, before, limit int) ([]service.ScanRuleVersion, error) {
	if err := f.fail("ScanRuleVersions"); err != nil {
		return nil, err
	}
	var out []service.ScanRuleVersion
	for _, v := range f.st.rules.Versions {
		if v.RuleID == id && v.OrgID == f.org && (before == 0 || v.Version < before) {
			x := v.ScanRuleVersion
			x.ProjectIDs = slices.Clone(x.ProjectIDs)
			x.CreatedBy = f.refp(&v.CreatedByID)
			out = append(out, x)
		}
	}
	slices.SortFunc(out, func(a, b service.ScanRuleVersion) int { return b.Version - a.Version })
	if len(out) > limit {
		out = out[:limit]
	}
	return out, nil
}

func (f *Fake) UserProjectRoles(_ context.Context, userID uuid.UUID) (map[uuid.UUID]rbac.Role, error) {
	out := map[uuid.UUID]rbac.Role{}
	for k, pm := range f.st.PMembers {
		if k[1] == userID && pm.OrgID == f.org {
			out[k[0]] = pm.Role
		}
	}
	return out, f.fail("UserProjectRoles")
}

func (f *Fake) LockRuleTests(context.Context, uuid.UUID) error { return f.fail("LockRuleTests") }

func (f *Fake) RuleTestsSince(_ context.Context, userID uuid.UUID, since time.Time) (int, time.Time, error) {
	n, oldest := 0, time.Time{}
	for _, t := range f.st.rules.Tests {
		if t.OrgID == f.org && t.CreatedBy == userID && t.CreatedAt.After(since) {
			n++
			if oldest.IsZero() || t.CreatedAt.Before(oldest) {
				oldest = t.CreatedAt
			}
		}
	}
	return n, oldest, f.fail("RuleTestsSince")
}

func (f *Fake) InsertRuleTest(_ context.Context, t service.NewRuleTest) error {
	if err := f.fail("InsertRuleTest"); err != nil {
		return err
	}
	if t.OrgID != f.org {
		return errRLS
	}
	if f.st.rules.Tests == nil {
		f.st.rules.Tests = map[uuid.UUID]RuleTestRow{}
	}
	f.st.rules.Tests[t.ID] = RuleTestRow{NewRuleTest: t, State: "queued"}
	f.st.rules.TestJobs = append(f.st.rules.TestJobs, worker.TestRulesArgs{OrgID: t.OrgID, TestID: t.ID})
	return nil
}

func (f *Fake) RuleTest(_ context.Context, id uuid.UUID) (service.RuleTest, error) {
	if err := f.fail("RuleTest"); err != nil {
		return service.RuleTest{}, err
	}
	t, ok := f.st.rules.Tests[id]
	if !ok || t.OrgID != f.org {
		return service.RuleTest{}, service.ErrNotFound
	}
	out := service.RuleTest{ID: t.ID, State: t.State, Findings: slices.Clone(t.Findings), Error: t.Error,
		CreatedAt: service.Time(t.CreatedAt), CreatedBy: t.CreatedBy}
	if t.FinishedAt != nil {
		at := service.Time(*t.FinishedAt)
		out.FinishedAt = &at
	}
	return out, nil
}

// orgRule emulates the issue lookup: the live rule with the key, else the
// most recently deleted one.
func (f *Fake) orgRule(i IssueRow) *service.IssueOrgRule {
	if (i.Tool != "opengrep" && i.Tool != "gitleaks") || !strings.HasPrefix(i.RuleID, rules.Prefix) {
		return nil
	}
	out := &service.IssueOrgRule{RuleID: i.RuleID}
	var best *RuleRow
	for _, r := range f.st.rules.Rules {
		if r.OrgID != i.OrgID || r.Tool != i.Tool || rules.Prefix+r.Key != i.RuleID {
			continue
		}
		if best == nil || (best.DeletedAt != nil && (r.DeletedAt == nil || r.DeletedAt.After(*best.DeletedAt))) {
			best = &r
		}
	}
	if best != nil {
		out.Name, out.ScanRuleID = &best.Name, &best.ID
	}
	return out
}

// ParseRule stands in for rules.Parse (service.Config.ParseRule) in tests. A
// body is lines of "field: value": "id" is the key and "severity" the
// severity (default medium). A line "bad" is a problem at that line, column
// 1; a body without an id is one problem without a position. The canonical
// form is the body without blank lines and surrounding space.
func ParseRule(tool rules.Tool, body []byte) (rules.Rule, []rules.Problem) {
	r := rules.Rule{Tool: tool, Severity: "medium"}
	var problems []rules.Problem
	var lines []string
	for n, line := range strings.Split(string(body), "\n") {
		line = strings.TrimSpace(line)
		if line == "" {
			continue
		}
		if line == "bad" {
			problems = append(problems, rules.Problem{Line: n + 1, Column: 1, Message: "bad line"})
		}
		if k, v, ok := strings.Cut(line, ":"); ok {
			switch strings.TrimSpace(k) {
			case "id":
				r.Key = strings.TrimSpace(v)
			case "severity":
				r.Severity = strings.TrimSpace(v)
			}
		}
		lines = append(lines, line)
	}
	if r.Key == "" {
		problems = append(problems, rules.Problem{Message: "the rule has no id"})
	}
	if len(problems) > 0 {
		return rules.Rule{}, problems
	}
	r.Canonical = []byte(strings.Join(lines, "\n") + "\n")
	return r, nil
}
