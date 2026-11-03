//go:build integration

package store_test

import (
	"encoding/json"
	"strings"
	"testing"
	"time"

	"github.com/aupv9/warden/backend/internal/service"
	"github.com/aupv9/warden/backend/internal/service/servicetest"
)

// The scan-rule routes against the real schema: versions, the optimistic
// lock, soft delete, RLS between orgs, a member's view, the audit trail
// (never the body), the test row with its River job (never the snippet), and
// the org rule on scans and issues.
func TestScanRulesAgainstSchema(t *testing.T) {
	w := newWorld(t)
	clock := time.Now().UTC()
	svc := service.New(w.db, w.objs, service.Config{ParseRule: servicetest.ParseRule}, nil)
	svc.SetClock(func() time.Time { return clock })
	a, b := w.org("SRA"), w.org("SRB")
	lead, dev, otherLead := w.actor("SRAlead", a.id), w.actor("SRAdev", a.id), w.actor("SRBlead", b.id)

	body := "id: no-eval\nseverity: critical\npattern: internal-host.corp\n"
	rule, err := svc.CreateScanRule(ctx, lead, service.CreateScanRuleInput{Tool: "opengrep", Name: "No eval", Body: body})
	if err != nil || rule.Version != 1 || rule.RuleID != "org.no-eval" || rule.CreatedBy == nil || rule.CreatedBy.Email == "" ||
		rule.ProjectIDs != nil || rule.Severity != "critical" {
		t.Fatal(rule, err)
	}
	scoped, err := svc.CreateScanRule(ctx, lead, service.CreateScanRuleInput{Tool: "gitleaks", Name: "Scoped", Body: "id: tok",
		ProjectIDs: []string{a.project.String()}})
	if err != nil || len(scoped.ProjectIDs) != 1 {
		t.Fatal(scoped, err)
	}
	// Duplicate key: 409 from the unique index, and the transaction is gone.
	if _, err := svc.CreateScanRule(ctx, lead, service.CreateScanRuleInput{Tool: "opengrep", Name: "x", Body: "id: no-eval"}); code(err) != "CONFLICT" {
		t.Fatal(err)
	}
	// Another org's project is unknown; another org sees nothing.
	if _, err := svc.CreateScanRule(ctx, lead, service.CreateScanRuleInput{Tool: "opengrep", Name: "x", Body: "id: y",
		ProjectIDs: []string{b.project.String()}}); code(err) != "VALIDATION_FAILED" {
		t.Fatal(err)
	}
	if _, err := svc.ScanRule(ctx, otherLead, rule.ID); code(err) != "NOT_FOUND" {
		t.Fatal(err)
	}
	if l, err := svc.ScanRules(ctx, otherLead, service.ScanRuleFilter{}); err != nil || len(l.Items) != 0 {
		t.Fatal(l, err)
	}
	if _, err := svc.CreateScanRule(ctx, otherLead, service.CreateScanRuleInput{Tool: "opengrep", Name: "x", Body: "id: no-eval"}); err != nil {
		t.Fatal(err) // keys are per org
	}
	// A developer of the project sees both, and can't write.
	if l, err := svc.ScanRules(ctx, dev, service.ScanRuleFilter{}); err != nil || len(l.Items) != 2 {
		t.Fatal(l, err)
	}
	if _, err := svc.UpdateScanRule(ctx, dev, rule.ID, service.UpdateScanRuleInput{Version: ptr(1), Enabled: ptr(false)}); code(err) != "FORBIDDEN" {
		t.Fatal(err)
	}

	// Updates: a version each, the lock, the history.
	clock = clock.Add(time.Minute)
	up, err := svc.UpdateScanRule(ctx, lead, rule.ID, service.UpdateScanRuleInput{Version: ptr(1), Name: ptr("No eval()"),
		Body: ptr("id: no-eval\nseverity: high\n")})
	if err != nil || up.Version != 2 || up.Severity != "high" || up.SHA256 == rule.SHA256 || up.UpdatedBy == nil {
		t.Fatal(up, err)
	}
	if _, err := svc.UpdateScanRule(ctx, lead, rule.ID, service.UpdateScanRuleInput{Version: ptr(1), Enabled: ptr(false)}); code(err) != "VERSION_CONFLICT" {
		t.Fatal(err)
	}
	if up, err = svc.UpdateScanRule(ctx, lead, rule.ID, service.UpdateScanRuleInput{Version: ptr(2), Enabled: ptr(false),
		ProjectIDs: service.Optional[[]string]{Set: true, Value: &[]string{a.project.String()}}}); err != nil || up.Version != 3 || up.Enabled {
		t.Fatal(up, err)
	}
	vs, err := svc.ScanRuleVersions(ctx, dev, rule.ID, service.PageParams{Limit: "2"})
	if err != nil || len(vs.Items) != 2 || vs.Items[0].Version != 3 || vs.Items[1].Version != 2 || vs.NextCursor == nil ||
		vs.Items[1].Body != "id: no-eval\nseverity: high\n" || vs.Items[0].CreatedBy == nil {
		t.Fatal(vs, err)
	}
	vs, err = svc.ScanRuleVersions(ctx, dev, rule.ID, service.PageParams{Limit: "2", Cursor: *vs.NextCursor})
	if err != nil || len(vs.Items) != 1 || vs.Items[0].Version != 1 || vs.Items[0].Body != body || vs.NextCursor != nil {
		t.Fatal(vs, err)
	}

	// Scans carry the rules they ran (written by the worker); issues name their rule.
	ownerExec(t, a.id, `UPDATE scan SET org_rules = $2 WHERE id = $1`, a.scan,
		`[{"rule_id": "org.no-eval", "tool": "opengrep", "version": 3, "sha256": "`+up.SHA256+`"}]`)
	sc, err := w.svc.Scan(ctx, dev, a.scan)
	if err != nil || len(sc.OrgRules) != 1 || sc.OrgRules[0].Version != 3 || sc.OrgRules[0].SHA256 != up.SHA256 {
		t.Fatal(sc, err)
	}
	if b, _ := json.Marshal(must(w.svc.Scan(ctx, w.actor("SRBdev", b.id), b.scan))); !strings.Contains(string(b), `"org_rules":[]`) {
		t.Fatal(string(b))
	}
	iss := w.issue(a, 1, "high", "open", nil, nil)
	ownerExec(t, a.id, `UPDATE issue SET rule_id = 'org.no-eval' WHERE id = $1`, iss)
	ghost := w.issue(a, 2, "high", "open", nil, nil)
	ownerExec(t, a.id, `UPDATE issue SET rule_id = 'org.gone' WHERE id = $1`, ghost)
	plain := w.issue(a, 3, "high", "open", nil, nil)
	if i := must(w.svc.Issue(ctx, dev, iss)); i.OrgRule == nil || *i.OrgRule.Name != "No eval()" || *i.OrgRule.ScanRuleID != rule.ID {
		t.Fatal(i.OrgRule)
	}
	if i := must(w.svc.Issue(ctx, dev, ghost)); i.OrgRule == nil || i.OrgRule.Name != nil || i.OrgRule.ScanRuleID != nil || i.OrgRule.RuleID != "org.gone" {
		t.Fatal(i.OrgRule)
	}
	if i := must(w.svc.Issue(ctx, dev, plain)); i.OrgRule != nil {
		t.Fatal(i.OrgRule)
	}

	// Delete: soft, versions kept, key free again, the issue still names it.
	if err := svc.DeleteScanRule(ctx, lead, rule.ID, "2"); code(err) != "VERSION_CONFLICT" {
		t.Fatal(err)
	}
	if err := svc.DeleteScanRule(ctx, lead, rule.ID, "3"); err != nil {
		t.Fatal(err)
	}
	if _, err := svc.ScanRule(ctx, lead, rule.ID); code(err) != "NOT_FOUND" {
		t.Fatal(err)
	}
	var versions int
	var deleted *time.Time
	ownerOne(t, a.id, `SELECT (SELECT count(*) FROM scan_rule_version WHERE scan_rule_id = $1), (SELECT deleted_at FROM scan_rule WHERE id = $1)`,
		[]any{rule.ID}, &versions, &deleted)
	if versions != 3 || deleted == nil {
		t.Fatal(versions, deleted)
	}
	if i := must(w.svc.Issue(ctx, dev, iss)); i.OrgRule == nil || *i.OrgRule.Name != "No eval()" || *i.OrgRule.ScanRuleID != rule.ID {
		t.Fatal(i.OrgRule)
	}
	again := must(svc.CreateScanRule(ctx, lead, service.CreateScanRuleInput{Tool: "opengrep", Name: "Again", Body: "id: no-eval"}))
	if i := must(w.svc.Issue(ctx, dev, iss)); *i.OrgRule.ScanRuleID != again.ID {
		t.Fatal(i.OrgRule)
	}

	// The audit trail names rules by id, tool, key and digest only.
	entries := must(w.svc.AuditLog(ctx, w.actor("SRAadmin", a.id), service.AuditFilter{}))
	var actions []string
	for _, e := range entries.Items {
		if !strings.HasPrefix(e.Action, "scan_rule.") {
			continue
		}
		actions = append(actions, e.Action)
		raw, _ := json.Marshal(e)
		if strings.Contains(string(raw), "internal-host.corp") || strings.Contains(string(raw), "No eval") {
			t.Fatal(string(raw))
		}
	}
	if strings.Join(actions, ",") != "scan_rule.created,scan_rule.deleted,scan_rule.disabled,scan_rule.updated,scan_rule.updated,scan_rule.created,scan_rule.created" {
		t.Fatal(actions)
	}

	// A test: the row, its job in the same transaction, the job naming the row only.
	snippet := "host = 'internal-host.corp'"
	test, err := svc.CreateRuleTest(ctx, lead, service.RuleTestInput{Tool: "opengrep", Body: body, Filename: "app.py", Snippet: &snippet})
	if err != nil || test.State != "queued" {
		t.Fatal(test, err)
	}
	var args string
	if err := w.pool.QueryRow(ctx, `SELECT args::text FROM river_job WHERE kind = 'test_rules' AND args->>'test_id' = $1 AND queue = 'scan'`,
		test.ID.String()).Scan(&args); err != nil || strings.Contains(args, "internal-host") || !strings.Contains(args, a.id.String()) {
		t.Fatal(args, err)
	}
	var stored string
	ownerOne(t, a.id, `SELECT snippet FROM scan_rule_test WHERE id = $1`, []any{test.ID}, &stored)
	if stored != snippet {
		t.Fatal(stored)
	}
	if got, err := svc.RuleTest(ctx, lead, test.ID); err != nil || got.State != "queued" || got.Findings == nil {
		t.Fatal(got, err)
	}
	if _, err := svc.RuleTest(ctx, w.actor("SRAadmin", a.id), test.ID); code(err) != "NOT_FOUND" {
		t.Fatal(err)
	}
	if _, err := svc.RuleTest(ctx, w.actor("SRBlead", b.id), test.ID); code(err) != "NOT_FOUND" {
		t.Fatal(err)
	}
	// As the worker finishes it: findings typed on the way out.
	ownerExec(t, a.id, `UPDATE scan_rule_test SET state = 'done', snippet = NULL, finished_at = now(),
		findings = '[{"line": 1, "end_line": 1, "message": "m", "match": "internal-host.corp"}]' WHERE id = $1`, test.ID)
	got := must(svc.RuleTest(ctx, lead, test.ID))
	if raw, _ := json.Marshal(got); got.State != "done" || len(got.Findings) != 1 || got.FinishedAt == nil || strings.Contains(string(raw), "internal-host") {
		t.Fatal(string(raw))
	}
	// The rate limit counts rows: 20 per user per hour.
	for i := range 19 {
		if _, err := svc.CreateRuleTest(ctx, lead, service.RuleTestInput{Tool: "gitleaks", Body: "id: t", Filename: "a", Snippet: ptr("")}); err != nil {
			t.Fatal(i, err)
		}
	}
	if _, err := svc.CreateRuleTest(ctx, lead, service.RuleTestInput{Tool: "gitleaks", Body: "id: t", Filename: "a", Snippet: ptr("")}); code(err) != "RATE_LIMITED" {
		t.Fatal(err)
	}
	var jobs int
	if err := w.pool.QueryRow(ctx, `SELECT count(*) FROM river_job WHERE kind = 'test_rules' AND args->>'org_id' = $1`, a.id.String()).Scan(&jobs); err != nil || jobs != 20 {
		t.Fatal(jobs, err)
	}
}
