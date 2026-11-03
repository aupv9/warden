//go:build integration

package worker

import (
	"context"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"testing"
	"time"

	"github.com/google/uuid"

	"github.com/aupv9/warden/backend/internal/scan/results"
	st "github.com/aupv9/warden/backend/internal/scan/scantest"
)

// orgRule inserts an org rule (the fake parser's body "key:severity").
func (it *itest) orgRule(tool, key, sev string, projects string) uuid.UUID {
	id := uuid.New()
	body := key + ":" + sev
	sum := sha256.Sum256([]byte(body))
	owner(it.t, it.org, fmt.Sprintf(`INSERT INTO scan_rule (id, org_id, tool, key, name, body_canonical, sha256, severity, project_ids, version)
		VALUES ('%s', '%s', '%s', '%s', 'n', '%s', '%s', '%s', %s, 2)`, id, it.org, tool, key, body, hex.EncodeToString(sum[:]), sev, projects))
	return id
}

func (it *itest) sourceScan(tools ...string) uuid.UUID {
	data, sha := zipBytes()
	id, key := it.scan("queued", sha, 0, tools...)
	it.store.objects[key] = data
	it.run(id)
	return id
}

// An org rule runs in the org's scans, its findings at its severity, and the
// scan records it. Its issue is fixed only by a scan that ran it: disabled,
// deleted or scoped to another project, the rule fixes nothing, while
// Warden's rules auto-fix as before.
func TestOrgRulesEndToEnd(t *testing.T) {
	fakeRules(t)
	it := newITest(t)
	ruleID := it.orgRule("opengrep", "no-eval", "low", "NULL")
	it.orgRule("opengrep", "elsewhere", "high", fmt.Sprintf("ARRAY['%s']::uuid[]", uuid.New())) // another project's
	found := st.Doc([]any{
		st.M{"ruleId": "rules.org.no-eval", "level": "error", "message": st.M{"text": "m"}, "locations": []any{st.Loc("/src/app/a.py", 1)}},
		st.M{"ruleId": "data.rules.r1", "level": "error", "message": st.M{"text": "m"}, "locations": []any{st.Loc("/src/app/a.py", 1)}},
	})
	it.sb.docs = map[string]st.M{"opengrep": found}
	scan := it.sourceScan("opengrep")

	var raw []byte
	it.one(fmt.Sprintf(`SELECT org_rules FROM scan WHERE id = '%s'`, scan), &raw)
	var refs []results.OrgRuleRef
	if err := json.Unmarshal(raw, &refs); err != nil || len(refs) != 1 || refs[0].RuleID != "org.no-eval" || refs[0].Version != 2 {
		t.Fatalf("%s %v", raw, err)
	}
	issue := func(rule string) (status, sev string) {
		it.one(fmt.Sprintf(`SELECT status::text, severity::text FROM issue WHERE project_id = '%s' AND rule_id = '%s'`, it.project, rule), &status, &sev)
		return
	}
	if s, sev := issue("org.no-eval"); s != "open" || sev != "low" {
		t.Fatal(s, sev)
	}
	if s, sev := issue("r1"); s != "open" || sev != "high" {
		t.Fatal(s, sev)
	}

	// Disabled: the next scan finds nothing; the built-in issue is fixed, the
	// org rule's stays open, and the scan records no org rule.
	owner(t, it.org, fmt.Sprintf(`UPDATE scan_rule SET enabled = false WHERE id = '%s'`, ruleID))
	it.sb.docs = nil
	it.sb.empty = true
	scan = it.sourceScan("opengrep")
	if s, _ := issue("org.no-eval"); s != "open" {
		t.Fatal("a disabled rule's issue was fixed:", s)
	}
	if s, _ := issue("r1"); s != "fixed" {
		t.Fatal("built-in issue not fixed:", s)
	}
	it.one(fmt.Sprintf(`SELECT org_rules FROM scan WHERE id = '%s'`, scan), &raw)
	if string(raw) != "[]" {
		t.Fatal(string(raw))
	}

	// Deleted: still open.
	owner(t, it.org, fmt.Sprintf(`UPDATE scan_rule SET enabled = true, deleted_at = now() WHERE id = '%s'`, ruleID))
	it.sourceScan("opengrep")
	if s, _ := issue("org.no-eval"); s != "open" {
		t.Fatal("a deleted rule's issue was fixed:", s)
	}

	// Live again (a new rule of the same key) and finding nothing: fixed.
	it.orgRule("opengrep", "no-eval", "low", fmt.Sprintf("ARRAY['%s']::uuid[]", it.project))
	scan = it.sourceScan("opengrep")
	if s, _ := issue("org.no-eval"); s != "fixed" {
		t.Fatal("the rule ran and found nothing, yet its issue is", s)
	}
	it.one(fmt.Sprintf(`SELECT org_rules FROM scan WHERE id = '%s'`, scan), &raw)
	if err := json.Unmarshal(raw, &refs); err != nil || len(refs) != 1 {
		t.Fatal(string(raw))
	}
}

// A rule test runs under RLS: running, then done with the findings, the
// snippet cleared; the prune fails a lost test and deletes day-old ones.
func TestRuleTestEndToEnd(t *testing.T) {
	fakeRules(t)
	it := newITest(t)
	newTest := func(age time.Duration, state string) uuid.UUID {
		id := uuid.New()
		owner(t, it.org, fmt.Sprintf(`INSERT INTO scan_rule_test (id, org_id, created_by, tool, body_canonical, filename, snippet, state, created_at)
			VALUES ('%s', '%s', '%s', 'opengrep', 'no-eval:high', 'app.py', 'eval(input())', '%s', now() - interval '%d seconds')`,
			id, it.org, it.user, state, int(age.Seconds())))
		return id
	}
	id := newTest(0, "queued")
	it.sb.docs = map[string]st.M{"opengrep": st.Doc(
		[]any{st.M{"ruleId": "rules.org.no-eval", "message": st.M{"text": "eval(input()) matched"}, "locations": []any{st.Loc("/src/app.py", 1)}}},
		st.M{"id": "rules.org.no-eval", "fullDescription": st.M{"text": "No eval"}},
	)}
	if err := it.env.RunRuleTest(context.Background(), TestRulesArgs{OrgID: it.org, TestID: id}, 1); err != nil {
		t.Fatal(err)
	}
	var state string
	var findings []byte
	var snippetGone, finished bool
	it.one(fmt.Sprintf(`SELECT state, findings, snippet IS NULL, finished_at IS NOT NULL FROM scan_rule_test WHERE id = '%s'`, id),
		&state, &findings, &snippetGone, &finished)
	if state != "done" || string(findings) != `[{"line": 1, "message": "No eval", "end_line": 1}]` || !snippetGone || !finished {
		t.Fatal(state, string(findings), snippetGone, finished)
	}
	// Another org's job can't see the test (RLS): the job is cancelled.
	if err := it.env.RunRuleTest(context.Background(), TestRulesArgs{OrgID: uuid.New(), TestID: id}, 1); err == nil {
		t.Fatal("test visible to another org")
	}

	lost := newTest(2*time.Hour, "running")
	old := newTest(25*time.Hour, "queued")
	if err := it.env.PruneRuleTests(context.Background()); err != nil {
		t.Fatal(err)
	}
	var errCode string
	it.one(fmt.Sprintf(`SELECT state, error, snippet IS NULL FROM scan_rule_test WHERE id = '%s'`, lost), &state, &errCode, &snippetGone)
	if state != "failed" || errCode != "scanner_failed" || !snippetGone {
		t.Fatal(state, errCode, snippetGone)
	}
	var n int
	it.one(fmt.Sprintf(`SELECT count(*) FROM scan_rule_test WHERE id IN ('%s', '%s')`, old, id), &n)
	if n != 1 {
		t.Fatal("day-old test not deleted, or a fresh one was")
	}
}
