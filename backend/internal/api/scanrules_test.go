package api

import (
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"strings"
	"testing"
	"time"

	"github.com/google/uuid"

	"github.com/aupv9/warden/backend/internal/service"
	"github.com/aupv9/warden/backend/internal/service/servicetest"
)

func rulesEnv(t *testing.T) *env {
	return newEnv(t, func(c *service.Config) { c.ParseRule = servicetest.ParseRule })
}

func ruleBody(key string, extra ...string) string {
	return "id: " + key + "\n\n" + strings.Join(append([]string{"severity: high"}, extra...), "\n") + "\n"
}

func (e *env) createRule(who, tool, key string, projects any) map[string]any {
	e.t.Helper()
	body := map[string]any{"tool": tool, "name": "Rule " + key, "body": ruleBody(key, "pattern: internal-secret-host")}
	if projects != nil {
		body["project_ids"] = projects
	}
	r := e.do("POST", "/scan-rules", who, body)
	e.expect(r, 201, "")
	return r.obj()
}

// No audit entry carries a rule's body or name.
func (e *env) assertRuleAuditClean() {
	e.t.Helper()
	for _, a := range e.f.AuditLog() {
		if !strings.HasPrefix(a.Action, "scan_rule.") {
			continue
		}
		raw, _ := json.Marshal(a.Data)
		if strings.Contains(string(raw), "internal-secret-host") || strings.Contains(string(raw), "Rule ") || len(a.Data) != 4 {
			e.t.Fatalf("%s: %s", a.Action, raw)
		}
		for _, k := range []string{"id", "tool", "key", "sha256"} {
			if _, ok := a.Data[k]; !ok {
				e.t.Fatalf("%s: %s", a.Action, raw)
			}
		}
	}
}

func auditActions(f *servicetest.Fake) []string {
	var out []string
	for _, a := range f.AuditLog() {
		if strings.HasPrefix(a.Action, "scan_rule.") {
			out = append(out, a.Action)
		}
	}
	return out
}

func TestScanRulePermissions(t *testing.T) {
	e := rulesEnv(t)
	rule := e.createRule(admin, "opengrep", "a", nil)
	id := rule["id"].(string)
	create := map[string]any{"tool": "opengrep", "name": "x", "body": ruleBody("x")}
	validate := map[string]any{"tool": "opengrep", "body": ruleBody("x")}
	test := map[string]any{"tool": "opengrep", "body": ruleBody("x"), "filename": "a.py", "snippet": "x = 1"}
	for _, who := range []string{owner, dev, viewer, outsider} {
		e.expect(e.do("POST", "/scan-rules", who, create), 403, "FORBIDDEN")
		e.expect(e.do("PATCH", "/scan-rules/"+id, who, map[string]any{"version": 1, "enabled": false}), 403, "FORBIDDEN")
		e.expect(e.do("DELETE", "/scan-rules/"+id+"?version=1", who, nil), 403, "FORBIDDEN")
		e.expect(e.do("POST", "/scan-rules/validate", who, validate), 403, "FORBIDDEN")
		e.expect(e.do("POST", "/scan-rules/tests", who, test), 403, "FORBIDDEN")
	}
	// Project members read rules; an org member without a project doesn't.
	for _, who := range []string{owner, dev, viewer, lead} {
		e.expect(e.do("GET", "/scan-rules", who, nil), 200, "")
		e.expect(e.do("GET", "/scan-rules/"+id, who, nil), 200, "")
		e.expect(e.do("GET", "/scan-rules/"+id+"/versions", who, nil), 200, "")
	}
	e.expect(e.do("GET", "/scan-rules", outsider, nil), 403, "FORBIDDEN")
	e.expect(e.do("GET", "/scan-rules/"+id, outsider, nil), 403, "FORBIDDEN")
	// Outside the org: 404 everywhere.
	e.expect(e.do("GET", "/scan-rules", stranger, nil), 404, "NOT_FOUND")
	e.expect(e.do("POST", "/scan-rules", stranger, create), 404, "NOT_FOUND")
	e.expect(e.do("GET", "/scan-rules/"+uuid.NewString(), lead, nil), 404, "NOT_FOUND")
	e.expect(e.do("GET", "/scan-rules/nope", lead, nil), 404, "NOT_FOUND")
	e.expect(e.do("GET", "/scan-rules/tests/"+uuid.NewString(), lead, nil), 404, "NOT_FOUND")

	// API tokens can't reach any scan-rule route, whatever the scope and creator.
	_, tok := e.newToken(owner, e.web, "scan:write", "issues:read")
	for _, c := range [][2]string{
		{"GET", "/scan-rules"}, {"POST", "/scan-rules"}, {"POST", "/scan-rules/validate"}, {"POST", "/scan-rules/tests"},
		{"GET", "/scan-rules/tests/" + uuid.NewString()}, {"GET", "/scan-rules/" + id}, {"PATCH", "/scan-rules/" + id},
		{"DELETE", "/scan-rules/" + id + "?version=1"}, {"GET", "/scan-rules/" + id + "/versions"},
	} {
		e.expect(e.doTok(c[0], c[1], tok, create), 403, "TOKEN_SCOPE")
	}
	if len(e.f.TestJobs()) != 0 {
		t.Fatal(e.f.TestJobs())
	}
}

// A member sees the rules of their projects only, and only their projects in
// a rule's list.
func TestScanRulesReadScope(t *testing.T) {
	e := rulesEnv(t)
	all := e.createRule(lead, "opengrep", "all", nil)
	apiOnly := e.createRule(lead, "opengrep", "api-only", []string{e.api.String()})
	both := e.createRule(lead, "gitleaks", "both", []string{e.web.String(), e.api.String()})

	r := e.do("GET", "/scan-rules", dev, nil)
	e.expect(r, 200, "")
	if len(r.items()) != 2 {
		t.Fatal(r.body)
	}
	for _, it := range r.items() {
		m := it.(map[string]any)
		switch m["key"] {
		case "all":
			if m["project_ids"] != nil {
				t.Fatal(r.body)
			}
		case "both":
			if ids := m["project_ids"].([]any); len(ids) != 1 || ids[0] != e.web.String() {
				t.Fatal(r.body)
			}
		default:
			t.Fatal(r.body)
		}
	}
	e.expect(e.do("GET", "/scan-rules/"+apiOnly["id"].(string), dev, nil), 404, "NOT_FOUND")
	e.expect(e.do("GET", "/scan-rules/"+apiOnly["id"].(string)+"/versions", dev, nil), 404, "NOT_FOUND")
	if v := e.do("GET", "/scan-rules/"+both["id"].(string)+"/versions", dev, nil); len(v.items()) != 1 ||
		len(v.items()[0].(map[string]any)["project_ids"].([]any)) != 1 {
		t.Fatal(v.body)
	}
	// The lead sees everything, as stored.
	if r := e.do("GET", "/scan-rules?tool=opengrep", lead, nil); len(r.items()) != 2 {
		t.Fatal(r.body)
	}
	if r := e.do("GET", "/scan-rules/"+both["id"].(string), admin, nil); len(r.obj()["project_ids"].([]any)) != 2 {
		t.Fatal(r.body)
	}
	e.expect(e.do("GET", "/scan-rules?tool=trivy", lead, nil), 422, "VALIDATION_FAILED")
	_ = all
}

func TestCreateScanRule(t *testing.T) {
	e := rulesEnv(t)
	body := "  id: no-eval\n\nseverity: critical\npattern: internal-secret-host\n"
	r := e.do("POST", "/scan-rules", lead, map[string]any{"tool": "opengrep", "name": " Rule no-eval ", "body": body})
	e.expect(r, 201, "")
	m := r.obj()
	canonical := "id: no-eval\nseverity: critical\npattern: internal-secret-host\n"
	sum := sha256.Sum256([]byte(canonical))
	if m["key"] != "no-eval" || m["rule_id"] != "org.no-eval" || m["body"] != canonical || m["sha256"] != hex.EncodeToString(sum[:]) ||
		m["severity"] != "critical" || m["version"] != 1.0 || m["enabled"] != true || m["project_ids"] != nil ||
		m["name"] != "Rule no-eval" || m["created_by"].(map[string]any)["email"] != lead || m["updated_by"].(map[string]any)["email"] != lead {
		t.Fatal(r.body)
	}
	if v := e.f.RuleVersions(uuid.MustParse(m["id"].(string))); len(v) != 1 || v[0].Version != 1 || v[0].Body != canonical {
		t.Fatal(v)
	}
	audit := e.f.AuditLog()
	if last := audit[len(audit)-1]; last.Action != "scan_rule.created" || last.TargetType != "scan_rule" ||
		last.Data["key"] != "no-eval" || last.Data["sha256"] != m["sha256"] || last.Data["tool"] != "opengrep" {
		t.Fatal(last)
	}
	e.assertRuleAuditClean()

	// Same key: 409 for the tool, fine for the other tool.
	e.expect(e.do("POST", "/scan-rules", lead, map[string]any{"tool": "opengrep", "name": "again", "body": ruleBody("no-eval")}), 409, "CONFLICT")
	e.expect(e.do("POST", "/scan-rules", lead, map[string]any{"tool": "gitleaks", "name": "again", "body": ruleBody("no-eval"),
		"enabled": false, "project_ids": []string{e.web.String()}}), 201, "")

	// Invalid bodies: RULE_INVALID with positions where known.
	r = e.do("POST", "/scan-rules", lead, map[string]any{"tool": "opengrep", "name": "x", "body": "id: x\nbad\n"})
	e.expect(r, 422, "RULE_INVALID")
	ps := r.Error.Metadata["problems"].([]any)
	if p := ps[0].(map[string]any); len(ps) != 1 || p["line"] != 2.0 || p["column"] != 1.0 || p["message"] != "bad line" {
		t.Fatal(r.body)
	}
	r = e.do("POST", "/scan-rules", lead, map[string]any{"tool": "opengrep", "name": "x", "body": "pattern: x"})
	e.expect(r, 422, "RULE_INVALID")
	if p := r.Error.Metadata["problems"].([]any)[0].(map[string]any); p["line"] != nil || p["column"] != nil {
		t.Fatal(r.body)
	}
	// A parser can't smuggle a bad key or severity past the service.
	e.expect(e.do("POST", "/scan-rules", lead, map[string]any{"tool": "opengrep", "name": "x", "body": "id: ../../etc"}), 422, "RULE_INVALID")
	e.expect(e.do("POST", "/scan-rules", lead, map[string]any{"tool": "opengrep", "name": "x", "body": "id: ok\nseverity: urgent"}), 422, "RULE_INVALID")

	for _, c := range []map[string]any{
		{"tool": "trivy", "name": "x", "body": ruleBody("t")},
		{"tool": "opengrep", "name": "", "body": ruleBody("t")},
		{"tool": "opengrep", "name": strings.Repeat("n", 201), "body": ruleBody("t")},
		{"tool": "opengrep", "name": "x\ny", "body": ruleBody("t")},
		{"tool": "opengrep", "name": "x", "body": ""},
		{"tool": "opengrep", "name": "x", "body": "id: t\x00"},
		{"tool": "opengrep", "name": "x", "body": ruleBody("t", strings.Repeat("p", 64<<10))},
		{"tool": "opengrep", "name": "x", "body": ruleBody("t"), "project_ids": []string{}},
		{"tool": "opengrep", "name": "x", "body": ruleBody("t"), "project_ids": []string{"nope"}},
		{"tool": "opengrep", "name": "x", "body": ruleBody("t"), "project_ids": []string{e.web.String(), e.web.String()}},
		{"tool": "opengrep", "name": "x", "body": ruleBody("t"), "project_ids": []string{uuid.NewString()}},
		{"tool": "opengrep", "name": "x", "body": ruleBody("t"), "secret": true},
	} {
		e.expect(e.do("POST", "/scan-rules", lead, c), 422, "VALIDATION_FAILED")
	}
	// Another org's project is unknown here.
	other := e.f.AddOrg("Other")
	foreign := e.f.AddProject(other, "FOR")
	e.expect(e.do("POST", "/scan-rules", lead, map[string]any{"tool": "opengrep", "name": "x", "body": ruleBody("t"),
		"project_ids": []string{foreign.String()}}), 422, "VALIDATION_FAILED")
}

func TestScanRuleLimits(t *testing.T) {
	e := rulesEnv(t)
	for i := range 200 {
		e.expect(e.do("POST", "/scan-rules", lead, map[string]any{"tool": "gitleaks", "name": "r", "body": ruleBody(fmt.Sprint("k", i))}), 201, "")
	}
	r := e.do("POST", "/scan-rules", lead, map[string]any{"tool": "gitleaks", "name": "r", "body": ruleBody("k200")})
	e.expect(r, 409, "CONFLICT")
	if !strings.Contains(r.Error.Message, "200") {
		t.Fatal(r.body)
	}
	// The other tool has its own count; a deleted rule frees its place.
	e.expect(e.do("POST", "/scan-rules", lead, map[string]any{"tool": "opengrep", "name": "r", "body": ruleBody("k200")}), 201, "")
	first := e.do("GET", "/scan-rules?tool=gitleaks", lead, nil).items()[0].(map[string]any)["id"].(string)
	e.expect(e.do("DELETE", "/scan-rules/"+first+"?version=1", lead, nil), 204, "")
	e.expect(e.do("POST", "/scan-rules", lead, map[string]any{"tool": "gitleaks", "name": "r", "body": ruleBody("k200")}), 201, "")

	// 1 MiB of canonical bodies per org, counting updates.
	e = rulesEnv(t)
	pad := func(n int) string { return strings.Repeat("p", n) }
	var ids []string
	for i := range 16 { // 16 × 65021 bytes
		r := e.do("POST", "/scan-rules", lead, map[string]any{"tool": "opengrep", "name": "r", "body": ruleBody(fmt.Sprint("b", i), pad(65000))})
		e.expect(r, 201, "")
		ids = append(ids, r.obj()["id"].(string))
	}
	e.expect(e.do("POST", "/scan-rules", lead, map[string]any{"tool": "gitleaks", "name": "r", "body": ruleBody("b16", pad(9000))}), 409, "CONFLICT")
	small := e.do("POST", "/scan-rules", lead, map[string]any{"tool": "gitleaks", "name": "r", "body": ruleBody("s", pad(7000))})
	e.expect(small, 201, "")
	// Growing a rule past the limit is refused; shrinking one is fine.
	e.expect(e.do("PATCH", "/scan-rules/"+small.obj()["id"].(string), lead, map[string]any{"version": 1, "body": ruleBody("s", pad(9000))}), 409, "CONFLICT")
	e.expect(e.do("PATCH", "/scan-rules/"+ids[0], lead, map[string]any{"version": 1, "body": ruleBody("b0")}), 200, "")
	e.expect(e.do("POST", "/scan-rules", lead, map[string]any{"tool": "gitleaks", "name": "r", "body": ruleBody("b16", pad(9000))}), 201, "")
}

func TestUpdateAndDeleteScanRule(t *testing.T) {
	e := rulesEnv(t)
	rule := e.createRule(admin, "opengrep", "upd", nil)
	id := rule["id"].(string)
	path := "/scan-rules/" + id

	e.expect(e.do("PATCH", path, lead, map[string]any{"name": "n"}), 422, "VALIDATION_FAILED")
	e.expect(e.do("PATCH", path, lead, map[string]any{"version": 1}), 422, "VALIDATION_FAILED")
	e.expect(e.do("PATCH", path, lead, map[string]any{"version": 2, "name": "n"}), 409, "VERSION_CONFLICT")
	e.expect(e.do("PATCH", "/scan-rules/"+uuid.NewString(), lead, map[string]any{"version": 1, "name": "n"}), 404, "NOT_FOUND")

	// No change: same version, nothing audited.
	r := e.do("PATCH", path, lead, map[string]any{"version": 1, "name": "Rule upd", "enabled": true, "body": rule["body"]})
	e.expect(r, 200, "")
	if r.obj()["version"] != 1.0 || len(auditActions(e.f)) != 1 {
		t.Fatal(r.body, auditActions(e.f))
	}

	r = e.do("PATCH", path, lead, map[string]any{"version": 1, "name": "Renamed", "project_ids": []string{e.web.String()}})
	e.expect(r, 200, "")
	if m := r.obj(); m["version"] != 2.0 || m["name"] != "Renamed" || len(m["project_ids"].([]any)) != 1 ||
		m["updated_by"].(map[string]any)["email"] != lead || m["created_by"].(map[string]any)["email"] != admin {
		t.Fatal(r.body)
	}
	r = e.do("PATCH", path, lead, map[string]any{"version": 2, "enabled": false, "project_ids": nil})
	e.expect(r, 200, "")
	if m := r.obj(); m["version"] != 3.0 || m["enabled"] != false || m["project_ids"] != nil {
		t.Fatal(r.body)
	}
	r = e.do("PATCH", path, lead, map[string]any{"version": 3, "enabled": true, "body": ruleBody("upd", "severity: low")})
	e.expect(r, 200, "")
	if m := r.obj(); m["version"] != 4.0 || m["severity"] != "low" || m["sha256"] == rule["sha256"] {
		t.Fatal(r.body)
	}
	// The key can't change, and the body must parse.
	e.expect(e.do("PATCH", path, lead, map[string]any{"version": 4, "body": ruleBody("other")}), 422, "RULE_INVALID")
	e.expect(e.do("PATCH", path, lead, map[string]any{"version": 4, "body": "id: upd\nbad"}), 422, "RULE_INVALID")
	e.expect(e.do("PATCH", path, lead, map[string]any{"version": 4, "project_ids": []string{}}), 422, "VALIDATION_FAILED")
	e.expect(e.do("PATCH", path, lead, map[string]any{"version": 4, "tool": "gitleaks"}), 422, "VALIDATION_FAILED")

	if got := auditActions(e.f); strings.Join(got, ",") !=
		"scan_rule.created,scan_rule.updated,scan_rule.updated,scan_rule.disabled,scan_rule.updated,scan_rule.enabled" {
		t.Fatal(got)
	}

	// History, newest first, paged.
	v := e.do("GET", path+"/versions?limit=3", dev, nil)
	e.expect(v, 200, "")
	if items := v.items(); len(items) != 3 || items[0].(map[string]any)["version"] != 4.0 || v.obj()["next_cursor"] == nil {
		t.Fatal(v.body)
	}
	v2 := e.do("GET", path+"/versions?limit=3&cursor="+v.obj()["next_cursor"].(string), dev, nil)
	if items := v2.items(); len(items) != 1 || items[0].(map[string]any)["version"] != 1.0 || v2.obj()["next_cursor"] != nil ||
		items[0].(map[string]any)["created_by"].(map[string]any)["email"] != admin {
		t.Fatal(v2.body)
	}
	e.expect(e.do("GET", path+"/versions?limit=101", dev, nil), 422, "VALIDATION_FAILED")
	e.expect(e.do("GET", path+"/versions?cursor=zz", dev, nil), 422, "VALIDATION_FAILED")

	// Delete: optimistic lock, soft delete, versions kept, key reusable.
	e.expect(e.do("DELETE", path, lead, nil), 422, "VALIDATION_FAILED")
	e.expect(e.do("DELETE", path+"?version=x", lead, nil), 422, "VALIDATION_FAILED")
	e.expect(e.do("DELETE", path+"?version=3", lead, nil), 409, "VERSION_CONFLICT")
	e.expect(e.do("DELETE", path+"?version=4", lead, nil), 204, "")
	e.expect(e.do("GET", path, lead, nil), 404, "NOT_FOUND")
	e.expect(e.do("PATCH", path, lead, map[string]any{"version": 4, "name": "x"}), 404, "NOT_FOUND")
	e.expect(e.do("DELETE", path+"?version=4", lead, nil), 404, "NOT_FOUND")
	stored, _ := e.f.StoredRule(uuid.MustParse(id))
	if stored.DeletedAt == nil || len(e.f.RuleVersions(stored.ID)) != 4 {
		t.Fatal(stored)
	}
	e.createRule(lead, "opengrep", "upd", nil)
	if got := auditActions(e.f); got[len(got)-2] != "scan_rule.deleted" {
		t.Fatal(got)
	}
	e.assertRuleAuditClean()
}

func TestValidateScanRule(t *testing.T) {
	e := rulesEnv(t)
	r := e.do("POST", "/scan-rules/validate", lead, map[string]any{"tool": "gitleaks", "body": "\nid: aws-like\nseverity: high\n"})
	e.expect(r, 200, "")
	if m := r.obj(); m["ok"] != true || m["key"] != "aws-like" || m["severity"] != "high" ||
		m["body"] != "id: aws-like\nseverity: high\n" || len(m["problems"].([]any)) != 0 {
		t.Fatal(r.body)
	}
	r = e.do("POST", "/scan-rules/validate", lead, map[string]any{"tool": "gitleaks", "body": "id: x\nbad"})
	e.expect(r, 200, "")
	if m := r.obj(); m["ok"] != false || m["key"] != nil || m["body"] != nil || len(m["problems"].([]any)) != 1 {
		t.Fatal(r.body)
	}
	e.expect(e.do("POST", "/scan-rules/validate", lead, map[string]any{"tool": "x", "body": "id: x"}), 422, "VALIDATION_FAILED")
	// Nothing stored, nothing audited.
	if len(e.do("GET", "/scan-rules", lead, nil).items()) != 0 || len(auditActions(e.f)) != 0 {
		t.Fatal("validate stored something")
	}
}

func TestRuleTests(t *testing.T) {
	e := rulesEnv(t)
	snippet := "password = 'internal-secret-host'"
	r := e.do("POST", "/scan-rules/tests", lead, map[string]any{"tool": "gitleaks", "body": ruleBody("t"), "filename": "config.py", "snippet": snippet})
	e.expect(r, 202, "")
	m := r.obj()
	if m["state"] != "queued" || len(m["findings"].([]any)) != 0 || m["error"] != nil || m["finished_at"] != nil {
		t.Fatal(r.body)
	}
	id := uuid.MustParse(m["id"].(string))
	stored, _ := e.f.StoredRuleTest(id)
	if stored.Snippet != snippet || stored.Filename != "config.py" || string(stored.Body) != "id: t\nseverity: high\n" {
		t.Fatal(stored)
	}
	// The job names the row; the snippet and body stay in the table.
	jobs := e.f.TestJobs()
	raw, _ := json.Marshal(jobs)
	if len(jobs) != 1 || jobs[0].TestID != id || jobs[0].OrgID != e.org || strings.Contains(string(raw), "internal-secret-host") ||
		jobs[0].Kind() != "test_rules" {
		t.Fatal(string(raw))
	}

	// Its creator only.
	e.expect(e.do("GET", "/scan-rules/tests/"+id.String(), lead, nil), 200, "")
	e.expect(e.do("GET", "/scan-rules/tests/"+id.String(), admin, nil), 404, "NOT_FOUND")
	e.expect(e.do("GET", "/scan-rules/tests/"+id.String(), owner, nil), 403, "FORBIDDEN")

	// As the worker leaves it: findings by line, no snippet.
	end := 3
	e.f.SetRuleTest(id, func(r *servicetest.RuleTestRow) {
		at := e.f.Now
		r.State, r.Snippet, r.FinishedAt = "done", "", &at
		r.Findings = []service.RuleTestFinding{{Line: 2, EndLine: &end, Message: "hardcoded password"}}
	})
	g := e.do("GET", "/scan-rules/tests/"+id.String(), lead, nil)
	if m := g.obj(); m["state"] != "done" || m["finished_at"] == nil ||
		m["findings"].([]any)[0].(map[string]any)["end_line"] != 3.0 || strings.Contains(g.body, "internal-secret-host") {
		t.Fatal(g.body)
	}
	// Kept a day.
	e.f.Now = e.f.Now.Add(25 * time.Hour)
	e.expect(e.do("GET", "/scan-rules/tests/"+id.String(), lead, nil), 404, "NOT_FOUND")

	for _, c := range []map[string]any{
		{"tool": "gitleaks", "body": ruleBody("t"), "filename": "..", "snippet": "x"},
		{"tool": "gitleaks", "body": ruleBody("t"), "filename": ".", "snippet": "x"},
		{"tool": "gitleaks", "body": ruleBody("t"), "filename": "../etc/passwd", "snippet": "x"},
		{"tool": "gitleaks", "body": ruleBody("t"), "filename": "a/b.py", "snippet": "x"},
		{"tool": "gitleaks", "body": ruleBody("t"), "filename": "", "snippet": "x"},
		{"tool": "gitleaks", "body": ruleBody("t"), "filename": strings.Repeat("a", 256), "snippet": "x"},
		{"tool": "gitleaks", "body": ruleBody("t"), "filename": "a.py"},
		{"tool": "gitleaks", "body": ruleBody("t"), "filename": "a.py", "snippet": "a\x00b"},
		{"tool": "gitleaks", "body": ruleBody("t"), "filename": "a.py", "snippet": strings.Repeat("s", 64<<10+1)},
		{"tool": "trivy", "body": ruleBody("t"), "filename": "a.py", "snippet": "x"},
	} {
		e.expect(e.do("POST", "/scan-rules/tests", lead, c), 422, "VALIDATION_FAILED")
	}
	e.expect(e.do("POST", "/scan-rules/tests", lead, map[string]any{"tool": "gitleaks", "body": "bad", "filename": "a.py", "snippet": ""}), 422, "RULE_INVALID")

	// 20 per user per hour; another user has their own count.
	for i := range 20 {
		e.expect(e.do("POST", "/scan-rules/tests", admin, map[string]any{"tool": "opengrep", "body": ruleBody("t"), "filename": "a.py", "snippet": ""}), 202, "")
		if i == 0 {
			e.f.Now = e.f.Now.Add(10 * time.Minute)
		}
	}
	r = e.do("POST", "/scan-rules/tests", admin, map[string]any{"tool": "opengrep", "body": ruleBody("t"), "filename": "a.py", "snippet": ""})
	e.expect(r, 429, "RATE_LIMITED")
	if r.header.Get("Retry-After") != "3000" { // the first was 10 minutes ago
		t.Fatal(r.header)
	}
	e.expect(e.do("POST", "/scan-rules/tests", lead, map[string]any{"tool": "opengrep", "body": ruleBody("t"), "filename": "a.py", "snippet": ""}), 202, "")
	if len(auditActions(e.f)) != 0 {
		t.Fatal(auditActions(e.f))
	}
}

// Scans list the org rules they ran; issues of an org rule name it, deleted or not.
func TestOrgRulesOnScansAndIssues(t *testing.T) {
	e := rulesEnv(t)
	scan := e.f.AddScan(e.web, e.u[dev], "completed", 10)
	r := e.do("GET", "/scans/"+scan.String(), dev, nil)
	e.expect(r, 200, "")
	if rules, ok := r.obj()["org_rules"].([]any); !ok || len(rules) != 0 {
		t.Fatal(r.body)
	}

	rule := e.createRule(lead, "opengrep", "no-eval", nil)
	// Each ref names the scan_rule row that ran; null on scans recorded
	// before v0.7, whose entries don't carry it.
	ruleRow := uuid.MustParse(rule["id"].(string))
	e.f.SetScanOrgRules(scan, service.ScanRuleRefs{
		{RuleID: "org.no-eval", Tool: "opengrep", Version: 1, SHA256: rule["sha256"].(string), ScanRuleID: &ruleRow},
		{RuleID: "org.old", Tool: "gitleaks", Version: 2, SHA256: "s"},
	})
	r = e.do("GET", "/scans/"+scan.String(), dev, nil)
	e.expect(r, 200, "")
	refs, _ := r.obj()["org_rules"].([]any)
	if len(refs) != 2 {
		t.Fatal(r.body)
	}
	if m := refs[0].(map[string]any); m["scan_rule_id"] != rule["id"] || m["rule_id"] != "org.no-eval" {
		t.Fatal(r.body)
	}
	if m := refs[1].(map[string]any); m["scan_rule_id"] != nil {
		t.Fatal(r.body)
	} else if _, present := m["scan_rule_id"]; !present {
		t.Fatal("scan_rule_id must be present (null):", r.body)
	}
	iss := e.f.AddIssue(e.web, "high", "open", nil)
	e.f.SetIssue(iss, func(i *servicetest.IssueRow) { i.Tool, i.RuleID = "opengrep", "org.no-eval" })
	plain := e.f.AddIssue(e.web, "high", "open", nil)
	ghost := e.f.AddIssue(e.web, "high", "open", nil)
	e.f.SetIssue(ghost, func(i *servicetest.IssueRow) { i.Tool, i.RuleID = "gitleaks", "org.gone" })

	get := func(id uuid.UUID) map[string]any {
		r := e.do("GET", "/issues/"+id.String(), dev, nil)
		e.expect(r, 200, "")
		v, _ := r.obj()["org_rule"].(map[string]any)
		return v
	}
	if o := get(iss); o["rule_id"] != "org.no-eval" || o["name"] != "Rule no-eval" || o["scan_rule_id"] != rule["id"] {
		t.Fatal(o)
	}
	if o := get(plain); o != nil {
		t.Fatal(o)
	}
	if o := get(ghost); o["rule_id"] != "org.gone" || o["name"] != nil || o["scan_rule_id"] != nil {
		t.Fatal(o)
	}
	e.expect(e.do("DELETE", "/scan-rules/"+rule["id"].(string)+"?version=1", lead, nil), 204, "")
	if o := get(iss); o["name"] != "Rule no-eval" || o["scan_rule_id"] != rule["id"] {
		t.Fatal(o)
	}
	// A new rule with the key takes over.
	again := e.createRule(lead, "opengrep", "no-eval", nil)
	if o := get(iss); o["scan_rule_id"] != again["id"] {
		t.Fatal(o)
	}
}
