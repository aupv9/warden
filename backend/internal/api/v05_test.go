package api

import (
	"errors"
	"testing"
	"time"
)

func TestOrgTargetsAPI(t *testing.T) {
	e := newEnv(t)
	e.f.AddScan(e.web, e.u[owner], "completed", 10)
	e.f.AddScan(e.api, e.u[lead], "completed", 10)
	archived := e.f.AddProject(e.org, "OLD")
	e.f.AddScan(archived, e.u[lead], "completed", 10)
	e.f.ArchiveProject(archived)

	r := e.do("GET", "/targets", lead, nil)
	e.expect(r, 200, "")
	if len(r.items()) != 2 || r.items()[0].(map[string]any)["project_key"] != "API" || r.items()[1].(map[string]any)["project_key"] != "WEB" {
		t.Fatal(r.body)
	}
	if it := r.items()[1].(map[string]any); it["project_id"] != e.web.String() || it["project_name"] != "WEB" || it["target"] != "" ||
		it["kind"] != "source" {
		t.Fatal(r.body)
	}
	// Members see their projects only; an org member without any sees none.
	if r := e.do("GET", "/targets", viewer, nil); len(r.items()) != 1 || r.items()[0].(map[string]any)["project_key"] != "WEB" {
		t.Fatal(r.body)
	}
	if r := e.do("GET", "/targets", outsider, nil); r.code != 200 || len(r.items()) != 0 {
		t.Fatal(r.body)
	}
	if r := e.do("GET", "/targets?kind=image", lead, nil); r.code != 200 || len(r.items()) != 0 {
		t.Fatal(r.body)
	}
	for _, k := range []string{"images", "SOURCE", "source,image"} {
		e.expect(e.do("GET", "/targets?kind="+k, lead, nil), 422, "VALIDATION_FAILED")
	}
	e.expect(e.do("GET", "/targets", stranger, nil), 404, "NOT_FOUND")
	_, tok := e.newToken(owner, e.web, "issues:read", "scan:write")
	e.expect(e.doTok("GET", "/targets", tok, nil), 403, "TOKEN_SCOPE")
}

func TestComponentEcosystemsAPI(t *testing.T) {
	e := newEnv(t)
	r := e.do("GET", "/components/ecosystems", viewer, nil)
	e.expect(r, 200, "")
	if r.items() == nil || len(r.items()) != 0 {
		t.Fatal(r.body)
	}
	e.expect(e.do("GET", "/components/ecosystems", stranger, nil), 404, "NOT_FOUND")
	_, tok := e.newToken(owner, e.web, "issues:read", "scan:write")
	e.expect(e.doTok("GET", "/components/ecosystems", tok, nil), 403, "TOKEN_SCOPE")
	e.f.Fail["ComponentEcosystems"] = errors.New("boom")
	e.expect(e.do("GET", "/components/ecosystems", viewer, nil), 500, "INTERNAL")
}

func TestVerifyAuditLog(t *testing.T) {
	e := newEnv(t)
	e.expect(e.do("POST", "/projects", lead, map[string]any{"key": "NEW", "name": "New"}), 201, "")
	before := len(e.f.AuditLog())

	r := e.do("POST", "/audit-log/verify", admin, nil)
	e.expect(r, 200, "")
	if d := r.obj(); d["ok"] != true || d["entries"] != float64(before) || d["first_bad_id"] != nil || d["verified_at"] != e.f.Now.Format(time.RFC3339) {
		t.Fatal(r.body)
	}
	// Recorded after the check: the entry isn't part of what it counted.
	a := e.f.AuditLog()
	if len(a) != before+1 || a[before].Action != "audit.verified" || a[before].Data["ok"] != true || a[before].Data["entries"] != before {
		t.Fatalf("%+v", a)
	}

	// A broken chain is a 200 with ok false and the first bad entry.
	e.f.AuditBadID = 2
	r = e.do("POST", "/audit-log/verify", lead, nil)
	if d := r.obj(); r.code != 200 || d["ok"] != false || d["first_bad_id"] != "2" || d["entries"] != float64(before+1) {
		t.Fatal(r.body)
	}
	if a := e.f.AuditLog(); a[len(a)-1].Data["ok"] != false || a[len(a)-1].Data["first_bad_id"] != "2" {
		t.Fatalf("%+v", a[len(a)-1])
	}
	e.f.AuditBadID = 0

	// view_audit_log only; tokens never.
	for _, who := range []string{owner, dev, viewer, outsider} {
		e.expect(e.do("POST", "/audit-log/verify", who, nil), 403, "FORBIDDEN")
	}
	e.expect(e.do("POST", "/audit-log/verify", stranger, nil), 404, "NOT_FOUND")
	_, tok := e.newToken(owner, e.web, "issues:read", "scan:write")
	e.expect(e.doTok("POST", "/audit-log/verify", tok, nil), 403, "TOKEN_SCOPE")
	e.expect(e.do("GET", "/audit-log/verify", admin, nil), 405, "METHOD_NOT_ALLOWED")

	// 10 per org per hour, whoever asks.
	for range 8 {
		e.f.Now = e.f.Now.Add(time.Minute)
		e.expect(e.do("POST", "/audit-log/verify", lead, nil), 200, "")
	}
	n := len(e.f.AuditLog())
	r = e.do("POST", "/audit-log/verify", admin, nil)
	e.expect(r, 429, "RATE_LIMITED")
	if ra := r.header.Get("Retry-After"); ra != "3119" { // the first two were 8 minutes and a second (the token) ago
		t.Fatal(ra)
	}
	if len(e.f.AuditLog()) != n {
		t.Fatal("a refused check was recorded")
	}
	e.f.Now = e.f.Now.Add(time.Hour)
	e.expect(e.do("POST", "/audit-log/verify", admin, nil), 200, "")

	// A failing check records nothing.
	e.f.Fail["VerifyAudit"] = errors.New("boom")
	n = len(e.f.AuditLog())
	e.expect(e.do("POST", "/audit-log/verify", admin, nil), 500, "INTERNAL")
	if len(e.f.AuditLog()) != n {
		t.Fatal("recorded a failed check")
	}
}
