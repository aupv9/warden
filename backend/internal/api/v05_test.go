package api

import (
	"errors"
	"testing"
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
