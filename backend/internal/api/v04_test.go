package api

import (
	"strings"
	"testing"

	"github.com/aupv9/warden/backend/internal/service"
)

func TestScanSBOMFormats(t *testing.T) {
	e := newEnv(t)
	both := e.f.AddScan(e.web, e.u[owner], "completed", 10)
	cdxOnly := e.f.AddScan(e.web, e.u[owner], "completed", 10)
	sum, spdxSum := strings.Repeat("ab", 32), strings.Repeat("cd", 32)
	e.f.SetScanSBOM(both, &service.ScanSBOM{Key: "sboms/o/b.cdx.json", Size: 10, SHA256: sum, Components: 3,
		SPDXKey: "sboms/o/b.spdx.json", SPDXSize: 20, SPDXSHA256: spdxSum})
	e.f.SetScanSBOM(cdxOnly, &service.ScanSBOM{Key: "sboms/o/c.cdx.json", Size: 10, SHA256: sum, Components: 3})

	r := e.do("GET", "/scans/"+both.String(), viewer, nil)
	if f := r.obj()["sbom"].(map[string]any)["formats"].([]any); len(f) != 2 || f[0] != "cyclonedx-json" || f[1] != "spdx-json" {
		t.Fatal(r.body)
	}
	r = e.do("GET", "/scans/"+both.String()+"/sbom?format=spdx", viewer, nil)
	e.expect(r, 200, "")
	if d := r.obj(); d["format"] != "spdx-json" || d["sha256"] != spdxSum || d["size"] != 20.0 || d["components"] != 3.0 {
		t.Fatal(r.body)
	}
	want := "sboms/o/b.spdx.json|WEB-" + both.String()[:8] + ".spdx.json|application/spdx+json"
	if len(e.objects.gets) != 1 || e.objects.gets[0] != want {
		t.Fatal(e.objects.gets)
	}
	if r := e.do("GET", "/scans/"+both.String()+"/sbom?format=cyclonedx", viewer, nil); r.obj()["format"] != "cyclonedx-json" || r.obj()["sha256"] != sum {
		t.Fatal(r.body)
	}
	// Not produced: 404. Unknown format: 422, before anything is looked up.
	e.expect(e.do("GET", "/scans/"+cdxOnly.String()+"/sbom?format=spdx", viewer, nil), 404, "NOT_FOUND")
	for _, f := range []string{"SPDX", "spdx-json", "cyclonedx-json", "xml", "spdx%00"} {
		r := e.do("GET", "/scans/"+both.String()+"/sbom?format="+f, viewer, nil)
		e.expect(r, 422, "VALIDATION_FAILED")
		if r.Error.Metadata["fields"].(map[string]any)["format"] == nil {
			t.Fatal(r.body)
		}
	}
}

func TestProjectTargetsAPI(t *testing.T) {
	e := newEnv(t)
	e.f.AddScan(e.web, e.u[owner], "completed", 10)
	r := e.do("GET", "/projects/"+e.web.String()+"/targets", viewer, nil)
	e.expect(r, 200, "")
	if items := r.items(); len(items) != 1 || items[0].(map[string]any)["target"] != "" || items[0].(map[string]any)["kind"] != "source" {
		t.Fatal(r.body)
	}
	e.expect(e.do("GET", "/projects/"+e.api.String()+"/targets", viewer, nil), 404, "NOT_FOUND")
	if r := e.do("GET", "/projects/"+e.api.String()+"/targets", lead, nil); r.code != 200 || r.items() == nil {
		t.Fatal(r.body) // an empty list, not null
	}
	e.expect(e.do("GET", "/projects/"+e.web.String()+"/targets", outsider, nil), 404, "NOT_FOUND")
}

func TestComponentQueryValidation(t *testing.T) {
	e := newEnv(t)
	for _, q := range []string{
		"q=" + strings.Repeat("a", 129), "ecosystem=bad%20eco", "ecosystem=" + strings.Repeat("a", 33), "version=" + strings.Repeat("1", 129),
		"project_id=x", "malicious=yes", "limit=0", "limit=201", "cursor=!!!", "q=a%00b",
	} {
		e.expect(e.do("GET", "/components?"+q, viewer, nil), 422, "VALIDATION_FAILED")
	}
	e.expect(e.do("GET", "/components?q=lodash&ecosystem=npm&malicious=true", viewer, nil), 200, "")
	for _, q := range []string{"", "ecosystem=npm", "ecosystem=npm&name=a", "ecosystem=npm&version=1", "ecosystem=npm&name=a&version=" + strings.Repeat("1", 129),
		"ecosystem=n%20pm&name=a&version=1", "name=a&version=1"} {
		e.expect(e.do("GET", "/components/usage?"+q, viewer, nil), 422, "VALIDATION_FAILED")
	}
	r := e.do("GET", "/components/usage?ecosystem=npm&name=lodash&version=4.17.21", viewer, nil)
	e.expect(r, 200, "")
	if r.items() == nil && r.obj()["items"] == nil {
		t.Fatal(r.body)
	}
	p := "/projects/" + e.web.String() + "/components"
	for _, q := range []string{"target=Bad_Repo:tag", "target=" + strings.Repeat("a", 256), "q=" + strings.Repeat("a", 129), "malicious=1"} {
		e.expect(e.do("GET", p+"?"+q, viewer, nil), 422, "VALIDATION_FAILED")
	}
	e.expect(e.do("GET", p+"?target=", viewer, nil), 200, "")
	e.expect(e.do("GET", p+"?target=ghcr.io/acme/api", viewer, nil), 200, "")
	e.expect(e.do("GET", "/projects/"+e.api.String()+"/components", viewer, nil), 404, "NOT_FOUND")
	e.expect(e.call("GET", "/api/v1/orgs/"+e.org.String()+"/components", stranger, nil, nil), 404, "NOT_FOUND")
}

// API tokens: issues:read may read its own project's components and targets;
// the org-wide inventory isn't for tokens.
func TestComponentsWithTokens(t *testing.T) {
	e := newEnv(t)
	_, issueTok := e.newToken(lead, e.web, "issues:read")
	_, scanTok := e.newToken(owner, e.web, "scan:write")
	for _, path := range []string{"/components", "/projects/" + e.web.String() + "/targets"} {
		e.expect(e.doTok("GET", path, scanTok, nil), 403, "TOKEN_SCOPE")
	}
	e.expect(e.doTok("GET", "/projects/"+e.web.String()+"/components", issueTok, nil), 200, "")
	e.expect(e.doTok("GET", "/projects/"+e.web.String()+"/targets", issueTok, nil), 200, "")
	// The lead sees every project, but the token is bound to WEB.
	e.expect(e.doTok("GET", "/projects/"+e.api.String()+"/components", issueTok, nil), 404, "NOT_FOUND")
	e.expect(e.doTok("GET", "/projects/"+e.api.String()+"/targets", issueTok, nil), 404, "NOT_FOUND")
	e.expect(e.doTok("GET", "/components", issueTok, nil), 403, "TOKEN_SCOPE")
	e.expect(e.doTok("GET", "/components/usage?ecosystem=npm&name=a&version=1", issueTok, nil), 403, "TOKEN_SCOPE")
}
