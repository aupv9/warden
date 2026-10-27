package api

import (
	"errors"
	"strings"
	"testing"

	"github.com/aupv9/warden/backend/internal/service"
)

func TestScanSBOM(t *testing.T) {
	e := newEnv(t)
	web := e.f.AddScan(e.web, e.u[owner], "completed", 10)
	api := e.f.AddScan(e.api, e.u[lead], "completed", 10)
	none := e.f.AddScan(e.web, e.u[owner], "completed", 10)
	sum := strings.Repeat("ab", 32)
	e.f.SetScanSBOM(web, &service.ScanSBOM{Key: "sboms/" + e.org.String() + "/" + web.String() + ".cdx.json", Size: 1234, SHA256: sum, Components: 175})
	e.f.SetScanSBOM(api, &service.ScanSBOM{Key: "sboms/x/api.cdx.json", Size: 1, SHA256: sum, Components: 1})

	// The scan says it has one.
	r := e.do("GET", "/scans/"+web.String(), viewer, nil)
	e.expect(r, 200, "")
	if s := r.obj()["sbom"].(map[string]any); s["components"] != 175.0 || s["size"] != 1234.0 || len(s) != 2 ||
		r.obj()["kind"] != "source" || r.obj()["target"] != "" || r.obj()["image_ref"] != nil {
		t.Fatal(r.body)
	}
	if r := e.do("GET", "/scans/"+none.String(), viewer, nil); r.obj()["sbom"] != nil {
		t.Fatal(r.body)
	}

	r = e.do("GET", "/scans/"+web.String()+"/sbom", viewer, nil)
	e.expect(r, 200, "")
	d := r.obj()
	if d["format"] != "cyclonedx-json" || d["sha256"] != sum || d["components"] != 175.0 || d["size"] != 1234.0 ||
		!strings.HasPrefix(d["url"].(string), "https://s3.test/sboms/") || d["expires_at"] == nil {
		t.Fatal(r.body)
	}
	want := "sboms/" + e.org.String() + "/" + web.String() + ".cdx.json|WEB-" + web.String()[:8] + ".cdx.json|application/vnd.cyclonedx+json"
	if len(e.objects.gets) != 1 || e.objects.gets[0] != want || !strings.HasSuffix(d["url"].(string), "ttl=5m0s") {
		t.Fatal(e.objects.gets, d["url"])
	}

	// No SBOM, someone else's project, another org: 404. Who can't see the project: 404 too.
	e.expect(e.do("GET", "/scans/"+none.String()+"/sbom", viewer, nil), 404, "NOT_FOUND")
	e.expect(e.do("GET", "/scans/"+api.String()+"/sbom", dev, nil), 404, "NOT_FOUND")
	e.expect(e.do("GET", "/scans/"+web.String()+"/sbom", outsider, nil), 404, "NOT_FOUND")
	e.expect(e.call("GET", "/api/v1/orgs/"+e.org.String()+"/scans/"+web.String()+"/sbom", stranger, nil, nil), 404, "NOT_FOUND")
	e.expect(e.do("GET", "/scans/not-a-uuid/sbom", viewer, nil), 404, "NOT_FOUND")
	e.expect(e.do("GET", "/scans/"+api.String()+"/sbom", lead, nil), 200, "")

	e.objects.presignErr = errors.New("no credentials")
	e.expect(e.do("GET", "/scans/"+web.String()+"/sbom", viewer, nil), 500, "INTERNAL")
}

// API tokens: scan:write or issues:read, in their own project only.
func TestScanSBOMWithTokens(t *testing.T) {
	e := newEnv(t)
	web := e.f.AddScan(e.web, e.u[owner], "completed", 10)
	api := e.f.AddScan(e.api, e.u[lead], "completed", 10)
	e.f.SetScanSBOM(web, &service.ScanSBOM{Key: "sboms/o/w.cdx.json", Size: 1, SHA256: strings.Repeat("a", 64), Components: 1})
	e.f.SetScanSBOM(api, &service.ScanSBOM{Key: "sboms/o/a.cdx.json", Size: 1, SHA256: strings.Repeat("a", 64), Components: 1})
	_, scanTok := e.newToken(owner, e.web, "scan:write")
	_, issueTok := e.newToken(lead, e.web, "issues:read")
	_, leadTok := e.newToken(lead, e.web, "scan:write")
	e.expect(e.doTok("GET", "/scans/"+web.String()+"/sbom", scanTok, nil), 200, "")
	e.expect(e.doTok("GET", "/scans/"+web.String()+"/sbom", issueTok, nil), 200, "")
	// The lead sees every project, but the token is bound to WEB.
	e.expect(e.doTok("GET", "/scans/"+api.String()+"/sbom", leadTok, nil), 404, "NOT_FOUND")
	e.expect(e.doTok("GET", "/scans/"+api.String()+"/sbom", issueTok, nil), 404, "NOT_FOUND")
	// The license policy is not for tokens.
	e.expect(e.doTok("GET", "/license-policy", scanTok, nil), 403, "TOKEN_SCOPE")
	e.expect(e.doTok("PUT", "/license-policy", issueTok, licenseBody()), 403, "TOKEN_SCOPE")
}

func licenseBody() map[string]any {
	return map[string]any{
		"categories": map[string]any{"forbidden": "block", "restricted": "review", "reciprocal": "allow", "notice": "allow",
			"permissive": "allow", "unencumbered": "allow", "unknown": "allow"},
		"deny": []string{"OFL-1.1"}, "allow": []string{"LGPL-2.1-only"},
	}
}

func TestLicensePolicyAPI(t *testing.T) {
	e := newEnv(t)
	// Off until a security lead sets it; any member can read it.
	r := e.do("GET", "/license-policy", viewer, nil)
	e.expect(r, 200, "")
	if p := r.obj(); p["enabled"] != false || len(p["categories"].(map[string]any)) != 7 ||
		p["categories"].(map[string]any)["forbidden"] != "allow" || len(p["deny"].([]any)) != 0 || p["allow"] == nil {
		t.Fatal(r.body)
	}
	e.expect(e.do("PUT", "/license-policy", admin, licenseBody()), 403, "FORBIDDEN")
	e.expect(e.do("PUT", "/license-policy", owner, licenseBody()), 403, "FORBIDDEN")

	r = e.do("PUT", "/license-policy", lead, licenseBody())
	e.expect(r, 200, "")
	if p := r.obj(); p["enabled"] != true || p["categories"].(map[string]any)["restricted"] != "review" || p["deny"].([]any)[0] != "OFL-1.1" {
		t.Fatal(r.body)
	}
	if r := e.do("GET", "/license-policy", dev, nil); r.obj()["enabled"] != true {
		t.Fatal(r.body)
	}
	audits := func() int {
		n := 0
		for _, a := range e.f.AuditLog() {
			if a.Action == "org.license_policy_changed" {
				n++
				if a.Data["from"].(service.LicensePolicy).Enabled || !a.Data["to"].(service.LicensePolicy).Enabled {
					t.Fatalf("%+v", a.Data)
				}
			}
		}
		return n
	}
	if audits() != 1 {
		t.Fatal("not audited")
	}
	// Unchanged: no write, no audit.
	e.expect(e.do("PUT", "/license-policy", lead, licenseBody()), 200, "")
	if audits() != 1 {
		t.Fatal("no-op audited")
	}

	bad := licenseBody()
	bad["categories"].(map[string]any)["forbidden"] = "deny"
	delete(bad["categories"].(map[string]any), "unknown")
	bad["categories"].(map[string]any)["evil"] = "allow"
	bad["deny"] = []string{"GPL-3.0-only", "<script>", "GPL-3.0-only"}
	bad["allow"] = []string{"GPL-3.0-only"}
	r = e.do("PUT", "/license-policy", lead, bad)
	e.expect(r, 422, "VALIDATION_FAILED")
	fields := r.Error.Metadata["fields"].(map[string]any)
	for _, f := range []string{"categories", "categories.forbidden", "categories.unknown", "deny[1]", "deny[2]", "allow[0]"} {
		if fields[f] == nil {
			t.Errorf("no error for %s: %v", f, fields)
		}
	}
	e.expect(e.do("PUT", "/license-policy", lead, map[string]any{"categories": nil, "deny": []string{}, "allow": []string{}}), 422, "VALIDATION_FAILED")
	r = e.do("PUT", "/license-policy", lead, map[string]any{"categories": licenseBody()["categories"]})
	e.expect(r, 422, "VALIDATION_FAILED")
	if f := r.Error.Metadata["fields"].(map[string]any); f["deny"] != "is required" || f["allow"] != "is required" {
		t.Fatal(r.body)
	}
	long := licenseBody()
	ids := make([]string, 101)
	for i := range ids {
		ids[i] = "LicenseRef-x" + strings.Repeat("a", i%50) + string(rune('a'+i%26))
	}
	long["deny"] = ids
	e.expect(e.do("PUT", "/license-policy", lead, long), 422, "VALIDATION_FAILED")
	e.expect(e.do("PUT", "/license-policy", lead, `{"categories":{},"deny":[],"allow":[],"extra":1}`), 422, "VALIDATION_FAILED")
	// The stored policy didn't change.
	if !strings.Contains(e.f.StoredLicensePolicy(e.org), `"OFL-1.1"`) {
		t.Fatal(e.f.StoredLicensePolicy(e.org))
	}
	e.expect(e.call("GET", "/api/v1/orgs/"+e.org.String()+"/license-policy", stranger, nil, nil), 404, "NOT_FOUND")
}
