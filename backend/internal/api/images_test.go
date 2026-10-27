package api

import (
	"strings"
	"testing"

	"github.com/aupv9/warden/backend/internal/service"
)

func imageBody() map[string]any {
	return map[string]any{"kind": "image", "file_name": "api.tar", "file_size": 50 << 20, "sha256": strings.Repeat("ab", 32),
		"target": "ghcr.io/acme/api", "image_ref": "ghcr.io/acme/api:1.2@sha256:" + strings.Repeat("0", 64)}
}

func TestCreateImageScan(t *testing.T) {
	e := newEnv(t, func(c *service.Config) {
		c.ImageUploadMaxBytes = 100 << 20
		c.Limits.ImageUploadMaxMB = 100
	})
	if l := e.call("GET", "/api/v1/me", dev, nil, nil).obj()["limits"].(map[string]any); l["image_upload_max_mb"] != 100.0 {
		t.Fatal(l)
	}
	r := e.do("POST", "/projects/"+e.web.String()+"/scans", dev, imageBody())
	e.expect(r, 201, "")
	sc := r.obj()["scan"].(map[string]any)
	id := sc["id"].(string)
	if sc["kind"] != "image" || sc["target"] != "ghcr.io/acme/api" || !strings.HasPrefix(sc["image_ref"].(string), "ghcr.io/acme/api:1.2@") ||
		len(sc["tools"].([]any)) != 1 || sc["tools"].([]any)[0] != "trivy" || sc["sbom"] != nil {
		t.Fatal(r.body)
	}
	if u := r.obj()["upload"].(map[string]any)["url"].(string); !strings.HasSuffix(u, "/scans/"+e.org.String()+"/"+id+".tar") {
		t.Fatal(u)
	}
	// Tools may be given, as long as they are just trivy.
	b := imageBody()
	b["tools"] = []string{"trivy"}
	delete(b, "image_ref")
	r = e.do("POST", "/projects/"+e.web.String()+"/scans", dev, b)
	e.expect(r, 201, "")
	if r.obj()["scan"].(map[string]any)["image_ref"] != nil {
		t.Fatal(r.body)
	}

	for name, c := range map[string]struct {
		change func(map[string]any)
		field  string
	}{
		"other tools":      {func(b map[string]any) { b["tools"] = []string{"trivy", "gitleaks"} }, "tools"},
		"no target":        {func(b map[string]any) { delete(b, "target") }, "target"},
		"tag in target":    {func(b map[string]any) { b["target"] = "ghcr.io/acme/api:1.2" }, "target"},
		"upper target":     {func(b map[string]any) { b["target"] = "GHCR.io/acme/api" }, "target"},
		"digest target":    {func(b map[string]any) { b["target"] = "acme/api@sha256:" + strings.Repeat("0", 64) }, "target"},
		"long target":      {func(b map[string]any) { b["target"] = strings.Repeat("a/", 128) + "b" }, "target"},
		"zip for image":    {func(b map[string]any) { b["file_name"] = "api.zip" }, "file_name"},
		"too large":        {func(b map[string]any) { b["file_size"] = 101 << 20 }, "file_size"},
		"long image_ref":   {func(b map[string]any) { b["image_ref"] = strings.Repeat("a", 513) }, "image_ref"},
		"control in ref":   {func(b map[string]any) { b["image_ref"] = "a\x1bb" }, "image_ref"},
		"bad kind":         {func(b map[string]any) { b["kind"] = "vm" }, "kind"},
		"source w/ target": {func(b map[string]any) { b["kind"] = "source"; b["file_name"] = "a.zip"; b["file_size"] = 10 }, "target"},
	} {
		b := imageBody()
		c.change(b)
		r := e.do("POST", "/projects/"+e.web.String()+"/scans", lead, b)
		if r.code != 422 || r.Error.Metadata["fields"].(map[string]any)[c.field] == nil {
			t.Errorf("%s: %s", name, r.body)
		}
	}
	// A source scan keeps the source limit and rejects a .tar.
	r = e.do("POST", "/projects/"+e.web.String()+"/scans", lead, map[string]any{"file_name": "a.tar", "file_size": 10, "sha256": strings.Repeat("ab", 32)})
	e.expect(r, 422, "VALIDATION_FAILED")
	r = e.do("POST", "/projects/"+e.web.String()+"/scans", lead, map[string]any{"file_name": "a.zip", "file_size": 11 << 20, "sha256": strings.Repeat("ab", 32)})
	e.expect(r, 422, "VALIDATION_FAILED")
	// Starting it queues a job; the worker reads kind and target from the scan row.
	e.objects.sizes["scans/"+e.org.String()+"/"+id+".tar"] = 50 << 20
	e.expect(e.do("POST", "/scans/"+id+"/start", dev, nil), 200, "")
	n := 0
	for _, a := range e.f.AuditLog() {
		if a.Action == "scan.created" && a.TargetID == id {
			n++
			if a.Data["kind"] != "image" || a.Data["target"] != "ghcr.io/acme/api" {
				t.Fatalf("%+v", a.Data)
			}
		}
	}
	if n != 1 {
		t.Fatal("not audited")
	}
}
