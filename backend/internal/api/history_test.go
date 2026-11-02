package api

import (
	"strings"
	"testing"

	"github.com/aupv9/warden/backend/internal/service"
)

func historyBody() map[string]any {
	return map[string]any{"kind": "history", "file_name": "repo.bundle", "file_size": 50 << 20, "sha256": strings.Repeat("ab", 32)}
}

// History scans: a .bundle within history_upload_max_mb, Gitleaks only, the
// target set by the server; an API token with scan:write may create one.
func TestCreateHistoryScan(t *testing.T) {
	e := newEnv(t, func(c *service.Config) {
		c.HistoryUploadMaxBytes = 100 << 20
		c.Limits.HistoryUploadMaxMB, c.Limits.HistoryMaxCommits = 100, 5000
	})
	if l := e.call("GET", "/api/v1/me", dev, nil, nil).obj()["limits"].(map[string]any); l["history_upload_max_mb"] != 100.0 ||
		l["history_max_commits"] != 5000.0 {
		t.Fatal(l)
	}
	r := e.do("POST", "/projects/"+e.web.String()+"/scans", dev, historyBody())
	e.expect(r, 201, "")
	sc := r.obj()["scan"].(map[string]any)
	id := sc["id"].(string)
	if sc["kind"] != "history" || sc["target"] != "(history)" || sc["image_ref"] != nil || sc["history"] != nil ||
		len(sc["tools"].([]any)) != 1 || sc["tools"].([]any)[0] != "gitleaks" {
		t.Fatal(r.body)
	}
	if u := r.obj()["upload"].(map[string]any)["url"].(string); !strings.HasSuffix(u, "/scans/"+e.org.String()+"/"+id+".bundle") {
		t.Fatal(u)
	}
	b := historyBody()
	b["tools"], b["file_name"] = []string{"gitleaks"}, "Repo.BUNDLE"
	e.expect(e.do("POST", "/projects/"+e.web.String()+"/scans", dev, b), 201, "")

	for name, c := range map[string]struct {
		change func(map[string]any)
		field  string
	}{
		"other tools":   {func(b map[string]any) { b["tools"] = []string{"gitleaks", "trivy"} }, "tools"},
		"only trivy":    {func(b map[string]any) { b["tools"] = []string{"trivy"} }, "tools"},
		"no tools":      {func(b map[string]any) { b["tools"] = []string{} }, "tools"},
		"target":        {func(b map[string]any) { b["target"] = "(history)" }, "target"},
		"image target":  {func(b map[string]any) { b["target"] = "ghcr.io/acme/api" }, "target"},
		"image_ref":     {func(b map[string]any) { b["image_ref"] = "x" }, "image_ref"},
		"zip":           {func(b map[string]any) { b["file_name"] = "repo.zip" }, "file_name"},
		"tar":           {func(b map[string]any) { b["file_name"] = "repo.tar" }, "file_name"},
		"no base name":  {func(b map[string]any) { b["file_name"] = ".bundle" }, "file_name"},
		"path":          {func(b map[string]any) { b["file_name"] = "../repo.bundle" }, "file_name"},
		"too large":     {func(b map[string]any) { b["file_size"] = 101 << 20 }, "file_size"},
		"bundle source": {func(b map[string]any) { delete(b, "kind") }, "file_name"},
		"bundle image":  {func(b map[string]any) { b["kind"] = "image"; b["target"] = "ghcr.io/acme/api" }, "file_name"},
	} {
		b := historyBody()
		c.change(b)
		r := e.do("POST", "/projects/"+e.web.String()+"/scans", lead, b)
		if r.code != 422 || r.Error.Metadata["fields"].(map[string]any)[c.field] == nil {
			t.Errorf("%s: %s", name, r.body)
		}
	}

	// API tokens use the same route.
	_, tok := e.newToken(owner, e.web, "scan:write")
	r = e.doTok("POST", "/projects/"+e.web.String()+"/scans", tok, historyBody())
	e.expect(r, 201, "")
	tokScan := r.obj()["scan"].(map[string]any)["id"].(string)
	e.objects.sizes["scans/"+e.org.String()+"/"+tokScan+".bundle"] = 50 << 20
	e.expect(e.doTok("POST", "/scans/"+tokScan+"/start", tok, nil), 200, "")

	for _, a := range e.f.AuditLog() {
		if a.Action == "scan.created" && a.TargetID == id && (a.Data["kind"] != "history" || a.Data["target"] != "(history)") {
			t.Fatalf("%+v", a.Data)
		}
	}
	// The issue list takes source=history.
	e.expect(e.do("GET", "/issues?source=history", dev, nil), 200, "")
	e.expect(e.do("GET", "/issues?source=git", dev, nil), 422, "VALIDATION_FAILED")
}
