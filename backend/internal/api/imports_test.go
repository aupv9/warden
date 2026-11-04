package api

import (
	"fmt"
	"strings"
	"testing"

	"github.com/google/uuid"

	"github.com/aupv9/warden/backend/internal/service"
	"github.com/aupv9/warden/backend/internal/service/servicetest"
)

func importBody() map[string]any {
	return map[string]any{"tool": "codeql", "category": "/language:python/", "file_name": "python.sarif",
		"file_size": 1 << 20, "sha256": strings.Repeat("Ab", 32)}
}

func importEnv(t *testing.T) *env {
	return newEnv(t, func(c *service.Config) { c.ImportMaxBytes, c.ImageUploadMaxBytes = 50<<20, 50<<20 })
}

// POST …/scans/import: an import scan with tools ['external'] and the target
// built from tool and category, a presigned upload, then the usual start.
func TestCreateImportScan(t *testing.T) {
	e := importEnv(t)
	path := "/projects/" + e.web.String() + "/scans/import"
	r := e.do("POST", path, dev, importBody())
	e.expect(r, 201, "")
	sc := r.obj()["scan"].(map[string]any)
	id := sc["id"].(string)
	im, _ := sc["import"].(map[string]any)
	if sc["kind"] != "import" || sc["target"] != "(import) codeql /language:python/" || fmt.Sprint(sc["tools"]) != "[external]" ||
		sc["status"] != "pending_upload" || sc["image_ref"] != nil || sc["pulled"] != false || im == nil ||
		im["tool"] != "codeql" || im["category"] != "/language:python/" || im["format"] != "sarif" ||
		im["tool_version"] != nil || im["results"] != nil || im["dropped"] != nil || im["screened"] != nil || len(im) != 7 {
		t.Fatal(r.body)
	}
	key := "scans/" + e.org.String() + "/" + id + ".import.json"
	if u := r.obj()["upload"].(map[string]any); u["url"] != "https://s3.test/"+key || u["method"] != "PUT" {
		t.Fatal(u)
	}
	if row := e.f.ScanRow(uuid.MustParse(id)); row.SHA256 != strings.Repeat("ab", 32) || row.ObjectKey != key {
		t.Fatalf("%+v", row)
	}
	var audited bool
	for _, a := range e.f.AuditLog() {
		if a.Action == "scan.created" && a.TargetID == id {
			audited = a.Data["kind"] == "import" && a.Data["target"] == "(import) codeql /language:python/" &&
				a.Data["import_tool"] == "codeql" && a.Data["import_format"] == "sarif"
		}
	}
	if !audited {
		t.Fatal(e.f.AuditLog())
	}
	// Other kinds carry import: null.
	src := e.do("POST", "/projects/"+e.web.String()+"/scans", dev, map[string]any{"file_name": "a.zip", "file_size": 10, "sha256": strings.Repeat("ab", 32)})
	if v, ok := src.obj()["scan"].(map[string]any)["import"]; !ok || v != nil {
		t.Fatal(src.body)
	}

	// Started like an upload: the job runs the scan's tools, ['external'].
	e.objects.sizes[key] = 1 << 20
	r = e.do("POST", "/scans/"+id+"/start", dev, nil)
	e.expect(r, 200, "")
	jobs := e.f.Jobs()
	if j := jobs[len(jobs)-1].Job; j.ScanID != id || j.ObjectKey != key || fmt.Sprint(j.Tools) != "[external]" {
		t.Fatalf("%+v", j)
	}
	// The worker records the import as a tool run of external; it reads back as is.
	e.f.SetToolRuns(uuid.MustParse(id), []service.ToolRun{{Tool: "external", ToolVersion: "2.19.0", Status: "succeeded"}})
	if r := e.do("GET", "/scans/"+id, viewer, nil); r.obj()["import"].(map[string]any)["tool"] != "codeql" ||
		r.obj()["tool_runs"].([]any)[0].(map[string]any)["tool"] != "external" {
		t.Fatal(r.body)
	}
	if l := e.do("GET", "/projects/"+e.web.String()+"/scans", viewer, nil); l.items()[0].(map[string]any)["import"] == nil &&
		l.items()[1].(map[string]any)["import"] == nil {
		t.Fatal(l.body)
	}

	// Defaults: format sarif, category empty, target without a trailing space.
	b := importBody()
	delete(b, "category")
	b["tool"], b["file_name"] = "external.my-scanner", "Report.JSON"
	r = e.do("POST", path, dev, b)
	e.expect(r, 201, "")
	if sc := r.obj()["scan"].(map[string]any); sc["target"] != "(import) external.my-scanner" ||
		sc["import"].(map[string]any)["category"] != "" {
		t.Fatal(r.body)
	}
	b = importBody()
	b["tool"], b["format"], b["category"] = "gitlab-sast", "gitlab-sast", ""
	r = e.do("POST", path, lead, b)
	e.expect(r, 201, "")
	if sc := r.obj()["scan"].(map[string]any); sc["target"] != "(import) gitlab-sast" || sc["import"].(map[string]any)["format"] != "gitlab-sast" {
		t.Fatal(r.body)
	}
}

// Everything the server derives the target and the object from is checked
// here, whatever the client: the worker and the database check again.
func TestCreateImportScanValidation(t *testing.T) {
	e := importEnv(t)
	path := "/projects/" + e.web.String() + "/scans/import"
	for name, c := range map[string]struct {
		change func(map[string]any)
		field  string
	}{
		"no tool":              {func(b map[string]any) { delete(b, "tool") }, "tool"},
		"warden scanner":       {func(b map[string]any) { b["tool"] = "gitleaks" }, "tool"},
		"trivy":                {func(b map[string]any) { b["tool"] = "trivy" }, "tool"},
		"bare external":        {func(b map[string]any) { b["tool"] = "external" }, "tool"},
		"external no key":      {func(b map[string]any) { b["tool"] = "external." }, "tool"},
		"external upper":       {func(b map[string]any) { b["tool"] = "external.Codeql" }, "tool"},
		"external long":        {func(b map[string]any) { b["tool"] = "external." + strings.Repeat("a", 33) }, "tool"},
		"external dot":         {func(b map[string]any) { b["tool"] = "external.a.b" }, "tool"},
		"tool newline":         {func(b map[string]any) { b["tool"] = "codeql\n" }, "tool"},
		"tool space":           {func(b map[string]any) { b["tool"] = "codeql x" }, "tool"},
		"tool upper":           {func(b map[string]any) { b["tool"] = "CodeQL" }, "tool"},
		"format":               {func(b map[string]any) { b["format"] = "sarif2" }, "format"},
		"format empty":         {func(b map[string]any) { b["format"] = "" }, "format"},
		"category space":       {func(b map[string]any) { b["category"] = "a b" }, "category"},
		"category quote":       {func(b map[string]any) { b["category"] = `a"b` }, "category"},
		"category paren":       {func(b map[string]any) { b["category"] = "(history)" }, "category"},
		"category newline":     {func(b map[string]any) { b["category"] = "a\nb" }, "category"},
		"category trailing nl": {func(b map[string]any) { b["category"] = "a\n" }, "category"},
		"category long":        {func(b map[string]any) { b["category"] = strings.Repeat("a", 101) }, "category"},
		"category unicode":     {func(b map[string]any) { b["category"] = "café" }, "category"},
		"zip":                  {func(b map[string]any) { b["file_name"] = "a.zip" }, "file_name"},
		"no base name":         {func(b map[string]any) { b["file_name"] = ".sarif" }, "file_name"},
		"path":                 {func(b map[string]any) { b["file_name"] = "../a.sarif" }, "file_name"},
		"backslash":            {func(b map[string]any) { b["file_name"] = `a\b.sarif` }, "file_name"},
		"control":              {func(b map[string]any) { b["file_name"] = "a\x1b[31m.sarif" }, "file_name"},
		"nul":                  {func(b map[string]any) { b["file_name"] = "a\x00.sarif" }, "file_name"},
		"name too long":        {func(b map[string]any) { b["file_name"] = strings.Repeat("a", 250) + ".sarif" }, "file_name"},
		"too large":            {func(b map[string]any) { b["file_size"] = 50<<20 + 1 }, "file_size"},
		"empty":                {func(b map[string]any) { b["file_size"] = 0 }, "file_size"},
		"sha256":               {func(b map[string]any) { b["sha256"] = "abc" }, "sha256"},
	} {
		b := importBody()
		c.change(b)
		r := e.do("POST", path, lead, b)
		if r.code != 422 || r.Error.Metadata["fields"].(map[string]any)[c.field] == nil {
			t.Errorf("%s: %s", name, r.body)
		}
	}
	// The shape is closed: tools, kind and target are the server's.
	for _, extra := range []map[string]any{{"tools": []string{"external"}}, {"kind": "import"}, {"target": "(import) codeql"}} {
		b := importBody()
		for k, v := range extra {
			b[k] = v
		}
		e.expect(e.do("POST", path, lead, b), 422, "VALIDATION_FAILED")
	}
	if n := len(e.f.AuditLog()); n != 0 {
		t.Fatal(e.f.AuditLog())
	}
}

func TestCreateImportScanAccess(t *testing.T) {
	e := importEnv(t)
	path := "/projects/" + e.web.String() + "/scans/import"
	e.expect(e.do("POST", path, viewer, importBody()), 403, "FORBIDDEN")
	e.expect(e.do("POST", path, outsider, importBody()), 404, "NOT_FOUND")
	e.expect(e.do("POST", "/projects/"+e.api.String()+"/scans/import", dev, importBody()), 404, "NOT_FOUND")
	// Validation doesn't tell a non-member anything either.
	e.expect(e.do("POST", path, outsider, map[string]any{"tool": "x", "file_name": "a", "file_size": 0, "sha256": ""}), 404, "NOT_FOUND")

	// API tokens: scan:write only, their own project only.
	_, tok := e.newToken(owner, e.web, "scan:write")
	r := e.doTok("POST", path, tok, importBody())
	e.expect(r, 201, "")
	if vt, _ := r.obj()["scan"].(map[string]any)["via_token"].(map[string]any); vt == nil {
		t.Fatal(r.body)
	}
	_, read := e.newToken(owner, e.web, "issues:read")
	e.expect(e.doTok("POST", path, read, importBody()), 403, "TOKEN_SCOPE")
	_, other := e.newToken(lead, e.api, "scan:write")
	e.expect(e.doTok("POST", path, other, importBody()), 404, "NOT_FOUND")

	// The hourly limit counts imports with every other scan (3 in newEnv).
	e.expect(e.do("POST", path, dev, importBody()), 201, "")
	e.expect(e.do("POST", path, dev, importBody()), 201, "")
	e.expect(e.do("POST", path, dev, importBody()), 201, "")
	r = e.do("POST", path, dev, importBody())
	if r.code != 429 || r.code_() != "RATE_LIMITED" || r.header.Get("Retry-After") == "" {
		t.Fatal(r.code, r.body)
	}

	// Archived projects take no scans.
	e.f.ArchiveProject(e.web)
	e.expect(e.do("POST", path, owner, importBody()), 409, "PROJECT_ARCHIVED")
}

// external is the tool of imported issues: never one a scan or a project
// chooses.
func TestExternalToolNeverChosen(t *testing.T) {
	e := newEnv(t, func(c *service.Config) {
		c.ImageUploadMaxBytes, c.HistoryUploadMaxBytes = 100<<20, 100<<20
		c.Registries = service.RegistryConfig{AllowHosts: []string{"ghcr.io"}}
	})
	sum := strings.Repeat("ab", 32)
	for name, c := range map[string]struct {
		path string
		body map[string]any
	}{
		"source":       {"/projects/" + e.web.String() + "/scans", map[string]any{"file_name": "a.zip", "file_size": 10, "sha256": sum, "tools": []string{"external"}}},
		"source mixed": {"/projects/" + e.web.String() + "/scans", map[string]any{"file_name": "a.zip", "file_size": 10, "sha256": sum, "tools": []string{"gitleaks", "external"}}},
		"image": {"/projects/" + e.web.String() + "/scans", map[string]any{"kind": "image", "target": "ghcr.io/acme/api", "file_name": "a.tar",
			"file_size": 10, "sha256": sum, "tools": []string{"external"}}},
		"history": {"/projects/" + e.web.String() + "/scans", map[string]any{"kind": "history", "file_name": "a.bundle", "file_size": 10,
			"sha256": sum, "tools": []string{"external"}}},
		"kind import": {"/projects/" + e.web.String() + "/scans", map[string]any{"kind": "import", "file_name": "a.zip", "file_size": 10, "sha256": sum}},
		"pull": {"/projects/" + e.web.String() + "/scans/pull", map[string]any{"image_ref": "ghcr.io/acme/api@sha256:" + sum,
			"tools": []string{"external"}}},
		"project": {"/projects", map[string]any{"key": "EXT", "name": "Ext", "default_tools": []string{"external"}}},
	} {
		who := lead // runs scans in every project
		if c.path == "/projects" {
			who = admin
		}
		field := "tools"
		switch name {
		case "kind import":
			field = "kind"
		case "project":
			field = "default_tools"
		}
		r := e.do("POST", c.path, who, c.body)
		if r.code != 422 || r.code_() != "VALIDATION_FAILED" || len(r.Error.Metadata["fields"].(map[string]any)) != 1 ||
			r.Error.Metadata["fields"].(map[string]any)[field] == nil {
			t.Errorf("%s: %d %s", name, r.code, r.body)
		}
	}
	if len(e.f.Jobs()) != 0 {
		t.Fatal(e.f.Jobs())
	}
}

// Imported issues: external_tool in the list and the detail, and the
// source=import, external_tool and tool=external filters.
func TestImportedIssues(t *testing.T) {
	e := importEnv(t)
	imported := e.f.AddIssue(e.web, "high", "open", nil)
	e.f.SetIssue(imported, func(i *servicetest.IssueRow) {
		tool := "codeql"
		i.Tool, i.ExternalTool, i.Target, i.RuleID = "external", &tool, "(import) codeql /language:go/", "go/sql-injection"
	})
	semgrep := e.f.AddIssue(e.web, "low", "open", nil)
	e.f.SetIssue(semgrep, func(i *servicetest.IssueRow) {
		tool := "semgrep"
		i.Tool, i.ExternalTool, i.Target = "external", &tool, "(import) semgrep"
	})
	image := e.f.AddIssue(e.web, "medium", "open", nil)
	e.f.SetIssue(image, func(i *servicetest.IssueRow) { i.Tool, i.Target = "trivy", "ghcr.io/acme/api" })
	code := e.f.AddIssue(e.web, "medium", "open", nil)

	keys := func(q string) string {
		r := e.do("GET", "/issues"+q, dev, nil)
		e.expect(r, 200, "")
		var out []string
		for _, it := range r.items() {
			out = append(out, it.(map[string]any)["id"].(string))
		}
		return strings.Join(out, ",")
	}
	has := func(got string, ids ...any) bool {
		for _, id := range ids {
			if !strings.Contains(got, fmt.Sprint(id)) {
				return false
			}
		}
		return len(strings.Split(got, ",")) == len(ids)
	}
	if got := keys("?source=import"); !has(got, imported, semgrep) {
		t.Fatal(got)
	}
	if got := keys("?source=image"); !has(got, image) {
		t.Fatal(got)
	}
	if got := keys("?source=code"); !has(got, code) {
		t.Fatal(got)
	}
	if got := keys("?external_tool=codeql"); !has(got, imported) {
		t.Fatal(got)
	}
	if got := keys("?tool=external&external_tool=semgrep"); !has(got, semgrep) {
		t.Fatal(got)
	}
	if got := keys("?tool=external"); !has(got, imported, semgrep) {
		t.Fatal(got)
	}
	if got := keys("?external_tool=sonarqube"); got != "" {
		t.Fatal(got)
	}
	for _, q := range []string{"?external_tool=trivy", "?external_tool=external", "?external_tool=CODEQL", "?tool=trivy&external_tool=codeql",
		"?source=imports", "?tool=externals"} {
		e.expect(e.do("GET", "/issues"+q, dev, nil), 422, "VALIDATION_FAILED")
	}

	r := e.do("GET", "/issues?source=import&sort=-severity", dev, nil)
	if it := r.items()[0].(map[string]any); it["external_tool"] != "codeql" || it["tool"] != "external" {
		t.Fatal(r.body)
	}
	if r := e.do("GET", "/issues/"+imported.String(), dev, nil); r.obj()["external_tool"] != "codeql" || r.obj()["target"] != "(import) codeql /language:go/" {
		t.Fatal(r.body)
	}
	if r := e.do("GET", "/issues/"+code.String(), dev, nil); r.obj()["external_tool"] != nil {
		t.Fatal(r.body)
	} else if _, ok := r.obj()["external_tool"]; !ok {
		t.Fatal("external_tool missing:", r.body)
	}

	// Targets: '(import) …' is kind import, never image. (The fake lists
	// the targets of scans.)
	b := importBody()
	b["category"] = "/language:go/"
	e.expect(e.do("POST", "/projects/"+e.web.String()+"/scans/import", dev, b), 201, "")
	b["tool"], b["category"] = "semgrep", ""
	e.expect(e.do("POST", "/projects/"+e.web.String()+"/scans/import", dev, b), 201, "")
	e.expect(e.do("POST", "/projects/"+e.web.String()+"/scans", dev, map[string]any{"kind": "image", "target": "ghcr.io/acme/api",
		"file_name": "a.tar", "file_size": 10, "sha256": strings.Repeat("ab", 32)}), 201, "")
	for _, q := range []string{"?kind=import", ""} {
		r := e.do("GET", "/targets"+q, lead, nil)
		e.expect(r, 200, "")
		n := 0
		for _, it := range r.items() {
			m := it.(map[string]any)
			if strings.HasPrefix(m["target"].(string), "(import) ") != (m["kind"] == "import") {
				t.Fatal(r.body)
			}
			if m["kind"] == "import" {
				n++
			}
		}
		if n != 2 {
			t.Fatal(q, r.body)
		}
	}
	if r := e.do("GET", "/targets?kind=image", lead, nil); strings.Contains(r.body, "(import)") {
		t.Fatal(r.body)
	}

	// The CSV names the tool in the tool cell; the filter applies too.
	rows := readCSV(t, e.export("?external_tool=codeql", dev))
	if len(rows) != 1 || rows[0][5] != "external:codeql" || rows[0][9] != "(import) codeql /language:go/" {
		t.Fatal(rows)
	}
	for _, row := range readCSV(t, e.export("", dev)) {
		if row[5] != "external:codeql" && row[5] != "external:semgrep" && strings.HasPrefix(row[5], "external") {
			t.Fatal(row)
		}
	}
	var entry map[string]any
	for _, a := range e.f.AuditLog() {
		if a.Action == "issues.exported" && a.Data["external_tool"] != nil {
			entry = a.Data
		}
	}
	if entry == nil || entry["external_tool"] != "codeql" || entry["tool"] != "external" {
		t.Fatal(e.f.AuditLog())
	}
}
