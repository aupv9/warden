//go:build integration

package store_test

import (
	"errors"
	"fmt"
	"strings"
	"testing"

	"github.com/google/uuid"
	"github.com/jackc/pgx/v5"
	"github.com/jackc/pgx/v5/pgconn"

	"github.com/aupv9/warden/backend/internal/ids"
	"github.com/aupv9/warden/backend/internal/service"
)

// ownerErr runs SQL as the schema owner with app.org_id set and returns the
// constraint it violated ("" when it succeeded, the error text otherwise).
func ownerErr(t *testing.T, org uuid.UUID, sql string, args ...any) string {
	t.Helper()
	conn, err := pgx.Connect(ctx, ownerURL)
	if err != nil {
		t.Fatal(err)
	}
	defer conn.Close(ctx)
	err = pgx.BeginFunc(ctx, conn, func(tx pgx.Tx) error {
		if _, err := tx.Exec(ctx, "SELECT set_config('app.org_id', $1, true)", org.String()); err != nil {
			return err
		}
		_, err := tx.Exec(ctx, sql, args...)
		return err
	})
	var pe *pgconn.PgError
	switch {
	case err == nil:
		return ""
	case errors.As(err, &pe) && pe.Code == "23514":
		return pe.ConstraintName
	default:
		return err.Error()
	}
}

func importWorld(t *testing.T) *world {
	w := newWorld(t)
	w.svc = service.New(w.db, w.objs, service.Config{UploadMaxBytes: 1 << 20, ImportMaxBytes: 50 << 20, RateLimitPerHour: 20}, nil)
	return w
}

// An import scan is stored as the service builds it (kind import, tools
// {external}, the target from tool and category, the import_* columns), the
// schema's CHECKs (00016) agree, it starts like an upload, and the worker's
// counts read back. Another org can't see it.
func TestImportScanRoundTrip(t *testing.T) {
	w := importWorld(t)
	f := w.org("IMP")
	dev := w.actor("IMPdev", f.id)
	cat := "/language:go/"
	created := must(w.svc.CreateImportScan(ctx, dev, f.project, service.ImportScanInput{Tool: "codeql", Category: &cat,
		FileName: "go.sarif", FileSize: 30 << 20, SHA256: strings.Repeat("E", 64)}))
	sc := must(w.svc.Scan(ctx, dev, created.Scan.ID))
	if sc.Kind != "import" || sc.Target != "(import) codeql /language:go/" || len(sc.Tools) != 1 || sc.Tools[0] != "external" ||
		sc.Status != "pending_upload" || sc.SHA256 != strings.Repeat("e", 64) || sc.FileSize != 30<<20 ||
		sc.ObjectKey != "scans/"+f.id.String()+"/"+sc.ID.String()+".import.json" || sc.Import == nil ||
		sc.Import.Tool != "codeql" || sc.Import.Category != cat || sc.Import.Format != "sarif" ||
		sc.Import.ToolVersion != nil || sc.Import.Results != nil || sc.Import.Dropped != nil || sc.Import.Screened != nil {
		t.Fatalf("%+v %+v", sc, sc.Import)
	}
	gl := must(w.svc.CreateImportScan(ctx, dev, f.project, service.ImportScanInput{Tool: "gitlab-sast", Format: ptr("gitlab-sast"),
		FileName: "gl-sast-report.json", FileSize: 10, SHA256: strings.Repeat("a", 64)}))
	if gl.Scan.Target != "(import) gitlab-sast" || gl.Scan.Import.Category != "" || gl.Scan.Import.Format != "gitlab-sast" {
		t.Fatalf("%+v", gl.Scan)
	}
	if src := must(w.svc.Scan(ctx, dev, f.scan)); src.Import != nil {
		t.Fatalf("%+v", src.Import)
	}

	// Started like an upload: the job carries the scan's tools.
	w.objs.sizes[sc.ObjectKey] = 30 << 20
	if st := must(w.svc.StartScan(ctx, dev, sc.ID)); st.Status != "queued" {
		t.Fatal(st.Status)
	}
	var jobTools string
	if err := w.pool.QueryRow(ctx, `SELECT args->>'tools' FROM river_job WHERE args->>'scan_id' = $1`, sc.ID.String()).Scan(&jobTools); err != nil {
		var keys string
		_ = w.pool.QueryRow(ctx, `SELECT args::text FROM river_job ORDER BY id DESC LIMIT 1`).Scan(&keys)
		t.Fatalf("%v: %s", err, keys)
	}
	if jobTools != `["external"]` {
		t.Fatal(jobTools)
	}
	ownerExec(t, f.id, `UPDATE scan SET status = 'completed', import_tool_version = '2.19.0', import_results = 12, import_dropped = 1,
		import_screened = 2 WHERE id = $1`, sc.ID)
	if im := must(w.svc.Scan(ctx, dev, sc.ID)).Import; im == nil || *im.ToolVersion != "2.19.0" || *im.Results != 12 || *im.Dropped != 1 || *im.Screened != 2 {
		t.Fatalf("%+v", im)
	}
	page := must(w.svc.Scans(ctx, dev, f.project, service.PageParams{}))
	n := 0
	for _, s := range page.Items {
		if s.Import != nil {
			n++
		}
	}
	if n != 2 {
		t.Fatal(n)
	}

	// The audit entry names the import.
	audit := must(w.svc.AuditLog(ctx, w.actor("IMPadmin", f.id), service.AuditFilter{}))
	found := false
	for _, a := range audit.Items {
		if a.Action == "scan.created" && a.TargetID != nil && *a.TargetID == sc.ID.String() {
			found = strings.Contains(string(a.Data), `"import_tool": "codeql"`) || strings.Contains(string(a.Data), `"import_tool":"codeql"`)
		}
	}
	if !found {
		t.Fatal("no scan.created entry for the import")
	}

	// RLS: another org's lead doesn't see it, even by id.
	o := w.org("IMQ")
	if _, err := w.svc.Scan(ctx, w.actor("IMQlead", o.id), sc.ID); code(err) != "NOT_FOUND" {
		t.Fatal(err)
	}
	if _, err := w.svc.CreateImportScan(ctx, w.actor("IMQlead", o.id), f.project, service.ImportScanInput{Tool: "codeql",
		FileName: "a.sarif", FileSize: 1, SHA256: strings.Repeat("a", 64)}); code(err) != "NOT_FOUND" {
		t.Fatal(err)
	}
	// A viewer can't import.
	viewer := w.user("IMPviewer")
	must(w.svc.AddMember(ctx, w.actor("IMPadmin", f.id), service.AddMemberInput{Email: viewer.Email, Role: "member"}))
	must(w.svc.SetProjectMember(ctx, w.actor("IMPlead", f.id), f.project, viewer.ID, service.SetProjectMemberInput{Role: "viewer"}))
	if _, err := w.svc.CreateImportScan(ctx, w.actor("IMPviewer", f.id), f.project, service.ImportScanInput{Tool: "codeql",
		FileName: "a.sarif", FileSize: 1, SHA256: strings.Repeat("a", 64)}); code(err) != "FORBIDDEN" {
		t.Fatal(err)
	}
}

// 00016's CHECKs: an import's kind, target and tools are tied together, no
// other scan has import columns or the tool external, and an issue has tool
// external exactly when it has an external_tool, on an '(import) …' target.
func TestImportSchemaChecks(t *testing.T) {
	w := importWorld(t)
	f := w.org("IMC")
	dev := w.actor("IMCdev", f.id)
	imp := must(w.svc.CreateImportScan(ctx, dev, f.project, service.ImportScanInput{Tool: "semgrep",
		FileName: "s.sarif", FileSize: 10, SHA256: strings.Repeat("a", 64)})).Scan.ID

	insert := func(kind, target, tools string, tool, category, format any) string {
		return ownerErr(t, f.id, `INSERT INTO scan (id, org_id, project_id, created_by, status, file_name, object_key, file_size, sha256,
			tools, kind, target, import_tool, import_category, import_format)
			VALUES ($1, $2, $3, $4, 'pending_upload', 'x.sarif', 'k', 1, $5, $6::text[], $7, $8, $9, $10, $11)`,
			ids.New(), f.id, f.project, w.users["IMCdev"].ID, strings.Repeat("a", 64), tools, kind, target, tool, category, format)
	}
	for name, c := range map[string]struct {
		kind, target, tools    string
		tool, category, format any
		want                   string
	}{
		"valid":               {"import", "(import) codeql /x/", "{external}", "codeql", "/x/", "sarif", ""},
		"valid no category":   {"import", "(import) external.my-tool", "{external}", "external.my-tool", "", "gitlab-sast", ""},
		"import without tool": {"import", "(import) codeql", "{external}", nil, nil, nil, "scan_import_fields"},
		"source with tool":    {"source", "", "{gitleaks}", "codeql", "", "sarif", "scan_import_fields"},
		"category missing":    {"import", "(import) codeql", "{external}", "codeql", nil, "sarif", "scan_import_fields"},
		"format missing":      {"import", "(import) codeql", "{external}", "codeql", "", nil, "scan_import_fields"},
		"target mismatch":     {"import", "(import) semgrep", "{external}", "codeql", "", "sarif", "scan_import_target"},
		"trailing space":      {"import", "(import) codeql ", "{external}", "codeql", "", "sarif", "scan_import_target"},
		"image target":        {"import", "ghcr.io/acme/api", "{external}", "codeql", "", "sarif", "scan_import_target"},
		"scanner tools":       {"import", "(import) codeql", "{gitleaks}", "codeql", "", "sarif", "scan_import_tools"},
		"extra tools":         {"import", "(import) codeql", "{external,trivy}", "codeql", "", "sarif", "scan_import_tools"},
		"external on source":  {"source", "", "{gitleaks,external}", nil, nil, nil, "scan_external_tool"},
		"external on history": {"history", "(history)", "{external}", nil, nil, nil, "scan_external_tool"},
		"warden scanner tool": {"import", "(import) gitleaks", "{external}", "gitleaks", "", "sarif", "scan_import_tool_check"},
		"tool with space":     {"import", "(import) codeql x", "{external}", "codeql x", "", "sarif", "scan_import_tool_check"},
		"category with space": {"import", "(import) codeql a b", "{external}", "codeql", "a b", "sarif", "scan_import_category_check"},
		"category with paren": {"import", "(import) codeql (x)", "{external}", "codeql", "(x)", "sarif", "scan_import_category_check"},
		"format":              {"import", "(import) codeql", "{external}", "codeql", "", "csv", "scan_import_format_check"},
		"kind":                {"imports", "x", "{gitleaks}", nil, nil, nil, "scan_kind_check"},
	} {
		if got := insert(c.kind, c.target, c.tools, c.tool, c.category, c.format); got != c.want {
			t.Errorf("%s: %q, want %q", name, got, c.want)
		}
	}
	// The worker's counts belong to imports only.
	if got := ownerErr(t, f.id, `UPDATE scan SET import_results = 1 WHERE id = $1`, f.scan); got != "scan_import_fields" {
		t.Error(got)
	}
	if got := ownerErr(t, f.id, `UPDATE scan SET import_results = -1 WHERE id = $1`, imp); got != "scan_import_results_check" {
		t.Error(got)
	}
	if got := ownerErr(t, f.id, `UPDATE scan SET import_tool_version = $2 WHERE id = $1`, imp, strings.Repeat("v", 101)); got != "scan_import_tool_version_check" {
		t.Error(got)
	}
	if got := ownerErr(t, f.id, `UPDATE scan SET import_category = '/x/' WHERE id = $1`, imp); got != "scan_import_target" {
		t.Error(got)
	}

	issue := func(n int, tool, externalTool any, target string) string {
		return ownerErr(t, f.id, `INSERT INTO issue (id, org_id, project_id, number, fingerprint, tool, rule_id, title, severity,
			first_seen_scan_id, last_seen_scan_id, target, external_tool)
			VALUES ($1, $2, $3, $4, $5, $6, 'r', 't', 'high', $7, $7, $8, $9)`,
			ids.New(), f.id, f.project, n, fmt.Sprintf("%064d", n), tool, imp, target, externalTool)
	}
	for name, c := range map[string]struct {
		n                  int
		tool, externalTool any
		target, want       string
	}{
		"imported":              {1, "external", "semgrep", "(import) semgrep", ""},
		"external.<key>":        {2, "external", "external.my-tool", "(import) external.my-tool", ""},
		"external without tool": {3, "external", nil, "(import) semgrep", "issue_external_tool"},
		"scanner with tool":     {4, "opengrep", "semgrep", "(import) semgrep", "issue_external_tool"},
		"external on code":      {5, "external", "semgrep", "", "issue_external_target"},
		"external on image":     {6, "external", "semgrep", "ghcr.io/acme/api", "issue_external_target"},
		"external on history":   {7, "external", "semgrep", "(history)", "issue_external_target"},
		"unknown external_tool": {8, "external", "trivy", "(import) trivy", "issue_external_tool_check"},
		"external_tool newline": {9, "external", "semgrep\n", "(import) semgrep", "issue_external_tool_check"},
		"scanner on code":       {10, "gitleaks", nil, "", ""},
	} {
		if got := issue(c.n, c.tool, c.externalTool, c.target); got != c.want {
			t.Errorf("%s: %q, want %q", name, got, c.want)
		}
	}
}

// Imported issues in the issue list, the detail, the export and the targets:
// source=import, external_tool and tool=external; image and code leave them
// out.
func TestImportedIssueFilters(t *testing.T) {
	w := importWorld(t)
	f := w.org("IMF")
	dev := w.actor("IMFdev", f.id)
	cat := "/language:go/"
	imp := must(w.svc.CreateImportScan(ctx, dev, f.project, service.ImportScanInput{Tool: "codeql", Category: &cat,
		FileName: "go.sarif", FileSize: 10, SHA256: strings.Repeat("a", 64)})).Scan
	ownerExec(t, f.id, `UPDATE scan SET status = 'completed' WHERE id = $1`, imp.ID)
	add := func(n int, tool string, externalTool any, target string) {
		ownerExec(t, f.id, `INSERT INTO issue (id, org_id, project_id, number, fingerprint, tool, rule_id, title, severity,
			first_seen_scan_id, last_seen_scan_id, target, external_tool, file_path)
			VALUES ($1, $2, $3, $4, $5, $6, 'go/sql-injection', 't', 'high', $7, $7, $8, $9, 'db.go')`,
			ids.New(), f.id, f.project, n, fmt.Sprintf("%064d", n), tool, imp.ID, target, externalTool)
	}
	add(1, "external", "codeql", imp.Target)
	add(2, "external", "semgrep", "(import) semgrep")
	add(3, "opengrep", nil, "")
	add(4, "trivy", nil, "ghcr.io/acme/api")
	add(5, "gitleaks", nil, "(history)")
	lead := w.actor("IMFlead", f.id)
	keys := func(fl service.IssueFilter) string {
		var out []string
		for _, it := range must(w.svc.Issues(ctx, lead, fl)).Items {
			out = append(out, it.Key)
		}
		return strings.Join(out, ",")
	}
	for name, c := range map[string]struct {
		f    service.IssueFilter
		want string
	}{
		"import":           {service.IssueFilter{Source: "import"}, "IMF-1,IMF-2"},
		"external_tool":    {service.IssueFilter{ExternalTool: "codeql"}, "IMF-1"},
		"tool external":    {service.IssueFilter{Tool: "external"}, "IMF-1,IMF-2"},
		"both":             {service.IssueFilter{Tool: "external", ExternalTool: "semgrep", Source: "import"}, "IMF-2"},
		"none of the tool": {service.IssueFilter{ExternalTool: "sonarqube"}, ""},
		"image":            {service.IssueFilter{Source: "image"}, "IMF-4"},
		"code":             {service.IssueFilter{Source: "code"}, "IMF-3"},
		"history":          {service.IssueFilter{Source: "history"}, "IMF-5"},
		"target":           {service.IssueFilter{Source: "import", Q: "IMF-1"}, "IMF-1"},
	} {
		c.f.Sort = "-severity"
		got := strings.Split(keys(c.f), ",")
		want := strings.Split(c.want, ",")
		if len(got) != len(want) || !sameSet(got, want) {
			t.Errorf("%s: %v, want %v", name, got, want)
		}
	}
	list := must(w.svc.Issues(ctx, lead, service.IssueFilter{Source: "import", ExternalTool: "codeql"}))
	if it := list.Items[0]; it.ExternalTool == nil || *it.ExternalTool != "codeql" || it.Tool != "external" || it.Target != imp.Target {
		t.Fatalf("%+v", it)
	}
	if iss := must(w.svc.Issue(ctx, lead, list.Items[0].ID)); iss.ExternalTool == nil || *iss.ExternalTool != "codeql" {
		t.Fatalf("%+v", iss)
	}
	code := must(w.svc.Issues(ctx, lead, service.IssueFilter{Source: "code"}))
	if code.Items[0].ExternalTool != nil {
		t.Fatalf("%+v", code.Items[0])
	}

	// The export: the same filter; the row carries the external tool.
	var rows []service.IssueExportRow
	err := w.svc.ExportIssues(ctx, lead, service.IssueFilter{Source: "import"}, func(service.IssueExport) error { return nil },
		func(r service.IssueExportRow) error { rows = append(rows, r); return nil })
	if err != nil || len(rows) != 2 {
		t.Fatal(rows, err)
	}
	for _, r := range rows {
		if r.Tool != "external" || r.ExternalTool == nil || (*r.ExternalTool != "codeql" && *r.ExternalTool != "semgrep") {
			t.Fatalf("%+v", r)
		}
	}

	// Targets: '(import) …' is kind import, and kind=import lists only those.
	kinds := map[string]string{}
	for _, x := range must(w.svc.ProjectTargets(ctx, dev, f.project)).Items {
		kinds[x.Target] = x.Kind
	}
	if kinds[imp.Target] != "import" || kinds["(import) semgrep"] != "import" || kinds["ghcr.io/acme/api"] != "image" ||
		kinds["(history)"] != "history" || kinds[""] != "source" {
		t.Fatalf("%+v", kinds)
	}
	ot := must(w.svc.OrgTargets(ctx, lead, "import")).Items
	if len(ot) != 2 || ot[0].Kind != "import" || ot[1].Kind != "import" {
		t.Fatalf("%+v", ot)
	}
	for _, x := range must(w.svc.OrgTargets(ctx, lead, "image")).Items {
		if x.Target != "ghcr.io/acme/api" {
			t.Fatalf("%+v", x)
		}
	}
}

func sameSet(a, b []string) bool {
	m := map[string]int{}
	for _, x := range a {
		m[x]++
	}
	for _, x := range b {
		m[x]--
	}
	for _, v := range m {
		if v != 0 {
			return false
		}
	}
	return true
}
