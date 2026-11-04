//go:build integration

package worker

import (
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/google/uuid"

	"github.com/aupv9/warden/backend/internal/scan/importer"
	"github.com/aupv9/warden/backend/internal/scan/redact"
	"github.com/aupv9/warden/backend/internal/scan/sandbox"
	st "github.com/aupv9/warden/backend/internal/scan/scantest"
)

// screeningGitleaks stands in for Gitleaks over an import's screening file:
// a finding for every line holding scantest.FakeSecret, redacted by the
// real warden-redact code.
func screeningGitleaks(scanDir string) st.M {
	b, _ := os.ReadFile(filepath.Join(scanDir, "src", importer.ScreenFile))
	results := []any{}
	for i, line := range strings.Split(string(b), "\n") {
		if strings.Contains(line, st.FakeSecret) {
			results = append(results, st.M{"ruleId": "aws-access-token", "message": st.M{"text": "detected"},
				"locations": []any{st.Loc("/src/"+importer.ScreenFile, i+1, st.FakeSecret)}})
		}
	}
	red, err := redact.Doc(st.RoundTrip(st.Doc(results)), st.HMACKey)
	if err != nil {
		panic(err)
	}
	return red
}

type codeqlResult struct{ rule, path, message string }

func codeqlSARIF(results ...codeqlResult) []byte {
	var rs []any
	for _, r := range results {
		rs = append(rs, st.M{"ruleId": r.rule, "message": st.M{"text": r.message},
			"locations": []any{st.M{"physicalLocation": st.M{"artifactLocation": st.M{"uri": r.path, "uriBaseId": "%SRCROOT%"},
				"region": st.M{"startLine": 7}}}},
			"partialFingerprints": st.M{"primaryLocationLineHash": r.rule + r.path + ":1"}})
	}
	b, _ := json.Marshal(st.M{"$schema": "https://json.schemastore.org/sarif-2.1.0.json", "version": "2.1.0", "runs": []any{st.M{
		"tool": st.M{"driver": st.M{"name": "CodeQL", "semanticVersion": "2.20.1", "rules": []any{
			st.M{"id": "js/xss", "shortDescription": st.M{"text": "Reflected XSS"}, "properties": st.M{"security-severity": "7.8",
				"tags": []any{"security", "external/cwe/cwe-079"}}},
			st.M{"id": "js/sql-injection", "shortDescription": st.M{"text": "SQL injection"}, "properties": st.M{"security-severity": "8.8"}},
		}}},
		"results": rs,
	}}})
	return b
}

// importScan inserts a queued import scan of codeql (in category, "" for
// none) with its file uploaded.
func (it *itest) importScan(category string, file []byte) uuid.UUID {
	id := uuid.New()
	key := "imports/" + it.org.String() + "/" + id.String() + ".sarif"
	sum := sha256.Sum256(file)
	target := "(import) codeql"
	if category != "" {
		target += " " + category
	}
	owner(it.t, it.org, fmt.Sprintf(`INSERT INTO scan (id, org_id, project_id, created_by, status, file_name, object_key, sha256,
		tools, kind, target, import_tool, import_category, import_format)
		VALUES ('%s', '%s', '%s', '%s', 'queued', 'codeql.sarif', '%s', '%s', '{external}', 'import', '%s', 'codeql', '%s', 'sarif')`,
		id, it.org, it.project, it.user, key, hex.EncodeToString(sum[:]), target, category))
	it.store.objects[key] = file
	return id
}

func (it *itest) issueStates(where string) map[string]string {
	it.t.Helper()
	var raw []byte
	it.one(fmt.Sprintf(`SELECT coalesce(jsonb_object_agg(rule_id || ' ' || coalesce(file_path, ''), status), '{}')
		FROM issue WHERE project_id = '%s' AND %s`, it.project, where), &raw)
	out := map[string]string{}
	if err := json.Unmarshal(raw, &out); err != nil {
		it.t.Fatal(err)
	}
	return out
}

// The whole import: screened, stored as tool external's issues of the
// import's target, auto-fixed by the next import of the same tool and
// category only, and never by a Warden scan (nor the other way round).
func TestImportLifecycle(t *testing.T) {
	it := newITest(t)
	it.sb.docFns = map[string]func(string) st.M{"gitleaks": screeningGitleaks}
	secret := st.FakeSecret

	// 1. A source scan opens a Warden issue (opengrep's r1 in app/a.py).
	data, sha := zipBytes()
	src, key := it.scan("queued", sha, 0, "opengrep")
	it.store.objects[key] = data
	it.run(src)

	// 2. The import: the secret in a message is screened out, the secret in
	// a path drops its result, a traversal is dropped.
	first := it.importScan("", codeqlSARIF(
		codeqlResult{"js/xss", "src/a.js", "user input " + secret + " reaches the page"},
		codeqlResult{"js/sql-injection", "src/db.js", "query built from input"},
		codeqlResult{"js/xss", "src/" + secret + ".js", "path"},
		codeqlResult{"js/xss", "../outside.js", "traversal"},
	))
	it.run(first)
	var status, version string
	var results, dropped, screened, runs int
	var toolVersion string
	it.one(fmt.Sprintf(`SELECT status, import_tool_version, import_results, import_dropped, import_screened,
		(SELECT count(*) FROM scan_tool_run WHERE scan_id = scan.id),
		(SELECT tool_version FROM scan_tool_run WHERE scan_id = scan.id AND tool = 'external' AND status = 'succeeded' AND findings_count = 2)
		FROM scan WHERE id = '%s'`, first), &status, &version, &results, &dropped, &screened, &runs, &toolVersion)
	if status != "completed" || version != "2.20.1" || results != 4 || dropped != 2 || screened != 2 || runs != 1 || toolVersion != "2.20.1" {
		t.Fatalf("scan %s %q %d/%d/%d, %d runs, %q", status, version, results, dropped, screened, runs, toolVersion)
	}
	if got := it.issueStates("tool = 'external' AND external_tool = 'codeql' AND target = '(import) codeql'"); len(got) != 2 ||
		got["js/xss src/a.js"] != "open" || got["js/sql-injection src/db.js"] != "open" {
		t.Fatalf("imported issues %v", got)
	}
	var stored string
	it.one(fmt.Sprintf(`SELECT coalesce(string_agg(concat_ws('|', title, description, remediation, file_path, snippet, rule_id), '|'), '') ||
		(SELECT coalesce(string_agg(raw::text, '|'), '') FROM occurrence o JOIN issue i ON i.id = o.issue_id WHERE i.project_id = '%s')
		FROM issue WHERE project_id = '%s'`, it.project, it.project), &stored)
	if strings.Contains(stored, secret) || strings.Contains(stored, secret[:12]) {
		t.Fatalf("secret stored: %s", stored)
	}
	var sev, cwe, desc string
	it.one(fmt.Sprintf(`SELECT severity::text, array_to_string(cwe, ','), coalesce(description, '') FROM issue
		WHERE project_id = '%s' AND rule_id = 'js/xss'`, it.project), &sev, &cwe, &desc)
	if sev != "high" || cwe != "CWE-79" || desc != "" { // the description fell back to the screened (empty) message
		t.Fatalf("xss issue %s %s %q", sev, cwe, desc)
	}

	// 3. Another category of the same tool: its own target; fixes nothing of
	// the first.
	goImport := it.importScan("/language:go/", codeqlSARIF(codeqlResult{"go/sqli", "cmd/main.go", "go"}))
	it.run(goImport)
	empty := it.importScan("/language:go/", codeqlSARIF())
	it.run(empty)
	if got := it.issueStates("target = '(import) codeql /language:go/'"); got["go/sqli cmd/main.go"] != "fixed" {
		t.Fatalf("go category %v", got)
	}
	if got := it.issueStates("target = '(import) codeql'"); got["js/xss src/a.js"] != "open" || got["js/sql-injection src/db.js"] != "open" {
		t.Fatalf("default category touched: %v", got)
	}

	// 4. A Warden source scan that finds nothing fixes its own issue, never
	// an imported one.
	it.sb.empty = true
	data, sha = zipBytes()
	src2, key2 := it.scan("queued", sha, 0, "opengrep")
	it.store.objects[key2] = data
	it.run(src2)
	it.sb.empty = false
	if got := it.issueStates("target = ''"); got["r1 a.py"] != "fixed" {
		t.Fatalf("source issue %v", got)
	}
	if got := it.issueStates("tool = 'external'"); got["js/xss src/a.js"] != "open" || got["js/sql-injection src/db.js"] != "open" {
		t.Fatalf("a source scan touched imported issues: %v", got)
	}

	// 5. Re-import without the SQL injection: fixed; the XSS, moved and with
	// the same partial fingerprint, keeps its issue. The source issue stays
	// as the source scan left it.
	again := it.importScan("", codeqlSARIF(codeqlResult{"js/xss", "src/a.js", "still here"}))
	it.run(again)
	if got := it.issueStates("tool = 'external' AND target = '(import) codeql'"); len(got) != 2 ||
		got["js/xss src/a.js"] != "open" || got["js/sql-injection src/db.js"] != "fixed" {
		t.Fatalf("re-import %v", got)
	}
	if got := it.issueStates("target = ''"); got["r1 a.py"] != "fixed" {
		t.Fatalf("an import touched the source issue: %v", got)
	}
	var reopenedSource int
	it.one(fmt.Sprintf(`SELECT count(*) FROM issue_event e JOIN issue i ON i.id = e.issue_id
		WHERE i.project_id = '%s' AND i.tool <> 'external' AND e.note LIKE '%%%s%%'`, it.project, again), &reopenedSource)
	if reopenedSource != 0 {
		t.Fatal("the import wrote events on a Warden issue")
	}

	// 6. Gitleaks can't screen: the import fails and stores nothing.
	it.sb.status["gitleaks"] = sandbox.Failed
	failed := it.importScan("", codeqlSARIF(codeqlResult{"js/new", "src/new.js", "new"}))
	it.run(failed)
	delete(it.sb.status, "gitleaks")
	var code string
	var n int
	it.one(fmt.Sprintf(`SELECT status || ' ' || coalesce(error_code, ''), (SELECT count(*) FROM issue WHERE rule_id = 'js/new')
		FROM scan WHERE id = '%s'`, failed), &code, &n)
	if code != "failed "+importer.CodeScreenFailed || n != 0 {
		t.Fatalf("scan %s, %d issues", code, n)
	}
}

// A file that isn't SARIF 2.1.0 fails the scan before anything runs.
func TestImportRejectedFile(t *testing.T) {
	it := newITest(t)
	id := it.importScan("", []byte(`{"version":"2.0.0","runs":[]}`))
	it.run(id)
	var code string
	it.one(fmt.Sprintf(`SELECT status || ' ' || coalesce(error_code, '') FROM scan WHERE id = '%s'`, id), &code)
	if code != "failed "+importer.CodeInvalid || len(it.sb.specs) != 0 {
		t.Fatalf("scan %s, ran %d", code, len(it.sb.specs))
	}
}
