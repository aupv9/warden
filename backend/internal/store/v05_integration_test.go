//go:build integration

package store_test

import (
	"encoding/json"
	"fmt"
	"strings"
	"testing"

	"github.com/google/uuid"

	"github.com/aupv9/warden/backend/internal/ids"
	"github.com/aupv9/warden/backend/internal/service"
)

// issueIn seeds an issue in any project of the fixture's org.
func issueIn(t *testing.T, f orgFixture, project uuid.UUID, n int, severity, status, title string) {
	t.Helper()
	ownerExec(t, f.id, `INSERT INTO issue (id, org_id, project_id, number, fingerprint, tool, rule_id, title, severity, status,
		first_seen_scan_id, last_seen_scan_id, file_path, start_line, cve)
		VALUES ($1, $2, $3, $4, $5, 'trivy', 'CVE-2024-0001', $6, $7, $8, $9, $9, 'go.sum', 12, '{CVE-2024-0001}')`,
		ids.New(), f.id, project, n, fmt.Sprintf("%064d", n), title, severity, status, f.scan)
}

func export(w *world, a *service.Actor, f service.IssueFilter) ([]service.IssueExportRow, service.IssueExport, error) {
	var (
		rows []service.IssueExportRow
		ex   service.IssueExport
	)
	err := w.svc.ExportIssues(ctx, a, f, func(e service.IssueExport) error { ex = e; return nil },
		func(r service.IssueExportRow) error { rows = append(rows, r); return nil })
	return rows, ex, err
}

func keys(rows []service.IssueExportRow) string {
	var out []string
	for _, r := range rows {
		out = append(out, r.Key)
	}
	return strings.Join(out, ",")
}

// The export has the issue list's visibility: leads see every unarchived
// project, members their own, nobody another org's; and the list's order.
func TestExportIssuesVisibility(t *testing.T) {
	w := newWorld(t)
	f := w.org("EXA")
	lead, dev := w.actor("EXAlead", f.id), w.actor("EXAdev", f.id)
	other := must(w.svc.CreateProject(ctx, lead, service.CreateProjectInput{Key: "EXB", Name: "Other"}))
	archived := must(w.svc.CreateProject(ctx, lead, service.CreateProjectInput{Key: "EXC", Name: "Archived"}))
	issueIn(t, f, f.project, 1, "low", "open", "=HYPERLINK(\"http://evil.test\")")
	issueIn(t, f, f.project, 2, "critical", "in_progress", "b")
	issueIn(t, f, f.project, 3, "high", "fixed", "c")
	issueIn(t, f, other.ID, 1, "high", "open", "d")
	issueIn(t, f, archived.ID, 1, "critical", "open", "e")
	ownerExec(t, f.id, `UPDATE project SET archived_at = now() WHERE id = $1`, archived.ID)
	g := w.org("EXZ")
	issueIn(t, g, g.project, 1, "critical", "open", "secret")

	rows, ex, err := export(w, lead, service.IssueFilter{Sort: service.SortSeverity})
	if err != nil || keys(rows) != "EXA-2,EXB-1,EXA-1" || ex.Rows != 3 || ex.Truncated || ex.OrgID != f.id {
		t.Fatal(keys(rows), ex, err)
	}
	r := rows[2]
	if r.Title != `=HYPERLINK("http://evil.test")` || r.ProjectName != "Project EXA" || r.FilePath == nil || *r.FilePath != "go.sum" ||
		r.Line == nil || *r.Line != 12 || len(r.CVE) != 1 || r.CreatedAt.T().IsZero() || r.Tool != "trivy" {
		t.Fatalf("%+v", r)
	}
	if rows, _, err := export(w, dev, service.IssueFilter{Sort: service.SortSeverity}); err != nil || keys(rows) != "EXA-2,EXA-1" {
		t.Fatal(keys(rows), err)
	}
	if rows, _, err := export(w, lead, service.IssueFilter{Status: []string{"fixed"}}); err != nil || keys(rows) != "EXA-3" {
		t.Fatal(keys(rows), err)
	}
	// Asked for by project, the archived one's issues stay readable, as in the list.
	if rows, _, err := export(w, lead, service.IssueFilter{ProjectID: archived.ID.String()}); err != nil || keys(rows) != "EXC-1" {
		t.Fatal(keys(rows), err)
	}
	if rows, _, err := export(w, dev, service.IssueFilter{ProjectID: other.ID.String()}); err != nil || len(rows) != 0 {
		t.Fatal(keys(rows), err)
	}
	if _, _, err := export(w, w.actor("EXZlead", f.id), service.IssueFilter{}); code(err) != "NOT_FOUND" {
		t.Fatal(err)
	}
	if _, _, err := export(w, lead, service.IssueFilter{Severity: []string{"urgent"}}); code(err) != "VALIDATION_FAILED" {
		t.Fatal(err)
	}

	// Recorded with the filters and the count, never the rows.
	log := must(w.svc.AuditLog(ctx, lead, service.AuditFilter{Action: "issues.exported"}))
	if len(log.Items) != 5 { // the refused ones aren't recorded
		t.Fatalf("%+v", log.Items)
	}
	var last map[string]any
	if err := json.Unmarshal(log.Items[0].Data, &last); err != nil || last["project_id"] != other.ID.String() || last["rows"] != 0.0 ||
		strings.Contains(string(log.Items[1].Data), "HYPERLINK") {
		t.Fatal(last, err)
	}
}

// POST /audit-log/verify recomputes the chain, records itself after the check
// without breaking the chain, reports tampering, and is rate limited per org.
func TestVerifyAuditLogChain(t *testing.T) {
	w := newWorld(t)
	f := w.org("AUV")
	admin, lead := w.actor("AUVadmin", f.id), w.actor("AUVlead", f.id)
	before := len(must(w.svc.AuditLog(ctx, admin, service.AuditFilter{PageParams: service.PageParams{Limit: "200"}})).Items)

	v := must(w.svc.VerifyAuditLog(ctx, admin))
	if !v.OK || v.Entries != before || v.FirstBadID != nil {
		t.Fatalf("%+v", v)
	}
	// The audit.verified entry is chained like any other.
	v = must(w.svc.VerifyAuditLog(ctx, lead))
	if !v.OK || v.Entries != before+1 {
		t.Fatalf("%+v", v)
	}
	if _, err := w.svc.VerifyAuditLog(ctx, w.actor("AUVdev", f.id)); code(err) != "FORBIDDEN" {
		t.Fatal(err)
	}

	// Tampering (owner rights only) is reported with the entry's id, and the
	// check is still recorded.
	var bad int64
	ownerExec(t, f.id, `UPDATE audit_log SET data = '{"x":1}' WHERE id = (SELECT min(id) FROM audit_log WHERE org_id = $1 AND action = 'member.added')`, f.id)
	must(0, w.pool.QueryRow(ctx, `SELECT min(id) FROM audit_log WHERE org_id = $1 AND action = 'member.added'`, f.id).Scan(&bad))
	v = must(w.svc.VerifyAuditLog(ctx, admin))
	if v.OK || v.FirstBadID == nil || *v.FirstBadID != fmt.Sprint(bad) || v.Entries != before+2 {
		t.Fatalf("%+v", v)
	}
	log := must(w.svc.AuditLog(ctx, admin, service.AuditFilter{Action: "audit.verified"}))
	var data map[string]any
	if len(log.Items) != 3 || json.Unmarshal(log.Items[0].Data, &data) != nil || data["ok"] != false || data["first_bad_id"] != fmt.Sprint(bad) {
		t.Fatalf("%+v", log.Items)
	}

	// 10 per org per hour.
	for range 7 {
		must(w.svc.VerifyAuditLog(ctx, lead))
	}
	if _, err := w.svc.VerifyAuditLog(ctx, admin); code(err) != "RATE_LIMITED" {
		t.Fatal(err)
	}
}
