//go:build integration

package store_test

import (
	"encoding/json"
	"fmt"
	"slices"
	"strings"
	"testing"
	"time"

	"github.com/google/uuid"
	"github.com/jackc/pgx/v5"

	"github.com/aupv9/warden/backend/internal/db"
	"github.com/aupv9/warden/backend/internal/domain/fingerprint"
	"github.com/aupv9/warden/backend/internal/domain/severity"
	"github.com/aupv9/warden/backend/internal/ids"
	"github.com/aupv9/warden/backend/internal/scan/results"
	"github.com/aupv9/warden/backend/internal/scan/sandbox"
	"github.com/aupv9/warden/backend/internal/scan/sarif"
	"github.com/aupv9/warden/backend/internal/service"
)

// TestGateBlockingNewFollowsProcessing runs real result processing and checks
// that blocking_new agrees with each scan's stats (new + reopened).
func TestGateBlockingNewFollowsProcessing(t *testing.T) {
	w := newHTTPWorld(t)
	f := w.org("GBN")
	tok := w.newToken("GBNowner", f.id, f.project, "scan:write").Secret
	finding := func(rule string, sev severity.Severity) sarif.Finding {
		l := 3
		return sarif.Finding{Tool: "opengrep", RuleID: rule, Title: rule, Severity: sev, FilePath: rule + ".py",
			StartLine: &l, EndLine: &l, ContentKey: fingerprint.CodeContentKey([]string{rule})}
	}
	a, b, c, d := finding("sqli", severity.High), finding("xss", severity.High), finding("rce", severity.Critical), finding("ssrf", severity.High)
	process := func(fs ...sarif.Finding) (uuid.UUID, results.Stats) {
		t.Helper()
		sc := must(w.svc.CreateScan(ctx, w.actor("GBNdev", f.id), f.project,
			service.CreateScanInput{FileName: "s.zip", FileSize: 10, SHA256: strings.Repeat("a", 64)})).Scan.ID
		ownerExec(t, f.id, `UPDATE scan SET status = 'running' WHERE id = $1`, sc)
		var p results.Plan
		err := db.WithOrg(ctx, w.pool, f.id, func(tx pgx.Tx) error {
			var err error
			p, err = results.Process(ctx, tx, results.Input{OrgID: f.id, ProjectID: f.project, ScanID: sc, Status: "completed",
				Runs: []sandbox.ToolRun{{Tool: "opengrep", Status: sandbox.Succeeded}}, Findings: map[string][]sarif.Finding{"opengrep": fs},
				GuardRatio: 0.5, Now: time.Now().UTC()})
			return err
		})
		if err != nil {
			t.Fatal(err)
		}
		return sc, p.Stats
	}
	type gateView struct {
		Blocking []struct {
			ID    uuid.UUID `json:"id"`
			Title string    `json:"title"`
		} `json:"blocking"`
		BlockingNew []uuid.UUID `json:"blocking_new"`
	}
	gate := func(sc uuid.UUID) (g gateView, titles map[uuid.UUID]string) {
		t.Helper()
		r := w.call("GET", "/orgs/"+f.id.String()+"/scans/"+sc.String()+"/gate", tok, nil)
		w.expect(r, 200, "")
		if err := json.Unmarshal(r.Data, &g); err != nil {
			t.Fatal(err)
		}
		titles = map[uuid.UUID]string{}
		for _, i := range g.Blocking {
			titles[i.ID] = i.Title
		}
		return g, titles
	}
	newTitles := func(sc uuid.UUID) []string {
		t.Helper()
		g, titles := gate(sc)
		var out []string
		for _, id := range g.BlockingNew {
			out = append(out, titles[id])
		}
		slices.Sort(out)
		return out
	}

	s1, st := process(a, b, c)
	if got := newTitles(s1); fmt.Sprint(got) != "[rce sqli xss]" || st.New != 3 {
		t.Fatalf("%v %+v", got, st)
	}
	// xss disappears (fixed); nothing is new.
	s2, st := process(a, c)
	if got := newTitles(s2); len(got) != 0 || st.Fixed != 1 {
		t.Fatalf("%v %+v", got, st)
	}
	// xss is back (reopened) and ssrf is new; sqli and rce were already open.
	s3, st := process(a, b, c, d)
	got := newTitles(s3)
	if fmt.Sprint(got) != "[ssrf xss]" || st.New+st.Reopened != len(got) {
		t.Fatalf("%v %+v", got, st)
	}
	// An earlier scan's answer doesn't change with later scans.
	if got := newTitles(s1); len(got) != 3 {
		t.Fatal(got)
	}

	// Look-alikes that this scan didn't write: an issue Inject created against
	// the scan (its created event has a note), and a user's reopen.
	g, _ := gate(s3)
	injected := ids.New()
	ownerExec(t, f.id, `INSERT INTO issue (id, org_id, project_id, number, fingerprint, tool, rule_id, title, severity, status,
		first_seen_scan_id, last_seen_scan_id) VALUES ($1, $2, $3, 100, $4, 'trivy', 'MAL-1', 'malicious', 'critical', 'open', $5, $5)`,
		injected, f.id, f.project, strings.Repeat("9", 64), s3)
	ownerExec(t, f.id, `INSERT INTO occurrence (org_id, issue_id, scan_id, raw) VALUES ($1, $2, $3, '{}')`, f.id, injected, s3)
	ownerExec(t, f.id, `INSERT INTO issue_event (org_id, issue_id, type, to_value, note)
		VALUES ($1, $2, 'created', 'open', 'found by malicious-package advisory MAL-1 (no scan)')`, f.id, injected)
	known := g.Blocking[0].ID // rce: first seen in s1
	if slices.Contains(g.BlockingNew, known) {
		t.Fatal("rce is not new in s3")
	}
	ownerExec(t, f.id, `INSERT INTO issue_event (org_id, issue_id, actor_id, type, from_value, to_value, note)
		VALUES ($1, $2, $3, 'status_changed', 'fixed', 'reopened', $4)`, f.id, known, w.users["GBNlead"].ID, results.ReopenNote(s3))
	g2, titles := gate(s3)
	if _, listed := titles[injected]; !listed || len(g2.BlockingNew) != 2 || slices.Contains(g2.BlockingNew, injected) ||
		slices.Contains(g2.BlockingNew, known) {
		t.Fatalf("%+v", g2)
	}
}
