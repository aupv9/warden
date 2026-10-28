//go:build integration

package store_test

import (
	"fmt"
	"strings"
	"testing"

	"github.com/aupv9/warden/backend/internal/ids"
	"github.com/aupv9/warden/backend/internal/service"
)

// A history scan is stored with kind history, target (history), Gitleaks
// only and a .bundle key (the schema's CHECKs agree with the service). Its
// stats and its issues' commits read back; source=history, image and code
// each see only their own issues; the targets list says kind history.
func TestHistoryScanRoundTrip(t *testing.T) {
	w := newWorld(t)
	f := w.org("HST")
	w.svc = service.New(w.db, w.objs, service.Config{UploadMaxBytes: 1 << 20, HistoryUploadMaxBytes: 1 << 30, RateLimitPerHour: 5}, nil)
	dev := w.actor("HSTdev", f.id)
	created := must(w.svc.CreateScan(ctx, dev, f.project, service.CreateScanInput{Kind: "history", FileName: "repo.bundle", FileSize: 500 << 20,
		SHA256: strings.Repeat("d", 64)}))
	sc := must(w.svc.Scan(ctx, dev, created.Scan.ID))
	if sc.Kind != "history" || sc.Target != "(history)" || sc.ImageRef != nil || len(sc.Tools) != 1 || sc.Tools[0] != "gitleaks" ||
		sc.ObjectKey != "scans/"+f.id.String()+"/"+sc.ID.String()+".bundle" || sc.History != nil {
		t.Fatalf("%+v", sc)
	}
	ownerExec(t, f.id, `UPDATE scan SET status = 'completed', history_commits = 2481, history_truncated = false WHERE id = $1`, sc.ID)
	if sc := must(w.svc.Scan(ctx, dev, sc.ID)); sc.History == nil || sc.History.Commits != 2481 || sc.History.Truncated {
		t.Fatalf("%+v", sc.History)
	}

	sha := strings.Repeat("ab", 20)
	issue := func(n int, target string, commit bool) {
		var s, c any
		if commit {
			s, c = sha, 3
		}
		ownerExec(t, f.id, `INSERT INTO issue (id, org_id, project_id, number, fingerprint, tool, rule_id, title, severity,
			first_seen_scan_id, last_seen_scan_id, target, file_path, commit_sha, committed_at, commit_count)
			VALUES ($1, $2, $3, $4, $5, 'gitleaks', 'aws-access-token', 'AWS', 'critical', $6, $6, $7, 'app/config.py', $8, '2023-05-06T07:08:09Z', $9)`,
			ids.New(), f.id, f.project, n, fmt.Sprintf("%064d", n), sc.ID, target, s, c)
	}
	issue(1, "(history)", true)
	issue(2, "", false)
	issue(3, "ghcr.io/acme/api", false)
	lead := w.actor("HSTlead", f.id)
	for source, want := range map[string]string{"history": "HST-1", "code": "HST-2", "image": "HST-3"} {
		p := must(w.svc.Issues(ctx, lead, service.IssueFilter{Source: source}))
		if len(p.Items) != 1 || p.Items[0].Key != want {
			t.Errorf("source=%s: %+v", source, p.Items)
		}
	}
	list := must(w.svc.Issues(ctx, lead, service.IssueFilter{Source: "history"}))
	iss := must(w.svc.Issue(ctx, lead, list.Items[0].ID))
	if iss.Commit == nil || iss.Commit.SHA != sha || iss.Commit.Count != 3 || iss.Commit.CommittedAt == nil ||
		iss.Commit.CommittedAt.T().Year() != 2023 || iss.Target != "(history)" {
		t.Fatalf("%+v", iss.Commit)
	}
	src := must(w.svc.Issues(ctx, lead, service.IssueFilter{Source: "code"}))
	if iss := must(w.svc.Issue(ctx, lead, src.Items[0].ID)); iss.Commit != nil {
		t.Fatalf("%+v", iss.Commit)
	}

	tg := must(w.svc.ProjectTargets(ctx, dev, f.project)).Items
	kinds := map[string]string{}
	for _, x := range tg {
		kinds[x.Target] = x.Kind
	}
	if kinds["(history)"] != "history" || kinds["ghcr.io/acme/api"] != "image" || kinds[""] != "source" {
		t.Fatalf("%+v", tg)
	}
}
