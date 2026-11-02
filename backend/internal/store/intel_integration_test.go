//go:build integration

package store_test

import (
	"fmt"
	"slices"
	"testing"
	"time"

	"github.com/google/uuid"

	"github.com/aupv9/warden/backend/internal/ids"
	"github.com/aupv9/warden/backend/internal/service"
)

// Synthetic CVE ids, built at test time (vuln_intel is global: keep them
// unique to this file).
func intelCVE(n int) string { return fmt.Sprintf("CVE-2031-%05d", n) }

// trivyIssue inserts an active Trivy issue with CVEs and a target.
func (w *world) trivyIssue(f orgFixture, n int, severity, rule, target string, cves ...string) uuid.UUID {
	id := ids.New()
	ownerExec(w.t, f.id, `INSERT INTO issue (id, org_id, project_id, number, fingerprint, tool, rule_id, title, severity, status,
		first_seen_scan_id, last_seen_scan_id, cve, target, package_name)
		VALUES ($1, $2, $3, $4, $5, 'trivy', $6, 'pkg vulnerable', $7, 'open', $8, $8, $9, $10, 'pkg')`,
		id, f.id, f.project, n, fmt.Sprintf("%064d", n), rule, severity, f.scan, cves, target)
	return id
}

func TestIssueIntelReadPath(t *testing.T) {
	w := newWorld(t)
	f := w.org("KEV")
	lead := w.actor("KEVlead", f.id)
	ownerExec(t, f.id, `INSERT INTO vuln_intel (cve, kev_added, kev_ransomware, epss, epss_percentile) VALUES
		($1, '2024-03-01', true, 0.9, 0.99), ($2, NULL, false, 0.7, 0.95), ($3, '2023-01-01', false, NULL, NULL), ($4, NULL, false, 0.7, 0.95)`,
		intelCVE(1), intelCVE(2), intelCVE(3), intelCVE(4))
	names := map[uuid.UUID]string{}
	add := func(name string, id uuid.UUID) { names[id] = name }
	add("kev-high-epss", w.trivyIssue(f, 1, "low", intelCVE(1), "", intelCVE(2), intelCVE(1)))
	add("epss", w.trivyIssue(f, 2, "high", intelCVE(2), "", intelCVE(2)))
	add("kev-image", w.trivyIssue(f, 3, "medium", intelCVE(3), "ghcr.io/acme/api", intelCVE(3)))
	add("epss-tie", w.trivyIssue(f, 4, "critical", intelCVE(4), "", intelCVE(4)))
	add("no-intel", w.trivyIssue(f, 5, "high", intelCVE(99), "", intelCVE(99)))
	add("license", w.trivyIssue(f, 6, "medium", "license:GPL-3.0-only", ""))
	add("code", w.issue(f, 7, "critical", "open", nil, nil))

	list := func(fl service.IssueFilter) ([]string, service.IssuePage) {
		t.Helper()
		p, err := w.svc.Issues(ctx, lead, fl)
		if err != nil {
			t.Fatal(err)
		}
		var out []string
		for _, it := range p.Items {
			out = append(out, names[it.ID])
		}
		return out, p
	}
	set := func(s []string) []string { s = slices.Clone(s); slices.Sort(s); return s }

	got, p := list(service.IssueFilter{KEV: "true"})
	if !slices.Equal(set(got), []string{"kev-high-epss", "kev-image"}) || p.CountsBySeverity != (service.SeverityCounts{Low: 1, Medium: 1}) {
		t.Fatal(got, p.CountsBySeverity)
	}
	// 0.7 is stored as real: the filter must still include a score of exactly 0.7.
	if got, _ := list(service.IssueFilter{EPSSMin: "0.7"}); !slices.Equal(set(got), []string{"epss", "epss-tie", "kev-high-epss"}) {
		t.Fatal(got)
	}
	if got, _ := list(service.IssueFilter{EPSSMin: "0.71"}); !slices.Equal(got, []string{"kev-high-epss"}) {
		t.Fatal(got)
	}
	for _, c := range []struct {
		f    service.IssueFilter
		want []string
	}{
		{service.IssueFilter{Kind: "vulnerability"}, []string{"epss", "epss-tie", "kev-high-epss", "kev-image", "no-intel"}},
		{service.IssueFilter{Kind: "license"}, []string{"license"}},
		{service.IssueFilter{Source: "image"}, []string{"kev-image"}},
		{service.IssueFilter{Target: "ghcr.io/acme/api", KEV: "true"}, []string{"kev-image"}},
		{service.IssueFilter{Source: "code", Tool: "trivy"}, []string{"epss", "epss-tie", "kev-high-epss", "license", "no-intel"}},
		{service.IssueFilter{Source: "code", KEV: "true"}, []string{"kev-high-epss"}},
	} {
		if got, _ := list(c.f); !slices.Equal(set(got), c.want) {
			t.Errorf("%+v: %v", c.f, got)
		}
	}

	// -epss: scores as the shortest decimal, highest first, ties by id, the
	// rest last; keyset pages give the same order with no repeats.
	all, p := list(service.IssueFilter{Sort: "-epss"})
	if len(all) != 7 || all[0] != "kev-high-epss" || !slices.Equal(set(all[1:3]), []string{"epss", "epss-tie"}) {
		t.Fatal(all)
	}
	if *p.Items[0].EPSS != 0.9 || *p.Items[1].EPSS != 0.7 || !p.Items[0].KEV || p.Items[6].EPSS != nil {
		t.Fatalf("%+v", p.Items)
	}
	var paged []string
	cursor := ""
	for range 10 {
		got, p := list(service.IssueFilter{Sort: "-epss", PageParams: service.PageParams{Limit: "2", Cursor: cursor}})
		paged = append(paged, got...)
		if p.NextCursor == nil {
			break
		}
		cursor = *p.NextCursor
	}
	if !slices.Equal(paged, all) {
		t.Fatalf("pages %v, list %v", paged, all)
	}

	var kevID uuid.UUID
	for id, n := range names {
		if n == "kev-high-epss" {
			kevID = id
		}
	}
	iss := must(w.svc.Issue(ctx, lead, kevID))
	if !iss.KEV || *iss.EPSS != 0.9 || *iss.EPSSPercentile != 0.99 || *iss.KEVAdded != "2024-03-01" || !iss.KEVRansomware ||
		iss.Severity != "low" || iss.Target != "" {
		t.Fatalf("%+v", iss)
	}

	tot := must(w.svc.IssueTotals(ctx, lead, ""))
	if tot.KEV != 2 || tot.Licenses != 1 || tot.Active != 7 {
		t.Fatalf("%+v", tot)
	}

	// Gate: the low KEV issue blocks only with fail_on_kev.
	var epssID uuid.UUID
	for id, n := range names {
		if n == "epss" {
			epssID = id
		}
	}
	for _, id := range []uuid.UUID{kevID, epssID} {
		ownerExec(t, f.id, `INSERT INTO occurrence (org_id, issue_id, scan_id, raw) VALUES ($1, $2, $3, '{}')`, f.id, id, f.scan)
	}
	ownerExec(t, f.id, `UPDATE scan SET status = 'completed', finished_at = now() WHERE id = $1`, f.scan)
	g := must(w.svc.Gate(ctx, lead, f.scan, "critical", ""))
	if !g.Pass || g.KEV != 1 || len(g.Blocking) != 0 {
		t.Fatalf("%+v", g)
	}
	g = must(w.svc.Gate(ctx, lead, f.scan, "critical", "true"))
	if g.Pass || !g.FailOnKEV || g.KEV != 1 || len(g.Blocking) != 1 || g.Blocking[0].ID != kevID || !g.Blocking[0].KEV || *g.Blocking[0].EPSS != 0.9 {
		t.Fatalf("%+v", g)
	}
	g = must(w.svc.Gate(ctx, lead, f.scan, "high", "true"))
	if g.Pass || len(g.Blocking) != 2 || g.Blocking[0].ID != epssID {
		t.Fatalf("%+v", g)
	}
	// An accepted KEV issue doesn't block.
	ownerExec(t, f.id, `UPDATE issue SET status = 'risk_accepted' WHERE id = $1`, kevID)
	if g = must(w.svc.Gate(ctx, lead, f.scan, "critical", "true")); !g.Pass || g.KEV != 0 {
		t.Fatalf("%+v", g)
	}
}

func TestVulnDataFreshness(t *testing.T) {
	w := newWorld(t)
	f := w.org("VDF")
	ownerExec(t, f.id, `INSERT INTO vuln_intel_source (name, updated_at, loaded_at, records, sha256, unsupported)
		VALUES ('kev', $1, now(), 1758, $2, NULL), ('trivy_db', $3, NULL, NULL, $2, NULL), ('osv_mal:PyPI', $1, now(), 11935, $2, 7)
		ON CONFLICT (name) DO UPDATE SET updated_at = EXCLUDED.updated_at, loaded_at = EXCLUDED.loaded_at, records = EXCLUDED.records,
			unsupported = EXCLUDED.unsupported`,
		time.Now().Add(-48*time.Hour), fmt.Sprintf("%064d", 1), time.Now().Add(-10*24*time.Hour))
	d := must(w.svc.VulnData(ctx, w.actor("VDFdev", f.id)))
	if len(d.Sources) != 11 {
		t.Fatalf("%+v", d)
	}
	if npm, pypi := d.Sources[3], d.Sources[4]; npm.Name != "osv_mal:npm" || !npm.Stale || npm.Unsupported != nil ||
		pypi.Name != "osv_mal:PyPI" || pypi.Stale || *pypi.Records != 11935 || *pypi.Unsupported != 7 {
		t.Fatalf("%+v %+v", npm, pypi)
	}
	trivy, kev, epss := d.Sources[0], d.Sources[1], d.Sources[2]
	if trivy.Name != "trivy_db" || !trivy.Stale || trivy.LoadedAt != nil || trivy.Records != nil {
		t.Fatalf("%+v", trivy)
	}
	if kev.Name != "kev" || kev.Stale || *kev.Records != 1758 || kev.LoadedAt == nil {
		t.Fatalf("%+v", kev)
	}
	if epss.Name != "epss" || !epss.Stale || epss.UpdatedAt != nil {
		t.Fatalf("%+v", epss)
	}
}
