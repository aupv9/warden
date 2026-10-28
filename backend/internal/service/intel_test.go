package service_test

import (
	"context"
	"encoding/base64"
	"fmt"
	"net/http"
	"strings"
	"testing"
	"time"

	"github.com/google/uuid"

	"github.com/aupv9/warden/backend/internal/domain/rbac"
	"github.com/aupv9/warden/backend/internal/service"
	"github.com/aupv9/warden/backend/internal/service/servicetest"
)

// Synthetic CVE ids, built at test time.
func testCVE(n int) string { return fmt.Sprintf("CVE-2024-%05d", n) }

func fp(v float64) *float64 { return &v }

func day(s string) *time.Time {
	t, _ := time.Parse(time.DateOnly, s)
	return &t
}

func TestIssueFilterValidation(t *testing.T) {
	x := newSetup(rbac.SecurityLead)
	ctx := context.Background()
	bad := []service.IssueFilter{
		{Kind: "secret"}, {Kind: "LICENSE"},
		{KEV: "yes"}, {KEV: "1"},
		{EPSSMin: "1.5"}, {EPSSMin: "-0.1"}, {EPSSMin: "NaN"}, {EPSSMin: "Inf"}, {EPSSMin: "-Inf"},
		{EPSSMin: "abc"}, {EPSSMin: "0.5; DROP TABLE issue"}, {EPSSMin: "0." + strings.Repeat("1", 40)},
		{Source: "binary"},
		{Target: "GHCR.io/Acme/API"}, {Target: "ghcr.io/acme/api:1.2"}, {Target: "ghcr.io/acme/api@sha256:" + strings.Repeat("a", 64)},
		{Target: "../etc/passwd"}, {Target: "a/" + strings.Repeat("b", 254)}, {Target: "%"}, {Target: "acme/api\n"},
		{Sort: "epss"}, {Sort: "-epss", PageParams: service.PageParams{Cursor: "x"}},
	}
	for _, f := range bad {
		_, err := x.s.Issues(ctx, x.actor(), f)
		if status(err) != http.StatusUnprocessableEntity {
			t.Errorf("%+v: %v", f, err)
		}
	}
	for _, f := range []service.IssueFilter{
		{Kind: "vulnerability", KEV: "true", EPSSMin: "0", Source: "code"},
		{Kind: "license", KEV: "false", EPSSMin: "1", Source: "image", Target: "ghcr.io/acme/api"},
		{EPSSMin: "0.05", Target: "localhost:5000/team/app__x", Sort: "-epss"},
	} {
		if _, err := x.s.Issues(ctx, x.actor(), f); err != nil {
			t.Errorf("%+v: %v", f, err)
		}
	}
	// All new fields report at once.
	_, err := x.s.Issues(ctx, x.actor(), service.IssueFilter{Kind: "x", KEV: "x", EPSSMin: "x", Source: "x", Target: "X"})
	if f := fields(err); len(f) != 5 {
		t.Fatal(err)
	}
}

// A cursor from another sort, or with an out-of-range score, is refused.
func TestEPSSCursorValidation(t *testing.T) {
	x := newSetup(rbac.SecurityLead)
	enc := func(c service.IssueCursor) string {
		b := fmt.Sprintf(`{"s":%q,"e":%v,"id":%q}`, c.Sort, *c.EPSS, c.ID)
		return base64.RawURLEncoding.EncodeToString([]byte(b))
	}
	for _, c := range []service.IssueCursor{
		{Sort: service.SortEPSS, EPSS: fp(1.5), ID: uuid.New()},
		{Sort: service.SortEPSS, EPSS: fp(-1), ID: uuid.New()},
		{Sort: service.SortSeverity, EPSS: fp(0.5), ID: uuid.New()},
	} {
		_, err := x.s.Issues(context.Background(), x.actor(), service.IssueFilter{Sort: "-epss", PageParams: service.PageParams{Cursor: enc(c)}})
		if status(err) != http.StatusUnprocessableEntity {
			t.Errorf("%+v: %v", c, err)
		}
	}
}

type intelWorld struct {
	setup
	ids map[string]uuid.UUID
}

// newIntelWorld: issues with and without intel, from code and from an image,
// plus a license issue.
func newIntelWorld(t *testing.T) intelWorld {
	x := newSetup(rbac.SecurityLead)
	w := intelWorld{setup: x, ids: map[string]uuid.UUID{}}
	add := func(name, sev, tool, rule, target string, cves ...string) {
		id := x.f.AddIssue(x.p, sev, "open", nil)
		x.f.SetIssue(id, func(r *servicetest.IssueRow) { r.Tool, r.RuleID, r.Target, r.CVE = tool, rule, target, cves })
		w.ids[name] = id
	}
	x.f.SetIntel(testCVE(1), servicetest.IntelRow{KEVAdded: day("2024-03-01"), Ransomware: true, EPSS: fp(0.9), Percentile: fp(0.99)})
	x.f.SetIntel(testCVE(2), servicetest.IntelRow{EPSS: fp(0.2), Percentile: fp(0.8)})
	x.f.SetIntel(testCVE(3), servicetest.IntelRow{KEVAdded: day("2023-01-01")}) // KEV, no score
	x.f.SetIntel(testCVE(4), servicetest.IntelRow{EPSS: fp(0.2), Percentile: fp(0.8)})
	add("kev-high-epss", "low", "trivy", testCVE(1), "", testCVE(2), testCVE(1)) // max over both CVEs
	add("epss-only", "high", "trivy", testCVE(2), "", testCVE(2))
	add("kev-no-score", "medium", "trivy", testCVE(3), "ghcr.io/acme/api", testCVE(3))
	add("same-score", "critical", "trivy", testCVE(4), "ghcr.io/acme/api", testCVE(4))
	add("no-intel", "high", "trivy", "CVE-2024-99999", "", "CVE-2024-99999")
	add("license", "high", "trivy", "license:GPL-3.0-only", "")
	add("code", "critical", "opengrep", "python.sqli", "")
	return w
}

func (w intelWorld) list(t *testing.T, f service.IssueFilter) []string {
	t.Helper()
	p, err := w.s.Issues(context.Background(), w.actor(), f)
	if err != nil {
		t.Fatal(err)
	}
	var out []string
	for _, it := range p.Items {
		for name, id := range w.ids {
			if id == it.ID {
				out = append(out, name)
			}
		}
	}
	return out
}

func sameSet(got []string, want ...string) bool {
	if len(got) != len(want) {
		return false
	}
	for _, w := range want {
		found := false
		for _, g := range got {
			found = found || g == w
		}
		if !found {
			return false
		}
	}
	return true
}

func TestIssueIntelFilters(t *testing.T) {
	w := newIntelWorld(t)
	for _, c := range []struct {
		f    service.IssueFilter
		want []string
	}{
		{service.IssueFilter{KEV: "true"}, []string{"kev-high-epss", "kev-no-score"}},
		{service.IssueFilter{EPSSMin: "0.2"}, []string{"kev-high-epss", "epss-only", "same-score"}},
		{service.IssueFilter{EPSSMin: "0.5"}, []string{"kev-high-epss"}},
		{service.IssueFilter{Kind: "vulnerability"}, []string{"kev-high-epss", "epss-only", "kev-no-score", "same-score", "no-intel"}},
		{service.IssueFilter{Kind: "license"}, []string{"license"}},
		{service.IssueFilter{Source: "image"}, []string{"kev-no-score", "same-score"}},
		{service.IssueFilter{Source: "code", Tool: "trivy"}, []string{"kev-high-epss", "epss-only", "no-intel", "license"}},
		{service.IssueFilter{Target: "ghcr.io/acme/api", KEV: "true"}, []string{"kev-no-score"}},
		{service.IssueFilter{Target: "ghcr.io/other/api"}, nil},
	} {
		if got := w.list(t, c.f); !sameSet(got, c.want...) {
			t.Errorf("%+v: got %v, want %v", c.f, got, c.want)
		}
	}
	// The severity chips count what the intel filters select.
	p, err := w.s.Issues(context.Background(), w.actor(), service.IssueFilter{KEV: "true", Severity: []string{"low"}})
	if err != nil || len(p.Items) != 1 || p.CountsBySeverity != (service.SeverityCounts{Low: 1, Medium: 1}) {
		t.Fatal(p, err)
	}
}

func TestIssueIntelFieldsAndEPSSSort(t *testing.T) {
	w := newIntelWorld(t)
	ctx := context.Background()
	// -epss: highest first, ties by id, unscored last; one page at a time.
	var order []string
	cursor := ""
	for range 10 {
		p, err := w.s.Issues(ctx, w.actor(), service.IssueFilter{Sort: "-epss", PageParams: service.PageParams{Limit: "2", Cursor: cursor}})
		if err != nil {
			t.Fatal(err)
		}
		for _, it := range p.Items {
			for name, id := range w.ids {
				if id == it.ID {
					order = append(order, name)
				}
			}
		}
		if p.NextCursor == nil {
			break
		}
		cursor = *p.NextCursor
	}
	if len(order) != 7 || order[0] != "kev-high-epss" || !sameSet(order[1:3], "epss-only", "same-score") || !sameSet(order[3:], "kev-no-score", "no-intel", "license", "code") {
		t.Fatal(order)
	}

	iss, err := w.s.Issue(ctx, w.actor(), w.ids["kev-high-epss"])
	if err != nil || !iss.KEV || *iss.EPSS != 0.9 || *iss.EPSSPercentile != 0.99 || *iss.KEVAdded != "2024-03-01" || !iss.KEVRansomware {
		t.Fatalf("%+v %v", iss, err)
	}
	// Intel never changes what the scanner said.
	if iss.Severity != "low" || iss.Status != "open" {
		t.Fatal(iss.Severity, iss.Status)
	}
	iss, err = w.s.Issue(ctx, w.actor(), w.ids["no-intel"])
	if err != nil || iss.KEV || iss.EPSS != nil || iss.EPSSPercentile != nil || iss.KEVAdded != nil || iss.KEVRansomware {
		t.Fatalf("%+v %v", iss, err)
	}
}

func TestIssueTotalsKEVAndLicenses(t *testing.T) {
	w := newIntelWorld(t)
	tot, err := w.s.IssueTotals(context.Background(), w.actor(), "")
	if err != nil || tot.KEV != 2 || tot.Licenses != 1 || tot.Active != 7 {
		t.Fatalf("%+v %v", tot, err)
	}
}

func TestGateFailOnKEV(t *testing.T) {
	w := newIntelWorld(t)
	ctx := context.Background()
	sc := w.f.AddScan(w.p, w.u, "completed", 10)
	// Only a low (KEV) and a medium (KEV, image) issue are in this scan.
	w.f.AddOccurrence(w.ids["kev-high-epss"], sc)
	w.f.AddOccurrence(w.ids["kev-no-score"], sc)
	w.f.AddOccurrence(w.ids["epss-only"], w.f.AddScan(w.p, w.u, "completed", 10))

	g, err := w.s.Gate(ctx, w.actor(), sc, "", "")
	if err != nil || !g.Pass || g.FailOnKEV || g.KEV != 2 || len(g.Blocking) != 0 {
		t.Fatalf("%+v %v", g, err)
	}
	g, err = w.s.Gate(ctx, w.actor(), sc, "high", "true")
	if err != nil || g.Pass || !g.FailOnKEV || g.KEV != 2 || len(g.Blocking) != 2 ||
		g.Blocking[0].ID != w.ids["kev-no-score"] || !g.Blocking[0].KEV || *g.Blocking[1].EPSS != 0.9 {
		t.Fatalf("%+v %v", g, err)
	}
	// A KEV issue that is accepted or a false positive doesn't block.
	w.f.SetIssue(w.ids["kev-high-epss"], func(r *servicetest.IssueRow) { r.Status = "risk_accepted" })
	w.f.SetIssue(w.ids["kev-no-score"], func(r *servicetest.IssueRow) { r.Status = "false_positive" })
	if g, err = w.s.Gate(ctx, w.actor(), sc, "high", "true"); err != nil || !g.Pass || g.KEV != 0 {
		t.Fatalf("%+v %v", g, err)
	}
	for _, bad := range []string{"yes", "1", "TRUE"} {
		if _, err := w.s.Gate(ctx, w.actor(), sc, "", bad); status(err) != http.StatusUnprocessableEntity {
			t.Fatal(bad, err)
		}
	}
	// Both invalid parameters are reported together.
	if _, err := w.s.Gate(ctx, w.actor(), sc, "info", "x"); len(fields(err)) != 2 {
		t.Fatal(err)
	}
}

func TestVulnData(t *testing.T) {
	x := newSetup(rbac.Member)
	now := x.f.Now
	fresh, old := service.Time(now.Add(-24*time.Hour)), service.Time(now.Add(-8*24*time.Hour))
	n := 1700
	x.f.SetVulnSource(service.VulnDataSource{Name: "kev", UpdatedAt: &fresh, LoadedAt: &fresh, Records: &n})
	x.f.SetVulnSource(service.VulnDataSource{Name: "trivy_db", UpdatedAt: &old})
	d, err := x.s.VulnData(context.Background(), x.actor())
	if err != nil || len(d.Sources) != 3 {
		t.Fatal(d, err)
	}
	trivy, kev, epss := d.Sources[0], d.Sources[1], d.Sources[2]
	if trivy.Name != "trivy_db" || !trivy.Stale || trivy.LoadedAt != nil {
		t.Fatalf("%+v", trivy)
	}
	if kev.Name != "kev" || kev.Stale || *kev.Records != 1700 {
		t.Fatalf("%+v", kev)
	}
	if epss.Name != "epss" || !epss.Stale || epss.UpdatedAt != nil || epss.Records != nil {
		t.Fatalf("%+v", epss)
	}
	stranger := &service.Actor{UserID: uuid.New(), OrgID: x.org}
	if _, err := x.s.VulnData(context.Background(), stranger); status(err) != http.StatusNotFound {
		t.Fatal(err)
	}
}
