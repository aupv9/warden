package api

import (
	"fmt"
	"net/url"
	"strings"
	"testing"
	"time"

	"github.com/google/uuid"

	"github.com/aupv9/warden/backend/internal/service"
	"github.com/aupv9/warden/backend/internal/service/servicetest"
)

func fp(v float64) *float64 { return &v }

// intelIssues: a KEV image issue, an EPSS-only code issue, a license issue.
func intelIssues(e *env) (kev, epss, license string) {
	cve := func(n int) string { return fmt.Sprintf("CVE-2024-%05d", n) } // synthetic
	added := time.Date(2024, 3, 1, 0, 0, 0, 0, time.UTC)
	e.f.SetIntel(cve(1), servicetest.IntelRow{KEVAdded: &added, Ransomware: true, EPSS: fp(0.9), Percentile: fp(0.99)})
	e.f.SetIntel(cve(2), servicetest.IntelRow{EPSS: fp(0.04753), Percentile: fp(0.91834)})
	set := func(sev, rule, target string, cves ...string) string {
		id := e.f.AddIssue(e.web, sev, "open", nil)
		e.f.SetIssue(id, func(r *servicetest.IssueRow) { r.Tool, r.RuleID, r.Target, r.CVE = "trivy", rule, target, cves })
		return id.String()
	}
	return set("low", cve(1), "ghcr.io/acme/api", cve(1)), set("high", cve(2), "", cve(2)), set("medium", "license:GPL-3.0-only", "")
}

func ids(r resp) []string {
	var out []string
	for _, it := range r.items() {
		out = append(out, it.(map[string]any)["id"].(string))
	}
	return out
}

func TestIssueListIntel(t *testing.T) {
	e := newEnv(t)
	kev, epss, license := intelIssues(e)
	e.f.AddIssue(e.web, "critical", "open", nil) // opengrep, no CVE

	r := e.do("GET", "/issues?sort=-epss", dev, nil)
	e.expect(r, 200, "")
	got := ids(r)
	if len(got) != 4 || got[0] != kev || got[1] != epss {
		t.Fatal(r.body)
	}
	first, second := r.items()[0].(map[string]any), r.items()[1].(map[string]any)
	if first["kev"] != true || first["epss"] != 0.9 || first["target"] != "ghcr.io/acme/api" ||
		second["kev"] != false || second["epss"] != 0.04753 || second["target"] != "" {
		t.Fatal(r.body)
	}
	// Issues without intel render explicit nulls/false, as the contract requires.
	last := r.items()[3].(map[string]any)
	if v, ok := last["epss"]; !ok || v != nil || last["kev"] != false {
		t.Fatal(r.body)
	}

	for query, want := range map[string][]string{
		"kev=true":                      {kev},
		"kev=false&kind=license":        {license},
		"epss_min=0.04753":              {kev, epss},
		"epss_min=0.5":                  {kev},
		"kind=vulnerability&sort=-epss": {kev, epss},
		"source=image":                  {kev},
		"target=" + url.QueryEscape("ghcr.io/acme/api"): {kev},
	} {
		r := e.do("GET", "/issues?"+query, dev, nil)
		e.expect(r, 200, "")
		got := ids(r)
		if len(got) != len(want) || (query == "kind=vulnerability&sort=-epss" && got[0] != kev) {
			t.Fatalf("%s: %s", query, r.body)
		}
		for _, w := range want {
			if !strings.Contains(r.body, w) {
				t.Fatalf("%s: %s", query, r.body)
			}
		}
	}

	// Keyset pagination over -epss, including the unscored tail.
	seen := map[string]bool{}
	next := ""
	for range 5 {
		r := e.do("GET", "/issues?sort=-epss&limit=1"+next, lead, nil)
		e.expect(r, 200, "")
		for _, id := range ids(r) {
			if seen[id] {
				t.Fatal("repeated", id)
			}
			seen[id] = true
		}
		c, _ := r.obj()["next_cursor"].(string)
		if c == "" {
			break
		}
		next = "&cursor=" + c
		e.expect(e.do("GET", "/issues?sort=due_at"+next, lead, nil), 422, "VALIDATION_FAILED") // cursor of another sort
	}
	if len(seen) != 4 {
		t.Fatal(seen)
	}

	r = e.do("GET", "/issues?kind=x&kev=yes&epss_min=NaN&source=x&target=UPPER&sort=epss", lead, nil)
	e.expect(r, 422, "VALIDATION_FAILED")
	if f := r.Error.Metadata["fields"].(map[string]any); len(f) != 6 {
		t.Fatal(r.body)
	}
	for _, q := range []string{"epss_min=1.01", "epss_min=-1", "epss_min=Inf", "target=a:b:c", "target=" + strings.Repeat("a", 256)} {
		e.expect(e.do("GET", "/issues?"+q, lead, nil), 422, "VALIDATION_FAILED")
	}

	// Detail adds the KEV date, ransomware and percentile.
	r = e.do("GET", "/issues/"+kev, dev, nil)
	e.expect(r, 200, "")
	d := r.obj()
	if d["kev_added"] != "2024-03-01" || d["kev_ransomware"] != true || d["epss_percentile"] != 0.99 || d["kev"] != true {
		t.Fatal(r.body)
	}
	r = e.do("GET", "/issues/"+license, dev, nil)
	if d := r.obj(); d["kev_added"] != nil || d["kev_ransomware"] != false || d["epss_percentile"] != nil || d["epss"] != nil {
		t.Fatal(r.body)
	}

	// Saved-view counts.
	r = e.do("GET", "/issues/counts", dev, nil)
	if r.obj()["kev"] != 1.0 || r.obj()["licenses"] != 1.0 {
		t.Fatal(r.body)
	}
}

func TestGateFailOnKEV(t *testing.T) {
	e := newEnv(t)
	kev, epss, _ := intelIssues(e)
	sc := e.f.AddScan(e.web, e.u[dev], "completed", 10)
	for _, id := range []string{kev, epss} {
		e.f.AddOccurrence(uuid.MustParse(id), sc)
	}
	path := "/scans/" + sc.String() + "/gate"

	// Without fail_on_kev the high issue blocks and the KEV low doesn't.
	r := e.do("GET", path, dev, nil)
	e.expect(r, 200, "")
	g := r.obj()
	if g["pass"] != false || g["fail_on_kev"] != false || g["kev"] != 1.0 || len(g["blocking"].([]any)) != 1 {
		t.Fatal(r.body)
	}
	// fail_on=critical: nothing at that level, but the KEV issue blocks.
	r = e.do("GET", path+"?fail_on=critical&fail_on_kev=true", dev, nil)
	g = r.obj()
	blocking := g["blocking"].([]any)
	if g["pass"] != false || g["fail_on_kev"] != true || len(blocking) != 1 ||
		blocking[0].(map[string]any)["id"] != kev || blocking[0].(map[string]any)["kev"] != true {
		t.Fatal(r.body)
	}
	if r := e.do("GET", path+"?fail_on=critical&fail_on_kev=false", dev, nil); r.obj()["pass"] != true {
		t.Fatal(r.body)
	}
	e.expect(e.do("GET", path+"?fail_on_kev=1", dev, nil), 422, "VALIDATION_FAILED")

	// The CI token reaches the parameter too.
	_, tok := e.newToken(lead, e.web, "scan:write")
	if r := e.doTok("GET", path+"?fail_on=critical&fail_on_kev=true", tok, nil); r.code != 200 || r.obj()["pass"] != false {
		t.Fatal(r.body)
	}
}

func TestVulnDataEndpoint(t *testing.T) {
	e := newEnv(t)
	at := service.Time(e.f.Now.Add(-time.Hour))
	n := 312000
	e.f.SetVulnSource(service.VulnDataSource{Name: "epss", UpdatedAt: &at, LoadedAt: &at, Records: &n})
	unsupported := 533
	e.f.SetVulnSource(service.VulnDataSource{Name: "osv_mal:npm", UpdatedAt: &at, LoadedAt: &at, Records: &n, Unsupported: &unsupported})

	r := e.do("GET", "/vuln-data", outsider, nil) // any member
	e.expect(r, 200, "")
	src := r.obj()["sources"].([]any)
	names := []string{"trivy_db", "kev", "epss", "osv_mal:npm", "osv_mal:PyPI", "osv_mal:Go", "osv_mal:Maven",
		"osv_mal:crates.io", "osv_mal:RubyGems", "osv_mal:NuGet", "osv_mal:Packagist"}
	if len(src) != len(names) {
		t.Fatal(r.body)
	}
	for i, name := range names {
		s := src[i].(map[string]any)
		if s["name"] != name || s["stale"] != (name != "epss" && name != "osv_mal:npm") {
			t.Fatal(r.body)
		}
		if want := any(nil); name == "osv_mal:npm" && s["unsupported"] != 533.0 || name != "osv_mal:npm" && s["unsupported"] != want {
			t.Fatal(r.body)
		}
		for _, k := range []string{"updated_at", "loaded_at", "records", "unsupported"} {
			if _, ok := s[k]; !ok {
				t.Fatalf("%s.%s missing: %s", name, k, r.body)
			}
		}
	}
	if e := src[2].(map[string]any); e["records"] != 312000.0 {
		t.Fatal(r.body)
	}
	e.expect(e.call("GET", "/api/v1/orgs/"+e.org.String()+"/vuln-data", stranger, nil, nil), 404, "NOT_FOUND")
	_, tok := e.newToken(lead, e.web, "issues:read")
	e.expect(e.doTok("GET", "/vuln-data", tok, nil), 403, "TOKEN_SCOPE")
}
