//go:build integration

package store_test

import (
	"fmt"
	"strings"
	"testing"

	"github.com/google/uuid"
	"github.com/jackc/pgx/v5"

	"github.com/aupv9/warden/backend/internal/domain/ecosystem"
	"github.com/aupv9/warden/backend/internal/ids"
	"github.com/aupv9/warden/backend/internal/service"
)

// component seeds one inventory row (results.Process writes them for real).
func component(t *testing.T, org, project, scan uuid.UUID, target, eco, name, version, path string, licenses ...string) {
	t.Helper()
	if licenses == nil {
		licenses = []string{}
	}
	ownerExec(t, org, `INSERT INTO component (org_id, project_id, target, scan_id, ecosystem, name, match_name, version, purl, path, licenses)
		VALUES ($1, $2, $3, $4, $5, $6, $7, $8, $9, $10, $11)`, org, project, target, scan, eco, name, ecosystem.MatchName(eco, name),
		version, "pkg:"+strings.ToLower(eco)+"/"+name+"@"+version, path, licenses)
}

// trivyIssue seeds an issue on a package.
func trivyIssue(t *testing.T, f orgFixture, project uuid.UUID, n int, target, pkg, version, status string) {
	t.Helper()
	ownerExec(t, f.id, `INSERT INTO issue (id, org_id, project_id, number, fingerprint, tool, rule_id, title, severity, status,
		first_seen_scan_id, last_seen_scan_id, file_path, package_name, package_version, target)
		VALUES ($1, $2, $3, $4, $5, 'trivy', 'CVE-2024-0001', 't', 'high', $6, $7, $7, 'package-lock.json', $8, $9, $10)`,
		ids.New(), f.id, project, n, fmt.Sprintf("%064d", n), status, f.scan, pkg, version, target)
}

func names(items []service.ComponentSummary) string {
	var out []string
	for _, c := range items {
		out = append(out, c.Ecosystem+":"+c.Name+"@"+c.Version)
	}
	return strings.Join(out, ",")
}

// The inventory search shows what the issue list would: org admins and
// security leads see every project, members only theirs; archived projects
// are left out. Prefixes are literal (LIKE wildcards escaped) and normalized.
func TestComponentInventory(t *testing.T) {
	w := newWorld(t)
	f := w.org("CMP")
	lead, dev := w.actor("CMPlead", f.id), w.actor("CMPdev", f.id)
	outsider := w.user("CMPout")
	must(w.svc.AddMember(ctx, w.actor("CMPadmin", f.id), service.AddMemberInput{Email: outsider.Email, Role: "member"}))
	other := must(w.svc.CreateProject(ctx, lead, service.CreateProjectInput{Key: "OTH", Name: "Other"}))
	archived := must(w.svc.CreateProject(ctx, lead, service.CreateProjectInput{Key: "ARC", Name: "Archived"}))
	ownerExec(t, f.id, `UPDATE scan SET status = 'completed', finished_at = now() WHERE id = $1`, f.scan)
	ownerExec(t, f.id, `UPDATE project SET archived_at = now() WHERE id = $1`, archived.ID)

	component(t, f.id, f.project, f.scan, "", "npm", "lodash", "4.17.15", "package-lock.json", "MIT")
	component(t, f.id, f.project, f.scan, "", "npm", "lodash", "4.17.15", "web/package-lock.json", "MIT", "ISC")
	component(t, f.id, f.project, f.scan, "ghcr.io/acme/web", "npm", "lodash", "4.17.15", "ghcr.io/acme/web::app/package-lock.json")
	component(t, f.id, f.project, f.scan, "", "npm", "a%b", "1.0.0", "package-lock.json")
	component(t, f.id, f.project, f.scan, "", "npm", "axb", "1.0.0", "package-lock.json")
	component(t, f.id, f.project, f.scan, "", "PyPI", "Foo_Bar", "1.0", "requirements.txt")
	component(t, f.id, f.project, f.scan, "", "Go", "github.com/acme/evil", "v1.2.3", "go.mod")
	component(t, f.id, other.ID, f.scan, "", "npm", "lodash", "4.17.15", "package-lock.json")
	component(t, f.id, other.ID, f.scan, "", "npm", "lodash", "4.17.21", "package-lock.json")
	component(t, f.id, archived.ID, f.scan, "", "npm", "lodash", "4.17.15", "package-lock.json")
	component(t, f.id, archived.ID, f.scan, "", "npm", "left-pad", "1.3.0", "package-lock.json")
	// Open issues on lodash 4.17.15: two active in CMP (source and image), one
	// fixed, and one in the archived project; the name as reported (any case).
	trivyIssue(t, f, f.project, 1, "", "Lodash", "4.17.15", "open")
	trivyIssue(t, f, f.project, 2, "ghcr.io/acme/web", "lodash", "4.17.15", "reopened")
	trivyIssue(t, f, f.project, 3, "", "lodash", "4.17.15", "fixed")
	trivyIssue(t, f, archived.ID, 4, "", "lodash", "4.17.15", "open")
	trivyIssue(t, f, other.ID, 5, "", "lodash", "4.17.21", "open")
	// Malicious: the Go module at 1.2.3 (OSV lists Go versions without v).
	ownerExec(t, f.id, `INSERT INTO malicious_package (id, ecosystem, name, match_name, all_versions, versions, modified)
		VALUES ('MAL-2026-1', 'Go', 'github.com/acme/evil', 'github.com/acme/evil', false, '{1.2.3}', now())
		ON CONFLICT DO NOTHING`)

	list := func(a *service.Actor, f service.ComponentFilter) service.Page[service.ComponentSummary] {
		t.Helper()
		return must(w.svc.Components(ctx, a, f))
	}
	all := list(lead, service.ComponentFilter{})
	if got := names(all.Items); got != "npm:a%b@1.0.0,npm:axb@1.0.0,PyPI:Foo_Bar@1.0,Go:github.com/acme/evil@v1.2.3,npm:lodash@4.17.15,npm:lodash@4.17.21" {
		t.Fatal(got)
	}
	l := all.Items[4]
	if l.Projects != 2 || l.Targets != 3 || l.OpenIssues != 2 || l.Malicious || len(l.Licenses) != 2 || l.Licenses[0] != "ISC" ||
		l.PURL == nil || *l.PURL != "pkg:npm/lodash@4.17.15" {
		t.Fatalf("%+v", l)
	}
	if e := all.Items[3]; !e.Malicious || e.OpenIssues != 0 {
		t.Fatalf("%+v", e)
	}
	if got := names(list(dev, service.ComponentFilter{}).Items); strings.Contains(got, "4.17.21") || !strings.Contains(got, "lodash@4.17.15") {
		t.Fatal(got)
	}
	if c := list(dev, service.ComponentFilter{Q: "lodash"}).Items; len(c) != 1 || c[0].Projects != 1 || c[0].Targets != 2 || c[0].OpenIssues != 2 {
		t.Fatalf("%+v", c)
	}
	if c := list(w.actor("CMPout", f.id), service.ComponentFilter{}).Items; len(c) != 0 {
		t.Fatalf("outsider sees %v", names(c))
	}

	for q, want := range map[string]string{
		"a%":       "npm:a%b@1.0.0",
		"a_":       "",
		"A":        "npm:a%b@1.0.0,npm:axb@1.0.0,Go:github.com/acme/evil@v1.2.3", // a/cme: a segment
		"evil":     "Go:github.com/acme/evil@v1.2.3",
		"foo.b":    "PyPI:Foo_Bar@1.0",
		"FOO_BAR":  "PyPI:Foo_Bar@1.0",
		"left-pad": "",
		`\`:        "",
	} {
		if got := names(list(lead, service.ComponentFilter{Q: q}).Items); got != want {
			t.Errorf("q=%q: %s", q, got)
		}
	}
	if got := names(list(lead, service.ComponentFilter{Q: "foo-bar", Ecosystem: "PyPI"}).Items); got != "PyPI:Foo_Bar@1.0" {
		t.Fatal(got)
	}
	if got := names(list(lead, service.ComponentFilter{Q: "foo-bar", Ecosystem: "npm"}).Items); got != "" {
		t.Fatal(got)
	}
	if got := names(list(lead, service.ComponentFilter{Version: "4.17.21"}).Items); got != "npm:lodash@4.17.21" {
		t.Fatal(got)
	}
	if got := names(list(lead, service.ComponentFilter{Malicious: "true"}).Items); got != "Go:github.com/acme/evil@v1.2.3" {
		t.Fatal(got)
	}
	if got := names(list(lead, service.ComponentFilter{ProjectID: other.ID.String()}).Items); got != "npm:lodash@4.17.15,npm:lodash@4.17.21" {
		t.Fatal(got)
	}
	// Pages follow the sort, without repeats.
	var seen []string
	p := service.ComponentFilter{PageParams: service.PageParams{Limit: "4"}}
	for {
		pg := list(lead, p)
		seen = append(seen, names(pg.Items))
		if pg.NextCursor == nil {
			break
		}
		p.Cursor = *pg.NextCursor
	}
	if strings.Join(seen, ",") != names(all.Items) || len(seen) != 2 {
		t.Fatal(seen)
	}

	// Usage: where lodash 4.17.15 is, as the caller may see it (no archived project).
	use := must(w.svc.ComponentUsage(ctx, lead, service.UsageFilter{Ecosystem: "npm", Name: "LODASH", Version: "4.17.15"}))
	var where []string
	for _, u := range use.Items {
		where = append(where, u.ProjectKey+"|"+u.Target+"|"+u.Path)
		if u.ScanID != f.scan || u.ScannedAt.T().IsZero() || u.FirstSeen.T().IsZero() || u.ProjectName == "" {
			t.Fatalf("%+v", u)
		}
	}
	if strings.Join(where, ",") != "CMP||package-lock.json,CMP||web/package-lock.json,CMP|ghcr.io/acme/web|ghcr.io/acme/web::app/package-lock.json,OTH||package-lock.json" {
		t.Fatal(where)
	}
	if u := must(w.svc.ComponentUsage(ctx, dev, service.UsageFilter{Ecosystem: "npm", Name: "lodash", Version: "4.17.15",
		PageParams: service.PageParams{Limit: "2"}})); len(u.Items) != 2 || u.NextCursor == nil {
		t.Fatalf("%+v", u)
	} else if u2 := must(w.svc.ComponentUsage(ctx, dev, service.UsageFilter{Ecosystem: "npm", Name: "lodash", Version: "4.17.15",
		PageParams: service.PageParams{Cursor: *u.NextCursor}})); len(u2.Items) != 1 || u2.Items[0].Target != "ghcr.io/acme/web" {
		t.Fatalf("%+v", u2)
	}
	if u := must(w.svc.ComponentUsage(ctx, dev, service.UsageFilter{Ecosystem: "npm", Name: "left-pad", Version: "1.3.0"})); len(u.Items) != 0 {
		t.Fatal("archived project listed")
	}

	// A project's own list: per target and path, with its issues.
	pc := must(w.svc.ProjectComponents(ctx, dev, f.project, service.ComponentFilter{Q: "lodash"}))
	if len(pc.Items) != 3 || pc.Items[0].Target != "" || pc.Items[0].OpenIssues != 1 || pc.Items[2].Target != "ghcr.io/acme/web" ||
		pc.Items[2].OpenIssues != 1 || pc.Items[0].FirstSeen.T().IsZero() {
		t.Fatalf("%+v", pc.Items)
	}
	if pc := must(w.svc.ProjectComponents(ctx, dev, f.project, service.ComponentFilter{HasTarget: true, Target: ""})); len(pc.Items) != 6 {
		t.Fatalf("%d source components", len(pc.Items))
	}
	if pc := must(w.svc.ProjectComponents(ctx, dev, f.project, service.ComponentFilter{Malicious: "true"})); len(pc.Items) != 1 || !pc.Items[0].Malicious {
		t.Fatalf("%+v", pc.Items)
	}
	if _, err := w.svc.ProjectComponents(ctx, dev, other.ID, service.ComponentFilter{}); code(err) != "NOT_FOUND" {
		t.Fatal(err)
	}
	// An archived project's own page stays readable, like its issues.
	if pc := must(w.svc.ProjectComponents(ctx, lead, archived.ID, service.ComponentFilter{})); len(pc.Items) != 2 {
		t.Fatalf("%+v", pc.Items)
	}
}

// RLS: another org's inventory is invisible even to its lead's queries.
func TestComponentInventoryIsolation(t *testing.T) {
	w := newWorld(t)
	a, b := w.org("CIA"), w.org("CIB")
	component(t, a.id, a.project, a.scan, "", "npm", "secret-internal", "1.0.0", "package-lock.json")
	if c := must(w.svc.Components(ctx, w.actor("CIBlead", b.id), service.ComponentFilter{})); len(c.Items) != 0 {
		t.Fatal(names(c.Items))
	}
	if c := must(w.svc.Components(ctx, w.actor("CIAlead", a.id), service.ComponentFilter{})); len(c.Items) != 1 {
		t.Fatal(names(c.Items))
	}
	// Even with app.org_id unset, warden_app reads nothing (FORCE RLS).
	var n int
	if err := pgx.BeginFunc(ctx, w.pool, func(tx pgx.Tx) error {
		return tx.QueryRow(ctx, `SELECT count(*) FROM component`).Scan(&n)
	}); err != nil || n != 0 {
		t.Fatal(n, err)
	}
}

func TestProjectTargets(t *testing.T) {
	w := newWorld(t)
	f := w.org("TGT")
	dev := w.actor("TGTdev", f.id)
	// Only a pending upload: no target yet.
	if tg := must(w.svc.ProjectTargets(ctx, dev, f.project)); len(tg.Items) != 0 {
		t.Fatalf("%+v", tg.Items)
	}
	ownerExec(t, f.id, `UPDATE scan SET status = 'completed' WHERE id = $1`, f.scan)
	img := ids.New()
	ownerExec(t, f.id, `INSERT INTO scan (id, org_id, project_id, created_by, status, file_name, tools, kind, target, created_at)
		SELECT $1, org_id, project_id, created_by, 'completed', 'api.tar', '{trivy}', 'image', 'ghcr.io/acme/api', now() + interval '1 minute'
		FROM scan WHERE id = $2`, img, f.scan)
	ownerExec(t, f.id, `INSERT INTO scan (id, org_id, project_id, created_by, status, file_name, tools, kind, target)
		SELECT $1, org_id, project_id, created_by, 'pending_upload', 'x.tar', '{trivy}', 'image', 'ghcr.io/acme/typo'
		FROM scan WHERE id = $2`, ids.New(), f.scan)
	trivyIssue(t, f, f.project, 1, "ghcr.io/acme/api", "musl", "1.2.3", "open")
	trivyIssue(t, f, f.project, 2, "ghcr.io/acme/api", "musl", "1.2.4", "fixed")
	trivyIssue(t, f, f.project, 3, "ghcr.io/acme/old", "musl", "1.2.4", "open") // its scans are gone from view, its issue isn't

	tg := must(w.svc.ProjectTargets(ctx, dev, f.project)).Items
	if len(tg) != 3 {
		t.Fatalf("%+v", tg)
	}
	src, api, old := tg[0], tg[1], tg[2]
	if src.Target != "" || src.Kind != "source" || src.LastScanAt == nil || src.OpenIssues != 0 ||
		api.Target != "ghcr.io/acme/api" || api.Kind != "image" || api.OpenIssues != 1 || api.LastScanAt == nil ||
		!api.LastScanAt.T().After(src.LastScanAt.T()) || old.LastScanAt != nil || old.OpenIssues != 1 {
		t.Fatalf("%+v", tg)
	}
	outsider := w.user("TGTout")
	must(w.svc.AddMember(ctx, w.actor("TGTadmin", f.id), service.AddMemberInput{Email: outsider.Email, Role: "member"}))
	if _, err := w.svc.ProjectTargets(ctx, w.actor("TGTout", f.id), f.project); code(err) != "NOT_FOUND" {
		t.Fatal(err)
	}
}

// The SQL forms of the ecosystem normalizations agree with the Go ones.
func TestEcosystemSQLMatchesGo(t *testing.T) {
	w := newWorld(t)
	cases := [][2]string{
		{"PyPI", "Foo__Bar.baz-QUX"}, {"PyPI", "a...b"}, {"PyPI", "V1.0RC1"}, {"crates.io", "Serde_JSON"}, {"Go", "v1.2.3"},
		{"Go", "1.2.3"}, {"Go", "vv1"}, {"Go", "github.com/Acme/X"}, {"npm", "@Scope/Pkg"}, {"npm", " Left-Pad "}, {"Maven", "Org.X:Y"},
		{"apk", "V1"}, {"NuGet", "Newtonsoft.Json"},
	}
	for _, c := range cases {
		var name, version string
		if err := pgx.BeginFunc(ctx, w.pool, func(tx pgx.Tx) error {
			return tx.QueryRow(ctx, `SELECT `+ecosystem.MatchNameSQL("$1::text", "$2::text")+`, `+ecosystem.MatchVersionSQL("$1::text", "$2::text"),
				c[0], c[1]).Scan(&name, &version)
		}); err != nil {
			t.Fatal(err)
		}
		if name != ecosystem.MatchName(c[0], c[1]) || version != ecosystem.MatchVersion(c[0], c[1]) {
			t.Errorf("%v: SQL %q %q, Go %q %q", c, name, version, ecosystem.MatchName(c[0], c[1]), ecosystem.MatchVersion(c[0], c[1]))
		}
	}
}

// The scan lists the SBOM formats it has; each downloads as its own file.
func TestScanSPDX(t *testing.T) {
	w := newWorld(t)
	f := w.org("SPX")
	dev := w.actor("SPXdev", f.id)
	cdx := "sboms/" + f.id.String() + "/" + f.scan.String() + ".cdx.json"
	ownerExec(t, f.id, `UPDATE scan SET sbom_key = $2, sbom_size = 99, sbom_sha256 = $3, sbom_components = 175,
		sbom_expires_at = now() + interval '1 day' WHERE id = $1`, f.scan, cdx, strings.Repeat("e", 64))
	if sc := must(w.svc.Scan(ctx, dev, f.scan)); len(sc.SBOM.Formats) != 1 || sc.SBOM.Formats[0] != "cyclonedx-json" {
		t.Fatalf("%+v", sc.SBOM)
	}
	if _, err := w.svc.ScanSBOM(ctx, dev, f.scan, "spdx"); code(err) != "NOT_FOUND" {
		t.Fatal(err)
	}
	spdx := "sboms/" + f.id.String() + "/" + f.scan.String() + ".spdx.json"
	ownerExec(t, f.id, `UPDATE scan SET sbom_spdx_key = $2, sbom_spdx_size = 120, sbom_spdx_sha256 = $3 WHERE id = $1`,
		f.scan, spdx, strings.Repeat("f", 64))
	if sc := must(w.svc.Scan(ctx, dev, f.scan)); len(sc.SBOM.Formats) != 2 || sc.SBOM.Formats[1] != "spdx-json" || sc.SBOM.Size != 99 {
		t.Fatalf("%+v", sc.SBOM)
	}
	d := must(w.svc.ScanSBOM(ctx, dev, f.scan, "spdx"))
	if d.Format != "spdx-json" || d.Size != 120 || d.SHA256 != strings.Repeat("f", 64) || d.Components != 175 ||
		d.URL != "https://s3.test/"+spdx+"?name=SPX-"+f.scan.String()[:8]+".spdx.json" {
		t.Fatalf("%+v", d)
	}
	if _, err := w.svc.ScanSBOM(ctx, dev, f.scan, "xml"); code(err) != "VALIDATION_FAILED" {
		t.Fatal(err)
	}
	// SPDX columns are all or none, and only with the CycloneDX ones.
	for _, q := range []string{
		`UPDATE scan SET sbom_spdx_size = NULL WHERE id = $1`,
		`UPDATE scan SET sbom_key = NULL, sbom_size = NULL, sbom_sha256 = NULL, sbom_components = NULL, sbom_expires_at = NULL WHERE id = $1`,
	} {
		conn := must(pgx.Connect(ctx, ownerURL))
		err := pgx.BeginFunc(ctx, conn, func(tx pgx.Tx) error {
			if _, err := tx.Exec(ctx, "SELECT set_config('app.org_id', $1, true)", f.id.String()); err != nil {
				return err
			}
			_, err := tx.Exec(ctx, q, f.scan)
			return err
		})
		_ = conn.Close(ctx)
		if err == nil || !strings.Contains(err.Error(), "scan_sbom_spdx_all_or_none") {
			t.Errorf("%s: %v", q, err)
		}
	}
	// Expired: neither format is served.
	ownerExec(t, f.id, `UPDATE scan SET sbom_expires_at = now() - interval '1 second' WHERE id = $1`, f.scan)
	if _, err := w.svc.ScanSBOM(ctx, dev, f.scan, "spdx"); code(err) != "NOT_FOUND" {
		t.Fatal(err)
	}
}
