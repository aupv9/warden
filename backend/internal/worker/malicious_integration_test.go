//go:build integration

package worker

import (
	"archive/zip"
	"bytes"
	"context"
	"fmt"
	"os"
	"path/filepath"
	"slices"
	"strings"
	"testing"
	"time"

	"github.com/google/uuid"
	"github.com/jackc/pgx/v5"

	"github.com/aupv9/warden/backend/internal/db"
)

// osvZip builds an OSV all.zip from advisory id → affected JSON (synthetic
// ids under MAL-2032-, built at test time).
func osvZip(t *testing.T, modified string, advisories map[string]string) []byte {
	t.Helper()
	var b bytes.Buffer
	w := zip.NewWriter(&b)
	ids := make([]string, 0, len(advisories))
	for id := range advisories {
		ids = append(ids, id)
	}
	slices.Sort(ids)
	for _, id := range ids {
		f, err := w.Create(id + ".json")
		if err != nil {
			t.Fatal(err)
		}
		fmt.Fprintf(f, `{"id":%q,"published":"2032-01-01T00:00:00Z","modified":%q,"summary":"Malicious code in %s","affected":%s}`,
			id, modified, id, advisories[id])
	}
	f, _ := w.Create("GHSA-xxxx-yyyy-zzzz.json")
	_, _ = f.Write([]byte(`{"id":"GHSA-xxxx-yyyy-zzzz"}`))
	if err := w.Close(); err != nil {
		t.Fatal(err)
	}
	return b.Bytes()
}

func npmAll(name string) string {
	return `[{"package":{"ecosystem":"npm","name":"` + name + `"},"ranges":[{"type":"SEMVER","events":[{"introduced":"0"}]}]}]`
}

func npmVersions(name string, versions ...string) string {
	return `[{"package":{"ecosystem":"npm","name":"` + name + `"},"versions":["` + strings.Join(versions, `","`) + `"]}]`
}

const npmLater = `[{"package":{"ecosystem":"npm","name":"later"},"ranges":[{"type":"SEMVER","events":[{"introduced":"1.2.0"}]}]}]`

// malReport is a Trivy report of package-lock.json files under the zip's
// root directory (app/), so their paths become package-lock.json and
// web/package-lock.json.
func malReport(pkgs ...string) string {
	var results []string
	for _, p := range pkgs {
		path, nameVer, _ := strings.Cut(p, " ")
		name, ver, _ := strings.Cut(nameVer, "@")
		results = append(results, fmt.Sprintf(`{"Target":"app/%s","Class":"lang-pkgs","Type":"npm","Packages":[
			{"Name":%q,"Version":%q,"Identifier":{"PURL":"pkg:npm/%s@%s"}}]}`, path, name, ver, strings.ToLower(name), ver))
	}
	return `{"Results":[` + strings.Join(results, ",") + `]}`
}

type malIssue struct {
	Number   int
	Severity string
	Status   string
	Path     string
	FP       string
	First    uuid.UUID
	Last     uuid.UUID
	Package  string
}

func (it *itest) malIssues() map[string]malIssue {
	it.t.Helper()
	out := map[string]malIssue{}
	err := db.WithOrg(context.Background(), ownerPool, it.org, func(tx pgx.Tx) error {
		rows, _ := tx.Query(context.Background(), `SELECT rule_id || ' ' || coalesce(file_path, ''), number, severity, status, file_path,
			fingerprint, first_seen_scan_id, last_seen_scan_id, package_name
			FROM issue WHERE project_id = $1 AND rule_id LIKE 'malicious:%'`, it.project)
		var k string
		var r malIssue
		_, err := pgx.ForEachRow(rows, []any{&k, &r.Number, &r.Severity, &r.Status, &r.Path, &r.FP, &r.First, &r.Last, &r.Package}, func() error {
			out[k] = r
			return nil
		})
		return err
	})
	if err != nil {
		it.t.Fatal(err)
	}
	return out
}

func (it *itest) count(q string, args ...any) int {
	it.t.Helper()
	var n int
	if err := db.WithOrg(context.Background(), ownerPool, it.org, func(tx pgx.Tx) error {
		return tx.QueryRow(context.Background(), q, args...).Scan(&n)
	}); err != nil {
		it.t.Fatalf("%s: %v", q, err)
	}
	return n
}

func (it *itest) component(scan uuid.UUID, name, version, path string) {
	it.t.Helper()
	owner(it.t, it.org, fmt.Sprintf(`INSERT INTO component (org_id, project_id, target, scan_id, ecosystem, name, match_name, version, path)
		VALUES ('%s', '%s', '', '%s', 'npm', '%s', '%s', '%s', '%s')`, it.org, it.project, scan, name, strings.ToLower(name), version, path))
}

// The whole malicious-package path against the schema, as warden_app: OSV
// load (diff-upsert, unsupported count, ids leaving), retro-match creating and
// reopening issues (never fixing), notifications, the next scan deduping on
// the same fingerprint and auto-fixing normally, and a scan-time match.
func TestMaliciousPackagesEndToEnd(t *testing.T) {
	ctx := context.Background()
	it := newITest(t)
	mirror := t.TempDir()
	it.env.MirrorDir = mirror
	it.env.Images = map[string]string{"trivy": "docker.io/aquasec/trivy:0.75.0@sha256:" + strings.Repeat("c", 64)}
	var enqueued []MatchMaliciousArgs
	old := enqueueMatch
	enqueueMatch = func(_ context.Context, _ DB, a MatchMaliciousArgs) error { enqueued = append(enqueued, a); return nil }
	defer func() { enqueueMatch = old }()

	lead, ownerID, dev := uuid.New(), uuid.New(), uuid.New()
	var stmts []string
	for _, u := range []struct {
		id   uuid.UUID
		role string
	}{{lead, "security_lead"}, {ownerID, "member"}, {dev, "member"}} {
		stmts = append(stmts,
			fmt.Sprintf(`INSERT INTO app_user (id, keycloak_sub, email, display_name) VALUES ('%s', '%s', '%s@x.test', 'u')`, u.id, u.id, u.id),
			fmt.Sprintf(`INSERT INTO org_member (org_id, user_id, role) VALUES ('%s', '%s', '%s')`, it.org, u.id, u.role))
	}
	stmts = append(stmts,
		fmt.Sprintf(`INSERT INTO project_member (org_id, project_id, user_id, role) VALUES ('%s', '%s', '%s', 'owner')`, it.org, it.project, ownerID),
		fmt.Sprintf(`INSERT INTO project_member (org_id, project_id, user_id, role) VALUES ('%s', '%s', '%s', 'developer')`, it.org, it.project, dev))
	owner(t, it.org, stmts...)

	writeOSV := func(modified string, advisories map[string]string) {
		p := filepath.Join(mirror, intelOSVDir, "npm.zip")
		if err := os.MkdirAll(filepath.Dir(p), 0o755); err != nil {
			t.Fatal(err)
		}
		if err := os.WriteFile(p+".tmp", osvZip(t, modified, advisories), 0o644); err != nil {
			t.Fatal(err)
		}
		if err := os.Rename(p+".tmp", p); err != nil {
			t.Fatal(err)
		}
	}
	malRows := func() []string {
		var out []string
		if err := db.WithOrg(ctx, ownerPool, uuid.Nil, func(tx pgx.Tx) error {
			rows, _ := tx.Query(ctx, `SELECT id || ' ' || name || ' ' || match_name || ' ' || all_versions || ' ' || array_to_string(versions, ',')
				FROM malicious_package WHERE id LIKE 'MAL-2032-%' ORDER BY id`)
			var s string
			_, err := pgx.ForEachRow(rows, []any{&s}, func() error { out = append(out, s); return nil })
			return err
		}); err != nil {
			t.Fatal(err)
		}
		return out
	}

	// 1. Load: two advisories, one unsupported range.
	writeOSV("2032-02-01T10:00:00Z", map[string]string{
		"MAL-2032-1": npmAll("Evil-Pkg"), "MAL-2032-2": npmVersions("typo", "2.0.0", "1.0.0"), "MAL-2032-3": npmLater})
	if err := it.env.LoadVulnIntel(ctx); err != nil {
		t.Fatal(err)
	}
	if got := malRows(); strings.Join(got, "|") != "MAL-2032-1 Evil-Pkg evil-pkg true |MAL-2032-2 typo typo false 1.0.0,2.0.0" {
		t.Fatal(got)
	}
	var updated time.Time
	var records, unsupported int
	if err := db.WithOrg(ctx, ownerPool, uuid.Nil, func(tx pgx.Tx) error {
		return tx.QueryRow(ctx, `SELECT updated_at, records, unsupported FROM vuln_intel_source WHERE name = 'osv_mal:npm'`).Scan(&updated, &records, &unsupported)
	}); err != nil {
		t.Fatal(err)
	}
	if !updated.Equal(time.Date(2032, 2, 1, 10, 0, 0, 0, time.UTC)) || records != 2 || unsupported != 1 {
		t.Fatal(updated, records, unsupported)
	}
	if len(enqueued) != 1 || enqueued[0].Ecosystem != "npm" || strings.Join(enqueued[0].Names, ",") != "evil-pkg,typo" || enqueued[0].All {
		t.Fatalf("%+v", enqueued)
	}
	// Unchanged file: skipped, nothing enqueued.
	if err := it.env.LoadVulnIntel(ctx); err != nil || len(enqueued) != 1 {
		t.Fatal(err, enqueued)
	}

	// 2. Retro-match against the inventory (BE-A fills component from scans;
	// here the rows are inserted directly).
	s0, _ := it.scan("completed", strings.Repeat("0", 64), 0, "trivy")
	it.component(s0, "Evil-Pkg", "1.0.0", "package-lock.json")
	it.component(s0, "typo", "2.0.0", "web/package-lock.json")
	it.component(s0, "typo", "2.0.1", "package-lock.json") // version not listed
	it.component(s0, "fine", "1.0.0", "package-lock.json")
	if err := it.env.MatchMalicious(ctx, enqueued[0]); err != nil {
		t.Fatal(err)
	}
	issues := it.malIssues()
	evil, typo := issues["malicious:MAL-2032-1 package-lock.json"], issues["malicious:MAL-2032-2 web/package-lock.json"]
	if len(issues) != 2 || evil.Severity != "critical" || evil.Status != "open" || evil.First != s0 || evil.Package != "Evil-Pkg" ||
		typo.Status != "open" {
		t.Fatalf("%+v", issues)
	}
	if n := it.count(`SELECT count(*) FROM issue_event e JOIN issue i ON i.id = e.issue_id WHERE i.project_id = $1
		AND e.type = 'created' AND e.note = 'found by malicious-package advisory MAL-2032-1 (no scan)'`, it.project); n != 1 {
		t.Fatal("created event note", n)
	}
	if n := it.count(`SELECT count(*) FROM outbox_event WHERE org_id = $1 AND type = 'component.malicious' AND dedupe_key LIKE 'mal:%:1'`, it.org); n != 2 {
		t.Fatal("component.malicious events", n)
	}
	// Idempotent: a second run (River retry) changes nothing.
	if err := it.env.MatchMalicious(ctx, MatchMaliciousArgs{Ecosystem: "npm", All: true}); err != nil {
		t.Fatal(err)
	}
	if len(it.malIssues()) != 2 || it.count(`SELECT count(*) FROM outbox_event WHERE org_id = $1 AND type = 'component.malicious'`, it.org) != 2 {
		t.Fatal("retro-match not idempotent")
	}

	// 3. Notifications: the security lead and the project owner, not the developer.
	if err := it.env.DispatchNotifications(ctx); err != nil {
		t.Fatal(err)
	}
	var who []string
	if err := db.WithOrg(ctx, ownerPool, it.org, func(tx pgx.Tx) error {
		rows, _ := tx.Query(ctx, `SELECT user_id::text || ' ' || title || ' ' || email_state FROM notification
			WHERE type = 'component.malicious' ORDER BY 1`)
		var s string
		_, err := pgx.ForEachRow(rows, []any{&s}, func() error { who = append(who, s); return nil })
		return err
	}); err != nil {
		t.Fatal(err)
	}
	if len(who) != 4 {
		t.Fatal(who)
	}
	for _, s := range who {
		if !strings.HasPrefix(s, lead.String()) && !strings.HasPrefix(s, ownerID.String()) || !strings.Contains(s, "Malicious package found: WEB-") ||
			!strings.HasSuffix(s, " pending") {
			t.Fatal(who)
		}
	}

	// 4. The next scan finds the same packages: same fingerprints, no new
	// issue, no new notification. web/ also has Evil-Pkg: a scan-time match.
	data, sha := zipBytes()
	it.sb.files = map[string]string{"trivy.json": malReport("package-lock.json Evil-Pkg@1.0.0", "web/package-lock.json typo@2.0.0",
		"web/package-lock.json Evil-Pkg@1.0.0")}
	s1, key := it.scan("queued", sha, 0, "trivy")
	it.store.objects[key] = data
	it.run(s1)
	issues = it.malIssues()
	webEvil := issues["malicious:MAL-2032-1 web/package-lock.json"]
	if len(issues) != 3 || issues["malicious:MAL-2032-1 package-lock.json"].FP != evil.FP ||
		issues["malicious:MAL-2032-1 package-lock.json"].Last != s1 || issues["malicious:MAL-2032-1 package-lock.json"].Number != evil.Number ||
		issues["malicious:MAL-2032-2 web/package-lock.json"].Last != s1 || webEvil.Severity != "critical" || webEvil.First != s1 {
		t.Fatalf("%+v", issues)
	}
	if n := it.count(`SELECT count(*) FROM outbox_event WHERE org_id = $1 AND type = 'component.malicious'`, it.org); n != 3 {
		t.Fatal("scan-time match not announced exactly once", n)
	}

	// 5. Evil-Pkg leaves package-lock.json: that issue auto-fixes normally.
	it.sb.files = map[string]string{"trivy.json": malReport("web/package-lock.json typo@2.0.0", "web/package-lock.json Evil-Pkg@1.0.0")}
	s2, key := it.scan("queued", sha, 0, "trivy")
	it.store.objects[key] = data
	it.run(s2)
	if st := it.malIssues()["malicious:MAL-2032-1 package-lock.json"].Status; st != "fixed" {
		t.Fatal(st)
	}
	// The inventory follows the scan (BE-A's replace; simulated): no reopen.
	owner(t, it.org, fmt.Sprintf(`DELETE FROM component WHERE project_id = '%s' AND name = 'Evil-Pkg'`, it.project))
	if err := it.env.MatchMalicious(ctx, MatchMaliciousArgs{Ecosystem: "npm", All: true}); err != nil {
		t.Fatal(err)
	}
	if st := it.malIssues()["malicious:MAL-2032-1 package-lock.json"].Status; st != "fixed" {
		t.Fatal(st)
	}

	// 6. The package comes back without a scan seeing an advisory change
	// (e.g. restored inventory) and the advisory is updated: reopened, never
	// fixed, and announced again.
	it.component(s2, "Evil-Pkg", "1.0.0", "package-lock.json")
	writeOSV("2032-02-02T10:00:00Z", map[string]string{"MAL-2032-1": npmAll("evil-pkg"), "MAL-2032-3": npmLater})
	if err := it.env.LoadVulnIntel(ctx); err != nil {
		t.Fatal(err)
	}
	// MAL-2032-2 left the feed: its row is gone, its issue stays open.
	if got := malRows(); strings.Join(got, "|") != "MAL-2032-1 evil-pkg evil-pkg true " {
		t.Fatal(got)
	}
	if len(enqueued) != 2 || strings.Join(enqueued[1].Names, ",") != "evil-pkg" {
		t.Fatalf("%+v", enqueued)
	}
	if err := it.env.MatchMalicious(ctx, enqueued[1]); err != nil {
		t.Fatal(err)
	}
	issues = it.malIssues()
	if issues["malicious:MAL-2032-1 package-lock.json"].Status != "reopened" || issues["malicious:MAL-2032-2 web/package-lock.json"].Status != "open" ||
		issues["malicious:MAL-2032-1 web/package-lock.json"].Status != "open" {
		t.Fatalf("%+v", issues)
	}
	if n := it.count(`SELECT count(*) FROM outbox_event WHERE org_id = $1 AND type = 'component.malicious'`, it.org); n != 4 {
		t.Fatal("reopen not announced", n)
	}
	if n := it.count(`SELECT count(*) FROM outbox_event WHERE org_id = $1 AND type = 'issue.reopened'`, it.org); n != 1 {
		t.Fatal("issue.reopened", n)
	}
	if n := it.count(`SELECT count(*) FROM issue_event WHERE org_id = $1 AND type = 'status_changed' AND to_value = 'fixed'
		AND note LIKE '%advisory%'`, it.org); n != 0 {
		t.Fatal("a feed fixed an issue")
	}
}

// The inventory keeps versions as reported: a Go module at v1.4.0 (and a
// PyPI release spelled 1.0RC1) matches advisories listing 1.4.0 (1.0rc1);
// the next version doesn't.
func TestRetroMatchNormalizesVersions(t *testing.T) {
	ctx := context.Background()
	it := newITest(t)
	if err := db.WithOrg(ctx, ownerPool, uuid.Nil, func(tx pgx.Tx) error {
		_, err := tx.Exec(ctx, `INSERT INTO malicious_package (id, ecosystem, name, match_name, all_versions, versions, summary, modified) VALUES
			('MAL-2034-1', 'Go', 'github.com/evil/mod', 'github.com/evil/mod', false, '{1.4.0}', 's', now()),
			('MAL-2034-2', 'PyPI', 'bad_pkg', 'bad-pkg', false, '{1.0rc1}', 's', now())`)
		return err
	}); err != nil {
		t.Fatal(err)
	}
	s0, _ := it.scan("completed", strings.Repeat("0", 64), 0, "trivy")
	for _, c := range []string{"Go github.com/Evil/mod github.com/evil/mod v1.4.0 go.mod", "Go github.com/Evil/mod github.com/evil/mod v1.4.1 tools/go.mod",
		"PyPI Bad_Pkg bad-pkg 1.0RC1 requirements.txt"} {
		f := strings.Fields(c)
		owner(t, it.org, fmt.Sprintf(`INSERT INTO component (org_id, project_id, target, scan_id, ecosystem, name, match_name, version, path)
			VALUES ('%s', '%s', '', '%s', '%s', '%s', '%s', '%s', '%s')`, it.org, it.project, s0, f[0], f[1], f[2], f[3], f[4]))
	}
	for _, a := range []MatchMaliciousArgs{{Ecosystem: "Go", Names: []string{"github.com/evil/mod"}}, {Ecosystem: "PyPI", All: true}} {
		if err := it.env.MatchMalicious(ctx, a); err != nil {
			t.Fatal(err)
		}
	}
	issues := it.malIssues()
	if len(issues) != 2 || issues["malicious:MAL-2034-1 go.mod"].Severity != "critical" || issues["malicious:MAL-2034-2 requirements.txt"].Package != "Bad_Pkg" {
		t.Fatalf("%+v", issues)
	}
}

// TestOSVRealLoad loads real OSV all.zip files (WARDEN_OSV_DIR holding
// <ecosystem>.zip, e.g. from scripts/sync-mirror.sh) through the loader and
// retro-matches a known malicious npm version (WARDEN_OSV_NPM_FIXTURE,
// "name@version"). Skipped without WARDEN_OSV_DIR.
func TestOSVRealLoad(t *testing.T) {
	dir := os.Getenv("WARDEN_OSV_DIR")
	if dir == "" {
		t.Skip("WARDEN_OSV_DIR not set")
	}
	ctx := context.Background()
	it := newITest(t)
	it.env.MirrorDir = t.TempDir()
	var enqueued []MatchMaliciousArgs
	old := enqueueMatch
	enqueueMatch = func(_ context.Context, _ DB, a MatchMaliciousArgs) error { enqueued = append(enqueued, a); return nil }
	defer func() { enqueueMatch = old }()
	if err := os.MkdirAll(filepath.Join(it.env.MirrorDir, intelOSVDir), 0o755); err != nil {
		t.Fatal(err)
	}
	for _, eco := range []string{"npm", "PyPI"} {
		if err := os.Symlink(filepath.Join(dir, eco+".zip"), filepath.Join(it.env.MirrorDir, intelOSVDir, eco+".zip")); err != nil {
			t.Fatal(err)
		}
	}
	start := time.Now()
	if err := it.env.LoadVulnIntel(ctx); err != nil {
		t.Fatal(err)
	}
	load := time.Since(start)
	start = time.Now()
	if err := it.env.LoadVulnIntel(ctx); err != nil {
		t.Fatal(err)
	}
	reload := time.Since(start)
	var summary []string
	if err := db.WithOrg(ctx, ownerPool, uuid.Nil, func(tx pgx.Tx) error {
		rows, _ := tx.Query(ctx, `SELECT s.name || ': records ' || s.records || ', unsupported ' || s.unsupported || ', updated ' || s.updated_at
			|| ', rows ' || (SELECT count(*) FROM malicious_package m WHERE 'osv_mal:' || m.ecosystem = s.name)
			FROM vuln_intel_source s WHERE s.name LIKE 'osv_mal:%' ORDER BY 1`)
		var s string
		_, err := pgx.ForEachRow(rows, []any{&s}, func() error { summary = append(summary, s); return nil })
		return err
	}); err != nil {
		t.Fatal(err)
	}
	t.Logf("first load %v, unchanged reload %v; %v; enqueued %+v", load.Round(time.Millisecond), reload.Round(time.Millisecond), summary, enqueued)
	if len(summary) != 2 || len(enqueued) != 2 || !enqueued[0].All {
		t.Fatal("unexpected load")
	}
	fixture := os.Getenv("WARDEN_OSV_NPM_FIXTURE")
	if fixture == "" {
		return
	}
	name, version, _ := strings.Cut(fixture, "@")
	s0, _ := it.scan("completed", strings.Repeat("0", 64), 0, "trivy")
	it.component(s0, name, version, "package-lock.json")
	start = time.Now()
	if err := it.env.MatchMalicious(ctx, MatchMaliciousArgs{Ecosystem: "npm", All: true}); err != nil {
		t.Fatal(err)
	}
	issues := it.malIssues()
	t.Logf("retro-match over all npm advisories %v: %v", time.Since(start).Round(time.Millisecond), issues)
	if len(issues) != 1 {
		t.Fatal(issues)
	}
}
