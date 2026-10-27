//go:build integration

package worker

import (
	"bytes"
	"context"
	"fmt"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/google/uuid"
	"github.com/jackc/pgx/v5"
	"github.com/jackc/pgx/v5/pgxpool"
	"github.com/testcontainers/testcontainers-go"
	tcpostgres "github.com/testcontainers/testcontainers-go/modules/postgres"
	"github.com/testcontainers/testcontainers-go/wait"

	"github.com/aupv9/warden/backend/internal/db"
	"github.com/aupv9/warden/backend/internal/migrations"
	"github.com/aupv9/warden/backend/internal/scan/orchestrator"
	"github.com/aupv9/warden/backend/internal/scan/sandbox"
	"github.com/aupv9/warden/backend/internal/scan/zipcheck"
)

var ownerPool, appPool *pgxpool.Pool

func TestMain(m *testing.M) {
	ctx := context.Background()
	c, err := tcpostgres.Run(ctx, "postgres:16-alpine",
		tcpostgres.WithDatabase("warden"), tcpostgres.WithUsername("warden_owner"), tcpostgres.WithPassword("owner-test-pw"),
		testcontainers.WithWaitStrategy(wait.ForLog("database system is ready to accept connections").WithOccurrence(2).WithStartupTimeout(60*time.Second)),
	)
	if err != nil {
		fmt.Fprintln(os.Stderr, "start postgres:", err)
		os.Exit(1)
	}
	code := func() int {
		defer func() { _ = testcontainers.TerminateContainer(c) }()
		ownerURL, _ := c.ConnectionString(ctx, "sslmode=disable")
		if ownerPool, err = pgxpool.New(ctx, ownerURL); err != nil {
			fmt.Fprintln(os.Stderr, err)
			return 1
		}
		if _, err := ownerPool.Exec(ctx, "CREATE ROLE warden_app LOGIN PASSWORD 'app-test-pw' NOSUPERUSER NOBYPASSRLS"); err != nil {
			fmt.Fprintln(os.Stderr, err)
			return 1
		}
		if err := migrations.Up(ctx, ownerURL); err != nil {
			fmt.Fprintln(os.Stderr, err)
			return 1
		}
		host, _ := c.Host(ctx)
		port, _ := c.MappedPort(ctx, "5432/tcp")
		if appPool, err = pgxpool.New(ctx, fmt.Sprintf("postgres://warden_app:app-test-pw@%s:%s/warden?sslmode=disable", host, port.Port())); err != nil {
			fmt.Fprintln(os.Stderr, err)
			return 1
		}
		return m.Run()
	}()
	os.Exit(code)
}

type itest struct {
	t                  *testing.T
	org, project, user uuid.UUID
	env                *Env
	store              *fakeStore
	sb                 *fakeSandbox
}

func owner(t *testing.T, org uuid.UUID, stmts ...string) {
	t.Helper()
	if err := db.WithOrg(context.Background(), ownerPool, org, func(tx pgx.Tx) error {
		for _, s := range stmts {
			if _, err := tx.Exec(context.Background(), s); err != nil {
				return fmt.Errorf("%s: %w", s, err)
			}
		}
		return nil
	}); err != nil {
		t.Fatal(err)
	}
}

func (it *itest) one(q string, dest ...any) {
	it.t.Helper()
	if err := db.WithOrg(context.Background(), ownerPool, it.org, func(tx pgx.Tx) error {
		return tx.QueryRow(context.Background(), q).Scan(dest...)
	}); err != nil {
		it.t.Fatalf("%s: %v", q, err)
	}
}

func newITest(t *testing.T) *itest {
	it := &itest{t: t, org: uuid.New(), project: uuid.New(), user: uuid.New(),
		store: &fakeStore{objects: map[string][]byte{}}, sb: &fakeSandbox{status: map[string]sandbox.ToolStatus{}}}
	owner(t, it.org,
		fmt.Sprintf(`INSERT INTO organization (id, name) VALUES ('%s', 'o')`, it.org),
		fmt.Sprintf(`INSERT INTO app_user (id, keycloak_sub, email, display_name) VALUES ('%s', '%s', '%s@x.test', 'u')`, it.user, it.user, it.user),
		fmt.Sprintf(`INSERT INTO project (id, org_id, key, name) VALUES ('%s', '%s', 'WEB', 'w')`, it.project, it.org),
	)
	scratch := filepath.Join(t.TempDir(), "scratch")
	_ = os.Mkdir(scratch, 0o700)
	it.env = &Env{Tx: PoolTx(appPool), Store: it.store, Sandbox: it.sb, Now: time.Now, Log: quietLog(),
		Settings: Settings{ScratchDir: scratch, MirrorDir: "/mirror", Runtime: "runc", Images: testImages,
			HMACMaster: bytes.Repeat([]byte("m"), 32), GuardRatio: 0.5, ScanTimeout: time.Minute,
			SourceRetention: time.Hour, AbandonUploadAfter: time.Hour, StuckAfter: 24 * time.Hour,
			Limits: orchestrator.Limits{Zip: zipcheck.DefaultLimits()}, SBOMRetention: 24 * time.Hour}}
	return it
}

func (it *itest) scan(status, sha string, age time.Duration, tools ...string) (uuid.UUID, string) {
	id := uuid.New()
	key := "scans/" + it.org.String() + "/" + id.String() + ".zip"
	owner(it.t, it.org, fmt.Sprintf(`INSERT INTO scan (id, org_id, project_id, created_by, status, file_name, object_key, sha256, tools, created_at)
		VALUES ('%s', '%s', '%s', '%s', '%s', 'a.zip', '%s', '%s', '{%s}', now() - interval '%d seconds')`,
		id, it.org, it.project, it.user, status, key, sha, tools[0], int(age.Seconds())))
	return id, key
}

func (it *itest) run(scanID uuid.UUID) {
	it.t.Helper()
	old := orchestrator.CancelPoll
	orchestrator.CancelPoll = 10 * time.Millisecond
	defer func() { orchestrator.CancelPoll = old }()
	if err := it.env.RunScan(context.Background(), orchestrator.Job{ScanID: scanID.String(), OrgID: it.org.String()}, 1); err != nil {
		it.t.Fatal(err)
	}
}

func TestScanEndToEnd(t *testing.T) {
	it := newITest(t)
	data, sha := zipBytes()
	id, key := it.scan("queued", sha, 0, "opengrep")
	it.store.objects[key] = data
	it.run(id)

	var status, toolStatus, version string
	var deleted, finished bool
	var issues, count int
	it.one(fmt.Sprintf(`SELECT status, source_deleted_at IS NOT NULL, finished_at IS NOT NULL FROM scan WHERE id = '%s'`, id), &status, &deleted, &finished)
	it.one(fmt.Sprintf(`SELECT status, tool_version, findings_count FROM scan_tool_run WHERE scan_id = '%s'`, id), &toolStatus, &version, &count)
	it.one(fmt.Sprintf(`SELECT count(*) FROM issue WHERE project_id = '%s'`, it.project), &issues)
	if status != "completed" || !deleted || !finished || toolStatus != "succeeded" || version != "v1" || count != 1 || issues != 1 {
		t.Fatal(status, deleted, finished, toolStatus, version, count, issues)
	}
	// A retry of the finished job changes nothing.
	it.run(id)
	it.one(fmt.Sprintf(`SELECT count(*) FROM issue WHERE project_id = '%s'`, it.project), &issues)
	if issues != 1 {
		t.Fatal("retry duplicated issues")
	}
}

// A Trivy scan stores its SBOM and opens license issues under the org's
// policy; the purge job later removes the SBOM, object and columns together.
func TestSBOMAndLicensesEndToEnd(t *testing.T) {
	it := newITest(t)
	it.env.Images = map[string]string{"trivy": "docker.io/aquasec/trivy:0.75.0@sha256:" + strings.Repeat("c", 64)}
	it.sb.files = map[string]string{"trivy.json": trivyReport, "sbom.cdx.json": `{"bomFormat":"CycloneDX","components":[{"name":"x"}]}`}
	owner(t, it.org, fmt.Sprintf(`UPDATE organization SET license_policy = '{"categories":{"restricted":"block"}}' WHERE id = '%s'`, it.org))
	data, sha := zipBytes()
	id, key := it.scan("queued", sha, 0, "trivy")
	it.store.objects[key] = data
	it.run(id)

	sbomKey := SBOMKey(it.org, id)
	var status, storedKey, severity string
	var components int
	it.one(fmt.Sprintf(`SELECT status, sbom_key, sbom_components FROM scan WHERE id = '%s'`, id), &status, &storedKey, &components)
	it.one(fmt.Sprintf(`SELECT severity FROM issue WHERE project_id = '%s' AND rule_id = 'license:GPL-3.0-only'`, it.project), &severity)
	if status != "completed" || storedKey != sbomKey || components != 1 || severity != "high" || it.store.objects[sbomKey] == nil {
		t.Fatal(status, storedKey, components, severity)
	}

	// Not expired yet: kept.
	if err := it.env.PurgeExpiredSources(context.Background()); err != nil || contains(it.store.deleted, sbomKey) {
		t.Fatal(err, it.store.deleted)
	}
	it.env.Now = func() time.Time { return time.Now().Add(it.env.SBOMRetention + time.Minute) }
	if err := it.env.PurgeExpiredSources(context.Background()); err != nil {
		t.Fatal(err)
	}
	var cleared bool
	it.one(fmt.Sprintf(`SELECT sbom_key IS NULL AND sbom_size IS NULL AND sbom_sha256 IS NULL AND sbom_components IS NULL
		AND sbom_expires_at IS NULL FROM scan WHERE id = '%s'`, id), &cleared)
	if !cleared || !contains(it.store.deleted, sbomKey) {
		t.Fatal(cleared, it.store.deleted)
	}
}

func TestRejectedScanSkipsTools(t *testing.T) {
	it := newITest(t)
	data, _ := zipBytes()
	id, key := it.scan("queued", fmt.Sprintf("%064d", 0), 0, "opengrep")
	it.store.objects[key] = data
	it.run(id)
	var status, code, tool string
	it.one(fmt.Sprintf(`SELECT s.status, s.error_code, r.status FROM scan s JOIN scan_tool_run r ON r.scan_id = s.id WHERE s.id = '%s'`, id), &status, &code, &tool)
	if status != "failed" || code != "CHECKSUM_MISMATCH" || tool != "skipped" {
		t.Fatal(status, code, tool)
	}
}

func TestCancelledScanIsCleanedUp(t *testing.T) {
	it := newITest(t)
	id, key := it.scan("cancelled", fmt.Sprintf("%064d", 0), 0, "trivy")
	it.store.objects[key] = []byte("x")
	it.run(id)
	var deleted, finished bool
	var tool string
	it.one(fmt.Sprintf(`SELECT s.source_deleted_at IS NOT NULL, s.finished_at IS NOT NULL, r.status FROM scan s JOIN scan_tool_run r ON r.scan_id = s.id WHERE s.id = '%s'`, id), &deleted, &finished, &tool)
	if !deleted || !finished || tool != "skipped" || len(it.sb.configs) != 0 {
		t.Fatal(deleted, finished, tool)
	}
}

func TestPurgeAgainstSchema(t *testing.T) {
	it := newITest(t)
	sha := fmt.Sprintf("%064d", 0)
	abandoned, aKey := it.scan("pending_upload", sha, 2*time.Hour, "trivy")
	fresh, _ := it.scan("pending_upload", sha, time.Minute, "trivy")
	old, oKey := it.scan("failed", sha, 3*time.Hour, "trivy")
	running, _ := it.scan("running", sha, 3*time.Hour, "trivy")
	if err := it.env.PurgeExpiredSources(context.Background()); err != nil {
		t.Fatal(err)
	}
	check := func(id uuid.UUID, wantStatus string, wantDeleted bool) {
		t.Helper()
		var status string
		var deleted bool
		it.one(fmt.Sprintf(`SELECT status, source_deleted_at IS NOT NULL FROM scan WHERE id = '%s'`, id), &status, &deleted)
		if status != wantStatus || deleted != wantDeleted {
			t.Errorf("%s: %s %v", id, status, deleted)
		}
	}
	check(abandoned, "cancelled", true)
	check(fresh, "pending_upload", false)
	check(old, "failed", true)
	check(running, "running", false) // younger than StuckAfter
	var code, tool string
	it.one(fmt.Sprintf(`SELECT s.error_code, r.status FROM scan s JOIN scan_tool_run r ON r.scan_id = s.id WHERE s.id = '%s'`, abandoned), &code, &tool)
	if code != CodeUploadAbandoned || tool != "skipped" {
		t.Fatal(code, tool)
	}
	if !contains(it.store.deleted, aKey) || !contains(it.store.deleted, oKey) {
		t.Fatal(it.store.deleted)
	}
}

func contains(s []string, v string) bool {
	for _, x := range s {
		if x == v {
			return true
		}
	}
	return false
}

func TestReopenExpiredAgainstSchema(t *testing.T) {
	it := newITest(t)
	approver := uuid.New()
	scanID, _ := it.scan("completed", fmt.Sprintf("%064d", 0), 0, "trivy")
	issue := uuid.New()
	exc := uuid.New()
	owner(t, it.org,
		fmt.Sprintf(`INSERT INTO app_user (id, keycloak_sub, email, display_name) VALUES ('%s', '%s', '%s@x.test', 'lead')`, approver, approver, approver),
		fmt.Sprintf(`INSERT INTO issue (id, org_id, project_id, number, fingerprint, tool, rule_id, title, severity, status, first_seen_scan_id, last_seen_scan_id)
			VALUES ('%s', '%s', '%s', 1, '%064d', 'trivy', 'CVE-1', 't', 'high', 'risk_accepted', '%s', '%s')`, issue, it.org, it.project, 1, scanID, scanID),
		// created 10 days ago, expired yesterday (the CHECK allows ≤ 180 days from creation)
		fmt.Sprintf(`INSERT INTO exception_request (id, org_id, issue_id, type, reason, requested_by, decided_by, status, expires_at, decided_at, created_at)
			VALUES ('%s', '%s', '%s', 'risk_accepted', 'accepted for the quarter, compensating control', '%s', '%s', 'approved', now() - interval '1 day', now() - interval '9 days', now() - interval '10 days')`,
			exc, it.org, issue, it.user, approver),
	)
	if err := it.env.ReopenExpiredRiskAccepted(context.Background()); err != nil {
		t.Fatal(err)
	}
	var excStatus, issueStatus string
	var version, events int
	var due bool
	it.one(fmt.Sprintf(`SELECT x.status, i.status, i.version, i.due_at IS NOT NULL, (SELECT count(*) FROM issue_event e WHERE e.issue_id = i.id AND e.actor_id IS NULL AND e.to_value = 'reopened')
		FROM exception_request x JOIN issue i ON i.id = x.issue_id WHERE x.id = '%s'`, exc), &excStatus, &issueStatus, &version, &due, &events)
	if excStatus != "expired" || issueStatus != "reopened" || version != 2 || !due || events != 1 {
		t.Fatal(excStatus, issueStatus, version, due, events)
	}
	// Running again finds nothing.
	if err := it.env.ReopenExpiredRiskAccepted(context.Background()); err != nil {
		t.Fatal(err)
	}
}
