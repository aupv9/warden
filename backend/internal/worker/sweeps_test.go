package worker

import (
	"bytes"
	"context"
	"errors"
	"strings"
	"testing"
	"time"

	"github.com/google/uuid"
	"github.com/riverqueue/river"
	"github.com/riverqueue/river/rivertype"

	"github.com/aupv9/warden/backend/internal/config"
	"github.com/aupv9/warden/backend/internal/scan/redact"
	"github.com/aupv9/warden/backend/internal/scan/sandbox"
	"github.com/aupv9/warden/backend/internal/scan/sarif"
	"github.com/aupv9/warden/backend/internal/worker/dbtest"
)

// sweepEnv: two orgs; every transaction records which org it was scoped to.
func sweepEnv(t *testing.T, steps ...dbtest.Step) (*Env, *dbtest.DB, *fakeStore, *[]uuid.UUID, []uuid.UUID) {
	orgs := []uuid.UUID{uuid.New(), uuid.New()}
	all := append([]dbtest.Step{{Prefix: "SELECT id FROM organization", Rows: [][]any{{orgs[0]}, {orgs[1]}}}}, steps...)
	db := dbtest.Loose(t, all...)
	store := &fakeStore{objects: map[string][]byte{}}
	var scoped []uuid.UUID
	env := &Env{
		Tx: func(_ context.Context, org uuid.UUID, fn func(DB) error) error {
			scoped = append(scoped, org)
			return fn(db)
		},
		Store: store, Now: func() time.Time { return time.Date(2026, 10, 26, 12, 0, 0, 0, time.UTC) }, Log: quietLog(),
		Settings: Settings{SourceRetention: time.Hour, AbandonUploadAfter: time.Hour, StuckAfter: 24 * time.Hour, Images: testImages},
	}
	return env, db, store, &scoped, orgs
}

func TestPurgeExpiredSources(t *testing.T) {
	abandoned, expired, keyless := uuid.New(), uuid.New(), uuid.New()
	env, db, store, scoped, orgs := sweepEnv(t,
		dbtest.Step{Prefix: "UPDATE scan SET status = 'cancelled', error_code = $2", Rows: [][]any{{abandoned, "scans/a.zip", []string{"opengrep"}}},
			Args: func(args []any) error {
				if args[1] != CodeUploadAbandoned || !args[0].(time.Time).Equal(time.Date(2026, 10, 26, 11, 0, 0, 0, time.UTC)) {
					t.Errorf("abandon args %v", args)
				}
				return nil
			}},
		dbtest.Step{Prefix: "INSERT INTO scan_tool_run", Affected: 1},
		dbtest.Step{Prefix: "SELECT id, object_key, tools FROM scan", Rows: [][]any{{expired, "scans/e.zip", []string{"trivy"}}, {keyless, nil, []string{"trivy"}}}},
		dbtest.Step{Prefix: "UPDATE scan SET source_deleted_at", Affected: 1},
	)
	if err := env.PurgeExpiredSources(context.Background()); err != nil {
		t.Fatal(err)
	}
	// Per org: both objects deleted (the fake returns the same rows for each org).
	if len(store.deleted) != 4 || store.deleted[0] != "scans/a.zip" || store.deleted[1] != "scans/e.zip" {
		t.Fatalf("deleted %v", store.deleted)
	}
	if n := len(db.Calls("UPDATE scan SET source_deleted_at")); n != 6 {
		t.Fatalf("source_deleted_at updates: %d", n)
	}
	if n := len(db.Calls("INSERT INTO scan_tool_run")); n != 2 {
		t.Fatalf("abandoned scans' tools not skipped: %d", n)
	}
	if (*scoped)[0] != uuid.Nil || (*scoped)[1] != orgs[0] {
		t.Fatalf("scoping %v", *scoped)
	}
}

func TestPurgeKeepsGoingAfterFailures(t *testing.T) {
	env, db, store, _, _ := sweepEnv(t,
		dbtest.Step{Prefix: "UPDATE scan SET status = 'cancelled'"},
		dbtest.Step{Prefix: "SELECT id, object_key, tools FROM scan", Rows: [][]any{{uuid.New(), "scans/e.zip", []string{"trivy"}}}},
		dbtest.Step{Prefix: "UPDATE scan SET source_deleted_at", Affected: 1},
	)
	store.delErr = errors.New("s3 down")
	err := env.PurgeExpiredSources(context.Background())
	if err == nil || !strings.Contains(err.Error(), "s3 down") {
		t.Fatal(err)
	}
	if len(store.deleted) != 2 || len(db.Calls("UPDATE scan SET source_deleted_at")) != 0 {
		t.Fatal("a failed delete must leave source_deleted_at NULL for the next run")
	}
}

func TestPurgeDBErrors(t *testing.T) {
	for _, s := range []dbtest.Step{
		{Prefix: "SELECT id FROM organization", Err: errors.New("down")},
		{Prefix: "UPDATE scan SET status = 'cancelled'", Err: errors.New("down")},
		{Prefix: "SELECT id, object_key, tools FROM scan", Err: errors.New("down")},
	} {
		env, _, _, _, _ := sweepEnv(t, dbtest.Step{Prefix: "UPDATE scan SET status = 'cancelled'"}, dbtest.Step{Prefix: "SELECT id, object_key, tools FROM scan"}, s)
		if err := env.PurgeExpiredSources(context.Background()); err == nil {
			t.Errorf("%s: error swallowed", s.Prefix)
		}
	}
	env, _, _, _, _ := sweepEnv(t,
		dbtest.Step{Prefix: "UPDATE scan SET status = 'cancelled'", Rows: [][]any{{uuid.New(), nil, []string{"trivy"}}}},
		dbtest.Step{Prefix: "INSERT INTO scan_tool_run", Err: errors.New("down")})
	if err := env.PurgeExpiredSources(context.Background()); err == nil {
		t.Error("skip error swallowed")
	}
	env, _, _, _, _ = sweepEnv(t,
		dbtest.Step{Prefix: "UPDATE scan SET status = 'cancelled'"},
		dbtest.Step{Prefix: "SELECT id, object_key, tools FROM scan", Rows: [][]any{{uuid.New(), nil, []string{"trivy"}}}},
		dbtest.Step{Prefix: "UPDATE scan SET source_deleted_at", Err: errors.New("down")})
	if err := env.PurgeExpiredSources(context.Background()); err == nil {
		t.Error("stamp error swallowed")
	}
}

func TestReopenExpiredRiskAccepted(t *testing.T) {
	reopen, moved := uuid.New(), uuid.New()
	env, db, _, _, _ := sweepEnv(t,
		dbtest.Step{Prefix: "SELECT x.id, x.issue_id", Rows: [][]any{
			{uuid.New(), reopen, "risk_accepted", "high"},
			{uuid.New(), moved, "fixed", "high"},
		}},
		dbtest.Step{Prefix: "SELECT sla_days FROM organization", Rows: row([]byte(`{"high":30}`))},
		dbtest.Step{Prefix: "UPDATE exception_request SET status = 'expired'", Affected: 1},
		dbtest.Step{Prefix: "UPDATE issue SET status = 'reopened'", Affected: 1, Args: func(args []any) error {
			if args[0] != reopen {
				t.Errorf("reopened %v", args[0])
			}
			due := args[2].(*time.Time)
			if !due.Equal(time.Date(2026, 11, 25, 12, 0, 0, 0, time.UTC)) {
				t.Errorf("due %v", due)
			}
			return nil
		}},
		dbtest.Step{Prefix: "INSERT INTO issue_event", Affected: 1},
		dbtest.Step{Prefix: "INSERT INTO outbox_event", Affected: 1},
	)
	if err := env.ReopenExpiredRiskAccepted(context.Background()); err != nil {
		t.Fatal(err)
	}
	// Two orgs × two exceptions expired; one issue reopened per org, with an
	// event and an issue.reopened notification each.
	if len(db.Calls("UPDATE exception_request")) != 4 || len(db.Calls("UPDATE issue SET status = 'reopened'")) != 2 ||
		len(db.Calls("INSERT INTO issue_event")) != 2 || len(db.Calls("INSERT INTO outbox_event")) != 2 {
		t.Fatal(len(db.Calls("")))
	}
	if c := db.Calls("INSERT INTO outbox_event")[0]; c.Args[1] != "issue.reopened" || !strings.Contains(string(c.Args[2].([]byte)), reopen.String()) {
		t.Fatalf("%+v", c)
	}
}

func TestReopenExpiredEdgeCases(t *testing.T) {
	// Nothing expired: no SLA lookup.
	env, db, _, _, _ := sweepEnv(t, dbtest.Step{Prefix: "SELECT x.id, x.issue_id"})
	if err := env.ReopenExpiredRiskAccepted(context.Background()); err != nil || len(db.Calls("SELECT sla_days")) != 0 {
		t.Fatal(err)
	}
	// Concurrent change: the guarded UPDATE matched nothing → no event.
	env, db, _, _, _ = sweepEnv(t,
		dbtest.Step{Prefix: "SELECT x.id, x.issue_id", Rows: [][]any{{uuid.New(), uuid.New(), "risk_accepted", "low"}}},
		dbtest.Step{Prefix: "SELECT sla_days FROM organization", Rows: row([]byte(`{}`))},
		dbtest.Step{Prefix: "UPDATE exception_request", Affected: 1},
		dbtest.Step{Prefix: "UPDATE issue SET status = 'reopened'", Affected: 0},
	)
	if err := env.ReopenExpiredRiskAccepted(context.Background()); err != nil || len(db.Calls("INSERT INTO issue_event")) != 0 {
		t.Fatal(err)
	}
	for _, bad := range []dbtest.Step{
		{Prefix: "SELECT x.id, x.issue_id", Err: errors.New("down")},
		{Prefix: "SELECT sla_days FROM organization", Err: errors.New("down")},
		{Prefix: "SELECT sla_days FROM organization", Rows: row([]byte(`[]`))},
		{Prefix: "UPDATE exception_request", Err: errors.New("down")},
		{Prefix: "UPDATE issue SET status = 'reopened'", Err: errors.New("down")},
		{Prefix: "INSERT INTO issue_event", Err: errors.New("down")},
		{Prefix: "INSERT INTO outbox_event", Err: errors.New("down")},
	} {
		base := []dbtest.Step{
			{Prefix: "SELECT x.id, x.issue_id", Rows: [][]any{{uuid.New(), uuid.New(), "risk_accepted", "low"}}},
			{Prefix: "SELECT sla_days FROM organization", Rows: row([]byte(`{}`))},
			{Prefix: "UPDATE exception_request", Affected: 1},
			{Prefix: "UPDATE issue SET status = 'reopened'", Affected: 1},
			{Prefix: "INSERT INTO issue_event", Affected: 1},
			{Prefix: "INSERT INTO outbox_event", Affected: 1},
		}
		for i := range base {
			if base[i].Prefix == bad.Prefix {
				base[i] = bad
			}
		}
		env, _, _, _, _ := sweepEnv(t, base...)
		if err := env.ReopenExpiredRiskAccepted(context.Background()); err == nil {
			t.Errorf("%s: error swallowed", bad.Prefix)
		}
	}
}

func TestPeriodicWorkersDelegate(t *testing.T) {
	env, _, _, _, _ := sweepEnv(t, dbtest.Step{Prefix: "SELECT id FROM organization", Err: errors.New("down")})
	if err := (PurgeExpiredSourcesWorker{Env: env}).Work(context.Background(), nil); err == nil {
		t.Fatal("purge")
	}
	if err := (ReopenExpiredRiskAcceptedWorker{Env: env}).Work(context.Background(), nil); err == nil {
		t.Fatal("reopen")
	}
	var cancel *river.JobCancelError
	for _, err := range []error{
		(PurgeExpiredSourcesWorker{}).Work(context.Background(), nil),
		(ReopenExpiredRiskAcceptedWorker{}).Work(context.Background(), nil),
		(&ScanWorker{}).Work(context.Background(), &river.Job[ScanArgs]{JobRow: &rivertype.JobRow{}}),
	} {
		if !errors.As(err, &cancel) {
			t.Fatalf("nil env: %v", err)
		}
	}
}

func TestConfig(t *testing.T) {
	cfg, err := Config(Options{})
	if err != nil || cfg.Workers != nil || len(cfg.PeriodicJobs) != 0 {
		t.Fatal("insert-only client must not run jobs")
	}
	cfg, err = Config(Options{ScanTimeout: 30 * time.Minute, ScanSlots: 3})
	if err != nil || cfg.Workers == nil || len(cfg.PeriodicJobs) != 0 {
		t.Fatal("no env: workers cancel, nothing periodic")
	}
	cfg, err = Config(Options{ScanTimeout: 30 * time.Minute, ScanSlots: 3, Env: &Env{}})
	if err != nil || len(cfg.PeriodicJobs) != 4 || cfg.Queues[QueueScan].MaxWorkers != 3 {
		t.Fatalf("%+v %v", cfg, err)
	}
	// Rescue must not fire while a scan (timeout + finalization) can still be running.
	if cfg.RescueStuckJobsAfter <= 30*time.Minute+finalizeTimeout {
		t.Fatal(cfg.RescueStuckJobsAfter)
	}
}

func TestOrgKey(t *testing.T) {
	master := bytes.Repeat([]byte("m"), 32)
	a1, err := OrgKey(master, "0193c3a2-0000-7000-8000-000000000001")
	if err != nil {
		t.Fatal(err)
	}
	a2, _ := OrgKey(master, "0193c3a2-0000-7000-8000-000000000001")
	b, _ := OrgKey(master, "0193c3a2-0000-7000-8000-000000000002")
	if !bytes.Equal(a1, a2) || bytes.Equal(a1, b) || len(a1) < redact.MinKeyBytes {
		t.Fatal("org keys must be stable, distinct and long enough for the redactor")
	}
	if bytes.Contains(a1, master) {
		t.Fatal("master key leaked into the org key")
	}
	if _, err := OrgKey(master[:31], "0193c3a2-0000-7000-8000-000000000001"); err == nil {
		t.Fatal("short master accepted")
	}
	if _, err := OrgKey(master, "../other"); err == nil {
		t.Fatal("bad org id accepted")
	}
	d := &liveDeps{env: &Env{Settings: Settings{HMACMaster: master}}}
	if k, err := d.HMACKey(context.Background(), "0193c3a2-0000-7000-8000-000000000001"); err != nil || !bytes.Equal(k, a1) {
		t.Fatal(err)
	}
}

func TestImageInfo(t *testing.T) {
	d := "sha256:" + strings.Repeat("c", 64)
	for ref, want := range map[string][2]string{
		"docker.io/aquasec/trivy:0.75.0@" + d:    {"0.75.0", d},
		"localhost:5000/warden/opengrep:v1@" + d: {"v1", d},
		"warden/gitleaks@" + d:                   {"", d},
		"warden/gitleaks:latest":                 {"", ""},
		"":                                       {"", ""},
	} {
		v, dg := imageInfo(ref)
		if v != want[0] || dg != want[1] {
			t.Errorf("%s: %q %q", ref, v, dg)
		}
	}
}

func TestToolError(t *testing.T) {
	str := func(p *string) string {
		if p == nil {
			return "<nil>"
		}
		return *p
	}
	for _, c := range []struct {
		run  sandbox.ToolRun
		want string
	}{
		{sandbox.ToolRun{Status: sandbox.Succeeded}, "<nil>"},
		{sandbox.ToolRun{Status: sandbox.Running}, "<nil>"},
		{sandbox.ToolRun{Status: sandbox.Timeout, Error: "timeout"}, "timeout"},
		{sandbox.ToolRun{Status: sandbox.Failed, Error: "cancelled"}, "cancelled"},
		{sandbox.ToolRun{Status: sandbox.Failed, Error: errNoImage}, errNoImage},
		{sandbox.ToolRun{Status: sandbox.Failed, Error: sarif.ErrSARIF.Error() + ": invalid SARIF JSON"}, "SARIF: invalid SARIF JSON"},
		{sandbox.ToolRun{Status: sandbox.Failed, Error: "Traceback: password = 'hunter2'"}, "scanner failed (details in worker logs)"},
	} {
		if got := str(toolError(c.run)); got != c.want {
			t.Errorf("%+v: %q", c.run, got)
		}
	}
	long := sandbox.ToolRun{Status: sandbox.Failed, Error: sarif.ErrSARIF.Error() + ": " + strings.Repeat("x", 500)}
	if len(*toolError(long)) != 300 {
		t.Fatal("not truncated")
	}
}

func TestLiveDepsEdges(t *testing.T) {
	db := dbtest.Loose(t,
		dbtest.Step{Prefix: "SELECT status FROM scan WHERE id = $1"},
		dbtest.Step{Prefix: "UPDATE scan SET source_deleted_at", Affected: 1},
	)
	store := &fakeStore{}
	sb := &fakeSandbox{}
	env := &Env{Tx: func(_ context.Context, _ uuid.UUID, fn func(DB) error) error { return fn(db) }, Store: store, Sandbox: sb, Log: quietLog(),
		Settings: Settings{Images: map[string]string{}}}
	d := &liveDeps{env: env, org: uuid.New(), scan: uuid.New(), attempt: 1}
	if c, err := d.IsCancelled(context.Background(), ""); err != nil || !c {
		t.Fatal("a vanished scan must stop", err)
	}
	if err := d.SetStatus(context.Background(), "", "completed"); err == nil {
		t.Fatal("orchestrator may only set running")
	}
	if r := d.RunTool(context.Background(), "trivy", "s", "/tmp/x"); r.Status != sandbox.Failed || r.Error != errNoImage || len(sb.configs) != 0 {
		t.Fatalf("%+v", r)
	}
	d.KillTool("s", "trivy")
	if len(sb.killed) != 1 {
		t.Fatal("kill")
	}
	store.delErr = errors.New("down")
	if err := d.DeleteObject(context.Background(), "k"); err == nil || len(db.Calls("UPDATE scan SET source_deleted_at")) != 0 {
		t.Fatal("source_deleted_at must stay NULL when the delete failed")
	}
}

func TestNewEnv(t *testing.T) {
	cfg := &config.Config{}
	cfg.Scan.HMACKey = config.Secret(strings.Repeat("k", 31))
	if _, err := NewEnv(cfg, nil, &fakeStore{}, quietLog()); err == nil {
		t.Fatal("short HMAC key accepted")
	}
	cfg.Scan.HMACKey = config.Secret(strings.Repeat("k", 64))
	cfg.Scan.ScratchDir, cfg.Scan.MirrorDir, cfg.Scan.SandboxRuntime = "rel/scratch", "/mirror", "runc"
	cfg.Scan.Images = testImages
	cfg.SMTP = config.SMTPSection{Host: "localhost", Port: 1025, From: "warden@localhost", PublicBaseURL: "javascript:alert(1)"}
	if _, err := NewEnv(cfg, nil, &fakeStore{}, quietLog()); err == nil {
		t.Fatal("bad public base URL accepted")
	}
	cfg.SMTP.PublicBaseURL, cfg.SMTP.From = "https://warden.example/", "not an address"
	if _, err := NewEnv(cfg, nil, &fakeStore{}, quietLog()); err == nil {
		t.Fatal("bad from address accepted")
	}
	cfg.SMTP.From, cfg.SMTP.DigestHour = "warden@example.com", 6
	env, err := NewEnv(cfg, nil, &fakeStore{}, quietLog())
	if err != nil {
		t.Fatal(err)
	}
	if env.PublicBaseURL != "https://warden.example" || env.DigestHour != 6 || env.Mailer == nil {
		t.Fatalf("%+v", env.Settings)
	}
	if !strings.HasSuffix(env.ScratchDir, "/rel/scratch") || env.ScratchDir[0] != '/' || env.AbandonUploadAfter != time.Hour {
		t.Fatalf("%+v", env.Settings)
	}
	if _, ok := env.Sandbox.(DockerSandbox); !ok {
		t.Fatal("production sandbox")
	}
}
