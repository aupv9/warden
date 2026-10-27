package worker

import (
	"archive/zip"
	"bytes"
	"context"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"io"
	"log/slog"
	"os"
	"path/filepath"
	"slices"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/google/uuid"
	"github.com/riverqueue/river"
	"github.com/riverqueue/river/rivertype"

	"github.com/aupv9/warden/backend/internal/scan/orchestrator"
	"github.com/aupv9/warden/backend/internal/scan/sandbox"
	st "github.com/aupv9/warden/backend/internal/scan/scantest"
	"github.com/aupv9/warden/backend/internal/scan/zipcheck"
	"github.com/aupv9/warden/backend/internal/storage"
	"github.com/aupv9/warden/backend/internal/worker/dbtest"
)

const objectKey = "scans/org/scan.zip"

var testImages = map[string]string{
	"opengrep": "warden/opengrep:v1@sha256:" + strings.Repeat("a", 64),
	"gitleaks": "ghcr.io/gitleaks/gitleaks:v8.30.1@sha256:" + strings.Repeat("b", 64),
}

type fakeStore struct {
	mu      sync.Mutex
	objects map[string][]byte
	deleted []string
	dlErr   error
	delErr  error
	putErr  error
	types   map[string]string // content type of each Put
}

func (s *fakeStore) Put(_ context.Context, key string, body []byte, sum, contentType string) error {
	if s.putErr != nil {
		return s.putErr
	}
	s.mu.Lock()
	defer s.mu.Unlock()
	if s.objects == nil {
		s.objects = map[string][]byte{}
	}
	if s.types == nil {
		s.types = map[string]string{}
	}
	h := sha256.Sum256(body)
	if hex.EncodeToString(h[:]) != sum {
		return errors.New("checksum mismatch")
	}
	s.objects[key], s.types[key] = body, contentType
	return nil
}

func (s *fakeStore) Download(_ context.Context, key, dest string) error {
	if s.dlErr != nil {
		return s.dlErr
	}
	s.mu.Lock()
	b, ok := s.objects[key]
	s.mu.Unlock()
	if !ok {
		return storage.ErrNotFound
	}
	return os.WriteFile(dest, b, 0o600)
}

func (s *fakeStore) Delete(_ context.Context, key string) error {
	s.mu.Lock()
	defer s.mu.Unlock()
	s.deleted = append(s.deleted, key)
	return s.delErr
}

type fakeSandbox struct {
	mu      sync.Mutex
	status  map[string]sandbox.ToolStatus // default Succeeded
	block   bool                          // Run waits for ctx or Kill
	killCh  chan struct{}
	killed  []string
	configs []sandbox.RunConfig
	specs   []sandbox.ToolSpec
	empty   bool // tools find nothing
	// files tools write besides their SARIF (file name -> content), reported as artifacts
	files map[string]string
}

func (f *fakeSandbox) Run(ctx context.Context, spec sandbox.ToolSpec, c sandbox.RunConfig) sandbox.ToolRun {
	f.mu.Lock()
	f.configs = append(f.configs, c)
	f.specs = append(f.specs, spec)
	f.mu.Unlock()
	if f.block {
		select {
		case <-ctx.Done():
			return sandbox.ToolRun{Tool: spec.Name, Status: sandbox.Timeout, Error: "timeout"}
		case <-f.killCh:
			return sandbox.ToolRun{Tool: spec.Name, Status: sandbox.Failed, Error: "cancelled"}
		}
	}
	if s, ok := f.status[spec.Name]; ok && s != sandbox.Succeeded {
		return sandbox.ToolRun{Tool: spec.Name, Status: s, Error: "exit 1: printing source line password=hunter2"}
	}
	out := filepath.Join(c.ScanDir, "out", spec.Name)
	_ = os.MkdirAll(out, 0o700)
	doc := st.Doc([]any{st.M{"ruleId": "r1", "message": st.M{"text": "m"}, "locations": []any{st.Loc("/src/app/a.py", 1)}}})
	if f.empty {
		doc = st.Doc([]any{})
	}
	b, _ := json.Marshal(doc)
	p := filepath.Join(out, "result.sarif")
	_ = os.WriteFile(p, b, 0o600)
	run := sandbox.ToolRun{Tool: spec.Name, Status: sandbox.Succeeded, DurationMS: 3, Sarif: p}
	for name, a := range spec.Artifacts {
		if body, ok := f.files[a.File]; ok {
			if run.Artifacts == nil {
				run.Artifacts = map[string]string{}
			}
			run.Artifacts[name] = filepath.Join(out, a.File)
			_ = os.WriteFile(run.Artifacts[name], []byte(body), 0o600)
		}
	}
	return run
}

func (f *fakeSandbox) Kill(_, tool string) {
	f.mu.Lock()
	defer f.mu.Unlock()
	f.killed = append(f.killed, tool)
	if f.killCh != nil {
		select {
		case <-f.killCh:
		default:
			close(f.killCh)
		}
	}
}

func zipBytes() ([]byte, string) {
	var buf bytes.Buffer
	zw := zip.NewWriter(&buf)
	w, _ := zw.Create("app/a.py")
	_, _ = w.Write([]byte("x = 1\n"))
	_ = zw.Close()
	sum := sha256.Sum256(buf.Bytes())
	return buf.Bytes(), hex.EncodeToString(sum[:])
}

type harness struct {
	t       *testing.T
	env     *Env
	db      *dbtest.DB
	store   *fakeStore
	sb      *fakeSandbox
	org     uuid.UUID
	scan    uuid.UUID
	project uuid.UUID
	sha     string
	orgs    []uuid.UUID // org of every transaction
	mu      sync.Mutex
}

func quietLog() *slog.Logger { return slog.New(slog.NewTextHandler(io.Discard, nil)) }

func row(vals ...any) [][]any { return [][]any{vals} }

// scanSteps answers every statement of a normal scan; overrides replace steps
// with the same prefix.
func (h *harness) scanSteps(status string, overrides ...dbtest.Step) []dbtest.Step {
	steps := []dbtest.Step{
		{Prefix: "SELECT status, project_id", Rows: row(status, h.project, objectKey, h.sha, []string{"opengrep"}, false, "WEB", "source", "")},
		{Prefix: "UPDATE scan SET status = 'running'", Affected: 1},
		{Prefix: "INSERT INTO scan_tool_run", Affected: 1},
		{Prefix: "SELECT status FROM scan WHERE id = $1", Rows: row("running")},
		{Prefix: "UPDATE scan SET source_deleted_at", Affected: 1},
		{Prefix: "SELECT status FROM scan WHERE id = $1 AND project_id", Rows: row("running")},
		{Prefix: "SELECT issue_seq FROM project", Rows: row(0)},
		{Prefix: "SELECT sla_days, license_policy FROM organization", Rows: row([]byte(`{"high":30}`), []byte(`{}`))},
		{Prefix: "SELECT id, fingerprint"},
		{Prefix: "SELECT assign_rules FROM project", Rows: row([]byte(`[]`))},
		{Prefix: "INSERT INTO outbox_event", Affected: 1},
		{Prefix: "UPDATE project SET issue_seq", Rows: row(1)},
		{Prefix: "INSERT INTO issue (", Affected: 1},
		{Prefix: "INSERT INTO issue_event", Affected: 1},
		{Prefix: "INSERT INTO occurrence", Affected: 1},
		{Prefix: "UPDATE scan_tool_run SET findings_count", Affected: 1},
		{Prefix: "UPDATE scan SET status = $2, error_code = NULL", Affected: 1},
		{Prefix: "UPDATE scan SET status = 'failed'", Affected: 1},
		{Prefix: "UPDATE scan SET finished_at", Affected: 1},
	}
	for _, o := range overrides {
		i := slices.IndexFunc(steps, func(s dbtest.Step) bool { return s.Prefix == o.Prefix })
		if i < 0 {
			steps = append(steps, o)
		} else {
			steps[i] = o
		}
	}
	return steps
}

func newHarness(t *testing.T, status string, overrides ...dbtest.Step) *harness {
	data, sha := zipBytes()
	h := &harness{t: t, org: uuid.New(), scan: uuid.New(), project: uuid.New(), sha: sha,
		store: &fakeStore{objects: map[string][]byte{objectKey: data}},
		sb:    &fakeSandbox{status: map[string]sandbox.ToolStatus{}}}
	h.db = dbtest.Loose(t, h.scanSteps(status, overrides...)...)
	scratch := filepath.Join(t.TempDir(), "scratch")
	if err := os.Mkdir(scratch, 0o700); err != nil {
		t.Fatal(err)
	}
	h.env = &Env{
		Tx: func(_ context.Context, org uuid.UUID, fn func(DB) error) error {
			h.mu.Lock()
			h.orgs = append(h.orgs, org)
			h.mu.Unlock()
			return fn(h.db)
		},
		Store: h.store, Sandbox: h.sb, Now: time.Now, Log: quietLog(),
		Settings: Settings{ScratchDir: scratch, MirrorDir: "/mirror", Runtime: "runsc", Images: testImages,
			HMACMaster: bytes.Repeat([]byte("m"), 32), GuardRatio: 0.5, ScanTimeout: time.Minute,
			SourceRetention: time.Hour, AbandonUploadAfter: time.Hour, StuckAfter: 24 * time.Hour,
			Limits: orchestrator.Limits{Zip: zipcheck.DefaultLimits()}, SBOMRetention: 24 * time.Hour},
	}
	return h
}

func (h *harness) job() orchestrator.Job {
	// Payload values are ignored in favour of the scan row.
	return orchestrator.Job{ScanID: h.scan.String(), OrgID: h.org.String(), ObjectKey: "ignored", SHA256: "ignored", Tools: []string{"trivy"}}
}

func (h *harness) run(attempt int) error {
	h.t.Helper()
	old := orchestrator.CancelPoll
	orchestrator.CancelPoll = 10 * time.Millisecond
	defer func() { orchestrator.CancelPoll = old }()
	return h.env.RunScan(context.Background(), h.job(), attempt)
}

func (h *harness) assertScoped() {
	h.t.Helper()
	for _, o := range h.orgs {
		if o != h.org {
			h.t.Fatalf("transaction outside the scan's org: %v", o)
		}
	}
}

func (h *harness) assertCleaned() {
	h.t.Helper()
	if !slices.Contains(h.store.deleted, objectKey) {
		h.t.Fatalf("object not deleted: %v", h.store.deleted)
	}
	if _, err := os.Stat(filepath.Join(h.env.ScratchDir, h.scan.String())); err == nil {
		h.t.Fatal("scratch directory left behind")
	}
}

func (h *harness) failedWith(code string) {
	h.t.Helper()
	calls := h.db.Calls("UPDATE scan SET status = 'failed'")
	if len(calls) != 1 || calls[0].Args[1] != code {
		h.t.Fatalf("want failed %s, got %v", code, calls)
	}
	if len(h.db.Calls("INSERT INTO issue")) != 0 {
		h.t.Fatal("issues written for a failed scan")
	}
	// The creator hears about it (scan.finished), in the same transaction.
	if ob := h.db.Calls("INSERT INTO outbox_event"); len(ob) != 1 || ob[0].Args[1] != "scan.finished" {
		h.t.Fatalf("outbox %v", ob)
	}
}

func TestRunScanHappyPath(t *testing.T) {
	h := newHarness(t, "queued")
	if err := h.run(1); err != nil {
		t.Fatal(err)
	}
	fin := h.db.Calls("UPDATE scan SET status = $2, error_code = NULL")
	if len(fin) != 1 || fin[0].Args[1] != "completed" {
		t.Fatalf("final %v", fin)
	}
	if len(h.db.Calls("INSERT INTO issue (")) != 1 {
		t.Fatal("issue not created")
	}
	if len(h.db.Calls("UPDATE scan SET source_deleted_at")) != 1 {
		t.Fatal("source_deleted_at not recorded")
	}
	// Tool run rows carry the image version and digest; DB values beat the job payload.
	for _, c := range h.db.Calls("INSERT INTO scan_tool_run") {
		if c.Args[3] != "opengrep" || c.Args[4] != "v1" || c.Args[5] != "sha256:"+strings.Repeat("a", 64) {
			t.Fatalf("tool run args %v", c.Args)
		}
	}
	if len(h.sb.configs) != 1 || h.sb.configs[0].Image != testImages["opengrep"] || h.sb.configs[0].Runtime != "runsc" {
		t.Fatalf("%+v", h.sb.configs)
	}
	if len(h.sb.killed) != 0 {
		t.Fatal("first attempt must not kill containers")
	}
	h.assertCleaned()
	h.assertScoped()
}

func TestRunScanRetryCleansUpPreviousAttempt(t *testing.T) {
	h := newHarness(t, "running")
	leftover := filepath.Join(h.env.ScratchDir, h.scan.String(), "src")
	if err := os.MkdirAll(filepath.Join(leftover, "pkg"), 0o700); err != nil || os.Chmod(leftover, 0o500) != nil {
		t.Fatal(err)
	}
	if err := h.run(2); err != nil {
		t.Fatal(err)
	}
	if !slices.Equal(h.sb.killed, []string{"opengrep"}) {
		t.Fatalf("leftover container not removed: %v", h.sb.killed)
	}
	if len(h.db.Calls("UPDATE scan SET status = $2, error_code = NULL")) != 1 {
		t.Fatal("not finished")
	}
	h.assertCleaned()
}

func TestRunScanSkipsFinishedScans(t *testing.T) {
	for _, s := range []string{"completed", "partial", "failed"} {
		h := newHarness(t, s)
		if err := h.run(2); err != nil {
			t.Fatal(err)
		}
		if n := len(h.db.Calls("")); n != 1 {
			t.Fatalf("%s: %d statements, want only the load", s, n)
		}
	}
}

func TestRunScanCancelledBeforeStart(t *testing.T) {
	h := newHarness(t, "cancelled")
	if err := h.run(1); err != nil {
		t.Fatal(err)
	}
	if len(h.sb.configs) != 0 || len(h.db.Calls("INSERT INTO issue")) != 0 {
		t.Fatal("cancelled scan ran")
	}
	c := h.db.Calls("UPDATE scan SET finished_at")
	if len(c) != 1 || c[0].Args[1] != true {
		t.Fatalf("%v", c)
	}
	if !slices.Equal(h.store.deleted, []string{objectKey}) {
		t.Fatal("upload of a cancelled scan not deleted")
	}
	// Tools that never ran are recorded as skipped.
	if len(h.db.Calls("INSERT INTO scan_tool_run (id, org_id, scan_id, tool, tool_version, image_digest, status) VALUES ($1, $2, $3, $4, $5, $6, 'skipped')")) != 1 {
		t.Fatal("tools not skipped")
	}
}

func TestRunScanCancelledBeforeStartDeleteFails(t *testing.T) {
	h := newHarness(t, "cancelled")
	h.store.delErr = errors.New("s3 down")
	if err := h.run(1); err != nil {
		t.Fatal(err)
	}
	if c := h.db.Calls("UPDATE scan SET finished_at"); c[0].Args[1] != false {
		t.Fatal("source_deleted_at set although the delete failed")
	}
}

// The API cancelled between load and start: the guarded UPDATE matches nothing.
func TestRunScanCancelRaceAtStart(t *testing.T) {
	h := newHarness(t, "queued", dbtest.Step{Prefix: "UPDATE scan SET status = 'running'", Affected: 0})
	if err := h.run(1); err != nil {
		t.Fatal(err)
	}
	if len(h.sb.configs) != 0 || len(h.db.Calls("UPDATE scan SET finished_at")) != 1 {
		t.Fatal("not handled as cancelled")
	}
	h.assertCleaned()
}

// Cancelled while scanners run: containers are killed, no issue changes.
func TestRunScanCancelledWhileRunning(t *testing.T) {
	var cancelled sync.Once
	var flag bool
	var mu sync.Mutex
	h := newHarness(t, "queued", dbtest.Step{Prefix: "SELECT status FROM scan WHERE id = $1", Do: func([]any) dbtest.Step {
		mu.Lock()
		defer mu.Unlock()
		st := "running"
		if flag {
			st = "cancelled"
		}
		cancelled.Do(func() { flag = true })
		return dbtest.Step{Rows: row(st)}
	}})
	h.sb.block, h.sb.killCh = true, make(chan struct{})
	if err := h.run(1); err != nil {
		t.Fatal(err)
	}
	if !slices.Contains(h.sb.killed, "opengrep") {
		t.Fatal("container not killed")
	}
	if len(h.db.Calls("SELECT issue_seq")) != 0 || len(h.db.Calls("UPDATE scan SET finished_at")) != 1 {
		t.Fatal("cancelled scan processed results")
	}
	h.assertCleaned()
}

// Cancelled after the scanners finished: the processor refuses, nothing changes.
func TestRunScanCancelledBeforeProcessing(t *testing.T) {
	h := newHarness(t, "queued", dbtest.Step{Prefix: "SELECT status FROM scan WHERE id = $1 AND project_id", Rows: row("cancelled")})
	if err := h.run(1); err != nil {
		t.Fatal(err)
	}
	if len(h.db.Calls("INSERT INTO issue")) != 0 || len(h.db.Calls("UPDATE scan SET finished_at")) != 1 {
		t.Fatal("not handled as cancelled")
	}
}

func TestRunScanFailures(t *testing.T) {
	t.Run("source already deleted", func(t *testing.T) {
		h := newHarness(t, "running", dbtest.Step{Prefix: "SELECT status, project_id", Rows: row("running", uuid.New(), objectKey, "x", []string{"opengrep"}, true, "WEB", "source", "")})
		if err := h.run(2); err != nil {
			t.Fatal(err)
		}
		h.failedWith(CodeSourceUnavailable)
	})
	t.Run("object missing", func(t *testing.T) {
		h := newHarness(t, "queued")
		delete(h.store.objects, objectKey)
		if err := h.run(1); err != nil {
			t.Fatal(err)
		}
		h.failedWith(CodeSourceNotFound)
		h.assertCleaned()
	})
	t.Run("object too large", func(t *testing.T) {
		h := newHarness(t, "queued")
		h.store.dlErr = storage.ErrTooLarge
		if err := h.run(1); err != nil {
			t.Fatal(err)
		}
		h.failedWith(CodeTooLarge)
	})
	t.Run("checksum mismatch", func(t *testing.T) {
		h := newHarness(t, "queued")
		h.sha = strings.Repeat("0", 64)
		h.db = dbtest.Loose(t, h.scanSteps("queued")...)
		if err := h.run(1); err != nil {
			t.Fatal(err)
		}
		h.failedWith("CHECKSUM_MISMATCH")
		if len(h.sb.configs) != 0 {
			t.Fatal("scanners ran on an unverified archive")
		}
		h.assertCleaned()
	})
	t.Run("all scanners failed, stderr not stored", func(t *testing.T) {
		h := newHarness(t, "queued")
		h.sb.status["opengrep"] = sandbox.Failed
		if err := h.run(1); err != nil {
			t.Fatal(err)
		}
		h.failedWith("ALL_SCANNERS_FAILED")
		for _, c := range h.db.Calls("INSERT INTO scan_tool_run") {
			if len(c.Args) < 9 {
				continue
			}
			if e, ok := c.Args[8].(*string); ok && e != nil && strings.Contains(*e, "hunter2") {
				t.Fatal("scanner stderr stored")
			}
		}
	})
	t.Run("timeout", func(t *testing.T) {
		h := newHarness(t, "queued")
		h.env.ScanTimeout = 50 * time.Millisecond
		h.sb.block, h.sb.killCh = true, make(chan struct{})
		if err := h.run(1); err != nil {
			t.Fatal(err)
		}
		h.failedWith(CodeTimeout)
		h.assertCleaned()
	})
	t.Run("processing error", func(t *testing.T) {
		h := newHarness(t, "queued", dbtest.Step{Prefix: "INSERT INTO issue (", Err: errors.New("disk full")})
		if err := h.run(1); err != nil {
			t.Fatal(err)
		}
		if c := h.db.Calls("UPDATE scan SET status = 'failed'"); len(c) != 1 || c[0].Args[1] != CodeInternal {
			t.Fatalf("%v", c)
		}
	})
	t.Run("internal error", func(t *testing.T) {
		h := newHarness(t, "queued")
		h.store.dlErr = errors.New("connection reset")
		if err := h.run(1); err != nil {
			t.Fatal(err)
		}
		h.failedWith(CodeInternal)
	})
}

const trivyReport = `{"Results":[{"Target":"app/package-lock.json","Class":"lang-pkgs","Packages":[
  {"Name":"gpl-thing","Version":"1.0.0","Licenses":["GPL-3.0-only"]}]},
  {"Class":"license","Licenses":[{"Category":"restricted","Name":"GPL-3.0-only"}]}]}`

// trivyHarness runs a trivy scan whose tool writes a JSON report and an SBOM,
// in an org whose license policy reviews restricted licenses.
func trivyHarness(t *testing.T, overrides ...dbtest.Step) *harness {
	h := newHarness(t, "queued")
	h.db = dbtest.Loose(t, h.scanSteps("queued", append([]dbtest.Step{
		{Prefix: "SELECT status, project_id", Rows: row("queued", h.project, objectKey, h.sha, []string{"trivy"}, false, "WEB", "source", "")},
		{Prefix: "SELECT sla_days, license_policy FROM organization", Rows: row([]byte(`{}`), []byte(`{"categories":{"restricted":"review"}}`))},
		{Prefix: "UPDATE project SET issue_seq", Rows: row(2)},
		{Prefix: "UPDATE scan SET sbom_key", Affected: 1},
	}, overrides...)...)...)
	h.env.Images = map[string]string{"trivy": "docker.io/aquasec/trivy:0.75.0@sha256:" + strings.Repeat("c", 64)}
	h.sb.files = map[string]string{"trivy.json": trivyReport, "sbom.cdx.json": `{"bomFormat":"CycloneDX","components":[{"name":"x"},{"name":"y"}]}`}
	return h
}

func TestRunScanStoresSBOMAndLicenseIssues(t *testing.T) {
	h := trivyHarness(t)
	if err := h.run(1); err != nil {
		t.Fatal(err)
	}
	key := "sboms/" + h.org.String() + "/" + h.scan.String() + ".cdx.json"
	if h.store.types[key] != "application/vnd.cyclonedx+json" || !strings.Contains(string(h.store.objects[key]), `"name":"WEB"`) {
		t.Fatalf("%v", h.store.types)
	}
	c := h.db.Calls("UPDATE scan SET sbom_key")
	if len(c) != 1 || c[0].Args[1] != key || c[0].Args[2] != int64(len(h.store.objects[key])) || c[0].Args[4] != 2 {
		t.Fatalf("%v", c)
	}
	if exp := c[0].Args[5].(time.Time); exp.Before(time.Now().Add(23*time.Hour)) || exp.After(time.Now().Add(25*time.Hour)) {
		t.Fatalf("expires %v", exp)
	}
	var rules []any
	for _, c := range h.db.Calls("INSERT INTO issue (") {
		rules = append(rules, c.Args[6])
	}
	if !slices.Contains(rules, any("license:GPL-3.0-only")) || !slices.Contains(rules, any("r1")) {
		t.Fatalf("issues %v", rules)
	}
	if slices.Contains(h.store.deleted, key) {
		t.Fatal("SBOM deleted")
	}
}

// Storing the SBOM is best effort: the scan completes without one.
func TestRunScanWithoutSBOMWhenStoreFails(t *testing.T) {
	h := trivyHarness(t)
	h.store.putErr = errors.New("bucket full")
	if err := h.run(1); err != nil {
		t.Fatal(err)
	}
	if len(h.db.Calls("UPDATE scan SET sbom_key")) != 0 {
		t.Fatal("columns set without an object")
	}
	if fin := h.db.Calls("UPDATE scan SET status = $2, error_code = NULL"); len(fin) != 1 || fin[0].Args[1] != "completed" {
		t.Fatalf("%v", fin)
	}
}

// Results that aren't recorded take their SBOM with them.
func TestRunScanDeletesSBOMOfUnrecordedResults(t *testing.T) {
	h := trivyHarness(t, dbtest.Step{Prefix: "INSERT INTO issue (", Err: errors.New("disk full")})
	if err := h.run(1); err != nil {
		t.Fatal(err)
	}
	key := "sboms/" + h.org.String() + "/" + h.scan.String() + ".cdx.json"
	if !slices.Contains(h.store.deleted, key) {
		t.Fatalf("deleted %v", h.store.deleted)
	}
	if c := h.db.Calls("UPDATE scan SET status = 'failed'"); len(c) != 1 || c[0].Args[1] != CodeInternal {
		t.Fatalf("%v", c)
	}
}

func TestRunScanJobErrors(t *testing.T) {
	var cancel *river.JobCancelError
	h := newHarness(t, "queued")
	if err := h.env.RunScan(context.Background(), orchestrator.Job{ScanID: "x", OrgID: h.org.String()}, 1); !errors.As(err, &cancel) {
		t.Fatalf("bad id: %v", err)
	}
	h = newHarness(t, "queued", dbtest.Step{Prefix: "SELECT status, project_id"})
	if err := h.run(1); !errors.As(err, &cancel) {
		t.Fatalf("missing scan: %v", err)
	}
	h = newHarness(t, "pending_upload")
	if err := h.run(1); !errors.As(err, &cancel) {
		t.Fatalf("pending upload: %v", err)
	}
	h = newHarness(t, "queued", dbtest.Step{Prefix: "SELECT status, project_id", Err: errors.New("db down")})
	if err := h.run(1); err == nil || errors.As(err, &cancel) {
		t.Fatalf("db error must be retried: %v", err)
	}
}

func TestScanWorkerDelegates(t *testing.T) {
	h := newHarness(t, "completed")
	w := &ScanWorker{Env: h.env, MaxRuntime: time.Hour}
	if err := w.Work(context.Background(), &river.Job[ScanArgs]{JobRow: &rivertype.JobRow{Attempt: 1}, Args: ScanArgs{Job: h.job()}}); err != nil {
		t.Fatal(err)
	}
	if w.Timeout(nil) != time.Hour {
		t.Fatal("timeout")
	}
}
