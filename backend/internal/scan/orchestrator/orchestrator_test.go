package orchestrator

import (
	"archive/zip"
	"bytes"
	"context"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"os"
	"path/filepath"
	"slices"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/aupv9/warden/backend/internal/scan/sandbox"
	st "github.com/aupv9/warden/backend/internal/scan/scantest"
)

type fakeDeps struct {
	root     string
	zip      []byte
	results  map[string]sandbox.ToolStatus
	cancel   bool
	block    chan struct{} // RunTool waits on this when set; closed by KillTool
	killOnce sync.Once
	mu       sync.Mutex
	deleted  []string
	statuses []ScanStatus
	killed   []string
	sawKey   bool
}

func (d *fakeDeps) ScratchRoot() string { return d.root }
func (d *fakeDeps) Download(_ context.Context, _ string, dest string) error {
	return os.WriteFile(dest, d.zip, 0o600)
}
func (d *fakeDeps) DeleteObject(_ context.Context, key string) error {
	d.deleted = append(d.deleted, key)
	return nil
}
func (d *fakeDeps) SetStatus(_ context.Context, _ string, s ScanStatus) error {
	d.statuses = append(d.statuses, s)
	return nil
}
func (d *fakeDeps) SetToolStatus(context.Context, string, sandbox.ToolRun) error { return nil }
func (d *fakeDeps) IsCancelled(context.Context, string) (bool, error)            { return d.cancel, nil }
func (d *fakeDeps) HMACKey(context.Context, string) ([]byte, error)              { return st.HMACKey, nil }
func (d *fakeDeps) KillTool(_ string, tool string) {
	d.mu.Lock()
	d.killed = append(d.killed, tool)
	d.mu.Unlock()
	if d.block != nil {
		d.killOnce.Do(func() { close(d.block) })
	}
}

func (d *fakeDeps) RunTool(_ context.Context, tool, _, scanDir string) sandbox.ToolRun {
	if d.block != nil {
		<-d.block
		return sandbox.ToolRun{Tool: tool, Status: sandbox.Failed, Error: "killed"}
	}
	if fi, err := os.Stat(filepath.Join(scanDir, "src")); err != nil || !fi.IsDir() {
		panic("src not extracted")
	}
	if _, err := os.Stat(filepath.Join(scanDir, "secrets", "hmac")); err == nil {
		d.mu.Lock()
		d.sawKey = true
		d.mu.Unlock()
	}
	status := d.results[tool]
	if status != sandbox.Succeeded {
		return sandbox.ToolRun{Tool: tool, Status: status, DurationMS: 1, Error: "boom"}
	}
	out := filepath.Join(scanDir, "out", tool)
	_ = os.MkdirAll(out, 0o700)
	doc := st.Doc([]any{st.M{"ruleId": "r1", "message": st.M{"text": "m"}, "locations": []any{st.Loc("/src/app/a.py", 1)}}})
	if tool == "gitleaks" {
		doc = st.GitleaksDoc() // unredacted on purpose: the parser must refuse it
	}
	b, _ := json.Marshal(doc)
	_ = os.WriteFile(filepath.Join(out, "result.sarif"), b, 0o600)
	return sandbox.ToolRun{Tool: tool, Status: status, DurationMS: 1, Sarif: filepath.Join(out, "result.sarif")}
}

func zipBytes(t *testing.T) ([]byte, string) {
	t.Helper()
	var buf bytes.Buffer
	zw := zip.NewWriter(&buf)
	w, _ := zw.Create("app/a.py")
	_, _ = w.Write([]byte("x = 1\n"))
	_ = zw.Close()
	sum := sha256.Sum256(buf.Bytes())
	return buf.Bytes(), hex.EncodeToString(sum[:])
}

func newDeps(t *testing.T, zip []byte, results map[string]sandbox.ToolStatus) *fakeDeps {
	root := filepath.Join(t.TempDir(), "scratch")
	_ = os.Mkdir(root, 0o700)
	return &fakeDeps{root: root, zip: zip, results: results}
}

func newJob(sha string, tools ...string) Job {
	return Job{ScanID: "scan-" + strings.Join(tools, "-"), OrgID: "o", ProjectID: "p", ObjectKey: "uploads/x.zip", SHA256: sha, Tools: tools}
}

func assertCleaned(t *testing.T, d *fakeDeps, j Job) {
	t.Helper()
	if _, err := os.Stat(filepath.Join(d.root, j.ScanID)); err == nil {
		t.Fatal("source must be deleted")
	}
	if !slices.Equal(d.deleted, []string{"uploads/x.zip"}) {
		t.Fatalf("deleted %v", d.deleted)
	}
}

func TestExecuteStatusAndCleanup(t *testing.T) {
	data, sha := zipBytes(t)
	for _, c := range []struct {
		results map[string]sandbox.ToolStatus
		want    ScanStatus
	}{
		{map[string]sandbox.ToolStatus{"opengrep": sandbox.Succeeded, "checkov": sandbox.Succeeded}, Completed},
		{map[string]sandbox.ToolStatus{"opengrep": sandbox.Succeeded, "checkov": sandbox.Timeout}, Partial},
		{map[string]sandbox.ToolStatus{"opengrep": sandbox.Failed, "checkov": sandbox.Timeout}, Failed},
	} {
		d := newDeps(t, data, c.results)
		j := newJob(sha, "opengrep", "checkov")
		out, err := Execute(context.Background(), j, d)
		if err != nil {
			t.Fatal(err)
		}
		if out.Status != c.want {
			t.Fatalf("status %s, want %s", out.Status, c.want)
		}
		assertCleaned(t, d, j)
		if c.want != Failed && out.Findings["opengrep"][0].FilePath != "a.py" {
			t.Fatalf("%+v", out.Findings)
		}
		if c.want == Failed && out.ErrorCode != "ALL_SCANNERS_FAILED" {
			t.Fatal(out.ErrorCode)
		}
	}
}

func TestRejectedZipStillCleansUp(t *testing.T) {
	d := newDeps(t, []byte("not a zip"), map[string]sandbox.ToolStatus{"opengrep": sandbox.Succeeded})
	j := newJob(strings.Repeat("0", 64), "opengrep")
	out, err := Execute(context.Background(), j, d)
	if err != nil {
		t.Fatal(err)
	}
	if out.Status != Failed || out.ErrorCode != "CHECKSUM_MISMATCH" {
		t.Fatalf("%+v", out)
	}
	assertCleaned(t, d, j)
}

func TestZipBombIsRejectedAndCleaned(t *testing.T) {
	var buf bytes.Buffer
	zw := zip.NewWriter(&buf)
	w, _ := zw.Create("bomb.txt")
	_, _ = w.Write(make([]byte, 8<<20))
	_ = zw.Close()
	sum := sha256.Sum256(buf.Bytes())
	d := newDeps(t, buf.Bytes(), map[string]sandbox.ToolStatus{"opengrep": sandbox.Succeeded})
	j := newJob(hex.EncodeToString(sum[:]), "opengrep")
	out, err := Execute(context.Background(), j, d)
	if err != nil {
		t.Fatal(err)
	}
	if out.ErrorCode != "ZIP_BOMB" {
		t.Fatalf("%+v", out)
	}
	assertCleaned(t, d, j)
}

func TestUnredactedGitleaksOutputFailsTheTool(t *testing.T) {
	data, sha := zipBytes(t)
	d := newDeps(t, data, map[string]sandbox.ToolStatus{"gitleaks": sandbox.Succeeded, "opengrep": sandbox.Succeeded})
	out, err := Execute(context.Background(), newJob(sha, "gitleaks", "opengrep"), d)
	if err != nil {
		t.Fatal(err)
	}
	if out.Status != Partial || out.Findings["gitleaks"] != nil || out.Runs[0].Status != sandbox.Failed {
		t.Fatalf("%+v", out)
	}
	if !d.sawKey {
		t.Fatal("hmac key not provided to gitleaks")
	}
}

func TestCancelKillsToolsAndWritesNoFindings(t *testing.T) {
	data, sha := zipBytes(t)
	d := newDeps(t, data, map[string]sandbox.ToolStatus{"opengrep": sandbox.Succeeded})
	d.cancel = true
	d.block = make(chan struct{})
	old := CancelPoll
	CancelPoll = 10 * time.Millisecond
	t.Cleanup(func() { CancelPoll = old })
	j := newJob(sha, "opengrep")
	out, err := Execute(context.Background(), j, d)
	if err != nil {
		t.Fatal(err)
	}
	if out.Status != Cancelled || len(out.Findings) != 0 || !slices.Equal(d.killed, []string{"opengrep"}) {
		t.Fatalf("%+v killed=%v", out, d.killed)
	}
	assertCleaned(t, d, j)
}

func TestUnknownToolRefused(t *testing.T) {
	data, sha := zipBytes(t)
	d := newDeps(t, data, nil)
	if _, err := Execute(context.Background(), newJob(sha, "evil"), d); err == nil {
		t.Fatal("unknown tool accepted")
	}
	if !slices.Equal(d.deleted, []string{"uploads/x.zip"}) {
		t.Fatal("object not deleted on error")
	}
}

func TestFinalStatus(t *testing.T) {
	ok, bad := sandbox.ToolRun{Status: sandbox.Succeeded}, sandbox.ToolRun{Status: sandbox.Failed}
	if FinalStatus([]sandbox.ToolRun{ok, ok}) != Completed || FinalStatus([]sandbox.ToolRun{ok, bad}) != Partial ||
		FinalStatus([]sandbox.ToolRun{bad}) != Failed {
		t.Fatal("final status")
	}
}

func TestNewHMACKey(t *testing.T) {
	k, err := NewHMACKey()
	if err != nil || len(k) != 64 {
		t.Fatal(k, err)
	}
}
