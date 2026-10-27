package orchestrator

import (
	"archive/tar"
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
	"github.com/aupv9/warden/backend/internal/scan/zipcheck"
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
	sawImage bool // src/image.tar, read-only, when a tool ran
	limits   *Limits
	// artifacts trivy writes besides its SARIF (file name -> content)
	trivyOut map[string]string
}

func (d *fakeDeps) Limits() Limits {
	if d.limits != nil {
		return *d.limits
	}
	return Limits{Zip: zipcheck.DefaultLimits(), ImageMaxBytes: 64 << 20}
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
	if st, err := os.Stat(filepath.Join(scanDir, "src", "image.tar")); err == nil && st.Mode().Perm() == 0o444 {
		d.mu.Lock()
		d.sawImage = true
		d.mu.Unlock()
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
	run := sandbox.ToolRun{Tool: tool, Status: status, DurationMS: 1, Sarif: filepath.Join(out, "result.sarif")}
	if tool == "trivy" {
		run.Artifacts = map[string]string{}
		for name, a := range sandbox.Tools["trivy"].Artifacts {
			if body, ok := d.trivyOut[a.File]; ok {
				run.Artifacts[name] = filepath.Join(out, a.File)
				_ = os.WriteFile(run.Artifacts[name], []byte(body), 0o600)
			}
		}
	}
	return run
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

// The configured archive limits apply, not zipcheck's defaults.
func TestConfiguredZipLimits(t *testing.T) {
	data, sha := zipBytes(t)
	for _, c := range []struct {
		limits zipcheck.Limits
		code   string
	}{
		{zipcheck.Limits{MaxZipBytes: int64(len(data)) - 1, MaxTotalBytes: 1 << 20, MaxEntries: 10}, "ZIP_TOO_LARGE"},
		{zipcheck.Limits{MaxZipBytes: 1 << 20, MaxTotalBytes: 3, MaxEntries: 10}, "ZIP_BOMB"},
		{zipcheck.Limits{MaxZipBytes: 1 << 20, MaxTotalBytes: 1 << 20, MaxEntries: 0}, "ZIP_TOO_MANY_FILES"},
		{zipcheck.Limits{MaxZipBytes: int64(len(data)), MaxTotalBytes: 6, MaxEntries: 1}, ""},
	} {
		d := newDeps(t, data, map[string]sandbox.ToolStatus{"opengrep": sandbox.Succeeded})
		d.limits = &Limits{Zip: c.limits}
		out, err := Execute(context.Background(), newJob(sha, "opengrep"), d)
		if err != nil || out.ErrorCode != c.code {
			t.Fatalf("%+v: %+v %v", c.limits, out, err)
		}
	}
}

const trivyReport = `{"Results":[{"Target":"app/package-lock.json","Class":"lang-pkgs","Packages":[
  {"Name":"gpl-thing","Version":"1.0.0","Licenses":["GPL-3.0-only"]}]},
  {"Target":"app/package-lock.json","Class":"license","Licenses":[{"Category":"restricted","Name":"GPL-3.0-only"}]}]}`

// Trivy's JSON report gives the licenses (with the same paths as its
// vulnerabilities) and its SBOM is stamped for the project.
func TestTrivyArtifacts(t *testing.T) {
	data, sha := zipBytes(t)
	d := newDeps(t, data, map[string]sandbox.ToolStatus{"trivy": sandbox.Succeeded})
	d.trivyOut = map[string]string{"trivy.json": trivyReport, "sbom.cdx.json": `{"bomFormat":"CycloneDX","components":[{"name":"a"}]}`}
	j := newJob(sha, "trivy")
	j.ProjectKey = "WEB"
	out, err := Execute(context.Background(), j, d)
	if err != nil || out.Status != Completed {
		t.Fatal(out, err)
	}
	if len(out.Licenses) != 1 || out.Licenses[0].FilePath != "package-lock.json" || out.Licenses[0].License != "GPL-3.0-only" {
		t.Fatalf("%+v", out.Licenses)
	}
	if out.SBOM == nil || out.SBOM.Components != 1 || !strings.Contains(string(out.SBOM.Data), `"name":"WEB"`) ||
		!strings.Contains(string(out.SBOM.Data), j.ScanID) {
		t.Fatalf("%+v", out.SBOM)
	}
	assertCleaned(t, d, j)

	// A bad SBOM costs only the SBOM.
	d = newDeps(t, data, map[string]sandbox.ToolStatus{"trivy": sandbox.Succeeded})
	d.trivyOut = map[string]string{"trivy.json": trivyReport, "sbom.cdx.json": `{"bomFormat":"SPDX"}`}
	if out, err := Execute(context.Background(), newJob(sha, "trivy"), d); err != nil || out.Status != Completed || out.SBOM != nil || len(out.Licenses) != 1 {
		t.Fatal(out, err)
	}
	// Without a valid JSON report Trivy's results are incomplete: the tool fails.
	for _, files := range []map[string]string{{}, {"trivy.json": `{"Results":"x"}`}} {
		d = newDeps(t, data, map[string]sandbox.ToolStatus{"trivy": sandbox.Succeeded})
		d.trivyOut = files
		out, err := Execute(context.Background(), newJob(sha, "trivy"), d)
		if err != nil || out.Status != Failed || out.Runs[0].Status != sandbox.Failed || out.Licenses != nil || out.SBOM != nil {
			t.Fatal(out, err)
		}
	}
}

// imageTar is a minimal docker save tarball.
func imageTar(t *testing.T, manifest string) ([]byte, string) {
	t.Helper()
	var buf bytes.Buffer
	tw := tar.NewWriter(&buf)
	for name, body := range map[string]string{"manifest.json": manifest, "c.json": "{}", "l/layer.tar": "layer"} {
		_ = tw.WriteHeader(&tar.Header{Name: name, Typeflag: tar.TypeReg, Mode: 0o644, Size: int64(len(body))})
		_, _ = tw.Write([]byte(body))
	}
	_ = tw.Close()
	sum := sha256.Sum256(buf.Bytes())
	return buf.Bytes(), hex.EncodeToString(sum[:])
}

const imageReport = `{"Metadata":{"OS":{"Family":"alpine"}},"Results":[
  {"Target":"/src/image.tar (alpine 3.18.0)","Class":"os-pkgs","Packages":[{"Name":"busybox","Version":"1.36.0-r9","Licenses":["GPL-2.0-only"]}]},
  {"Target":"usr/local/bin/app","Class":"lang-pkgs","Packages":[{"Name":"golang.org/x/net","Version":"v0.1.0","Licenses":["BSD-3-Clause"]}]}]}`

func imageJob(sha string, tools ...string) Job {
	j := newJob(sha, tools...)
	j.ObjectKey, j.Kind, j.Target = "uploads/x.zip", KindImage, "ghcr.io/acme/api"
	return j
}

// Image scans: the verified tarball is mounted read-only (never extracted),
// only Trivy runs, paths carry the target, and the upload and scratch copy
// are removed like a zip's.
func TestImageScan(t *testing.T) {
	data, sha := imageTar(t, `[{"Config":"c.json","Layers":["l/layer.tar"]}]`)
	d := newDeps(t, data, map[string]sandbox.ToolStatus{"trivy": sandbox.Succeeded})
	d.trivyOut = map[string]string{"trivy.json": imageReport}
	j := imageJob(sha, "trivy")
	out, err := Execute(context.Background(), j, d)
	if err != nil || out.Status != Completed || !d.sawImage {
		t.Fatal(out, err, d.sawImage)
	}
	if len(out.Licenses) != 2 || out.Licenses[0].FilePath != "ghcr.io/acme/api::alpine" || out.Licenses[1].FilePath != "ghcr.io/acme/api::usr/local/bin/app" {
		t.Fatalf("%+v", out.Licenses)
	}
	// The fake SARIF finding is at /src/app/a.py: prefixed with the target.
	if fs := out.Findings["trivy"]; len(fs) != 1 || fs[0].FilePath != "ghcr.io/acme/api::src/app/a.py" {
		t.Fatalf("%+v", fs)
	}
	assertCleaned(t, d, j)

	// Other tools are refused for images (the API never queues them).
	d = newDeps(t, data, nil)
	if _, err := Execute(context.Background(), imageJob(sha, "trivy", "gitleaks"), d); err == nil {
		t.Fatal("gitleaks ran on an image")
	}
	if !slices.Equal(d.deleted, []string{"uploads/x.zip"}) {
		t.Fatal("upload not deleted")
	}
}

func TestImageRejections(t *testing.T) {
	two := `[{"Config":"c.json","Layers":["l/layer.tar"]},{"Config":"c.json","Layers":["l/layer.tar"]}]`
	for _, c := range []struct {
		manifest string
		sha      bool // correct checksum
		limit    int64
		code     string
	}{
		{`[{"Config":"c.json","Layers":["missing.tar"]}]`, true, 0, "IMAGE_INVALID"},
		{two, true, 0, "IMAGE_MULTIPLE"},
		{`[{"Config":"c.json","Layers":["l/layer.tar"]}]`, true, 100, "IMAGE_TOO_LARGE"},
		{`[{"Config":"c.json","Layers":["l/layer.tar"]}]`, false, 0, "CHECKSUM_MISMATCH"},
	} {
		data, sha := imageTar(t, c.manifest)
		if !c.sha {
			sha = strings.Repeat("0", 64)
		}
		d := newDeps(t, data, map[string]sandbox.ToolStatus{"trivy": sandbox.Succeeded})
		if c.limit != 0 {
			d.limits = &Limits{Zip: zipcheck.DefaultLimits(), ImageMaxBytes: c.limit}
		}
		j := imageJob(sha, "trivy")
		out, err := Execute(context.Background(), j, d)
		if err != nil || out.Status != Failed || out.ErrorCode != c.code {
			t.Fatalf("%s: %+v %v", c.code, out, err)
		}
		assertCleaned(t, d, j)
	}
}
