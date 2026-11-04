package orchestrator

import (
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

	"github.com/aupv9/warden/backend/internal/scan/importer"
	"github.com/aupv9/warden/backend/internal/scan/redact"
	"github.com/aupv9/warden/backend/internal/scan/sandbox"
	"github.com/aupv9/warden/backend/internal/scan/sarif"
	st "github.com/aupv9/warden/backend/internal/scan/scantest"
)

// importDeps: the uploaded file, and a Gitleaks that flags every line of the
// screening file holding scantest.FakeSecret (redacted by the real
// warden-redact code). The scanner image can't run in unit tests.
type importDeps struct {
	root   string
	file   []byte
	limits Limits
	// gitleaks: the screening run's status (default Succeeded); doc replaces
	// its SARIF; noSarif reports success without one.
	gitleaks sandbox.ToolStatus
	doc      string
	noSarif  bool
	cancel   bool

	mu       sync.Mutex
	ran      []string
	tools    []sandbox.ToolRun
	deleted  []string
	killed   []string
	screened []byte                 // the screening file Gitleaks saw
	modes    map[string]os.FileMode // of what it saw, by path under the scan directory
}

func (d *importDeps) Limits() Limits      { return d.limits }
func (d *importDeps) ScratchRoot() string { return d.root }
func (d *importDeps) Download(_ context.Context, _, dest string) error {
	return os.WriteFile(dest, d.file, 0o600)
}
func (d *importDeps) DeleteObject(_ context.Context, key string) error {
	d.deleted = append(d.deleted, key)
	return nil
}
func (d *importDeps) SetStatus(context.Context, string, ScanStatus) error { return nil }
func (d *importDeps) SetToolStatus(_ context.Context, _ string, r sandbox.ToolRun) error {
	d.mu.Lock()
	defer d.mu.Unlock()
	d.tools = append(d.tools, r)
	return nil
}
func (d *importDeps) IsCancelled(context.Context, string) (bool, error) { return d.cancel, nil }
func (d *importDeps) HMACKey(context.Context, string) ([]byte, error)   { return st.HMACKey, nil }
func (d *importDeps) KillTool(_, tool string) {
	d.mu.Lock()
	d.killed = append(d.killed, tool)
	d.mu.Unlock()
}

func (d *importDeps) RunTool(_ context.Context, tool, _, scanDir string) sandbox.ToolRun {
	d.mu.Lock()
	defer d.mu.Unlock()
	d.ran = append(d.ran, tool)
	d.modes = map[string]os.FileMode{}
	_ = filepath.WalkDir(scanDir, func(p string, e os.DirEntry, err error) error {
		if err == nil {
			rel, _ := filepath.Rel(scanDir, p)
			if fi, err := e.Info(); err == nil {
				d.modes[rel] = fi.Mode().Perm()
			}
		}
		return nil
	})
	d.screened, _ = os.ReadFile(filepath.Join(scanDir, "src", importer.ScreenFile))
	if d.gitleaks != "" && d.gitleaks != sandbox.Succeeded {
		return sandbox.ToolRun{Tool: tool, Status: d.gitleaks, Error: "boom"}
	}
	out := filepath.Join(scanDir, "out", tool)
	_ = os.MkdirAll(out, 0o700)
	p := filepath.Join(out, "result.sarif")
	body := d.doc
	if body == "" {
		results := []any{}
		for i, line := range strings.Split(string(d.screened), "\n") {
			if strings.Contains(line, st.FakeSecret) {
				results = append(results, st.M{"ruleId": "aws-access-token", "message": st.M{"text": "detected"},
					"locations": []any{st.Loc("/src/"+importer.ScreenFile, i+1, st.FakeSecret)}})
			}
		}
		red, err := redact.Doc(st.RoundTrip(st.Doc(results)), st.HMACKey)
		if err != nil {
			panic(err)
		}
		b, _ := json.Marshal(red)
		body = string(b)
	}
	_ = os.WriteFile(p, []byte(body), 0o600)
	if d.noSarif {
		p = ""
	}
	return sandbox.ToolRun{Tool: tool, Status: sandbox.Succeeded, Sarif: p}
}

func importReport() []byte {
	res := func(rule, uri, msg string) st.M {
		return st.M{"ruleId": rule, "message": st.M{"text": msg},
			"locations": []any{st.M{"physicalLocation": st.M{"artifactLocation": st.M{"uri": uri, "uriBaseId": "%SRCROOT%"},
				"region": st.M{"startLine": 3}}}}}
	}
	b, _ := json.Marshal(st.M{"version": "2.1.0", "runs": []any{st.M{
		"tool": st.M{"driver": st.M{"name": "CodeQL", "semanticVersion": "2.20.1", "rules": []any{
			st.M{"id": "js/xss", "shortDescription": st.M{"text": "XSS"}, "properties": st.M{"security-severity": "7.8"}},
		}}},
		"results": []any{
			res("js/xss", "src/a.js", "the token "+st.FakeSecret+" flows here"),
			res("js/xss", "src/b.js", "clean"),
			res("js/xss", "../escape.js", "outside"),
			res("js/xss", "config/"+st.FakeSecret+".js", "in the path"),
		},
	}}})
	return b
}

func newImport(t *testing.T, file []byte) (*importDeps, Job) {
	root := filepath.Join(t.TempDir(), "scratch")
	if err := os.Mkdir(root, 0o700); err != nil {
		t.Fatal(err)
	}
	sum := sha256.Sum256(file)
	return &importDeps{root: root, file: file}, Job{ScanID: "scan-import", OrgID: "o", ProjectID: "p",
		ObjectKey: "imports/x.sarif", SHA256: hex.EncodeToString(sum[:]), Tools: []string{sarif.ToolExternal},
		Kind: KindImport, Target: "(import) codeql", Import: &Import{Tool: "codeql", Format: importer.FormatSARIF}}
}

func assertImportCleaned(t *testing.T, d *importDeps, j Job) {
	t.Helper()
	if _, err := os.Stat(filepath.Join(d.root, j.ScanID)); err == nil {
		t.Fatal("scan directory left behind")
	}
	if !slices.Equal(d.deleted, []string{j.ObjectKey}) {
		t.Fatalf("deleted %v", d.deleted)
	}
}

func TestImportScreensWithGitleaks(t *testing.T) {
	d, j := newImport(t, importReport())
	j.OrgRules = map[string]OrgRules{"gitleaks": {Config: []byte("[[rules]]\nid = \"org.k\"\n")}, "opengrep": {Config: []byte("rules: []")}}
	out, err := Execute(context.Background(), j, d)
	if err != nil {
		t.Fatal(err)
	}
	assertImportCleaned(t, d, j)
	if out.Status != Completed || len(out.Runs) != 1 || out.Runs[0].Tool != sarif.ToolExternal || out.Runs[0].Status != sandbox.Succeeded {
		t.Fatalf("%+v", out)
	}
	// Gitleaks ran once, over the screening file alone (read-only), with the
	// org's Gitleaks rules and the HMAC key; no scan_tool_run of its own.
	if !slices.Equal(d.ran, []string{"gitleaks"}) || d.modes["src/"+importer.ScreenFile] != 0o444 || d.modes["src"] != 0o555 ||
		d.modes["rules/gitleaks.toml"] != 0o444 || d.modes["secrets/hmac"] == 0 {
		t.Fatalf("ran %v, saw %v", d.ran, d.modes)
	}
	for p := range d.modes {
		if strings.HasPrefix(p, "src/") && p != "src/"+importer.ScreenFile || p == "rules/opengrep.yml" || p == "import.json" {
			t.Fatalf("the sandbox saw %s", p)
		}
	}
	for _, r := range d.tools {
		if r.Tool != sarif.ToolExternal {
			t.Fatalf("tool status of %s", r.Tool)
		}
	}
	if !strings.Contains(string(d.screened), "src/a.js\n") || !strings.Contains(string(d.screened), st.FakeSecret) {
		t.Fatalf("screened %q", d.screened)
	}
	fs := out.Findings[sarif.ToolExternal]
	if len(fs) != 2 || fs[0].FilePath != "src/a.js" || fs[0].Description != "" || fs[1].Description != "clean" ||
		fs[0].Title != "XSS" || fs[0].ImportTarget != j.Target || fs[0].Severity != "high" {
		t.Fatalf("%+v", fs)
	}
	// Results 4 read; the traversal and the secret path dropped; the message
	// and the path screened.
	if im := out.Import; im == nil || im.Results != 4 || im.Dropped != 2 || im.Screened != 2 || im.ToolVersion != "2.20.1" {
		t.Fatalf("%+v", out.Import)
	}
	b, _ := json.Marshal(out)
	if strings.Contains(string(b), st.FakeSecret) {
		t.Fatalf("secret in the outcome: %s", b)
	}
}

// Whatever keeps Gitleaks from screening, nothing comes back.
func TestImportScreeningFailsClosed(t *testing.T) {
	for name, set := range map[string]func(*importDeps){
		"failed":          func(d *importDeps) { d.gitleaks = sandbox.Failed },
		"timeout":         func(d *importDeps) { d.gitleaks = sandbox.Timeout },
		"no SARIF":        func(d *importDeps) { d.noSarif = true },
		"not JSON":        func(d *importDeps) { d.doc = "{" },
		"no results":      func(d *importDeps) { d.doc = `{"version":"2.1.0","runs":[{}]}` },
		"result w/o line": func(d *importDeps) { d.doc = `{"version":"2.1.0","runs":[{"results":[{"ruleId":"x"}]}]}` },
	} {
		t.Run(name, func(t *testing.T) {
			d, j := newImport(t, importReport())
			set(d)
			out, err := Execute(context.Background(), j, d)
			if err != nil {
				t.Fatal(err)
			}
			if out.Status != Failed || out.ErrorCode != importer.CodeScreenFailed || out.Findings != nil || out.Import != nil ||
				out.Runs[0].Tool != sarif.ToolExternal || out.Runs[0].Status != sandbox.Failed {
				t.Fatalf("%+v", out)
			}
			assertImportCleaned(t, d, j)
		})
	}
}

func TestImportRejected(t *testing.T) {
	for name, c := range map[string]struct {
		file   []byte
		format string
		limit  int64
		badSHA bool
		code   string
	}{
		"not JSON":          {[]byte("<xml/>"), importer.FormatSARIF, 0, false, importer.CodeInvalid},
		"wrong version":     {[]byte(`{"version":"2.0.0","runs":[]}`), importer.FormatSARIF, 0, false, importer.CodeInvalid},
		"SARIF as GitLab":   {importReport(), importer.FormatGitLab, 0, false, importer.CodeInvalid},
		"over the limit":    {importReport(), importer.FormatSARIF, 100, false, importer.CodeTooLarge},
		"checksum mismatch": {importReport(), importer.FormatSARIF, 0, true, "CHECKSUM_MISMATCH"},
		"depth bomb":        {[]byte(strings.Repeat("[", 100_000)), importer.FormatSARIF, 0, false, importer.CodeInvalid},
	} {
		t.Run(name, func(t *testing.T) {
			d, j := newImport(t, c.file)
			d.limits.ImportMaxBytes = c.limit
			j.Import.Format = c.format
			if c.badSHA {
				j.SHA256 = strings.Repeat("0", 64)
			}
			out, err := Execute(context.Background(), j, d)
			if err != nil {
				t.Fatal(err)
			}
			if out.Status != Failed || out.ErrorCode != c.code || len(d.ran) != 0 {
				t.Fatalf("%+v, ran %v", out, d.ran)
			}
			assertImportCleaned(t, d, j)
		})
	}
}

func TestImportNothingToScreen(t *testing.T) {
	d, j := newImport(t, []byte(`{"version":"2.1.0","runs":[{"tool":{"driver":{"name":"x"}},"results":[]}]}`))
	out, err := Execute(context.Background(), j, d)
	if err != nil {
		t.Fatal(err)
	}
	if out.Status != Completed || len(d.ran) != 0 || len(out.Findings[sarif.ToolExternal]) != 0 || out.Import.Results != 0 {
		t.Fatalf("%+v, ran %v", out, d.ran)
	}
}

func TestImportCancelled(t *testing.T) {
	d, j := newImport(t, importReport())
	d.cancel = true
	out, err := Execute(context.Background(), j, d)
	if err != nil {
		t.Fatal(err)
	}
	if out.Status != Cancelled || out.Findings != nil || !slices.Equal(d.killed, []string{"gitleaks"}) {
		t.Fatalf("%+v, killed %v", out, d.killed)
	}
	assertImportCleaned(t, d, j)
}

func TestImportNeedsItsSettings(t *testing.T) {
	d, j := newImport(t, importReport())
	j.Import = nil
	if _, err := Execute(context.Background(), j, d); err == nil {
		t.Fatal("import without settings")
	}
	d, j = newImport(t, importReport())
	j.Tools = []string{"gitleaks"}
	if _, err := Execute(context.Background(), j, d); err == nil || len(d.ran) != 0 {
		t.Fatal("import running a Warden scanner")
	}
}
