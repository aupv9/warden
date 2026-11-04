package orchestrator

import (
	"context"
	"errors"
	"fmt"
	"io"
	"log/slog"
	"os"
	"path/filepath"
	"slices"
	"time"

	"github.com/aupv9/warden/backend/internal/scan/importer"
	"github.com/aupv9/warden/backend/internal/scan/sandbox"
	"github.com/aupv9/warden/backend/internal/scan/sarif"
	"github.com/aupv9/warden/backend/internal/scan/zipcheck"
)

// KindImport: another tool's results (a SARIF file or a GitLab SAST report),
// imported as findings of tool sarif.ToolExternal.
const KindImport = "import"

// Import is an import scan's settings (scan.import_tool, import_category,
// import_format), set by the worker from the scan row.
type Import struct {
	Tool, Category, Format string
}

// ImportStats is what an import scan records (scan.import_tool_version,
// import_results, import_dropped, import_screened).
type ImportStats struct {
	ToolVersion                string
	Results, Dropped, Screened int
}

// DefaultImportMaxBytes is scan.import_max_mb's default.
const DefaultImportMaxBytes = 50 << 20

// screenTool screens an import's strings: the source scans' Gitleaks, so the
// org's Gitleaks rules run too (Job.OrgRules["gitleaks"]).
const screenTool = "gitleaks"

// executeImport runs an import scan: download the file and verify its
// checksum and size, parse it (importer: nothing is unpacked or run),
// screen every string it keeps with Gitleaks in the sandbox, and return
// the findings as tool external's. Without a successful screening nothing
// is returned: the scan fails IMPORT_SCREEN_FAILED.
func executeImport(ctx context.Context, job Job, deps Deps, scanDir string) (*Outcome, error) {
	if job.Import == nil || !slices.Equal(job.Tools, []string{sarif.ToolExternal}) {
		return nil, errors.New("import scan without its settings, or with tools other than external")
	}
	if err := deps.SetStatus(ctx, job.ScanID, Running); err != nil {
		return nil, err
	}
	if err := os.Mkdir(scanDir, 0o700); err != nil {
		return nil, err
	}
	started := time.Now()
	toolRun := func(st sandbox.ToolStatus, msg string) sandbox.ToolRun {
		return sandbox.ToolRun{Tool: sarif.ToolExternal, Status: st, DurationMS: time.Since(started).Milliseconds(), Error: msg}
	}
	setTool := func(r sandbox.ToolRun) {
		if err := deps.SetToolStatus(ctx, job.ScanID, r); err != nil {
			slog.Warn("set tool status", "scan_id", job.ScanID, "tool", r.Tool, "err", err)
		}
	}
	fail := func(code string) (*Outcome, error) {
		r := toolRun(sandbox.Failed, code)
		setTool(r)
		return &Outcome{Status: Failed, ErrorCode: code, Runs: []sandbox.ToolRun{r}}, nil
	}
	setTool(toolRun(sandbox.Running, ""))

	rep, err := loadImport(ctx, job, deps, scanDir)
	if code, ok := rejection(job, err); ok {
		return fail(code)
	}
	if err != nil {
		return nil, err
	}

	screen := rep.Screen()
	if !screen.Empty() {
		matches, cancelled, err := runScreen(ctx, job, deps, scanDir, screen)
		switch {
		case cancelled:
			return &Outcome{Status: Cancelled}, nil
		case err != nil:
			// Never the strings or Gitleaks' stderr: they may hold the secret.
			slog.Warn("import screening failed; nothing is stored", "scan_id", job.ScanID, "err", err)
			return fail(importer.CodeScreenFailed)
		}
		rep.Apply(screen, matches)
	}
	run := toolRun(sandbox.Succeeded, "")
	setTool(run)
	return &Outcome{
		Status: Completed, Runs: []sandbox.ToolRun{run},
		Findings: map[string][]sarif.Finding{sarif.ToolExternal: rep.Findings(job.Target)},
		Import:   &ImportStats{ToolVersion: rep.ToolVersion, Results: rep.Read, Dropped: rep.Dropped, Screened: rep.Screened},
	}, nil
}

// loadImport downloads the file, checks its checksum and size, and parses
// it. Its rejections are *zipcheck.Rejected (CHECKSUM_MISMATCH) and
// *importer.Rejected.
func loadImport(ctx context.Context, job Job, deps Deps, scanDir string) (*importer.Report, error) {
	maxBytes := deps.Limits().ImportMaxBytes
	if maxBytes <= 0 {
		maxBytes = DefaultImportMaxBytes
	}
	path := filepath.Join(scanDir, "import.json")
	if err := deps.Download(ctx, job.ObjectKey, path); err != nil {
		return nil, err
	}
	if err := zipcheck.VerifyChecksum(path, job.SHA256); err != nil {
		return nil, err
	}
	f, err := os.Open(path)
	if err != nil {
		return nil, err
	}
	defer f.Close()
	raw, err := io.ReadAll(io.LimitReader(f, maxBytes+1))
	if err != nil {
		return nil, err
	}
	if int64(len(raw)) > maxBytes {
		return nil, &importer.Rejected{Code: importer.CodeTooLarge, Detail: fmt.Sprintf("larger than %d bytes", maxBytes)}
	}
	if err := os.Remove(path); err != nil {
		return nil, err
	}
	return importer.Parse(raw, job.Import.Format)
}

// runScreen writes the screening file to src/ (read-only, the only file
// there) and runs Gitleaks over it, with the org's Gitleaks rules and its
// HMAC key as in a source scan, polling for cancellation. The run is
// recorded on no scan_tool_run: the import's tool is external.
func runScreen(ctx context.Context, job Job, deps Deps, scanDir string, s *importer.Screen) ([]importer.Lines, bool, error) {
	srcDir := filepath.Join(scanDir, "src")
	if err := os.Mkdir(srcDir, 0o755); err != nil {
		return nil, false, err
	}
	if err := WriteReadOnly(filepath.Join(srcDir, importer.ScreenFile), s.Bytes()); err != nil {
		return nil, false, err
	}
	// The sandbox user (65532) reads it; nobody writes it. RemoveAll undoes this.
	if err := os.Chmod(srcDir, 0o555); err != nil {
		return nil, false, err
	}
	screenJob := job
	screenJob.Tools = []string{screenTool}
	if err := writeOrgRules(filepath.Join(scanDir, sandbox.RulesDir), screenJob); err != nil {
		return nil, false, err
	}
	key, err := deps.HMACKey(ctx, job.OrgID)
	if err != nil {
		return nil, false, err
	}
	if err := writeKey(filepath.Join(scanDir, "secrets", "hmac"), key); err != nil {
		return nil, false, err
	}

	done := make(chan sandbox.ToolRun, 1)
	go func() { done <- deps.RunTool(ctx, screenTool, job.ScanID, scanDir) }()
	tick := time.NewTicker(CancelPoll)
	defer tick.Stop()
	var run sandbox.ToolRun
	cancelled := false
	for waiting := true; waiting; {
		if !cancelled {
			c, err := deps.IsCancelled(ctx, job.ScanID)
			if err != nil {
				slog.Warn("cancel check", "scan_id", job.ScanID, "err", err)
			}
			if c {
				cancelled = true
				deps.KillTool(job.ScanID, screenTool)
			}
		}
		select {
		case run = <-done:
			waiting = false
		case <-tick.C:
		}
	}
	if cancelled {
		return nil, true, nil
	}
	if run.Status != sandbox.Succeeded || run.Sarif == "" {
		return nil, false, fmt.Errorf("gitleaks %s", run.Status)
	}
	m, err := importer.Matches(run.Sarif)
	return m, false, err
}
