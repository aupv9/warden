// Package orchestrator runs one scan: download, verify, extract, run the scanners
// in parallel, parse their SARIF, and always delete the uploaded source.
package orchestrator

import (
	"context"
	"crypto/rand"
	"encoding/hex"
	"errors"
	"fmt"
	"log/slog"
	"os"
	"path/filepath"
	"slices"
	"sync"
	"time"

	"github.com/aupv9/warden/backend/internal/scan/sandbox"
	"github.com/aupv9/warden/backend/internal/scan/sarif"
	"github.com/aupv9/warden/backend/internal/scan/zipcheck"
)

var CancelPoll = 5 * time.Second

type ScanStatus string

const (
	PendingUpload ScanStatus = "pending_upload"
	Queued        ScanStatus = "queued"
	Running       ScanStatus = "running"
	Completed     ScanStatus = "completed"
	Partial       ScanStatus = "partial"
	Failed        ScanStatus = "failed"
	Cancelled     ScanStatus = "cancelled"
)

type Job struct {
	ScanID    string   `json:"scan_id"`
	OrgID     string   `json:"org_id"`
	ProjectID string   `json:"project_id"`
	ObjectKey string   `json:"object_key"`
	SHA256    string   `json:"sha256"`
	Tools     []string `json:"tools"`
	Attempt   int      `json:"attempt"`
}

type Outcome struct {
	Status    ScanStatus
	ErrorCode string
	Runs      []sandbox.ToolRun
	Findings  map[string][]sarif.Finding
	Warnings  []string
}

// Deps is everything the orchestrator needs from storage, the database and Docker.
type Deps interface {
	ScratchRoot() string
	Download(ctx context.Context, objectKey, dest string) error
	DeleteObject(ctx context.Context, objectKey string) error
	SetStatus(ctx context.Context, scanID string, status ScanStatus) error
	SetToolStatus(ctx context.Context, scanID string, run sandbox.ToolRun) error
	IsCancelled(ctx context.Context, scanID string) (bool, error)
	HMACKey(ctx context.Context, orgID string) ([]byte, error)
	RunTool(ctx context.Context, tool, scanID, scanDir string) sandbox.ToolRun
	KillTool(scanID, tool string)
}

func FinalStatus(runs []sandbox.ToolRun) ScanStatus {
	ok := 0
	for _, r := range runs {
		if r.Status == sandbox.Succeeded {
			ok++
		}
	}
	switch {
	case ok == len(runs):
		return Completed
	case ok > 0:
		return Partial
	}
	return Failed
}

// Execute runs the scan. Whatever happens, the scan directory and the uploaded
// object are deleted before it returns.
func Execute(ctx context.Context, job Job, deps Deps) (out *Outcome, err error) {
	scanDir := filepath.Join(deps.ScratchRoot(), job.ScanID)
	defer func() {
		if cerr := cleanup(job, deps, scanDir); cerr != nil && err == nil {
			err = cerr
		}
	}()
	return execute(ctx, job, deps, scanDir)
}

func execute(ctx context.Context, job Job, deps Deps, scanDir string) (*Outcome, error) {
	for _, t := range job.Tools {
		if _, ok := sandbox.Tools[t]; !ok {
			return nil, fmt.Errorf("unknown tool %q", t)
		}
	}
	if err := deps.SetStatus(ctx, job.ScanID, Running); err != nil {
		return nil, err
	}
	if err := os.Mkdir(scanDir, 0o700); err != nil {
		return nil, err
	}
	zipPath := filepath.Join(scanDir, "src.zip")
	if err := deps.Download(ctx, job.ObjectKey, zipPath); err != nil {
		return nil, err
	}
	srcDir := filepath.Join(scanDir, "src")
	extracted, err := verifyAndExtract(zipPath, job.SHA256, srcDir)
	var rej *zipcheck.Rejected
	if errors.As(err, &rej) {
		slog.Info("scan rejected", "scan_id", job.ScanID, "code", rej.Code, "detail", rej.Detail)
		return &Outcome{Status: Failed, ErrorCode: rej.Code}, nil
	}
	if err != nil {
		return nil, err
	}
	if err := os.Remove(zipPath); err != nil {
		return nil, err
	}

	if slices.Contains(job.Tools, "gitleaks") {
		key, err := deps.HMACKey(ctx, job.OrgID)
		if err != nil {
			return nil, err
		}
		if err := writeKey(filepath.Join(scanDir, "secrets", "hmac"), key); err != nil {
			return nil, err
		}
	}

	runs, cancelled := runTools(ctx, job, deps, scanDir)
	if cancelled {
		return &Outcome{Status: Cancelled, Warnings: extracted.Warnings}, nil
	}

	out := &Outcome{Runs: runs, Warnings: extracted.Warnings, Findings: map[string][]sarif.Finding{}}
	for i := range runs {
		run := &runs[i]
		if run.Status != sandbox.Succeeded || run.Sarif == "" {
			continue
		}
		fs, err := parseRun(run.Sarif, run.Tool, extracted.RootDir, srcDir)
		if err != nil {
			run.Status, run.Error = sandbox.Failed, err.Error()
			if err := deps.SetToolStatus(ctx, job.ScanID, *run); err != nil {
				return nil, err
			}
			continue
		}
		out.Findings[run.Tool] = fs
	}
	out.Status = FinalStatus(runs)
	if out.Status == Failed {
		out.ErrorCode = "ALL_SCANNERS_FAILED"
	}
	return out, nil
}

func verifyAndExtract(zipPath, sha, dest string) (*zipcheck.Result, error) {
	if err := zipcheck.VerifyChecksum(zipPath, sha); err != nil {
		return nil, err
	}
	return zipcheck.Extract(zipPath, dest, zipcheck.DefaultLimits())
}

func parseRun(path, tool, rootDir, srcDir string) ([]sarif.Finding, error) {
	doc, err := sarif.Load(path)
	if err != nil {
		return nil, err
	}
	return sarif.Parse(doc, tool, sarif.Options{RootDir: rootDir, SourceRoot: srcDir})
}

// WriteKey writes the HMAC key file mounted read-only into the Gitleaks sandbox.
func writeKey(path string, key []byte) error {
	if err := os.Mkdir(filepath.Dir(path), 0o700); err != nil {
		return err
	}
	if err := os.WriteFile(path, key, 0o400); err != nil {
		return err
	}
	// The sandbox user (65532) must read it; the directory stays 0700 to everyone else on the host.
	return os.Chmod(path, 0o444)
}

// runTools starts every tool and polls for cancellation; on cancel it kills the
// containers that are still running and reports cancelled=true.
func runTools(ctx context.Context, job Job, deps Deps, scanDir string) ([]sandbox.ToolRun, bool) {
	runs := make([]sandbox.ToolRun, len(job.Tools))
	var wg sync.WaitGroup
	done := make(chan struct{})
	finished := make([]bool, len(job.Tools))
	var mu sync.Mutex

	for i, tool := range job.Tools {
		if err := deps.SetToolStatus(ctx, job.ScanID, sandbox.ToolRun{Tool: tool, Status: sandbox.Running}); err != nil {
			slog.Warn("set tool status", "scan_id", job.ScanID, "tool", tool, "err", err)
		}
		wg.Add(1)
		go func() {
			defer wg.Done()
			r := deps.RunTool(ctx, tool, job.ScanID, scanDir)
			if err := deps.SetToolStatus(ctx, job.ScanID, r); err != nil {
				slog.Warn("set tool status", "scan_id", job.ScanID, "tool", tool, "err", err)
			}
			mu.Lock()
			runs[i], finished[i] = r, true
			mu.Unlock()
		}()
	}
	go func() { wg.Wait(); close(done) }()

	tick := time.NewTicker(CancelPoll)
	defer tick.Stop()
	for {
		cancelled, err := deps.IsCancelled(ctx, job.ScanID)
		if err != nil {
			slog.Warn("cancel check", "scan_id", job.ScanID, "err", err)
		}
		if cancelled {
			mu.Lock()
			for i, tool := range job.Tools {
				if !finished[i] {
					deps.KillTool(job.ScanID, tool)
				}
			}
			mu.Unlock()
			<-done
			return nil, true
		}
		select {
		case <-done:
			return runs, false
		case <-tick.C:
		}
	}
}

func cleanup(job Job, deps Deps, scanDir string) error {
	err := zipcheck.RemoveAll(scanDir)
	ctx, cancel := context.WithTimeout(context.Background(), time.Minute)
	defer cancel()
	if derr := deps.DeleteObject(ctx, job.ObjectKey); derr != nil {
		slog.Error("failed to delete uploaded object; retention sweep will retry", "object_key", job.ObjectKey, "err", derr)
	}
	return err
}

// NewHMACKey returns a fresh per-org key (64 hex chars).
func NewHMACKey() ([]byte, error) {
	b := make([]byte, 32)
	if _, err := rand.Read(b); err != nil {
		return nil, err
	}
	return []byte(hex.EncodeToString(b)), nil
}
