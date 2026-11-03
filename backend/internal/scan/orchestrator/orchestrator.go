// Package orchestrator runs one scan: download, verify, extract, run the scanners
// in parallel, parse their SARIF, and always delete the uploaded source.
package orchestrator

import (
	"bytes"
	"context"
	"crypto/rand"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"log/slog"
	"maps"
	"os"
	"path/filepath"
	"regexp"
	"slices"
	"sync"
	"time"

	"github.com/aupv9/warden/backend/internal/domain/fingerprint"
	"github.com/aupv9/warden/backend/internal/domain/severity"
	"github.com/aupv9/warden/backend/internal/scan/bundlecheck"
	"github.com/aupv9/warden/backend/internal/scan/imagecheck"
	"github.com/aupv9/warden/backend/internal/scan/sandbox"
	"github.com/aupv9/warden/backend/internal/scan/sarif"
	"github.com/aupv9/warden/backend/internal/scan/sbom"
	"github.com/aupv9/warden/backend/internal/scan/trivyjson"
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
	// Kind is source (a zip), image (a docker save tarball, Trivy only) or
	// history (a git bundle, Gitleaks only); Target is the image repository,
	// or HistoryTarget. Both are set by the worker from the scan row.
	Kind   string `json:"kind,omitempty"`
	Target string `json:"target,omitempty"`
	// ProjectKey names the SBOM's root component (set by the worker from the database).
	ProjectKey string `json:"-"`
	// OrgRules are the org's own rules per tool (set by the worker from the
	// database, never from the job's JSON). Only tools in Tools that take org
	// rules (sandbox.OrgRulesFile) get them.
	OrgRules map[string]OrgRules `json:"-"`
}

// OrgRules is one tool's org rules for a scan: the scanner config rendered
// from them (internal/rules), which the sandbox mounts read-only, and the
// severity of each rule's findings by rule id ("org.<key>").
type OrgRules struct {
	Config   []byte
	Severity map[string]severity.Severity
}

// Scan kinds (scan.kind).
const (
	KindSource  = "source"
	KindImage   = "image"
	KindHistory = "history"
)

// HistoryTarget is every history scan's target (migration 00011).
const HistoryTarget = fingerprint.HistoryPath

func (j Job) kind() string {
	if j.Kind == "" {
		return KindSource
	}
	return j.Kind
}

type Outcome struct {
	Status    ScanStatus
	ErrorCode string
	Runs      []sandbox.ToolRun
	Findings  map[string][]sarif.Finding
	// Licenses: every package license Trivy reported, when Trivy succeeded
	// (FilePath set). Which become issues is the org's policy, applied later.
	Licenses []trivyjson.License
	// Packages: every package Trivy reported, when Trivy succeeded
	// (FilePath set), for the component inventory and the malicious-package match.
	Packages []trivyjson.Package
	// SBOM: Trivy's CycloneDX SBOM, stamped; nil when there is none.
	SBOM *sbom.Stamped
	// SPDX: Trivy's SPDX SBOM, stamped; nil when there is none.
	SPDX *sbom.Stamped
	// History: how many commits a history scan read, when Gitleaks succeeded.
	History  *History
	Warnings []string
	// OrgRulesLoaded: by tool, the org rules each tool that succeeded listed
	// in its SARIF (sarif.LoadedOrgRules): the ones that ran. Opengrep runs
	// the rest of a config when one rule fails to load.
	OrgRulesLoaded map[string]map[string]bool
}

// History is what warden-gitleaks reports about a history scan
// (sandbox.ArtifactHistory): the commits Gitleaks read, and whether
// HistoryMaxCommits cut the history short.
type History struct {
	Commits   int
	Truncated bool
}

// Limits come from the configuration (scan.*).
type Limits struct {
	Zip zipcheck.Limits
	// ImageMaxBytes caps image tarballs (scan.image_upload_max_mb).
	ImageMaxBytes int64
	// HistoryMaxBytes caps git bundles (scan.history_upload_max_mb), and
	// HistoryMaxCommits how many commits a history scan reads
	// (scan.history_max_commits, the newest).
	HistoryMaxBytes   int64
	HistoryMaxCommits int
}

// Deps is everything the orchestrator needs from storage, the database and Docker.
type Deps interface {
	Limits() Limits
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
	kind := job.kind()
	for _, t := range job.Tools {
		if !knownTool(kind, t) {
			return nil, fmt.Errorf("unknown tool %q for a %s scan", t, kind)
		}
	}
	if err := deps.SetStatus(ctx, job.ScanID, Running); err != nil {
		return nil, err
	}
	if err := os.Mkdir(scanDir, 0o700); err != nil {
		return nil, err
	}
	srcDir := filepath.Join(scanDir, "src")
	var src *prepared
	var err error
	switch kind {
	case KindImage:
		var layers int
		src, err = prepareFile(ctx, job, deps, scanDir, srcDir, "image.tar", func(p string) error {
			r, err := imagecheck.Check(p, imagecheck.Limits{MaxBytes: deps.Limits().ImageMaxBytes})
			if err == nil {
				layers = r.Layers
			}
			return err
		})
		if err == nil {
			src.imageLayers = layers
		}
	case KindHistory:
		src, err = prepareFile(ctx, job, deps, scanDir, srcDir, "repo.bundle", func(p string) error {
			_, err := bundlecheck.Check(p, bundlecheck.Limits{MaxBytes: deps.Limits().HistoryMaxBytes})
			return err
		})
	default:
		src, err = prepareSource(ctx, job, deps, scanDir, srcDir)
	}
	if code, ok := rejection(job, err); ok {
		return &Outcome{Status: Failed, ErrorCode: code}, nil
	}
	if err != nil {
		return nil, err
	}

	if err := writeOrgRules(filepath.Join(scanDir, sandbox.RulesDir), job); err != nil {
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
		return &Outcome{Status: Cancelled, Warnings: src.warnings}, nil
	}
	if code, ok := sandboxRejection(job, runs); ok {
		return &Outcome{Status: Failed, ErrorCode: code, Runs: runs}, nil
	}

	out := &Outcome{Runs: runs, Warnings: src.warnings, Findings: map[string][]sarif.Finding{}}
	for i := range runs {
		run := &runs[i]
		if run.Status != sandbox.Succeeded || run.Sarif == "" {
			continue
		}
		var loaded map[string]bool
		if len(job.OrgRules[run.Tool].Severity) > 0 {
			loaded = map[string]bool{}
		}
		// Gitleaks in an image scan: the layers' digests come from its layer report.
		var layers []string
		var err error
		if kind == KindImage && run.Tool == "gitleaks" {
			layers, err = loadLayers(job, run.Artifacts[sandbox.ArtifactLayers], src.imageLayers)
		}
		var fs []sarif.Finding
		var rep *trivyjson.Report
		if err == nil {
			fs, rep, err = parseRun(*run, src.rootDir, srcDir, job.Target, kind == KindHistory, layers, job.OrgRules[run.Tool].Severity, loaded)
		}
		if err == nil && kind == KindHistory {
			out.History, err = loadHistory(run.Artifacts[sandbox.ArtifactHistory], deps.Limits().HistoryMaxCommits)
		}
		if err != nil {
			slog.Warn("scanner output rejected", "scan_id", job.ScanID, "tool", run.Tool, "err", err)
			run.Status, run.Error = sandbox.Failed, err.Error()
			if err := deps.SetToolStatus(ctx, job.ScanID, *run); err != nil {
				return nil, err
			}
			continue
		}
		out.Findings[run.Tool] = fs
		if loaded != nil {
			if out.OrgRulesLoaded == nil {
				out.OrgRulesLoaded = map[string]map[string]bool{}
			}
			out.OrgRulesLoaded[run.Tool] = loaded
		}
		if run.Tool == "trivy" && rep != nil {
			out.Licenses, out.Packages = rep.Licenses, rep.Packages
			// Non-nil even when empty: Trivy succeeded, so the inventory
			// becomes empty rather than kept (nil means Trivy didn't report).
			if out.Packages == nil {
				out.Packages = []trivyjson.Package{}
			}
			out.SBOM = stampArtifact(job, "SBOM", run.Artifacts[sandbox.ArtifactSBOM], sbom.Stamp)
			out.SPDX = stampArtifact(job, "SPDX SBOM", run.Artifacts[sandbox.ArtifactSPDX], sbom.StampSPDX)
		}
	}
	out.Status = FinalStatus(runs)
	if out.Status == Failed {
		out.ErrorCode = "ALL_SCANNERS_FAILED"
	}
	return out, nil
}

// prepared is the scanned input under src/.
type prepared struct {
	rootDir  string // the zip's single top-level directory, if any
	warnings []string
	// imageLayers: how many layers imagecheck found in the image's manifest.
	imageLayers int
}

// rejection returns the error code of an upload the checks refused.
func rejection(job Job, err error) (string, bool) {
	var zr *zipcheck.Rejected
	if errors.As(err, &zr) {
		slog.Info("scan rejected", "scan_id", job.ScanID, "code", zr.Code, "detail", zr.Detail)
		return zr.Code, true
	}
	var ir *imagecheck.Rejected
	if errors.As(err, &ir) {
		slog.Info("scan rejected", "scan_id", job.ScanID, "code", ir.Code, "detail", ir.Detail)
		return ir.Code, true
	}
	var br *bundlecheck.Rejected
	if errors.As(err, &br) {
		slog.Info("scan rejected", "scan_id", job.ScanID, "code", br.Code, "detail", br.Detail)
		return br.Code, true
	}
	return "", false
}

// knownTool: image scans run Trivy and Gitleaks, history scans Gitleaks only.
func knownTool(kind, tool string) bool {
	switch kind {
	case KindImage:
		return slices.Contains(sandbox.ImageToolNames, tool)
	case KindHistory:
		return slices.Contains(sandbox.HistoryToolNames, tool)
	}
	_, ok := sandbox.Tools[tool]
	return ok
}

// sandboxRejection: Gitleaks' sandbox found the upload unusable, which the
// checks outside can't tell, as they never unpack it; these are rejections of
// the upload like the others.
//
//   - History: bundlecheck reads only the header and the pack's framing, so a
//     shallow clone's bundle (no prerequisites, but the boundary's parents
//     missing) or objects that fail fsck show up only when git fetches it.
//   - Image: imagecheck never opens the layers, so layers that expand past the
//     limit (a decompression bomb) or aren't tars show up only when
//     warden-layers reads them. The whole scan fails, Trivy's results too:
//     Trivy read the same layers.
func sandboxRejection(job Job, runs []sandbox.ToolRun) (string, bool) {
	codes := map[int]string{}
	detail := ""
	switch job.kind() {
	case KindHistory:
		codes[sandbox.ExitHistoryIncomplete], codes[sandbox.ExitHistoryUnreadable] = bundlecheck.CodeIncomplete, bundlecheck.CodeInvalid
		detail = "git could not fetch the bundle"
	case KindImage:
		codes[sandbox.ExitImageTooLarge], codes[sandbox.ExitImageUnreadable] = imagecheck.CodeTooLarge, imagecheck.CodeInvalid
		detail = "gitleaks could not read the layers"
	default:
		return "", false
	}
	for _, r := range runs {
		if r.Tool != "gitleaks" || r.Status != sandbox.Failed {
			continue
		}
		if code, ok := codes[r.ExitCode]; ok {
			slog.Info("scan rejected", "scan_id", job.ScanID, "code", code, "detail", detail)
			return code, true
		}
	}
	return "", false
}

// maxLayersArtifact bounds layers.json; the sandbox caps it too.
const maxLayersArtifact = 64 << 10

var layerDigest = regexp.MustCompile(`^sha256:[0-9a-f]{64}$`)

// loadLayers reads the layer report warden-layers wrote (layerscan.Report):
// a digest for each of the image's layers (as many as imagecheck found), and
// what it didn't scan. It comes out of the sandbox, so it is checked like
// any scanner output; without it Gitleaks' findings have no layer. (The
// worker doesn't import layerscan: nothing that unpacks layers is linked
// into it.)
func loadLayers(job Job, path string, want int) ([]string, error) {
	if path == "" {
		return nil, fmt.Errorf("%w: gitleaks wrote no layer report (or one over the size cap)", sarif.ErrSARIF)
	}
	f, err := os.Open(path)
	if err != nil {
		return nil, err
	}
	defer f.Close()
	raw, err := io.ReadAll(io.LimitReader(f, maxLayersArtifact+1))
	if err != nil {
		return nil, err
	}
	var rep struct {
		Layers    []string `json:"layers"`
		Skipped   int      `json:"skipped_files"`
		Whiteouts int      `json:"whiteouts"`
		Unsafe    int      `json:"unsafe_entries"`
	}
	dec := json.NewDecoder(bytes.NewReader(raw))
	dec.DisallowUnknownFields()
	err = dec.Decode(&rep)
	if err == nil {
		if _, terr := dec.Token(); !errors.Is(terr, io.EOF) {
			err = errors.New("trailing data")
		}
	}
	ok := err == nil && len(raw) <= maxLayersArtifact && len(rep.Layers) == want && want > 0 &&
		rep.Skipped >= 0 && rep.Whiteouts >= 0 && rep.Unsafe >= 0
	for _, d := range rep.Layers {
		ok = ok && layerDigest.MatchString(d)
	}
	if !ok {
		return nil, fmt.Errorf("%w: invalid layer report", sarif.ErrSARIF)
	}
	if rep.Skipped > 0 || rep.Unsafe > 0 {
		slog.Info("image layers: entries gitleaks did not read", "scan_id", job.ScanID,
			"skipped_files", rep.Skipped, "unsafe_entries", rep.Unsafe)
	}
	return rep.Layers, nil
}

// maxHistoryArtifact bounds history.json; the sandbox caps it too.
const maxHistoryArtifact = 256

// loadHistory reads the history report warden-gitleaks wrote: exactly
// {"commits": n, "truncated": b}, n at most the commit limit. It comes out of
// the sandbox, so it is checked like any scanner output; without it the
// run's results can't be trusted to cover the history.
func loadHistory(path string, maxCommits int) (*History, error) {
	if path == "" {
		return nil, fmt.Errorf("%w: gitleaks wrote no history report (or one over the size cap)", sarif.ErrSARIF)
	}
	f, err := os.Open(path)
	if err != nil {
		return nil, err
	}
	defer f.Close()
	raw, err := io.ReadAll(io.LimitReader(f, maxHistoryArtifact+1))
	if err != nil {
		return nil, err
	}
	var v struct {
		Commits   *int  `json:"commits"`
		Truncated *bool `json:"truncated"`
	}
	dec := json.NewDecoder(bytes.NewReader(raw))
	dec.DisallowUnknownFields()
	err = dec.Decode(&v)
	if err == nil {
		if _, terr := dec.Token(); !errors.Is(terr, io.EOF) {
			err = errors.New("trailing data")
		}
	}
	if err != nil || len(raw) > maxHistoryArtifact || v.Commits == nil || v.Truncated == nil ||
		*v.Commits < 0 || *v.Commits > maxCommits {
		return nil, fmt.Errorf("%w: invalid history report", sarif.ErrSARIF)
	}
	return &History{Commits: *v.Commits, Truncated: *v.Truncated}, nil
}

// prepareSource downloads the zip, verifies and extracts it into src/.
func prepareSource(ctx context.Context, job Job, deps Deps, scanDir, srcDir string) (*prepared, error) {
	zipPath := filepath.Join(scanDir, "src.zip")
	if err := deps.Download(ctx, job.ObjectKey, zipPath); err != nil {
		return nil, err
	}
	extracted, err := verifyAndExtract(zipPath, job.SHA256, srcDir, deps.Limits().Zip)
	if err != nil {
		return nil, err
	}
	if err := os.Remove(zipPath); err != nil {
		return nil, err
	}
	return &prepared{rootDir: extracted.RootDir, warnings: extracted.Warnings}, nil
}

// prepareFile downloads an upload that is scanned as one file (an image
// tarball, a git bundle), verifies its checksum and checks it (imagecheck,
// bundlecheck: it is never extracted), then puts it at src/<name>, read-only,
// for the sandbox to mount. No scanner runs unless check passed.
func prepareFile(ctx context.Context, job Job, deps Deps, scanDir, srcDir, name string, check func(string) error) (*prepared, error) {
	path := filepath.Join(scanDir, name)
	if err := deps.Download(ctx, job.ObjectKey, path); err != nil {
		return nil, err
	}
	if err := zipcheck.VerifyChecksum(path, job.SHA256); err != nil {
		return nil, err
	}
	if err := check(path); err != nil {
		return nil, err
	}
	if err := os.Mkdir(srcDir, 0o755); err != nil {
		return nil, err
	}
	dest := filepath.Join(srcDir, name)
	if err := os.Rename(path, dest); err != nil {
		return nil, err
	}
	// The sandbox user (65532) reads it; nobody writes it. RemoveAll undoes this.
	if err := os.Chmod(dest, 0o444); err != nil {
		return nil, err
	}
	return &prepared{}, os.Chmod(srcDir, 0o555)
}

func verifyAndExtract(zipPath, sha, dest string, limits zipcheck.Limits) (*zipcheck.Result, error) {
	if err := zipcheck.VerifyChecksum(zipPath, sha); err != nil {
		return nil, err
	}
	return zipcheck.Extract(zipPath, dest, limits)
}

// parseRun parses a tool's SARIF and, for Trivy, its JSON report: the
// licenses and packages (returned with FilePath set), and for image scans the
// OS that names OS package findings. imageTarget is "" for source scans;
// history is set for history scans (Gitleaks in git mode); layers are the
// image's layer digests for Gitleaks in an image scan (nil otherwise). When
// loaded is non-nil, it receives the org rules the tool loaded
// (sarif.LoadedOrgRules).
func parseRun(run sandbox.ToolRun, rootDir, srcDir, imageTarget string, history bool, layers []string,
	orgRules map[string]severity.Severity, loaded map[string]bool) ([]sarif.Finding, *trivyjson.Report, error) {
	opts := sarif.Options{RootDir: rootDir, SourceRoot: srcDir, History: history, OrgRules: orgRules}
	if layers != nil {
		opts.ImageTarget, opts.ImageLayers = imageTarget, layers
	}
	var rep *trivyjson.Report
	if run.Tool == "trivy" {
		// The SARIF is converted from this report: without it (or with a
		// report that fails the checks) Trivy's results are incomplete.
		p := run.Artifacts[sandbox.ArtifactTrivyJSON]
		if p == "" {
			return nil, nil, errors.New("trivy wrote no JSON report (or one over the size cap)")
		}
		var err error
		if rep, err = trivyjson.Load(p); err != nil {
			return nil, nil, err
		}
		opts.ImageTarget, opts.OSLabel = imageTarget, rep.OSFamily
	}
	doc, err := sarif.Load(run.Sarif)
	if err != nil {
		return nil, nil, err
	}
	if loaded != nil {
		maps.Copy(loaded, sarif.LoadedOrgRules(doc, run.Tool))
	}
	fs, err := sarif.Parse(doc, run.Tool, opts)
	if err != nil || rep == nil {
		return fs, nil, err
	}
	// Licenses and packages get the paths their package's vulnerabilities get.
	filePath := func(target, class string) string {
		p := fingerprint.NormPath(target, rootDir, false)
		if imageTarget != "" {
			if class == trivyjson.ClassOSPackages {
				p = sarif.ImageArtifact
			}
			p = sarif.ImagePath(imageTarget, rep.OSFamily, p)
		}
		return p
	}
	for i := range rep.Licenses {
		l := &rep.Licenses[i]
		l.FilePath = filePath(l.Target, l.Class)
	}
	for i := range rep.Packages {
		p := &rep.Packages[i]
		p.FilePath = filePath(p.Target, p.Class)
	}
	return fs, rep, nil
}

// stampArtifact returns one of the scan's SBOMs (what names it in logs) ready
// to store, or nil. A missing or invalid SBOM costs only that SBOM: the scan's
// results don't depend on it.
func stampArtifact(job Job, what, path string, stamp func(raw []byte, name, scanID string) (*sbom.Stamped, error)) *sbom.Stamped {
	if path == "" {
		slog.Warn("trivy wrote no "+what+" (or one over the size cap)", "scan_id", job.ScanID)
		return nil
	}
	f, err := os.Open(path)
	if err != nil {
		slog.Warn("read "+what, "scan_id", job.ScanID, "err", err)
		return nil
	}
	defer f.Close()
	raw, err := io.ReadAll(io.LimitReader(f, sbom.MaxBytes+1))
	if err == nil {
		var s *sbom.Stamped
		if s, err = stamp(raw, job.ProjectKey, job.ScanID); err == nil {
			return s
		}
	}
	slog.Warn(what+" rejected", "scan_id", job.ScanID, "err", err)
	return nil
}

// writeOrgRules writes each tool's rendered org rules to dir/<file>
// (sandbox.OrgRulesFile), read-only, for the sandbox to mount into that tool
// alone. Nothing is written when the scan has no org rules.
func writeOrgRules(dir string, job Job) error {
	var tools []string
	for _, t := range job.Tools {
		if len(job.OrgRules[t].Config) > 0 {
			tools = append(tools, t)
		}
	}
	if len(tools) == 0 {
		return nil
	}
	if err := os.Mkdir(dir, 0o755); err != nil {
		return err
	}
	for _, t := range tools {
		file := sandbox.OrgRulesFile(t)
		if file == "" {
			return fmt.Errorf("%s takes no org rules", t)
		}
		if err := WriteReadOnly(filepath.Join(dir, file), job.OrgRules[t].Config); err != nil {
			return err
		}
	}
	// The sandbox user (65532) reads them; nobody writes them. RemoveAll undoes this.
	return os.Chmod(dir, 0o555)
}

// WriteReadOnly creates path (which must not exist yet) holding data,
// readable by the sandbox user and writable by nobody.
func WriteReadOnly(path string, data []byte) error {
	f, err := os.OpenFile(path, os.O_WRONLY|os.O_CREATE|os.O_EXCL, 0o600)
	if err != nil {
		return err
	}
	_, err = f.Write(data)
	if cerr := f.Close(); err == nil {
		err = cerr
	}
	if err != nil {
		return err
	}
	return os.Chmod(path, 0o444)
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
