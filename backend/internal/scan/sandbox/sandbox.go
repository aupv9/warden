// Package sandbox runs one scanner in a throw-away container: gVisor, no
// network, read-only rootfs, non-root, no capabilities, pids/cpu/memory limits. The argv is built here and nowhere else.
package sandbox

import (
	"context"
	"errors"
	"fmt"
	"io"
	"os"
	"os/exec"
	"path/filepath"
	"regexp"
	"slices"
	"strconv"
	"time"
)

const (
	SandboxUID = "65532:65532"
	StderrTail = 4096
)

var immutableImage = regexp.MustCompile(`^(\S+@sha256:[0-9a-f]{64}|sha256:[0-9a-f]{64})$`)

type ToolSpec struct {
	Name         string
	Timeout      time.Duration
	CPUs         string
	Memory       string
	Command      []string // Command[0] becomes --entrypoint
	SarifName    string
	NeedsHMACKey bool
	TmpExec      bool // Opengrep's binary self-extracts into /tmp and execs
	OKExitCodes  []int
	// TmpfsSize sizes /tmp (default 256m); Trivy unpacks image layers there.
	TmpfsSize string
	// Artifacts are reports the tool writes to /out besides its SARIF, by name.
	Artifacts map[string]ArtifactSpec
	// OrgRules is the file under <ScanDir>/rules holding the org's rendered
	// rules for this tool (OrgRulesFile), mounted read-only at /rules/<file>;
	// "" when the tool runs Warden's rules only. Set by WithOrgRules and
	// RuleTestTool, never from the upload.
	OrgRules string
}

// ArtifactSpec is one extra report: its file name under /out and the largest
// size Warden reads. Like the SARIF, it is derived from hostile input.
type ArtifactSpec struct {
	File     string
	MaxBytes int64
}

// Trivy's artifacts (see trivyScript).
const (
	ArtifactTrivyJSON = "trivy_json"
	ArtifactSBOM      = "sbom"
	ArtifactSPDX      = "spdx"
)

// trivyFlags: offline, nothing read from the scanned tree. The JSON report
// lists every package (--list-all-pkgs) with its licenses, for the license
// policy and the SBOM.
const trivyFlags = "--scanners vuln,license --list-all-pkgs --cache-dir /data --cache-backend memory " +
	"--skip-db-update --skip-java-db-update --offline-scan --format json --output /out/trivy.json"

// trivyScript runs one Trivy scan and derives from its JSON report the SARIF
// (vulnerabilities and licenses; the SARIF parser keeps only vulnerabilities)
// and the CycloneDX and SPDX SBOMs. It is a constant: nothing from the upload
// is interpolated. A failed SBOM conversion loses only that SBOM (a partial
// file is removed), not the results.
func trivyScript(scan string) string {
	return "set -eu; trivy " + scan + " " + trivyFlags +
		" && trivy convert --format sarif --output /out/result.sarif /out/trivy.json" +
		" && { trivy convert --format cyclonedx --output /out/sbom.cdx.json /out/trivy.json || rm -f /out/sbom.cdx.json; }" +
		" && { trivy convert --format spdx-json --output /out/sbom.spdx.json /out/trivy.json || rm -f /out/sbom.spdx.json; }"
}

var trivyArtifacts = map[string]ArtifactSpec{
	ArtifactTrivyJSON: {File: "trivy.json", MaxBytes: 256 << 20},
	ArtifactSBOM:      {File: "sbom.cdx.json", MaxBytes: 64 << 20},
	ArtifactSPDX:      {File: "sbom.spdx.json", MaxBytes: 64 << 20},
}

// Tools is the fixed scanner set. Uploaded code can't configure its own scan: every
// config path is explicit, and scanners don't read config or ignore files
// from the scanned directory.
var Tools = map[string]ToolSpec{
	"gitleaks": {
		Name: "gitleaks", Timeout: 5 * time.Minute, CPUs: "0.25", Memory: "512m",
		Command:      []string{"warden-gitleaks"},
		NeedsHMACKey: true,
	},
	"opengrep": {
		Name: "opengrep", Timeout: 15 * time.Minute, CPUs: "1", Memory: "2g",
		Command: []string{
			"opengrep", "scan", "--config", "/data/rules", "--disable-nosem",
			"--sarif", "--output", "/out/result.sarif", "/src",
		},
		TmpExec:     true,
		OKExitCodes: []int{0, 2}, // 2 = some files failed to parse; SARIF still written
	},
	"trivy": {
		// The pinned upstream image is Alpine, so it has sh: no Warden-built image needed.
		Name: "trivy", Timeout: 10 * time.Minute, CPUs: "0.5", Memory: "1g",
		Command:   []string{"sh", "-c", trivyScript("fs /src")},
		Artifacts: trivyArtifacts,
	},
	"checkov": {
		// 512m and 1g were SIGKILLed under gVisor, which accounts sentry memory to the container.
		Name: "checkov", Timeout: 10 * time.Minute, CPUs: "0.25", Memory: "2g",
		Command: []string{
			"checkov", "-d", "/src", "--output", "sarif", "--output-file-path", "/out",
			"--skip-download", "--skip-framework", "secrets", "sca_package", "sca_image", // Gitleaks is the only secret scanner: only its output is redacted
			"--quiet", "--soft-fail",
		},
		SarifName: "results_sarif.sarif",
	},
}

// ToolNames is the canonical order.
var ToolNames = []string{"gitleaks", "opengrep", "trivy", "checkov"}

// ImageTools are the scanners of image scans (kind image): only Trivy, reading
// the verified `docker save` tarball mounted read-only at /src/image.tar.
// Images are larger than source trees: more /tmp, memory and time.
var ImageTools = map[string]ToolSpec{
	"trivy": {
		Name: "trivy", Timeout: 15 * time.Minute, CPUs: "1", Memory: "3g", TmpfsSize: "1g",
		Command:   []string{"sh", "-c", trivyScript("image --input /src/image.tar")},
		Artifacts: trivyArtifacts,
	},
}

// ArtifactHistory is a history scan's commit count (see HistoryStats).
const ArtifactHistory = "history"

// Exit codes of warden-gitleaks in history mode for a bundle git can't use.
const (
	ExitHistoryIncomplete = 3 // commits are missing (a shallow clone's bundle)
	ExitHistoryUnreadable = 4 // git refused the bundle (fsck errors)
)

// HistoryLimits size the history scan's sandbox (scan.history_*).
type HistoryLimits struct {
	MaxBytes   int64 // the largest bundle
	MaxCommits int
	// ScanTimeout bounds the whole scan (scan.timeout); Gitleaks gets at most that.
	ScanTimeout time.Duration
}

// historyTimeout: reading every commit takes longer than reading one tree.
const historyTimeout = 25 * time.Minute

// HistoryTool is the scanner of history scans (kind history): Gitleaks in git
// mode over the verified bundle mounted read-only at /src/repo.bundle (see
// scanners/gitleaks/warden-gitleaks). git fetches the bundle into a fresh
// repository in /tmp, which holds about the bundle's size again (tmpfs pages
// count towards the memory limit). The commit limit is an argument set here,
// never anything from the upload.
func HistoryTool(l HistoryLimits) ToolSpec {
	repoMB := l.MaxBytes>>20 + l.MaxBytes>>22 + 256 // the pack, its index, the raw SARIF
	timeout := historyTimeout
	if l.ScanTimeout > 0 && l.ScanTimeout < timeout {
		timeout = l.ScanTimeout
	}
	return ToolSpec{
		Name: "gitleaks", Timeout: timeout, CPUs: "1",
		Memory:       strconv.FormatInt(repoMB+1536, 10) + "m",
		TmpfsSize:    strconv.FormatInt(repoMB, 10) + "m",
		Command:      []string{"warden-gitleaks", "history", strconv.Itoa(max(l.MaxCommits, 1))},
		NeedsHMACKey: true,
		Artifacts:    map[string]ArtifactSpec{ArtifactHistory: {File: "history.json", MaxBytes: 256}},
	}
}

// HistoryToolNames: history scans run Gitleaks only.
var HistoryToolNames = []string{"gitleaks"}

// RulesDir is the directory under the scan directory that holds the org's
// rendered rules, one file per tool (OrgRulesFile). Warden writes it; the
// sandbox mounts only the running tool's file, read-only, at /rules/<file>.
const RulesDir = "rules"

// orgRulesFiles: the tools that take org rules (internal/rules) and the file
// each one's rules are rendered to.
var orgRulesFiles = map[string]string{
	"opengrep": "opengrep.yml",
	"gitleaks": "gitleaks.toml",
}

// OrgRulesFile is the file name of tool's org rules under RulesDir, or ""
// when the tool takes none.
func OrgRulesFile(tool string) string { return orgRulesFiles[tool] }

// WithOrgRules returns spec running the org's rules in addition to Warden's
// (never instead of them):
//
//   - Opengrep gets a second --config /rules/opengrep.yml. It names rules after
//     their config's directory, so their ids come out as "rules.org.<key>"
//     (sarif.Parse maps them back to "org.<key>").
//   - warden-gitleaks gets the mode org-rules, which extends Warden's config
//     with /rules/gitleaks.toml (see scanners/gitleaks/warden-gitleaks); the
//     findings still go through warden-redact.
//
// The mode is an argument set here, never anything from the upload. spec's
// own Command is not modified.
func WithOrgRules(spec ToolSpec) (ToolSpec, error) {
	file := OrgRulesFile(spec.Name)
	if file == "" || len(spec.Command) == 0 {
		return ToolSpec{}, fmt.Errorf("%s takes no org rules", spec.Name)
	}
	cmd := slices.Clone(spec.Command)
	switch spec.Name {
	case "opengrep":
		i := slices.Index(cmd, "/data/rules")
		if i < 1 || cmd[i-1] != "--config" {
			return ToolSpec{}, errors.New("opengrep command has no --config /data/rules")
		}
		cmd = slices.Insert(cmd, i+1, "--config", "/rules/"+file)
	case "gitleaks":
		if cmd[0] != "warden-gitleaks" {
			return ToolSpec{}, errors.New("gitleaks command is not warden-gitleaks")
		}
		cmd = slices.Insert(cmd, 1, "org-rules")
	}
	spec.Command, spec.OrgRules = cmd, file
	return spec, nil
}

// RuleTestTimeout bounds one rule test run (job test_rules).
const RuleTestTimeout = 2 * time.Minute

// RuleTestTool is the sandbox of a rule test: one draft org rule against a
// snippet under /src, with none of Warden's rules, so the results are the
// draft's alone. Gitleaks still goes through warden-redact (mode rules-only):
// the snippet may hold a real secret.
func RuleTestTool(tool string) (ToolSpec, error) {
	file := OrgRulesFile(tool)
	switch tool {
	case "opengrep":
		return ToolSpec{
			Name: "opengrep", Timeout: RuleTestTimeout, CPUs: "1", Memory: "2g",
			Command: []string{
				"opengrep", "scan", "--config", "/rules/" + file, "--disable-nosem",
				"--sarif", "--output", "/out/result.sarif", "/src",
			},
			TmpExec:     true,
			OKExitCodes: []int{0, 2},
			OrgRules:    file,
		}, nil
	case "gitleaks":
		return ToolSpec{
			Name: "gitleaks", Timeout: RuleTestTimeout, CPUs: "0.25", Memory: "512m",
			Command:      []string{"warden-gitleaks", "rules-only"},
			NeedsHMACKey: true,
			OrgRules:     file,
		}, nil
	}
	return ToolSpec{}, fmt.Errorf("%s takes no org rules", tool)
}

func (s ToolSpec) tmpfsSize() string {
	if s.TmpfsSize == "" {
		return "256m"
	}
	return s.TmpfsSize
}

func (s ToolSpec) sarifName() string {
	if s.SarifName == "" {
		return "result.sarif"
	}
	return s.SarifName
}

func (s ToolSpec) okExit(code int) bool {
	if len(s.OKExitCodes) == 0 {
		return code == 0
	}
	return slices.Contains(s.OKExitCodes, code)
}

type ToolStatus string

const (
	Queued    ToolStatus = "queued"
	Running   ToolStatus = "running"
	Succeeded ToolStatus = "succeeded"
	Failed    ToolStatus = "failed"
	Timeout   ToolStatus = "timeout"
	Skipped   ToolStatus = "skipped"
)

type ToolRun struct {
	Tool       string
	Status     ToolStatus
	DurationMS int64
	Sarif      string // path of the SARIF file when Succeeded
	Error      string
	// ExitCode is the tool's exit status when it failed by exiting (0 otherwise).
	ExitCode int
	// Artifacts: the path of each artifact the tool wrote as a regular file
	// within its size cap. A missing or oversized one is left out; that doesn't
	// fail the tool.
	Artifacts map[string]string
}

func ContainerName(scanID, tool string) string {
	return "warden-" + scanID + "-" + tool
}

type RunConfig struct {
	ScanID    string
	ScanDir   string // holds src/, out/<tool>/, secrets/hmac
	Image     string // must be pinned by digest
	Runtime   string // runsc in CI/prod
	MirrorDir string
}

func DockerArgv(spec ToolSpec, c RunConfig) ([]string, error) {
	if !immutableImage.MatchString(c.Image) {
		return nil, errors.New("scanner image must be pinned by digest")
	}
	tmpExec := "noexec"
	if spec.TmpExec {
		tmpExec = "exec"
	}
	argv := []string{
		"docker", "run", "--rm",
		"--name", ContainerName(c.ScanID, spec.Name),
		"--label", LabelScan + "=" + c.ScanID,
		"--runtime=" + c.Runtime,
		"--network=none",
		"--read-only",
		"--tmpfs", "/tmp:rw," + tmpExec + ",nosuid,size=" + spec.tmpfsSize() + ",mode=1777",
		"--user", SandboxUID,
		"--cap-drop=ALL",
		"--security-opt=no-new-privileges",
		"--pids-limit=256",
		"--cpus=" + spec.CPUs,
		"--memory=" + spec.Memory,
		"--memory-swap=" + spec.Memory,
		"--workdir", "/tmp",
		"--env", "HOME=/tmp",
		"-v", filepath.Join(c.ScanDir, "src") + ":/src:ro",
		"-v", filepath.Join(c.ScanDir, "out", spec.Name) + ":/out:rw",
		"-v", filepath.Join(c.MirrorDir, spec.Name) + ":/data:ro",
	}
	if spec.NeedsHMACKey {
		argv = append(argv, "-v", filepath.Join(c.ScanDir, "secrets", "hmac")+":/run/warden/hmac:ro")
	}
	if spec.OrgRules != "" {
		// Only this tool's file: no tool sees another's rules.
		if spec.OrgRules != OrgRulesFile(spec.Name) {
			return nil, fmt.Errorf("%s: unexpected org rules file %q", spec.Name, spec.OrgRules)
		}
		argv = append(argv, "-v", filepath.Join(c.ScanDir, RulesDir, spec.OrgRules)+":/rules/"+spec.OrgRules+":ro")
	}
	argv = append(argv, "--entrypoint", spec.Command[0], c.Image)
	return append(argv, spec.Command[1:]...), nil
}

// Kill removes the tool's container; used on timeout and cancel.
func Kill(scanID, tool string) {
	ctx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
	defer cancel()
	_ = exec.CommandContext(ctx, "docker", "rm", "-f", ContainerName(scanID, tool)).Run()
}

// tailWriter keeps the last n bytes written.
type tailWriter struct {
	n   int
	buf []byte
}

func (w *tailWriter) Write(p []byte) (int, error) {
	w.buf = append(w.buf, p...)
	if len(w.buf) > w.n {
		w.buf = w.buf[len(w.buf)-w.n:]
	}
	return len(p), nil
}

func Run(ctx context.Context, spec ToolSpec, c RunConfig) ToolRun {
	outDir := filepath.Join(c.ScanDir, "out", spec.Name)
	if err := os.MkdirAll(outDir, 0o700); err != nil {
		return ToolRun{Tool: spec.Name, Status: Failed, Error: err.Error()}
	}
	// The container runs as 65532 and must be able to write its report.
	if err := os.Chmod(outDir, 0o777); err != nil {
		return ToolRun{Tool: spec.Name, Status: Failed, Error: err.Error()}
	}
	argv, err := DockerArgv(spec, c)
	if err != nil {
		return ToolRun{Tool: spec.Name, Status: Failed, Error: err.Error()}
	}

	ctx, cancel := context.WithTimeout(ctx, spec.Timeout)
	defer cancel()
	started := time.Now()
	stderr := &tailWriter{n: StderrTail}
	cmd := exec.CommandContext(ctx, "docker", argv[1:]...) // argv[0] is always "docker"
	cmd.Stdout = io.Discard
	cmd.Stderr = stderr
	cmd.WaitDelay = 10 * time.Second
	err = cmd.Run()
	ms := time.Since(started).Milliseconds()

	// Killing the docker CLI doesn't stop the container; remove it explicitly.
	if ctx.Err() != nil {
		Kill(c.ScanID, spec.Name)
		if errors.Is(ctx.Err(), context.DeadlineExceeded) {
			return ToolRun{Tool: spec.Name, Status: Timeout, DurationMS: ms, Error: "timeout"}
		}
		return ToolRun{Tool: spec.Name, Status: Failed, DurationMS: ms, Error: "cancelled"}
	}
	code := 0
	if err != nil {
		var exitErr *exec.ExitError
		if !errors.As(err, &exitErr) {
			return ToolRun{Tool: spec.Name, Status: Failed, DurationMS: ms, Error: err.Error()}
		}
		code = exitErr.ExitCode()
	}
	sarif := filepath.Join(outDir, spec.sarifName())
	st, statErr := os.Lstat(sarif)
	if !spec.okExit(code) || statErr != nil || !st.Mode().IsRegular() {
		msg := string(stderr.buf)
		if msg == "" {
			msg = fmt.Sprintf("exit %d", code)
		}
		return ToolRun{Tool: spec.Name, Status: Failed, DurationMS: ms, Error: msg, ExitCode: code}
	}
	return ToolRun{Tool: spec.Name, Status: Succeeded, DurationMS: ms, Sarif: sarif, Artifacts: artifacts(spec, outDir)}
}

// artifacts returns the tool's artifacts that are regular files (Lstat: a
// symlink the tool planted is not followed) within their size caps.
func artifacts(spec ToolSpec, outDir string) map[string]string {
	if len(spec.Artifacts) == 0 {
		return nil
	}
	out := map[string]string{}
	for name, a := range spec.Artifacts {
		p := filepath.Join(outDir, a.File)
		if st, err := os.Lstat(p); err == nil && st.Mode().IsRegular() && st.Size() <= a.MaxBytes {
			out[name] = p
		}
	}
	return out
}
