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
		return ToolRun{Tool: spec.Name, Status: Failed, DurationMS: ms, Error: msg}
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
