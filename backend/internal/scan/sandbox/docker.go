package sandbox

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"os/exec"
	"regexp"
	"sort"
	"strings"
	"time"
)

// LabelScan marks every scanner container with its scan id
// (warden.scan=<id>), so operators and the worker's startup cleanup can tell
// Warden's containers from others (`docker ps --filter label=warden.scan`).
const LabelScan = "warden.scan"

// Runner runs one docker CLI command, given as argv (never through a shell),
// and returns its standard output. Tests substitute a fake.
type Runner interface {
	Run(ctx context.Context, argv ...string) ([]byte, error)
}

// ExecRunner runs commands with os/exec. Output is capped: these commands
// print a few lines, and the worker must not buffer an unbounded stream.
type ExecRunner struct{}

const maxCommandOutput = 1 << 20

func (ExecRunner) Run(ctx context.Context, argv ...string) ([]byte, error) {
	if len(argv) == 0 || argv[0] != "docker" {
		return nil, errors.New("sandbox: only docker commands are run")
	}
	cmd := exec.CommandContext(ctx, "docker", argv[1:]...)
	var stdout capped
	stdout.n = maxCommandOutput
	stderr := &tailWriter{n: 512}
	cmd.Stdout, cmd.Stderr = &stdout, stderr
	cmd.WaitDelay = 5 * time.Second
	if err := cmd.Run(); err != nil {
		if msg := strings.TrimSpace(string(stderr.buf)); msg != "" {
			return stdout.Bytes(), fmt.Errorf("%s: %w: %s", argv[1], err, msg)
		}
		return stdout.Bytes(), fmt.Errorf("%s: %w", argv[1], err)
	}
	return stdout.Bytes(), nil
}

// capped keeps the first n bytes written and drops the rest.
type capped struct {
	bytes.Buffer
	n int
}

func (c *capped) Write(p []byte) (int, error) {
	if room := c.n - c.Len(); room > 0 {
		c.Buffer.Write(p[:min(len(p), room)])
	}
	return len(p), nil
}

// Runtimes lists the OCI runtimes the Docker daemon knows (runc, runsc, …).
// An error means the daemon is unreachable.
func Runtimes(ctx context.Context, r Runner) ([]string, error) {
	ctx, cancel := context.WithTimeout(ctx, 15*time.Second)
	defer cancel()
	out, err := r.Run(ctx, "docker", "info", "--format", "{{json .Runtimes}}")
	if err != nil {
		return nil, err
	}
	var m map[string]json.RawMessage
	if err := json.Unmarshal(bytes.TrimSpace(out), &m); err != nil {
		return nil, fmt.Errorf("docker info: unexpected runtimes output: %w", err)
	}
	names := make([]string, 0, len(m))
	for n := range m {
		names = append(names, n)
	}
	sort.Strings(names)
	return names, nil
}

// ImagePresent reports whether the image is in the local store.
func ImagePresent(ctx context.Context, r Runner, ref string) bool {
	ctx, cancel := context.WithTimeout(ctx, 15*time.Second)
	defer cancel()
	_, err := r.Run(ctx, "docker", "image", "inspect", "--format", "{{.Id}}", "--", ref)
	return err == nil
}

// ErrNotPullable: a local image ID (sha256:…) names content, not a
// registry location; it can only be built or loaded on this host.
var ErrNotPullable = errors.New("a local image ID can't be pulled")

// PullTimeout bounds one image pull.
const PullTimeout = 10 * time.Minute

// Pull fetches a digest-pinned registry image. The digest makes the content
// what the configuration names, wherever it comes from.
func Pull(ctx context.Context, r Runner, ref string) error {
	if !immutableImage.MatchString(ref) {
		return errors.New("scanner image must be pinned by digest")
	}
	if strings.HasPrefix(ref, "sha256:") {
		return ErrNotPullable
	}
	ctx, cancel := context.WithTimeout(ctx, PullTimeout)
	defer cancel()
	_, err := r.Run(ctx, "docker", "pull", "--quiet", "--", ref)
	return err
}

// Container is a scanner container left on the host.
type Container struct {
	Name   string
	ScanID string
	Tool   string
}

// scannerName is ContainerName's exact shape: the worker names containers
// after the scan's UUID and a known tool. Nothing else is ever removed, so
// another project's "warden-…" containers (Compose names this project's own
// services warden-api-1 and so on) are never touched.
var scannerName = regexp.MustCompile(`^warden-([0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12})-(gitleaks|opengrep|trivy|checkov)$`)

// ParseContainerName returns the scan id and tool of a name ContainerName
// made for a scan (a UUID) and a known tool; ok is false for anything else.
func ParseContainerName(name string) (scanID, tool string, ok bool) {
	m := scannerName.FindStringSubmatch(name)
	if m == nil {
		return "", "", false
	}
	return m[1], m[2], true
}

// ScannerContainers lists containers (running or not) named like scanner
// containers. One whose warden.scan label disagrees with its name is left
// out: it is not one Warden made.
func ScannerContainers(ctx context.Context, r Runner) ([]Container, error) {
	ctx, cancel := context.WithTimeout(ctx, 30*time.Second)
	defer cancel()
	out, err := r.Run(ctx, "docker", "ps", "--all", "--no-trunc", "--filter", "name=warden-", // a substring; scannerName decides
		"--format", `{{.Names}}{{"\t"}}{{.Label "`+LabelScan+`"}}`)
	if err != nil {
		return nil, err
	}
	var cs []Container
	for _, line := range strings.Split(string(out), "\n") {
		name, label, _ := strings.Cut(strings.TrimSpace(line), "\t")
		m := scannerName.FindStringSubmatch(name)
		if m == nil || (label != "" && label != m[1]) {
			continue
		}
		cs = append(cs, Container{Name: name, ScanID: m[1], Tool: m[2]})
	}
	return cs, nil
}

// RemoveContainer force-removes a scanner container by name.
func RemoveContainer(ctx context.Context, r Runner, name string) error {
	if !scannerName.MatchString(name) {
		return errors.New("not a scanner container name")
	}
	ctx, cancel := context.WithTimeout(ctx, 30*time.Second)
	defer cancel()
	_, err := r.Run(ctx, "docker", "rm", "--force", "--", name)
	return err
}
