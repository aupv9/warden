package worker

import (
	"context"
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"regexp"
	"slices"
	"strings"
	"sync"
	"time"

	"github.com/google/uuid"
	"github.com/jackc/pgx/v5"

	"github.com/aupv9/warden/backend/internal/scan/sandbox"
	"github.com/aupv9/warden/backend/internal/scan/sandbox/kube"
	"github.com/aupv9/warden/backend/internal/scan/zipcheck"
)

// Preflight checks the scanner sandbox before the worker takes jobs, and
// cleans up after a crash. With the docker backend:
//
//   - the Docker daemon answers and knows scan.sandbox_runtime;
//   - every configured scanner image is present, or is pulled (pinned by
//     digest, so what arrives is what the configuration names);
//   - scanner containers and scratch directories of scans that are no longer
//     queued or running are removed.
//
// With the kubernetes backend, preflightKube.
//
// With strict (app.env=prod) a failed check is returned and stops the
// worker; otherwise it is logged, so a laptop without gVisor or images still
// starts. Cleanup failures are only logged: they cost disk space, not safety.
func (e *Env) Preflight(ctx context.Context, docker sandbox.Runner, strict bool) error {
	if e.Kube != nil {
		return e.preflightKube(ctx, strict)
	}
	var fatal []error
	problem := e.problems(strict, &fatal)

	runtimes, err := sandbox.Runtimes(ctx, docker)
	daemon := err == nil
	switch {
	case err != nil:
		problem(fmt.Errorf("docker daemon unreachable: %w", err))
	case !slices.Contains(runtimes, e.Runtime):
		problem(fmt.Errorf("docker has no %q runtime (scan.sandbox_runtime); it knows %s", e.Runtime, strings.Join(runtimes, ", ")))
	}

	e.cleanup(ctx, func(ctx context.Context, active map[string]bool) {
		if daemon {
			e.removeContainers(ctx, docker, active)
		}
	})

	if daemon {
		for _, tool := range sandbox.ToolNames {
			ref := e.Images[tool]
			if ref == "" || sandbox.ImagePresent(ctx, docker, ref) {
				continue // a missing setting is reported by NewEnv (and refused in prod by config)
			}
			e.Log.Info("pulling scanner image", "tool", tool, "image", ref)
			if err := sandbox.Pull(ctx, docker, ref); err != nil {
				problem(fmt.Errorf("scan.images.%s: image not present and not pulled: %w", tool, err))
			}
		}
	}
	return errors.Join(fatal...)
}

// problems returns the reporter of failed checks: collected into fatal when
// strict, logged otherwise.
func (e *Env) problems(strict bool, fatal *[]error) func(error) {
	return func(err error) {
		if strict {
			*fatal = append(*fatal, err)
			return
		}
		e.Log.Warn("worker preflight: "+err.Error()+"; scans may fail", "strict", false)
	}
}

// preflightKube checks the kubernetes sandbox:
//
//   - every scanner image and scan.kube.io_image is name@sha256:<digest>: a
//     kubelet pulls them (by digest, so what runs is what the configuration
//     names), and can't pull a local image ID;
//   - scan.kube.runtime_class exists with handler runsc. The worker's Role is
//     namespaced and may not read RuntimeClasses (cluster-scoped); then the
//     canary's own check stands in for it;
//   - scanner Pods and scratch directories of scans that are no longer
//     queued or running are removed;
//   - a canary Pod, with the scanner Pods' settings, tries TCP connections
//     to the internet (1.1.1.1:443), the API server's service and the
//     cluster DNS (when the worker runs in the cluster). If any connects the
//     namespace isn't isolated (no default-deny NetworkPolicy, or a CNI that
//     doesn't enforce one); a canary that doesn't run on gVisor means the
//     RuntimeClass isn't gVisor. Either is fatal in prod, as is a canary that
//     can't run: isolation would be unknown.
func (e *Env) preflightKube(ctx context.Context, strict bool) error {
	var fatal []error
	problem := e.problems(strict, &fatal)
	k := e.Kube
	ctx, cancel := context.WithTimeout(ctx, kube.PreflightTimeout)
	defer cancel()

	for _, tool := range sandbox.ToolNames {
		if ref := e.Images[tool]; ref != "" && !kube.Pinned(ref) {
			problem(fmt.Errorf("scan.images.%s: the kubernetes backend needs a registry image pinned as name@sha256:<digest> (a kubelet can't pull a local image ID)", tool))
		}
	}
	if !kube.Pinned(k.IOImage) {
		problem(errors.New("scan.kube.io_image is not pinned as name@sha256:<digest>"))
	}

	rc, rcErr := k.RuntimeClass(ctx)
	switch rc {
	case kube.RuntimeClassBad:
		problem(rcErr)
	case kube.RuntimeClassUnknown:
		e.Log.Warn("worker preflight: "+rcErr.Error()+"; the canary checks for gVisor from inside a pod instead",
			"runtime_class", k.Config.RuntimeClass)
	}

	e.cleanup(ctx, func(ctx context.Context, active map[string]bool) { e.removePods(ctx, active) })

	var extra []string
	if dns := k.ClusterDNS(); dns != "" {
		extra = append(extra, dns)
	}
	res, err := k.Canary(ctx, extra)
	switch {
	case err != nil:
		problem(fmt.Errorf("network canary in %s: %w; the sandbox's isolation is unknown", k.Namespace, err))
	case len(res.Reached) > 0:
		problem(fmt.Errorf("sandbox namespace %s is not isolated: a canary pod connected to %s (it needs a default-deny NetworkPolicy and a CNI that enforces it)",
			k.Namespace, strings.Join(res.Reached, ", ")))
	}
	if err == nil && !res.GVisor {
		if rc == kube.RuntimeClassGVisor {
			e.Log.Warn("worker preflight: the canary pod did not detect gVisor, although the RuntimeClass's handler is runsc")
		} else {
			problem(fmt.Errorf("the canary pod did not run on gVisor (scan.kube.runtime_class %q)", k.Config.RuntimeClass))
		}
	}
	if err == nil && len(res.Reached) == 0 {
		e.Log.Info("sandbox namespace isolated", "namespace", k.Namespace, "tried", res.Tried, "gvisor", res.GVisor)
	}
	return errors.Join(fatal...)
}

// activeScans are the scans that may own a container or scratch directory
// right now: queued (a worker may be about to start it: RunScan clears the
// scratch directory before marking it running) or running. Rule tests
// (ruletest.go) name theirs after the test, so active tests count too.
func (e *Env) activeScans(ctx context.Context) (map[string]bool, error) {
	active := map[string]bool{}
	var mu sync.Mutex
	err := e.forEachOrg(ctx, "preflight_cleanup", func(org uuid.UUID) error {
		return e.Tx(ctx, org, func(db DB) error {
			rows, err := db.Query(ctx, `SELECT id FROM scan WHERE status IN ('queued', 'running')
				UNION ALL SELECT id FROM scan_rule_test WHERE state IN ('queued', 'running')`)
			if err != nil {
				return err
			}
			ids, err := pgx.CollectRows(rows, pgx.RowTo[uuid.UUID])
			mu.Lock()
			defer mu.Unlock()
			for _, id := range ids {
				active[id.String()] = true
			}
			return err
		})
	})
	return active, err
}

// scratchName is a per-scan scratch directory: the scan id, as RunScan names it.
var scratchName = regexp.MustCompile(`^[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}$`)

// cleanup removes what crashed attempts left: the backend's containers or
// Pods (sandboxes) and scratch directories of scans that are not active. If
// the active scans can't be listed, nothing is removed: a running scan's
// files must never be deleted under it (several workers may share a host or
// a namespace).
func (e *Env) cleanup(ctx context.Context, sandboxes func(context.Context, map[string]bool)) {
	ctx, cancel := context.WithTimeout(ctx, 2*time.Minute)
	defer cancel()
	active, err := e.activeScans(ctx)
	if err != nil {
		e.Log.Warn("worker preflight: can't list active scans; leftover containers and scratch directories are kept", "err", err)
		return
	}
	sandboxes(ctx, active)
	entries, err := os.ReadDir(e.ScratchDir)
	if err != nil {
		if !errors.Is(err, os.ErrNotExist) {
			e.Log.Warn("worker preflight: can't read scan.scratch_dir", "err", err)
		}
		return
	}
	for _, d := range entries {
		// Only directories named like a scan: anything else in scratch_dir is
		// not Warden's to delete. A symlink is never followed.
		if !d.IsDir() || d.Type()&os.ModeSymlink != 0 || !scratchName.MatchString(d.Name()) || active[d.Name()] {
			continue
		}
		if err := zipcheck.RemoveAll(filepath.Join(e.ScratchDir, d.Name())); err != nil {
			e.Log.Warn("worker preflight: leftover scratch directory not removed", "scan_id", d.Name(), "err", err)
			continue
		}
		e.Log.Info("removed leftover scratch directory", "scan_id", d.Name())
	}
}

func (e *Env) removeContainers(ctx context.Context, docker sandbox.Runner, active map[string]bool) {
	cs, err := sandbox.ScannerContainers(ctx, docker)
	if err != nil {
		e.Log.Warn("worker preflight: can't list scanner containers", "err", err)
	}
	for _, c := range cs {
		if active[c.ScanID] {
			continue
		}
		if err := sandbox.RemoveContainer(ctx, docker, c.Name); err != nil {
			e.Log.Warn("worker preflight: leftover scanner container not removed", "container", c.Name, "err", err)
			continue
		}
		e.Log.Info("removed leftover scanner container", "container", c.Name, "scan_id", c.ScanID)
	}
}

func (e *Env) removePods(ctx context.Context, active map[string]bool) {
	pods, err := e.Kube.ScannerPods(ctx)
	if err != nil {
		e.Log.Warn("worker preflight: can't list scanner pods", "err", err)
	}
	for _, p := range pods {
		if active[p.ScanID] {
			continue
		}
		if err := e.Kube.RemovePod(ctx, p.Name); err != nil {
			e.Log.Warn("worker preflight: leftover scanner pod not removed", "pod", p.Name, "err", err)
			continue
		}
		e.Log.Info("removed leftover scanner pod", "pod", p.Name, "scan_id", p.ScanID)
	}
}

// SandboxChecker is the worker's "sandbox" readiness check: Probe says
// whether the backend can run scanners (DockerProbe, kube.Backend.Ready).
// Results are cached briefly. Only "unavailable" is reported; the reason is
// logged.
type SandboxChecker struct {
	Probe func(context.Context) error
	TTL   time.Duration
	Now   func() time.Time
	Warn  func(msg string, args ...any)

	mu   sync.Mutex
	at   time.Time
	last error
}

var errSandboxUnavailable = errors.New("unavailable")

func (c *SandboxChecker) Name() string { return "sandbox" }

func (c *SandboxChecker) Check(ctx context.Context) error {
	c.mu.Lock()
	defer c.mu.Unlock()
	if !c.at.IsZero() && c.Now().Sub(c.at) < c.TTL {
		return c.last
	}
	c.last = nil
	if err := c.Probe(ctx); err != nil {
		c.Warn("sandbox readiness check failed", "err", err)
		c.last = errSandboxUnavailable
	}
	c.at = c.Now()
	return c.last
}

// DockerProbe: the daemon answers and still knows the sandbox runtime.
func DockerProbe(docker sandbox.Runner, runtime string) func(context.Context) error {
	return func(ctx context.Context) error {
		runtimes, err := sandbox.Runtimes(ctx, docker)
		if err != nil {
			return err
		}
		if !slices.Contains(runtimes, runtime) {
			return fmt.Errorf("docker has no %q runtime", runtime)
		}
		return nil
	}
}
