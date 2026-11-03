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
	"github.com/aupv9/warden/backend/internal/scan/zipcheck"
)

// Preflight checks the scanner host before the worker takes jobs, and cleans
// up after a crash:
//
//   - the Docker daemon answers and knows scan.sandbox_runtime;
//   - every configured scanner image is present, or is pulled (pinned by
//     digest, so what arrives is what the configuration names);
//   - scanner containers and scratch directories of scans that are no longer
//     queued or running are removed.
//
// With strict (app.env=prod) a failed check is returned and stops the
// worker; otherwise it is logged, so a laptop without gVisor or images still
// starts. Cleanup failures are only logged: they cost disk space, not safety.
func (e *Env) Preflight(ctx context.Context, docker sandbox.Runner, strict bool) error {
	var fatal []error
	problem := func(err error) {
		if strict {
			fatal = append(fatal, err)
			return
		}
		e.Log.Warn("worker preflight: "+err.Error()+"; scans may fail", "strict", false)
	}

	runtimes, err := sandbox.Runtimes(ctx, docker)
	daemon := err == nil
	switch {
	case err != nil:
		problem(fmt.Errorf("docker daemon unreachable: %w", err))
	case !slices.Contains(runtimes, e.Runtime):
		problem(fmt.Errorf("docker has no %q runtime (scan.sandbox_runtime); it knows %s", e.Runtime, strings.Join(runtimes, ", ")))
	}

	e.cleanup(ctx, docker, daemon)

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

// cleanup removes what crashed attempts left: containers (only with a
// reachable daemon) and scratch directories of scans that are not active.
// If the active scans can't be listed, nothing is removed: a running scan's
// files must never be deleted under it (several workers may share a host).
func (e *Env) cleanup(ctx context.Context, docker sandbox.Runner, daemon bool) {
	ctx, cancel := context.WithTimeout(ctx, 2*time.Minute)
	defer cancel()
	active, err := e.activeScans(ctx)
	if err != nil {
		e.Log.Warn("worker preflight: can't list active scans; leftover containers and scratch directories are kept", "err", err)
		return
	}
	if daemon {
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

// DockerChecker is the worker's "docker" readiness check: the daemon answers
// and still knows the sandbox runtime. Results are cached briefly, as each
// check runs the docker CLI. Only "unavailable" is reported; the reason is
// logged.
type DockerChecker struct {
	Docker  sandbox.Runner
	Runtime string
	TTL     time.Duration
	Now     func() time.Time
	Warn    func(msg string, args ...any)

	mu   sync.Mutex
	at   time.Time
	last error
}

var errDockerUnavailable = errors.New("unavailable")

func (c *DockerChecker) Name() string { return "docker" }

func (c *DockerChecker) Check(ctx context.Context) error {
	c.mu.Lock()
	defer c.mu.Unlock()
	if !c.at.IsZero() && c.Now().Sub(c.at) < c.TTL {
		return c.last
	}
	runtimes, err := sandbox.Runtimes(ctx, c.Docker)
	switch {
	case err != nil:
		c.Warn("docker readiness check failed", "err", err)
		c.last = errDockerUnavailable
	case !slices.Contains(runtimes, c.Runtime):
		c.Warn("docker readiness check failed: sandbox runtime missing", "runtime", c.Runtime)
		c.last = errDockerUnavailable
	default:
		c.last = nil
	}
	c.at = c.Now()
	return c.last
}
