// warden-worker runs background jobs: scans (queue "scan"), notifications and
// periodic sweeps (queue "default"). `warden-worker -healthcheck` probes a
// running instance's admin listener (admin.addr), as the worker has no other
// HTTP server and the container image has no shell or curl.
package main

import (
	"context"
	"errors"
	"flag"
	"fmt"
	"log/slog"
	"os"
	"sync"
	"time"

	"github.com/aupv9/common-go/health"
	"github.com/jackc/pgx/v5"
	"github.com/jackc/pgx/v5/pgxpool"
	"github.com/riverqueue/river"
	"go.uber.org/fx"

	"github.com/aupv9/warden/backend/internal/app"
	"github.com/aupv9/warden/backend/internal/config"
	"github.com/aupv9/warden/backend/internal/db"
	"github.com/aupv9/warden/backend/internal/metrics"
	"github.com/aupv9/warden/backend/internal/scan/sandbox"
	"github.com/aupv9/warden/backend/internal/storage"
	"github.com/aupv9/warden/backend/internal/worker"
)

func main() {
	healthcheck := flag.Bool("healthcheck", false, "GET /healthz on admin.addr and exit 0 if healthy")
	flag.Parse()
	cfg, err := config.LoadServer()
	if err != nil {
		fmt.Fprintln(os.Stderr, err)
		os.Exit(2)
	}
	if *healthcheck {
		os.Exit(app.ProbeAdmin(cfg.Admin.Addr))
	}
	fx.New(appOptions(cfg)).Run()
}

// appOptions is the worker's dependency graph.
func appOptions(cfg *config.Config) fx.Option {
	return fx.Options(
		app.Core(cfg),
		db.Module,
		fx.Supply(app.AdminHealth(true)),
		fx.Provide(
			func() (*storage.Client, error) {
				sc := storage.FromSection(cfg.Storage)
				// The download cap fits the largest upload of any kind; the
				// orchestrator applies each kind's own limit after the download.
				sc.MaxObjectBytes = int64(max(cfg.Scan.UploadMaxMB, cfg.Scan.ImageUploadMaxMB, cfg.Scan.HistoryUploadMaxMB, cfg.Scan.ImportMaxMB)) << 20
				return storage.New(sc)
			},
			func(pool *pgxpool.Pool, store *storage.Client, log *slog.Logger) (*worker.Env, error) {
				return worker.NewEnv(cfg, pool, store, log)
			},
			func(pool *pgxpool.Pool, env *worker.Env) (*river.Client[pgx.Tx], error) {
				return worker.NewClient(pool, worker.Options{ScanTimeout: cfg.Scan.Timeout, ScanSlots: cfg.Scan.SlotsPerNode, Env: env})
			},
		),
		// In this order: readiness checks, then the host checks and cleanup
		// (before any job can start a container), then River.
		fx.Invoke(registerStorageCheck, registerSandboxCheck, registerGauges, preflight, run),
		// Running scans must finish their cleanup (source deletion) before exit.
		fx.StopTimeout(cfg.Scan.Timeout+10*time.Minute),
	)
}

var errStorageUnavailable = errors.New("unavailable")

// registerStorageCheck reports only "unavailable"; the reason (endpoint, bucket,
// credentials) is logged.
func registerStorageCheck(reg *health.Registry, store *storage.Client, log *slog.Logger) {
	reg.Register(health.CheckerFunc{CheckerName: "storage", CheckFn: func(ctx context.Context) error {
		if err := store.Ping(ctx); err != nil {
			log.Warn("storage readiness check failed", slog.Any("error", err))
			return errStorageUnavailable
		}
		return nil
	}})
}

// registerSandboxCheck: "sandbox" is ready when the backend can run
// scanners (docker: the daemon and its runtime; kubernetes: the API server
// for the namespace and the RuntimeClass).
func registerSandboxCheck(c *config.Config, env *worker.Env, reg *health.Registry, log *slog.Logger) {
	probe := worker.DockerProbe(sandbox.ExecRunner{}, c.Scan.SandboxRuntime)
	if env.Kube != nil {
		probe = env.Kube.Ready
	}
	reg.Register(&worker.SandboxChecker{Probe: probe, TTL: 15 * time.Second, Now: time.Now, Warn: log.Warn})
}

// registerGauges: the queue depth and feed ages are read from the database
// on scrape; only the worker exports them, so several API replicas don't
// repeat the same series.
func registerGauges(pool *pgxpool.Pool, log *slog.Logger) error {
	return metrics.Registry.Register(metrics.NewDBGauges(pool, log))
}

// preflight checks the sandbox (docker: the daemon, the runtime and the
// images; kubernetes: the RuntimeClass, pinned images and a network canary)
// and removes what a crashed worker left behind. In prod a failed check
// stops the worker.
func preflight(c *config.Config, env *worker.Env) error {
	return env.Preflight(context.Background(), sandbox.ExecRunner{}, c.App.Env == config.EnvProd)
}

// run starts River once the database schema is the binary's: on an older
// one, jobs would fail on missing columns, so the worker waits (not ready)
// until warden-migrate has run.
func run(lc fx.Lifecycle, client *river.Client[pgx.Tx], gate *app.SchemaGate, sd fx.Shutdowner, log *slog.Logger) {
	// Only the wait is cancelled on stop. River gets its own context: it is
	// its lifetime, and cancelling it would cancel running scans instead of
	// letting Stop wait for them.
	waitCtx, cancelWait := context.WithCancel(context.Background())
	var wg sync.WaitGroup
	lc.Append(fx.Hook{
		OnStart: func(context.Context) error {
			wg.Add(1)
			go func() {
				defer wg.Done()
				if gate.Wait(waitCtx, 15*time.Second) != nil {
					return // stopping
				}
				if err := client.Start(context.Background()); err != nil {
					log.Error("job runner failed to start", "err", err)
					_ = sd.Shutdown(fx.ExitCode(1))
				}
			}()
			return nil
		},
		OnStop: func(ctx context.Context) error {
			cancelWait()
			wg.Wait()
			return client.Stop(ctx) // a no-op if River never started
		},
	})
}
