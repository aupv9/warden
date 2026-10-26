// warden-worker runs background jobs: scans (queue "scan"), notifications and
// periodic sweeps (queue "default").
package main

import (
	"context"
	"errors"
	"fmt"
	"log/slog"
	"os"
	"time"

	"github.com/aupv9/common-go/health"
	"github.com/jackc/pgx/v5"
	"github.com/jackc/pgx/v5/pgxpool"
	"github.com/riverqueue/river"
	"go.uber.org/fx"

	"github.com/aupv9/warden/backend/internal/app"
	"github.com/aupv9/warden/backend/internal/config"
	"github.com/aupv9/warden/backend/internal/db"
	"github.com/aupv9/warden/backend/internal/storage"
	"github.com/aupv9/warden/backend/internal/worker"
)

func main() {
	cfg, err := config.Load()
	if err != nil {
		fmt.Fprintln(os.Stderr, err)
		os.Exit(2)
	}
	fx.New(
		app.Core(cfg),
		db.Module,
		fx.Provide(
			func() (*storage.Client, error) {
				sc := storage.FromSection(cfg.Storage)
				sc.MaxObjectBytes = int64(cfg.Scan.UploadMaxMB) << 20
				return storage.New(sc)
			},
			func(pool *pgxpool.Pool, store *storage.Client, log *slog.Logger) (*worker.Env, error) {
				return worker.NewEnv(cfg, pool, store, log)
			},
			func(pool *pgxpool.Pool, env *worker.Env) (*river.Client[pgx.Tx], error) {
				return worker.NewClient(pool, worker.Options{ScanTimeout: cfg.Scan.Timeout, ScanSlots: cfg.Scan.SlotsPerNode, Env: env})
			},
		),
		fx.Invoke(registerStorageCheck, run),
		// Running scans must finish their cleanup (source deletion) before exit.
		fx.StopTimeout(cfg.Scan.Timeout+10*time.Minute),
	).Run()
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

func run(lc fx.Lifecycle, client *river.Client[pgx.Tx]) {
	lc.Append(fx.Hook{
		// River's context is its lifetime; fx's OnStart context ends after startup.
		OnStart: func(context.Context) error { return client.Start(context.Background()) },
		OnStop:  client.Stop,
	})
}
