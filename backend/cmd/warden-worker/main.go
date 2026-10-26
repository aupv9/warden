// warden-worker runs background jobs: scans (queue "scan"), notifications and
// periodic sweeps (queue "default").
package main

import (
	"context"
	"fmt"
	"os"
	"time"

	"github.com/jackc/pgx/v5"
	"github.com/jackc/pgx/v5/pgxpool"
	"github.com/riverqueue/river"
	"go.uber.org/fx"

	"github.com/aupv9/warden/backend/internal/app"
	"github.com/aupv9/warden/backend/internal/config"
	"github.com/aupv9/warden/backend/internal/db"
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
		fx.Provide(func(pool *pgxpool.Pool) (*river.Client[pgx.Tx], error) {
			return worker.NewClient(pool, worker.Options{ScanTimeout: cfg.Scan.Timeout, ScanSlots: cfg.Scan.SlotsPerNode})
		}),
		fx.Invoke(run),
		// Running scans must finish their cleanup (source deletion) before exit.
		fx.StopTimeout(cfg.Scan.Timeout+5*time.Minute),
	).Run()
}

func run(lc fx.Lifecycle, client *river.Client[pgx.Tx]) {
	lc.Append(fx.Hook{
		// River's context is its lifetime; fx's OnStart context ends after startup.
		OnStart: func(context.Context) error { return client.Start(context.Background()) },
		OnStop:  client.Stop,
	})
}
