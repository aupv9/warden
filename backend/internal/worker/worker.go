// Package worker defines the background jobs (River, Postgres-backed). Scans run
// on the "scan" queue; notifications and sweeps on "default".
package worker

import (
	"context"
	"errors"
	"time"

	"github.com/jackc/pgx/v5"
	"github.com/jackc/pgx/v5/pgxpool"
	"github.com/riverqueue/river"
	"github.com/riverqueue/river/riverdriver/riverpgxv5"

	"github.com/aupv9/warden/backend/internal/scan/orchestrator"
)

const (
	QueueScan = "scan"
	// MaxScanAttempts: a scan whose worker died is retried exactly once.
	MaxScanAttempts = 2
)

var errNoEnv = river.JobCancel(errors.New("worker has no job environment"))

// ScanArgs is enqueued by the API on scan start. Field names and JSON are a
// contract with the API: keep them stable.
type ScanArgs struct {
	orchestrator.Job
}

func (ScanArgs) Kind() string { return "run_scan" }

func (ScanArgs) InsertOpts() river.InsertOpts {
	return river.InsertOpts{Queue: QueueScan, MaxAttempts: MaxScanAttempts}
}

type ScanWorker struct {
	river.WorkerDefaults[ScanArgs]
	Env        *Env
	MaxRuntime time.Duration
}

func (w *ScanWorker) Timeout(*river.Job[ScanArgs]) time.Duration { return w.MaxRuntime }

func (w *ScanWorker) Work(ctx context.Context, job *river.Job[ScanArgs]) error {
	if w.Env == nil {
		return errNoEnv
	}
	return w.Env.RunScan(ctx, job.Args.Job, job.Attempt)
}

type PurgeExpiredSourcesArgs struct{}

func (PurgeExpiredSourcesArgs) Kind() string { return "purge_expired_sources" }

type PurgeExpiredSourcesWorker struct {
	river.WorkerDefaults[PurgeExpiredSourcesArgs]
	Env *Env
}

func (w PurgeExpiredSourcesWorker) Work(ctx context.Context, _ *river.Job[PurgeExpiredSourcesArgs]) error {
	if w.Env == nil {
		return errNoEnv
	}
	return w.Env.PurgeExpiredSources(ctx)
}

type ReopenExpiredRiskAcceptedArgs struct{}

func (ReopenExpiredRiskAcceptedArgs) Kind() string { return "reopen_expired_risk_accepted" }

type ReopenExpiredRiskAcceptedWorker struct {
	river.WorkerDefaults[ReopenExpiredRiskAcceptedArgs]
	Env *Env
}

func (w ReopenExpiredRiskAcceptedWorker) Work(ctx context.Context, _ *river.Job[ReopenExpiredRiskAcceptedArgs]) error {
	if w.Env == nil {
		return errNoEnv
	}
	return w.Env.ReopenExpiredRiskAccepted(ctx)
}

// HourlyAt fires once an hour at the given minute.
type HourlyAt int

func (m HourlyAt) Next(now time.Time) time.Time {
	next := now.Truncate(time.Hour).Add(time.Duration(m) * time.Minute)
	if !next.After(now) {
		next = next.Add(time.Hour)
	}
	return next
}

type Options struct {
	ScanTimeout time.Duration
	ScanSlots   int
	// Env runs the jobs. Without it (queue plumbing tests) every job is
	// cancelled and no periodic job is scheduled.
	Env *Env
}

// Config builds the River configuration. ScanSlots=0 gives an insert-only
// client (the API enqueues scans but doesn't run them).
func Config(opts Options) (*river.Config, error) {
	cfg := &river.Config{}
	if opts.ScanSlots <= 0 {
		return cfg, nil
	}
	workers := river.NewWorkers()
	river.AddWorker(workers, &ScanWorker{Env: opts.Env, MaxRuntime: opts.ScanTimeout + finalizeTimeout + time.Minute})
	river.AddWorker(workers, PurgeExpiredSourcesWorker{Env: opts.Env})
	river.AddWorker(workers, ReopenExpiredRiskAcceptedWorker{Env: opts.Env})
	cfg.Workers = workers
	cfg.Queues = map[string]river.QueueConfig{
		QueueScan:          {MaxWorkers: opts.ScanSlots},
		river.QueueDefault: {MaxWorkers: 10},
	}
	// Must exceed the job's runtime, or a running scan would be "rescued" and run twice.
	cfg.RescueStuckJobsAfter = opts.ScanTimeout + finalizeTimeout + 10*time.Minute
	if opts.Env == nil {
		return cfg, nil
	}
	cfg.PeriodicJobs = []*river.PeriodicJob{
		river.NewPeriodicJob(river.PeriodicInterval(10*time.Minute),
			func() (river.JobArgs, *river.InsertOpts) { return PurgeExpiredSourcesArgs{}, nil },
			&river.PeriodicJobOpts{ID: "purge_expired_sources", RunOnStart: true}),
		river.NewPeriodicJob(HourlyAt(15),
			func() (river.JobArgs, *river.InsertOpts) { return ReopenExpiredRiskAcceptedArgs{}, nil },
			&river.PeriodicJobOpts{ID: "reopen_expired_risk_accepted"}),
	}
	return cfg, nil
}

// NewClient builds the River client. Pass Options{} with ScanSlots=0 for an
// insert-only client.
func NewClient(pool *pgxpool.Pool, opts Options) (*river.Client[pgx.Tx], error) {
	cfg, err := Config(opts)
	if err != nil {
		return nil, err
	}
	return river.NewClient(riverpgxv5.New(pool), cfg)
}
