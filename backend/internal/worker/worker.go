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

var errNotImplemented = errors.New("scan persistence layer not implemented yet")

type ScanArgs struct {
	orchestrator.Job
}

func (ScanArgs) Kind() string { return "run_scan" }

func (ScanArgs) InsertOpts() river.InsertOpts {
	return river.InsertOpts{Queue: QueueScan, MaxAttempts: MaxScanAttempts}
}

type ScanWorker struct {
	river.WorkerDefaults[ScanArgs]
	MaxRuntime time.Duration
}

func (w *ScanWorker) Timeout(*river.Job[ScanArgs]) time.Duration { return w.MaxRuntime }

func (w *ScanWorker) Work(context.Context, *river.Job[ScanArgs]) error {
	// TODO: live orchestrator.Deps (S3, Postgres, Docker) → orchestrator.Execute → result processor.
	return river.JobCancel(errNotImplemented)
}

type PurgeExpiredSourcesArgs struct{}

func (PurgeExpiredSourcesArgs) Kind() string { return "purge_expired_sources" }

type PurgeExpiredSourcesWorker struct {
	river.WorkerDefaults[PurgeExpiredSourcesArgs]
}

func (PurgeExpiredSourcesWorker) Work(context.Context, *river.Job[PurgeExpiredSourcesArgs]) error {
	return river.JobCancel(errors.New("purge_expired_sources not implemented yet"))
}

type ReopenExpiredRiskAcceptedArgs struct{}

func (ReopenExpiredRiskAcceptedArgs) Kind() string { return "reopen_expired_risk_accepted" }

type ReopenExpiredRiskAcceptedWorker struct {
	river.WorkerDefaults[ReopenExpiredRiskAcceptedArgs]
}

func (ReopenExpiredRiskAcceptedWorker) Work(context.Context, *river.Job[ReopenExpiredRiskAcceptedArgs]) error {
	return river.JobCancel(errors.New("reopen_expired_risk_accepted not implemented yet"))
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
}

// NewClient builds the River client. Pass Options{} with ScanSlots=0 for an
// insert-only client (the API enqueues scans but doesn't run them).
func NewClient(pool *pgxpool.Pool, opts Options) (*river.Client[pgx.Tx], error) {
	cfg := &river.Config{}
	if opts.ScanSlots > 0 {
		workers := river.NewWorkers()
		river.AddWorker(workers, &ScanWorker{MaxRuntime: opts.ScanTimeout + 5*time.Minute})
		river.AddWorker(workers, PurgeExpiredSourcesWorker{})
		river.AddWorker(workers, ReopenExpiredRiskAcceptedWorker{})
		cfg.Workers = workers
		cfg.Queues = map[string]river.QueueConfig{
			QueueScan:          {MaxWorkers: opts.ScanSlots},
			river.QueueDefault: {MaxWorkers: 10},
		}
		// Must exceed the scan timeout, or a running scan would be "rescued" and run twice.
		cfg.RescueStuckJobsAfter = opts.ScanTimeout + 10*time.Minute
		cfg.PeriodicJobs = []*river.PeriodicJob{
			river.NewPeriodicJob(river.PeriodicInterval(10*time.Minute),
				func() (river.JobArgs, *river.InsertOpts) { return PurgeExpiredSourcesArgs{}, nil },
				&river.PeriodicJobOpts{ID: "purge_expired_sources"}),
			river.NewPeriodicJob(HourlyAt(15),
				func() (river.JobArgs, *river.InsertOpts) { return ReopenExpiredRiskAcceptedArgs{}, nil },
				&river.PeriodicJobOpts{ID: "reopen_expired_risk_accepted"}),
		}
	}
	return river.NewClient(riverpgxv5.New(pool), cfg)
}
