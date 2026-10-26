package worker

import (
	"context"
	"time"

	"github.com/google/uuid"
	"github.com/jackc/pgx/v5"
	"github.com/riverqueue/river"

	"github.com/aupv9/warden/backend/internal/notify"
)

// DispatchNotificationsArgs runs the notification dispatcher over every org.
// Every transaction that writes outbox events enqueues one (the API in the same
// transaction, the worker right after its commit), and a periodic run every
// minute catches anything else. It is not unique: River's uniqueness also
// covers running and recently completed jobs, so an event committed just after
// a dispatch started would wait for the next periodic run. Dispatch is
// idempotent and takes rows with SKIP LOCKED, so extra runs are cheap no-ops.
type DispatchNotificationsArgs struct{}

func (DispatchNotificationsArgs) Kind() string { return "dispatch_notifications" }

// kickDispatch enqueues a dispatch after work that may have written outbox
// events outside the API (scan results, sweeps). Best effort: the periodic run
// delivers them anyway if this insert fails.
func kickDispatch(ctx context.Context) {
	if c, err := river.ClientFromContextSafely[pgx.Tx](ctx); err == nil {
		_, _ = c.Insert(ctx, DispatchNotificationsArgs{}, nil)
	}
}

type DispatchNotificationsWorker struct {
	river.WorkerDefaults[DispatchNotificationsArgs]
	Env *Env
}

func (w DispatchNotificationsWorker) Work(ctx context.Context, _ *river.Job[DispatchNotificationsArgs]) error {
	if w.Env == nil {
		return errNoEnv
	}
	return w.Env.DispatchNotifications(ctx)
}

// SLADigestArgs writes the daily SLA digest events.
type SLADigestArgs struct{}

func (SLADigestArgs) Kind() string { return "sla_digest" }

type SLADigestWorker struct {
	river.WorkerDefaults[SLADigestArgs]
	Env *Env
}

func (w SLADigestWorker) Work(ctx context.Context, _ *river.Job[SLADigestArgs]) error {
	if w.Env == nil {
		return errNoEnv
	}
	return w.Env.SLADigest(ctx)
}

// DailyAt fires once a day at the given UTC hour.
type DailyAt int

func (h DailyAt) Next(now time.Time) time.Time {
	now = now.UTC()
	next := now.Truncate(24 * time.Hour).Add(time.Duration(h) * time.Hour)
	if !next.After(now) {
		next = next.Add(24 * time.Hour)
	}
	return next
}

func (e *Env) dispatcher() *notify.Dispatcher {
	return &notify.Dispatcher{
		Tx: func(ctx context.Context, org uuid.UUID, fn func(notify.DB) error) error {
			return e.Tx(ctx, org, func(db DB) error { return fn(db) })
		},
		Mailer: e.Mailer, BaseURL: e.PublicBaseURL, Now: e.Now, Log: e.Log,
	}
}

// DispatchNotifications turns every org's outbox into notifications and sends
// due emails. One org's failure doesn't stop the others.
func (e *Env) DispatchNotifications(ctx context.Context) error {
	d := e.dispatcher()
	return e.forEachOrg(ctx, "dispatch_notifications", func(org uuid.UUID) error { return d.DispatchOrg(ctx, org) })
}

// SLADigest writes today's digest events (idempotent per user and UTC day).
func (e *Env) SLADigest(ctx context.Context) error {
	d := e.dispatcher()
	return e.forEachOrg(ctx, "sla_digest", func(org uuid.UUID) error {
		n, err := d.Digest(ctx, org)
		if n > 0 {
			e.Log.Info("sla digest queued", "org_id", org, "recipients", n)
		}
		return err
	})
}
