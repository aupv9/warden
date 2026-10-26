package worker

import (
	"context"
	"time"

	"github.com/google/uuid"
	"github.com/riverqueue/river"

	"github.com/aupv9/warden/backend/internal/notify"
)

// DispatchNotificationsArgs runs the notification dispatcher over every org.
// The API enqueues it with each outbox event; River keeps at most one per
// dedupe period, and the periodic run every minute catches the rest.
type DispatchNotificationsArgs struct{}

func (DispatchNotificationsArgs) Kind() string { return "dispatch_notifications" }

func (DispatchNotificationsArgs) InsertOpts() river.InsertOpts {
	return river.InsertOpts{UniqueOpts: river.UniqueOpts{ByPeriod: 5 * time.Second}}
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
