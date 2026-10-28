package worker

import (
	"context"
	"time"

	"github.com/google/uuid"
	"github.com/jackc/pgx/v5"
	"github.com/riverqueue/river"

	"github.com/aupv9/warden/backend/internal/notify"
	"github.com/aupv9/warden/backend/internal/secretbox"
	"github.com/aupv9/warden/backend/internal/webhook"
)

// WebhookSettings configure webhook delivery.
type WebhookSettings struct {
	// Keys decrypt URLs and secrets (secrets.key); nil fails every delivery
	// with key_unavailable.
	Keys *secretbox.Keyring
	// Client sends (webhook.NewClient with webhook.allow_hosts).
	Client *webhook.Client
	// FailureLimit: consecutive failed deliveries before a webhook is turned off.
	FailureLimit int
}

// SendWebhooksArgs sends due webhook deliveries in every org. It runs every
// minute (retries are minutes apart at the least), after each notification
// dispatch, and when a test is queued. Like dispatch it is not unique: the
// lease on next_at makes concurrent runs split the work.
type SendWebhooksArgs struct{}

func (SendWebhooksArgs) Kind() string { return "send_webhooks" }

type SendWebhooksWorker struct {
	river.WorkerDefaults[SendWebhooksArgs]
	Env *Env
}

// Timeout covers one run's per-org budget (webhook.Sender) with room to spare;
// River's default (one minute) would cut a batch of slow endpoints short.
func (w SendWebhooksWorker) Timeout(*river.Job[SendWebhooksArgs]) time.Duration {
	return 10 * time.Minute
}

func (w SendWebhooksWorker) Work(ctx context.Context, _ *river.Job[SendWebhooksArgs]) error {
	if w.Env == nil {
		return errNoEnv
	}
	return w.Env.SendWebhooks(ctx)
}

// PruneWebhookDeliveriesArgs deletes deliveries older than 30 days (hourly).
type PruneWebhookDeliveriesArgs struct{}

func (PruneWebhookDeliveriesArgs) Kind() string { return "prune_webhook_deliveries" }

type PruneWebhookDeliveriesWorker struct {
	river.WorkerDefaults[PruneWebhookDeliveriesArgs]
	Env *Env
}

func (w PruneWebhookDeliveriesWorker) Work(ctx context.Context, _ *river.Job[PruneWebhookDeliveriesArgs]) error {
	if w.Env == nil {
		return errNoEnv
	}
	return w.Env.PruneWebhookDeliveries(ctx)
}

// kickWebhooks enqueues a send after a dispatch that may have queued
// deliveries. Best effort, like kickDispatch.
func kickWebhooks(ctx context.Context) {
	if c, err := river.ClientFromContextSafely[pgx.Tx](ctx); err == nil {
		_, _ = c.Insert(ctx, SendWebhooksArgs{}, nil)
	}
}

func (e *Env) webhookQueue() *webhook.Queue {
	return &webhook.Queue{BaseURL: e.PublicBaseURL, Now: e.Now, Log: e.Log}
}

func (e *Env) webhookSender() *webhook.Sender {
	client := e.Webhooks.Client
	if client == nil {
		client = webhook.NewClient(webhook.Policy{}, webhook.ClientOptions{})
	}
	return &webhook.Sender{
		Tx: func(ctx context.Context, org uuid.UUID, fn func(notify.DB) error) error {
			return e.Tx(ctx, org, func(db DB) error { return fn(db) })
		},
		Keys: e.Webhooks.Keys, Client: client, FailureLimit: e.Webhooks.FailureLimit, Now: e.Now, Log: e.Log,
	}
}

// SendWebhooks delivers every org's due webhook deliveries. A webhook turned
// off on the way emits webhook.disabled, which the dispatch kicked here sends.
func (e *Env) SendWebhooks(ctx context.Context) error {
	s := e.webhookSender()
	disabled := false
	err := e.forEachOrg(ctx, "send_webhooks", func(org uuid.UUID) error {
		d, err := s.DeliverOrg(ctx, org)
		disabled = disabled || d
		return err
	})
	if disabled {
		kickDispatch(ctx)
	}
	return err
}

// PruneWebhookDeliveries deletes every org's deliveries older than 30 days.
func (e *Env) PruneWebhookDeliveries(ctx context.Context) error {
	s := e.webhookSender()
	return e.forEachOrg(ctx, "prune_webhook_deliveries", func(org uuid.UUID) error {
		n, err := s.Prune(ctx, org)
		if n > 0 {
			e.Log.Info("pruned webhook deliveries", "org_id", org, "deleted", n)
		}
		return err
	})
}
