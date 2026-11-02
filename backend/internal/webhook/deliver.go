package webhook

import (
	"context"
	"errors"
	"log/slog"
	"strconv"
	"sync"
	"time"

	"github.com/google/uuid"
	"github.com/jackc/pgx/v5"

	"github.com/aupv9/warden/backend/internal/auditlog"
	"github.com/aupv9/warden/backend/internal/metrics"
	"github.com/aupv9/warden/backend/internal/notify"
	"github.com/aupv9/warden/backend/internal/secretbox"
)

// Retries is the wait before each retry of a retryable failure; a delivery is
// tried at most len(Retries)+1 times, over about 21 hours.
var Retries = []time.Duration{time.Minute, 5 * time.Minute, 30 * time.Minute, 2 * time.Hour, 6 * time.Hour, 12 * time.Hour}

const (
	// DefaultFailureLimit: after this many deliveries in a row end failed, the
	// webhook is turned off (webhook.failure_limit).
	DefaultFailureLimit = 10
	// Retention: deliveries older than this are pruned (and not listed).
	Retention = 30 * 24 * time.Hour

	claimBatch = 20
	// lease: a claimed delivery is retried after this if its sender died. It
	// must exceed a batch's sending time: claimBatch/parallel × Timeout.
	lease    = 5 * time.Minute
	parallel = 4
	// budget bounds one run per org, so a slow org doesn't hold the job.
	budget = 3 * time.Minute
)

// Sender delivers an org's due webhook deliveries (the send_webhooks job).
type Sender struct {
	Tx notify.TxFunc
	// Keys decrypts URLs and secrets; nil (no secrets.key) fails every
	// delivery with key_unavailable.
	Keys   *secretbox.Keyring
	Client *Client
	// FailureLimit: consecutive failed deliveries before the webhook is
	// turned off (DefaultFailureLimit when 0).
	FailureLimit int
	Now          func() time.Time
	Log          *slog.Logger
}

type claimed struct {
	ID        uuid.UUID
	WebhookID uuid.UUID
	Type      string
	Payload   string
	Attempts  int
	Kind      string
	Enabled   bool
	Sealed    Sealed
}

// DeliverOrg sends the org's due deliveries. It reports whether a webhook was
// turned off (a webhook.disabled event to dispatch).
func (s *Sender) DeliverOrg(ctx context.Context, org uuid.UUID) (bool, error) {
	deadline := s.Now().Add(budget)
	var disabledAny bool
	for s.Now().Before(deadline) && ctx.Err() == nil {
		batch, err := s.claim(ctx, org)
		if err != nil || len(batch) == 0 {
			return disabledAny, err
		}
		var (
			wg   sync.WaitGroup
			mu   sync.Mutex
			errs []error
			sem  = make(chan struct{}, parallel)
		)
		for _, c := range batch {
			wg.Add(1)
			sem <- struct{}{}
			go func() {
				defer func() { <-sem; wg.Done() }()
				disabled, err := s.deliver(ctx, org, c)
				mu.Lock()
				defer mu.Unlock()
				disabledAny = disabledAny || disabled
				if err != nil {
					errs = append(errs, err)
				}
			}()
		}
		wg.Wait()
		if err := errors.Join(errs...); err != nil {
			return disabledAny, err
		}
		if len(batch) < claimBatch {
			break
		}
	}
	return disabledAny, nil
}

// claim leases up to claimBatch due deliveries in a short transaction (SKIP
// LOCKED, so concurrent senders split the work).
func (s *Sender) claim(ctx context.Context, org uuid.UUID) ([]claimed, error) {
	now := s.Now().UTC()
	var out []claimed
	err := s.Tx(ctx, org, func(db notify.DB) error {
		rows, err := db.Query(ctx, `UPDATE webhook_delivery d SET next_at = $2
			FROM webhook w
			WHERE w.id = d.webhook_id AND d.id IN (
				SELECT id FROM webhook_delivery WHERE state = 'pending' AND next_at <= $1
				ORDER BY next_at, id LIMIT $3 FOR UPDATE SKIP LOCKED)
			RETURNING d.id, d.webhook_id, d.type, d.payload::text, d.attempts, w.kind, w.enabled, w.url_enc, w.secret_enc, w.key_id`,
			now, now.Add(lease), claimBatch)
		if err != nil {
			return err
		}
		out, err = pgx.CollectRows(rows, func(r pgx.CollectableRow) (claimed, error) {
			var c claimed
			return c, r.Scan(&c.ID, &c.WebhookID, &c.Type, &c.Payload, &c.Attempts, &c.Kind, &c.Enabled,
				&c.Sealed.URL, &c.Sealed.Secret, &c.Sealed.KeyID)
		})
		return err
	})
	return out, err
}

// outcome is what to record for one claimed delivery.
type outcome struct {
	attempted bool // an HTTP attempt was made (attempts and last_attempt_at change)
	result    Result
	final     bool // delivered or failed for good
}

func (s *Sender) deliver(ctx context.Context, org uuid.UUID, c claimed) (bool, error) {
	test := c.Type == notify.WebhookTest
	var o outcome
	switch {
	case !test && !c.Enabled:
		// Turned off after the delivery was queued: not sent, not counted.
		o = outcome{result: Result{Error: ErrDisabled}, final: true}
	default:
		url, secret, err := Open(s.Keys, org, c.WebhookID, c.Sealed)
		if err != nil {
			// secrets.key is missing or changed without old_keys: an operator
			// problem, not the endpoint's, so it doesn't count as a failure.
			s.Log.Warn("webhook not sent: can't decrypt its URL or secret", "org_id", org, "webhook_id", c.WebhookID,
				"delivery_id", c.ID, "key_id", c.Sealed.KeyID, "err", err)
			o = outcome{result: Result{Error: ErrKeyUnavailable}, final: true}
			break
		}
		req := Request{URL: url, Kind: c.Kind, Body: []byte(c.Payload)}
		if c.Kind == KindGeneric {
			ts := s.Now().Unix()
			req.Headers = map[string]string{
				"webhook-id":        c.ID.String(),
				"webhook-timestamp": strconv.FormatInt(ts, 10),
				"webhook-signature": Sign(secret, c.ID.String(), ts, req.Body),
			}
		}
		res := s.Client.Send(ctx, req)
		o = outcome{attempted: true, result: res,
			// A test is tried once; others retry while the schedule lasts.
			final: res.Delivered() || !res.Retryable() || test || c.Attempts+1 > len(Retries)}
		if !res.Delivered() {
			// Never the URL: for Slack it is the credential.
			s.Log.Info("webhook delivery failed", "org_id", org, "webhook_id", c.WebhookID, "delivery_id", c.ID,
				"attempt", c.Attempts+1, "error", res.Error, "status", res.StatusCode, "final", o.final)
		}
	}
	disabled, err := s.record(ctx, org, c, o, test)
	if err == nil {
		countDelivery(o, test)
	}
	return disabled, err
}

// countDelivery records a recorded outcome in the metrics: delivered,
// retrying (a failure with a retry scheduled) or failed (for good, including
// deliveries not sent because the webhook was off or the key unavailable). A
// delivered real event is also a notification sent over the webhook channel.
func countDelivery(o outcome, test bool) {
	switch {
	case o.result.Delivered():
		metrics.WebhookDelivery("delivered")
		if !test {
			metrics.NotificationsSent(metrics.ChannelWebhook, 1)
		}
	case o.final:
		metrics.WebhookDelivery("failed")
	default:
		metrics.WebhookDelivery("retrying")
	}
}

// record stores the outcome, and for a final one of a real event updates the
// webhook's failure count, turning it off at the limit or on 410 Gone.
func (s *Sender) record(ctx context.Context, org uuid.UUID, c claimed, o outcome, test bool) (bool, error) {
	now := s.Now().UTC()
	disabled := false
	err := s.Tx(ctx, org, func(db notify.DB) error {
		attempts, last := c.Attempts, (*time.Time)(nil)
		if o.attempted {
			attempts, last = attempts+1, &now
		}
		var status *int
		if o.result.StatusCode != 0 {
			status = &o.result.StatusCode
		}
		var errCode *string
		if o.result.Error != "" {
			errCode = &o.result.Error
		}
		state, next, delivered := "pending", (*time.Time)(nil), (*time.Time)(nil)
		switch {
		case o.result.Delivered():
			state, delivered = "delivered", &now
		case o.final:
			state = "failed"
		default:
			t := now.Add(Retries[min(c.Attempts, len(Retries)-1)])
			next = &t
		}
		tag, err := db.Exec(ctx, `UPDATE webhook_delivery SET state = $2, attempts = $3, status_code = $4, error = $5,
				next_at = $6, last_attempt_at = coalesce($7, last_attempt_at), delivered_at = $8
			WHERE id = $1 AND state = 'pending'`, c.ID, state, attempts, status, errCode, next, last, delivered)
		if err != nil || tag.RowsAffected() == 0 || test || !o.attempted || !o.final {
			return err // gone meanwhile (webhook deleted), or nothing to count
		}
		if state == "delivered" {
			_, err := db.Exec(ctx, `UPDATE webhook SET consecutive_failures = 0 WHERE id = $1 AND consecutive_failures > 0`, c.WebhookID)
			return err
		}
		var (
			failures int
			enabled  bool
		)
		err = db.QueryRow(ctx, `UPDATE webhook SET consecutive_failures = consecutive_failures + 1 WHERE id = $1
			RETURNING consecutive_failures, enabled`, c.WebhookID).Scan(&failures, &enabled)
		if errors.Is(err, pgx.ErrNoRows) {
			return nil
		}
		if err != nil {
			return err
		}
		limit := s.FailureLimit
		if limit <= 0 {
			limit = DefaultFailureLimit
		}
		if !enabled || (!o.result.Gone() && failures < limit) {
			return nil
		}
		reason := "failures"
		if o.result.Gone() {
			reason = "gone"
		}
		disabled, err = Disable(ctx, db, org, c.WebhookID, reason, now)
		return err
	})
	return disabled, err
}

// Disable turns a webhook off with disabled_reason 'failures', and in the same
// transaction writes the webhook.disabled event (org admins and security leads
// are told) and the audit entry, with no actor: Warden did it. why is "gone"
// (410) or "failures" (the limit). It reports false if the webhook was
// already off.
func Disable(ctx context.Context, db notify.DB, org, id uuid.UUID, why string, now time.Time) (bool, error) {
	var name, kind, hint string
	var failures int
	err := db.QueryRow(ctx, `UPDATE webhook SET enabled = false, disabled_reason = 'failures', updated_at = $2
		WHERE id = $1 AND enabled RETURNING name, kind, url_hint, consecutive_failures`, id, now).Scan(&name, &kind, &hint, &failures)
	if errors.Is(err, pgx.ErrNoRows) {
		return false, nil
	}
	if err != nil {
		return false, err
	}
	if err := notify.Insert(ctx, db, notify.Event{OrgID: org, Type: notify.WebhookDisabled,
		Payload: notify.Payload{WebhookID: &id}}); err != nil {
		return false, err
	}
	return true, auditlog.Append(ctx, db, auditlog.Record{OrgID: org, Action: "webhook.disabled", TargetType: "webhook",
		TargetID: id.String(), Data: map[string]any{"name": name, "kind": kind, "url_hint": hint, "reason": why,
			"consecutive_failures": failures}})
}

// Prune deletes the org's deliveries older than Retention.
func (s *Sender) Prune(ctx context.Context, org uuid.UUID) (int64, error) {
	var n int64
	err := s.Tx(ctx, org, func(db notify.DB) error {
		tag, err := db.Exec(ctx, `DELETE FROM webhook_delivery WHERE created_at < $1`, s.Now().UTC().Add(-Retention))
		n = tag.RowsAffected()
		return err
	})
	return n, err
}
