package store

import (
	"context"
	"errors"
	"fmt"
	"time"

	"github.com/google/uuid"
	"github.com/jackc/pgx/v5"

	"github.com/aupv9/warden/backend/internal/secretbox"
	"github.com/aupv9/warden/backend/internal/service"
	"github.com/aupv9/warden/backend/internal/webhook"
	"github.com/aupv9/warden/backend/internal/worker"
)

// Webhooks (v0.4 wave 2). Both tables have forced RLS; every query runs under
// the caller's app.org_id.

const webhookSelect = `SELECT w.id, w.org_id, w.kind, w.name, w.url_hint, w.url_enc, w.secret_enc, w.key_id, w.events,
		w.project_ids, w.min_severity::text, w.enabled, w.disabled_reason, w.consecutive_failures,
		u.id, u.email::text, u.display_name, w.created_at, w.updated_at,
		ld.at, ld.state, ld.status_code
	FROM webhook w JOIN app_user u ON u.id = w.created_by
	LEFT JOIN LATERAL (SELECT coalesce(d.delivered_at, d.last_attempt_at, d.created_at) AS at, d.state, d.status_code
		FROM webhook_delivery d WHERE d.webhook_id = w.id ORDER BY d.created_at DESC, d.id DESC LIMIT 1) ld ON true`

func scanWebhook(row pgx.CollectableRow) (service.WebhookRecord, error) {
	var (
		w      service.WebhookRecord
		at     *time.Time
		state  *string
		status *int
	)
	err := row.Scan(&w.ID, &w.OrgID, &w.Kind, &w.Name, &w.URLHint, &w.Sealed.URL, &w.Sealed.Secret, &w.Sealed.KeyID, &w.Events,
		&w.ProjectIDs, &w.MinSeverity, &w.Enabled, &w.DisabledReason, &w.ConsecutiveFailures,
		&w.CreatedBy.ID, &w.CreatedBy.Email, &w.CreatedBy.DisplayName, &w.CreatedAt, &w.UpdatedAt, &at, &state, &status)
	if at != nil && state != nil {
		w.LastDelivery = &service.WebhookLastDelivery{At: service.Time(*at), State: *state, StatusCode: status}
	}
	if w.ProjectIDs == nil {
		w.ProjectIDs = []uuid.UUID{}
	}
	return w, err
}

func (r *Repo) Webhooks(ctx context.Context) ([]service.WebhookRecord, error) {
	rows, _ := r.tx.Query(ctx, webhookSelect+` ORDER BY w.created_at, w.id`)
	return collect(rows, scanWebhook)
}

func (r *Repo) Webhook(ctx context.Context, id uuid.UUID, forUpdate bool) (service.WebhookRecord, error) {
	q := webhookSelect + ` WHERE w.id = $1`
	if forUpdate {
		q += ` FOR UPDATE OF w`
	}
	rows, _ := r.tx.Query(ctx, q, id)
	w, err := pgx.CollectExactlyOneRow(rows, scanWebhook)
	return w, mapErr(err)
}

func (r *Repo) LockWebhooks(ctx context.Context, orgID uuid.UUID) error {
	_, err := r.tx.Exec(ctx, `SELECT pg_advisory_xact_lock(hashtextextended('warden.webhooks:' || $1::text, 0))`, orgID)
	return err
}

func (r *Repo) CountWebhooks(ctx context.Context) (int, error) {
	var n int
	err := r.tx.QueryRow(ctx, `SELECT count(*) FROM webhook`).Scan(&n)
	return n, err
}

func (r *Repo) InsertWebhook(ctx context.Context, w service.WebhookRecord) error {
	_, err := r.tx.Exec(ctx, `INSERT INTO webhook (id, org_id, kind, name, url_hint, url_enc, secret_enc, key_id, events,
			project_ids, min_severity, enabled, created_by, created_at, updated_at)
		VALUES ($1, $2, $3, $4, $5, $6, $7, $8, $9, $10, $11::severity, $12, $13, $14, $15)`,
		w.ID, w.OrgID, w.Kind, w.Name, w.URLHint, w.Sealed.URL, w.Sealed.Secret, w.Sealed.KeyID, w.Events,
		w.ProjectIDs, w.MinSeverity, w.Enabled, w.CreatedBy.ID, w.CreatedAt.T(), w.UpdatedAt.T())
	return mapErr(err)
}

func (r *Repo) UpdateWebhook(ctx context.Context, w service.WebhookRecord) error {
	_, err := r.tx.Exec(ctx, `UPDATE webhook SET name = $2, url_hint = $3, url_enc = $4, secret_enc = $5, key_id = $6,
			events = $7, project_ids = $8, min_severity = $9::severity, enabled = $10, disabled_reason = $11,
			consecutive_failures = $12, updated_at = $13
		WHERE id = $1`,
		w.ID, w.Name, w.URLHint, w.Sealed.URL, w.Sealed.Secret, w.Sealed.KeyID, w.Events, w.ProjectIDs, w.MinSeverity,
		w.Enabled, w.DisabledReason, w.ConsecutiveFailures, w.UpdatedAt.T())
	return mapErr(err)
}

func (r *Repo) DeleteWebhook(ctx context.Context, id uuid.UUID) error {
	_, err := r.tx.Exec(ctx, `DELETE FROM webhook WHERE id = $1`, id)
	return mapErr(err)
}

func (r *Repo) MissingProjects(ctx context.Context, ids []uuid.UUID) ([]uuid.UUID, error) {
	rows, _ := r.tx.Query(ctx, `SELECT x FROM unnest($1::uuid[]) x WHERE NOT EXISTS (SELECT 1 FROM project p WHERE p.id = x)
		ORDER BY x`, ids)
	return collect(rows, pgx.RowTo[uuid.UUID])
}

// InsertWebhookDelivery queues a delivery and, in the same transaction, a
// send_webhooks job, so a test goes out within seconds rather than at the next
// periodic run.
func (r *Repo) InsertWebhookDelivery(ctx context.Context, d service.NewWebhookDelivery) error {
	if _, err := r.tx.Exec(ctx, `INSERT INTO webhook_delivery (id, org_id, webhook_id, type, payload, next_at, created_at)
		VALUES ($1, $2, $3, $4, $5, $6, $6)`, d.ID, d.OrgID, d.WebhookID, d.Type, string(d.Payload), d.CreatedAt); err != nil {
		return mapErr(err)
	}
	if r.river == nil {
		return nil
	}
	_, err := r.river.InsertTx(ctx, r.tx, worker.SendWebhooksArgs{}, nil)
	return err
}

func (r *Repo) WebhookTestsSince(ctx context.Context, webhookID uuid.UUID, since time.Time) (int, time.Time, error) {
	var (
		n      int
		oldest *time.Time
	)
	err := r.tx.QueryRow(ctx, `SELECT count(*), min(created_at) FROM webhook_delivery
		WHERE webhook_id = $1 AND type = 'webhook.test' AND created_at > $2`, webhookID, since).Scan(&n, &oldest)
	if oldest == nil {
		return n, time.Time{}, err
	}
	return n, *oldest, err
}

func (r *Repo) WebhookDeliveries(ctx context.Context, webhookID uuid.UUID, since time.Time, state string, after *service.DeliveryCursor, limit int) ([]service.WebhookDelivery, error) {
	var a args
	q := `SELECT id, type, state, attempts, status_code, error, created_at, last_attempt_at,
			CASE WHEN state = 'pending' THEN next_at END, delivered_at
		FROM webhook_delivery WHERE webhook_id = ` + a.add(webhookID) + ` AND created_at >= ` + a.add(since)
	if state != "" {
		q += ` AND state = ` + a.add(state)
	}
	if after != nil {
		q += ` AND (created_at, id) < (` + a.add(after.CreatedAt) + `, ` + a.add(after.ID) + `)`
	}
	q += ` ORDER BY created_at DESC, id DESC LIMIT ` + a.add(limit)
	rows, _ := r.tx.Query(ctx, q, a...)
	return collect(rows, func(row pgx.CollectableRow) (service.WebhookDelivery, error) {
		var d service.WebhookDelivery
		return d, row.Scan(&d.ID, &d.Type, &d.State, &d.Attempts, &d.StatusCode, &d.Error, &d.CreatedAt,
			&d.LastAttemptAt, &d.NextAttemptAt, &d.DeliveredAt)
	})
}

// ReencryptWebhooks moves every webhook's URL and secret to the active key
// (warden-admin secrets rotate), org by org under each org's RLS scope, so
// the old key can then be dropped from secrets.old_keys. Rows no key in the
// keyring can open are left as they are and returned: those webhooks fail
// with key_unavailable until someone edits or recreates them. Each org with
// re-encrypted rows gets one audit entry with no actor.
func ReencryptWebhooks(ctx context.Context, d *DB, keys *secretbox.Keyring) (int, []uuid.UUID, error) {
	if !keys.Available() {
		return 0, nil, errors.New("secrets.key is not set")
	}
	var orgs []uuid.UUID
	err := d.InOrg(ctx, uuid.Nil, func(sr service.Repo) error {
		rows, _ := sr.(*Repo).tx.Query(ctx, `SELECT id FROM organization ORDER BY id`)
		var err error
		orgs, err = collect(rows, pgx.RowTo[uuid.UUID])
		return err
	})
	if err != nil {
		return 0, nil, err
	}
	done, unreadable := 0, []uuid.UUID{}
	for _, org := range orgs {
		err := d.InOrg(ctx, org, func(sr service.Repo) error {
			r := sr.(*Repo)
			type row struct {
				id uuid.UUID
				s  webhook.Sealed
			}
			rows, _ := r.tx.Query(ctx, `SELECT id, url_enc, secret_enc, key_id FROM webhook WHERE key_id <> $1
				ORDER BY id FOR UPDATE`, keys.ActiveID())
			list, err := collect(rows, func(cr pgx.CollectableRow) (row, error) {
				var x row
				return x, cr.Scan(&x.id, &x.s.URL, &x.s.Secret, &x.s.KeyID)
			})
			if err != nil {
				return err
			}
			n := 0
			for _, x := range list {
				s, _, err := webhook.Reseal(keys, org, x.id, x.s)
				if err != nil {
					unreadable = append(unreadable, x.id)
					continue
				}
				if _, err := r.tx.Exec(ctx, `UPDATE webhook SET url_enc = $2, secret_enc = $3, key_id = $4 WHERE id = $1`,
					x.id, s.URL, s.Secret, s.KeyID); err != nil {
					return err
				}
				n++
			}
			done += n
			if n == 0 {
				return nil
			}
			return r.AppendAudit(ctx, service.AuditRecord{OrgID: org, Action: "webhook.reencrypted", TargetType: "org",
				TargetID: org.String(), Data: map[string]any{"count": n, "key_id": keys.ActiveID(), "via": "warden-admin"}})
		})
		if err != nil {
			return done, unreadable, fmt.Errorf("org %s: %w", org, err)
		}
	}
	return done, unreadable, nil
}
