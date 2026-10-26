package store

import (
	"context"
	"errors"

	"github.com/google/uuid"
	"github.com/jackc/pgx/v5"

	"github.com/aupv9/warden/backend/internal/notify"
	"github.com/aupv9/warden/backend/internal/service"
	"github.com/aupv9/warden/backend/internal/worker"
)

// InUser runs fn with app.user_id set (and app.org_id unset): of the RLS
// tables only the user's own notifications are visible (migration 00004).
func (d *DB) InUser(ctx context.Context, userID uuid.UUID, fn func(service.Repo) error) error {
	if userID == uuid.Nil {
		return errors.New("store: InUser needs a user id")
	}
	return pgx.BeginFunc(ctx, d.pool, func(tx pgx.Tx) error {
		if _, err := tx.Exec(ctx, "SELECT set_config('app.user_id', $1, true)", userID.String()); err != nil {
			return err
		}
		return fn(&Repo{tx: tx, river: d.river})
	})
}

// AppendOutbox writes the event and, when a job client is configured, enqueues
// one dispatch per transaction in that same transaction (a bulk assign of 100
// issues gets one job, not 100).
func (r *Repo) AppendOutbox(ctx context.Context, e notify.Event) error {
	if err := notify.Insert(ctx, r.tx, e); err != nil {
		return err
	}
	if r.river == nil || r.dispatchQueued {
		return nil
	}
	if _, err := r.river.InsertTx(ctx, r.tx, worker.DispatchNotificationsArgs{}, nil); err != nil {
		return err
	}
	r.dispatchQueued = true
	return nil
}

// Notifications lists the user's notifications in orgs they still belong to.
func (r *Repo) Notifications(ctx context.Context, q service.NotificationQuery) ([]service.Notification, error) {
	var a args
	sql := `SELECT n.id, n.org_id, n.type, n.title, n.link, au.id, au.email::text, au.display_name, n.read_at, n.created_at
		FROM notification n
		JOIN org_member m ON m.org_id = n.org_id AND m.user_id = n.user_id
		LEFT JOIN app_user au ON au.id = n.actor_id
		WHERE n.user_id = ` + a.add(q.UserID)
	if q.Unread {
		sql += ` AND n.read_at IS NULL`
	}
	if q.After != nil {
		sql += ` AND (n.created_at, n.id) < (` + a.add(q.After.CreatedAt) + `, ` + a.add(q.After.ID) + `)`
	}
	sql += ` ORDER BY n.created_at DESC, n.id DESC LIMIT ` + a.add(q.Limit)
	rows, _ := r.tx.Query(ctx, sql, a...)
	return collect(rows, func(row pgx.CollectableRow) (service.Notification, error) {
		var (
			n             service.Notification
			aID           *uuid.UUID
			aEmail, aName *string
		)
		err := row.Scan(&n.ID, &n.OrgID, &n.Type, &n.Title, &n.Link, &aID, &aEmail, &aName, &n.ReadAt, &n.CreatedAt)
		n.Actor = userRef(aID, aEmail, aName)
		return n, err
	})
}

func (r *Repo) UnreadCount(ctx context.Context, userID uuid.UUID) (int, error) {
	var n int
	err := r.tx.QueryRow(ctx, `SELECT count(*) FROM notification n
		JOIN org_member m ON m.org_id = n.org_id AND m.user_id = n.user_id
		WHERE n.user_id = $1 AND n.read_at IS NULL`, userID).Scan(&n)
	return n, mapErr(err)
}

func (r *Repo) MarkRead(ctx context.Context, userID uuid.UUID, ids []uuid.UUID) error {
	var err error
	if ids == nil {
		_, err = r.tx.Exec(ctx, `UPDATE notification SET read_at = now() WHERE user_id = $1 AND read_at IS NULL`, userID)
	} else {
		_, err = r.tx.Exec(ctx, `UPDATE notification SET read_at = now() WHERE user_id = $1 AND read_at IS NULL AND id = ANY($2)`,
			userID, ids)
	}
	return mapErr(err)
}

func (r *Repo) NotificationPrefs(ctx context.Context, userID uuid.UUID) (map[string]bool, error) {
	rows, _ := r.tx.Query(ctx, `SELECT type, email FROM notification_pref WHERE user_id = $1`, userID)
	out := map[string]bool{}
	var (
		typ   string
		email bool
	)
	_, err := pgx.ForEachRow(rows, []any{&typ, &email}, func() error {
		out[typ] = email
		return nil
	})
	return out, err
}

func (r *Repo) SetNotificationPref(ctx context.Context, userID uuid.UUID, typ string, email bool) error {
	_, err := r.tx.Exec(ctx, `INSERT INTO notification_pref (user_id, type, email) VALUES ($1, $2, $3)
		ON CONFLICT (user_id, type) DO UPDATE SET email = EXCLUDED.email`, userID, typ, email)
	return mapErr(err)
}
