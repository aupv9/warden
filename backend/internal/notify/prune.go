package notify

import (
	"context"
	"fmt"
	"time"

	"github.com/google/uuid"
)

// Retention is how long in-app notifications are kept (notify.read_retention,
// notify.unread_retention), counted from when they were written.
type Retention struct {
	Read, Unread time.Duration
}

const (
	// MinRetention matches the config minimum; the database function refuses
	// anything newer than 23 hours anyway.
	MinRetention = 24 * time.Hour
	pruneBatch   = 1000
	// maxPruneBatches bounds one run per org (and its time under lock); the
	// next hourly run continues where this one stopped.
	maxPruneBatches = 50
)

// PruneOrg deletes the org's notifications older than the retention (read and
// unread separately) and the dispatched outbox events nothing refers to any
// more, in short transactions of at most pruneBatch rows per table. It goes
// through warden_prune_notifications (00013_notification_retention.sql): the
// app role has no DELETE on either table.
func PruneOrg(ctx context.Context, tx TxFunc, org uuid.UUID, now time.Time, r Retention) (notes, events int64, err error) {
	if r.Read < MinRetention || r.Unread < MinRetention {
		return 0, 0, fmt.Errorf("notification retention under %s (read %s, unread %s)", MinRetention, r.Read, r.Unread)
	}
	readBefore, unreadBefore := now.UTC().Add(-r.Read), now.UTC().Add(-r.Unread)
	for range maxPruneBatches {
		var n, e int64
		err = tx(ctx, org, func(db DB) error {
			return db.QueryRow(ctx, `SELECT notifications, events FROM warden_prune_notifications($1, $2, $3)`,
				readBefore, unreadBefore, pruneBatch).Scan(&n, &e)
		})
		if err != nil {
			return notes, events, err
		}
		notes, events = notes+n, events+e
		if n < pruneBatch && e < pruneBatch {
			break
		}
	}
	return notes, events, nil
}
