package webhook

import (
	"context"
	"errors"
	"log/slog"
	"slices"
	"time"

	"github.com/google/uuid"
	"github.com/jackc/pgx/v5"

	"github.com/aupv9/warden/backend/internal/domain/severity"
	"github.com/aupv9/warden/backend/internal/ids"
	"github.com/aupv9/warden/backend/internal/notify"
)

// Queue writes deliveries for outbox events (notify.WebhookQueue).
type Queue struct {
	// BaseURL is the validated smtp.public_base_url links start with.
	BaseURL string
	Now     func() time.Time
	Log     *slog.Logger
}

var _ notify.WebhookQueue = (*Queue)(nil)

type subscriber struct {
	ID          uuid.UUID
	Kind        string
	ProjectIDs  []uuid.UUID
	MinSeverity *string
}

// severityFiltered are the event types min_severity applies to: those about
// one issue's arrival or change. Exception and scan events are always sent.
var severityFiltered = []string{notify.IssueAssigned, notify.IssueReopened, notify.ComponentMalicious}

// Enqueue runs in the dispatcher's transaction (app.org_id = org): one pending
// delivery per enabled webhook subscribed to the event, unique per (webhook,
// event), so a dispatch retried after a crash adds nothing. Facts are loaded
// only when some webhook wants the event.
func (q *Queue) Enqueue(ctx context.Context, db notify.DB, org uuid.UUID, eventID int64, typ string, payload []byte) error {
	rows, err := db.Query(ctx, `SELECT id, kind, project_ids, min_severity::text FROM webhook
		WHERE enabled AND $1 = ANY(events) ORDER BY created_at, id`, typ)
	if err != nil {
		return err
	}
	subs, err := pgx.CollectRows(rows, func(r pgx.CollectableRow) (subscriber, error) {
		var s subscriber
		return s, r.Scan(&s.ID, &s.Kind, &s.ProjectIDs, &s.MinSeverity)
	})
	if err != nil || len(subs) == 0 {
		return err
	}
	f, ok, err := notify.LoadFacts(ctx, db, org, eventID, typ, payload)
	if errors.Is(err, notify.ErrMalformed) {
		q.Log.Error("skipping malformed outbox event for webhooks", "org_id", org, "event_id", eventID, "type", typ)
		return nil
	}
	if err != nil || !ok {
		return err
	}
	now := q.Now().UTC()
	for _, s := range subs {
		if !matches(s, typ, f) {
			continue
		}
		id := ids.New()
		body, err := Body(s.Kind, NewEvent(id, typ, f, q.BaseURL))
		if err != nil {
			return err
		}
		if len(body) > MaxBody {
			// Can't happen with today's column limits; never block the outbox on it.
			q.Log.Error("webhook body too large; not sent", "org_id", org, "webhook_id", s.ID, "event_id", eventID)
			continue
		}
		if _, err := db.Exec(ctx, `INSERT INTO webhook_delivery (id, org_id, webhook_id, event_id, type, payload, next_at, created_at)
			VALUES ($1, $2, $3, $4, $5, $6, $7, $7) ON CONFLICT (webhook_id, event_id) DO NOTHING`,
			id, org, s.ID, eventID, typ, string(body), now); err != nil {
			return err
		}
	}
	return nil
}

func matches(s subscriber, typ string, f notify.Facts) bool {
	if len(s.ProjectIDs) > 0 && (f.Project == nil || !slices.Contains(s.ProjectIDs, f.Project.ID)) {
		return false
	}
	if s.MinSeverity != nil && f.Issue != nil && slices.Contains(severityFiltered, typ) &&
		severity.Rank(severity.Severity(f.Issue.Severity)) > severity.Rank(severity.Severity(*s.MinSeverity)) {
		return false
	}
	return true
}
