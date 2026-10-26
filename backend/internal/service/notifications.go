package service

import (
	"context"
	"slices"
	"time"

	"github.com/google/uuid"

	"github.com/aupv9/warden/backend/internal/notify"
)

// v02Repo is the data access added in v0.2; it is part of Repo.
type v02Repo interface {
	NotificationRepo
	PolicyRepo
	MetricsRepo
}

// NotificationRepo: the outbox (written in the caller's org transaction) and
// the caller's own notifications (read in an InUser transaction).
type NotificationRepo interface {
	// AppendOutbox writes an outbox event in the current transaction (and
	// nudges the dispatcher).
	AppendOutbox(ctx context.Context, e notify.Event) error
	Notifications(ctx context.Context, q NotificationQuery) ([]Notification, error)
	UnreadCount(ctx context.Context, userID uuid.UUID) (int, error)
	// MarkRead marks the user's notifications read: ids, or all of them when ids is nil.
	MarkRead(ctx context.Context, userID uuid.UUID, ids []uuid.UUID) error
	// NotificationPrefs returns the user's explicit choices by type.
	NotificationPrefs(ctx context.Context, userID uuid.UUID) (map[string]bool, error)
	SetNotificationPref(ctx context.Context, userID uuid.UUID, typ string, email bool) error
}

type Notification struct {
	ID        uuid.UUID `json:"id"`
	OrgID     uuid.UUID `json:"org_id"`
	Type      string    `json:"type"`
	Title     string    `json:"title"`
	Link      string    `json:"link"`
	Actor     *UserRef  `json:"actor"`
	ReadAt    *Time     `json:"read_at"`
	CreatedAt Time      `json:"created_at"`
}

type NotificationCursor struct {
	CreatedAt time.Time `json:"t"`
	ID        uuid.UUID `json:"id"`
}

type NotificationQuery struct {
	UserID uuid.UUID
	Unread bool
	After  *NotificationCursor
	Limit  int
}

type NotificationPref struct {
	Type  string `json:"type"`
	Email bool   `json:"email"`
}

type Count struct {
	Count int `json:"count"`
}

// outbox appends an event for the actor's org in the current transaction.
func outbox(ctx context.Context, r Repo, a *Actor, typ string, p notify.Payload) error {
	if p.ActorID == nil && a != nil {
		p.ActorID = notify.ID(a.UserID)
	}
	return r.AppendOutbox(ctx, notify.Event{OrgID: a.OrgID, Type: typ, Payload: p})
}

type NotificationFilter struct {
	Unread string
	PageParams
}

// Notifications lists the caller's notifications (all orgs they still belong
// to), newest first.
func (s *Service) Notifications(ctx context.Context, userID uuid.UUID, f NotificationFilter) (Page[Notification], error) {
	q := NotificationQuery{UserID: userID}
	fe := fieldErrors{}
	switch f.Unread {
	case "", "false":
	case "true":
		q.Unread = true
	default:
		fe.add("unread", "must be true or false")
	}
	limit, err := f.limit()
	if err != nil {
		fe.add("limit", "must be an integer between 1 and 200")
	}
	q.Limit = limit + 1
	if f.Cursor != "" {
		q.After = &NotificationCursor{}
		if decodeCursor(f.Cursor, q.After) != nil {
			fe.add("cursor", "invalid cursor")
		}
	}
	if err := fe.err(); err != nil {
		return Page[Notification]{}, err
	}
	var out Page[Notification]
	err = s.db.InUser(ctx, userID, func(r Repo) error {
		rows, err := r.Notifications(ctx, q)
		if err != nil {
			return err
		}
		out.Items, out.NextCursor = page(rows, limit, func(n Notification) any {
			return NotificationCursor{CreatedAt: n.CreatedAt.T(), ID: n.ID}
		})
		return nil
	})
	return out, err
}

func (s *Service) UnreadNotifications(ctx context.Context, userID uuid.UUID) (Count, error) {
	var out Count
	err := s.db.InUser(ctx, userID, func(r Repo) error {
		n, err := r.UnreadCount(ctx, userID)
		out.Count = n
		return err
	})
	return out, err
}

type MarkReadInput struct {
	IDs *[]string `json:"ids"`
	All *bool     `json:"all"`
}

const maxMarkRead = 200

// MarkNotificationsRead marks some or all of the caller's notifications read.
// Ids that aren't the caller's are ignored (RLS hides them anyway).
func (s *Service) MarkNotificationsRead(ctx context.Context, userID uuid.UUID, in MarkReadInput) error {
	var ids []uuid.UUID
	switch {
	case in.All != nil && in.IDs != nil:
		return errField("body", "give either ids or all, not both")
	case in.All != nil:
		if !*in.All {
			return errField("all", "must be true")
		}
	case in.IDs != nil:
		if n := len(*in.IDs); n < 1 || n > maxMarkRead {
			return errField("ids", "must contain 1 to 200 notification ids")
		}
		for _, raw := range *in.IDs {
			id, err := uuid.Parse(raw)
			if err != nil {
				return errField("ids", "must contain notification ids")
			}
			ids = append(ids, id)
		}
	default:
		return errField("body", "give ids or all")
	}
	return s.db.InUser(ctx, userID, func(r Repo) error { return r.MarkRead(ctx, userID, ids) })
}

// NotificationPrefs returns every type with the caller's choice or its default.
func (s *Service) NotificationPrefs(ctx context.Context, userID uuid.UUID) (Items[NotificationPref], error) {
	var out Items[NotificationPref]
	err := s.db.InUser(ctx, userID, func(r Repo) error {
		set, err := r.NotificationPrefs(ctx, userID)
		if err != nil {
			return err
		}
		out = prefItems(set)
		return nil
	})
	return out, err
}

func prefItems(set map[string]bool) Items[NotificationPref] {
	out := Items[NotificationPref]{Items: make([]NotificationPref, 0, len(notify.Types))}
	for _, t := range notify.Types {
		email, ok := set[t]
		if !ok {
			email = notify.DefaultEmail(t)
		}
		out.Items = append(out.Items, NotificationPref{Type: t, Email: email})
	}
	return out
}

type NotificationPrefsInput struct {
	Items []NotificationPref `json:"items"`
}

func (s *Service) SetNotificationPrefs(ctx context.Context, userID uuid.UUID, in NotificationPrefsInput) (Items[NotificationPref], error) {
	if len(in.Items) == 0 || len(in.Items) > len(notify.Types) {
		return Items[NotificationPref]{}, errField("items", "must list 1 to 7 notification types")
	}
	var seen []string
	for _, p := range in.Items {
		if !notify.ValidType(p.Type) {
			return Items[NotificationPref]{}, errField("items", "unknown notification type")
		}
		if slices.Contains(seen, p.Type) {
			return Items[NotificationPref]{}, errField("items", "lists a type twice")
		}
		seen = append(seen, p.Type)
	}
	var out Items[NotificationPref]
	err := s.db.InUser(ctx, userID, func(r Repo) error {
		for _, p := range in.Items {
			if err := r.SetNotificationPref(ctx, userID, p.Type, p.Email); err != nil {
				return err
			}
		}
		set, err := r.NotificationPrefs(ctx, userID)
		if err != nil {
			return err
		}
		out = prefItems(set)
		return nil
	})
	return out, err
}
