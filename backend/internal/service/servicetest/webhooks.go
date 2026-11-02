package servicetest

import (
	"context"
	"maps"
	"slices"
	"strings"
	"time"

	"github.com/google/uuid"

	"github.com/aupv9/warden/backend/internal/service"
)

// DeliveryRow is a stored webhook delivery.
type DeliveryRow struct {
	service.WebhookDelivery
	OrgID     uuid.UUID
	WebhookID uuid.UUID
	Payload   []byte
}

// webhookState holds the webhook tables (v0.4 wave 2).
type webhookState struct {
	Hooks      map[uuid.UUID]service.WebhookRecord
	Deliveries []DeliveryRow
}

func (w webhookState) clone() webhookState {
	return webhookState{Hooks: maps.Clone(w.Hooks), Deliveries: slices.Clone(w.Deliveries)}
}

func (f *Fake) hook(id uuid.UUID) (service.WebhookRecord, bool) {
	w, ok := f.st.hooks.Hooks[id]
	return w, ok && w.OrgID == f.org
}

// StoredWebhook returns a webhook row as stored (any org).
func (f *Fake) StoredWebhook(id uuid.UUID) (service.WebhookRecord, bool) {
	w, ok := f.st.hooks.Hooks[id]
	return w, ok
}

// SetWebhook changes a stored webhook (e.g. as the worker would turn it off).
func (f *Fake) SetWebhook(id uuid.UUID, fn func(*service.WebhookRecord)) {
	w := f.st.hooks.Hooks[id]
	fn(&w)
	f.st.hooks.Hooks[id] = w
}

// Deliveries returns the stored deliveries of a webhook, oldest first.
func (f *Fake) Deliveries(webhookID uuid.UUID) []DeliveryRow {
	var out []DeliveryRow
	for _, d := range f.st.hooks.Deliveries {
		if d.WebhookID == webhookID {
			out = append(out, d)
		}
	}
	return out
}

// AddDelivery stores a delivery (seeding).
func (f *Fake) AddDelivery(d DeliveryRow) { f.st.hooks.Deliveries = append(f.st.hooks.Deliveries, d) }

func (f *Fake) withLast(w service.WebhookRecord) service.WebhookRecord {
	var last *DeliveryRow
	for i, d := range f.st.hooks.Deliveries {
		if d.WebhookID == w.ID && (last == nil || !d.CreatedAt.T().Before(last.CreatedAt.T())) {
			last = &f.st.hooks.Deliveries[i]
		}
	}
	if last != nil {
		at := last.CreatedAt
		if last.DeliveredAt != nil {
			at = *last.DeliveredAt
		} else if last.LastAttemptAt != nil {
			at = *last.LastAttemptAt
		}
		w.LastDelivery = &service.WebhookLastDelivery{At: at, State: last.State, StatusCode: last.StatusCode}
	}
	u := f.st.Users[w.CreatedBy.ID]
	w.CreatedBy = service.UserRef{ID: u.ID, Email: u.Email, DisplayName: u.DisplayName}
	return w
}

func (f *Fake) Webhooks(_ context.Context) ([]service.WebhookRecord, error) {
	if err := f.fail("Webhooks"); err != nil {
		return nil, err
	}
	var out []service.WebhookRecord
	for _, w := range f.st.hooks.Hooks {
		if w.OrgID == f.org {
			out = append(out, f.withLast(w))
		}
	}
	slices.SortFunc(out, func(a, b service.WebhookRecord) int {
		if c := a.CreatedAt.T().Compare(b.CreatedAt.T()); c != 0 {
			return c
		}
		return strings.Compare(a.ID.String(), b.ID.String())
	})
	return out, nil
}

func (f *Fake) Webhook(_ context.Context, id uuid.UUID, _ bool) (service.WebhookRecord, error) {
	if err := f.fail("Webhook"); err != nil {
		return service.WebhookRecord{}, err
	}
	w, ok := f.hook(id)
	if !ok {
		return service.WebhookRecord{}, service.ErrNotFound
	}
	return f.withLast(w), nil
}

func (f *Fake) LockWebhooks(_ context.Context, _ uuid.UUID) error { return f.fail("LockWebhooks") }

func (f *Fake) CountWebhooks(_ context.Context) (int, error) {
	n := 0
	for _, w := range f.st.hooks.Hooks {
		if w.OrgID == f.org {
			n++
		}
	}
	return n, f.fail("CountWebhooks")
}

func (f *Fake) InsertWebhook(_ context.Context, w service.WebhookRecord) error {
	if err := f.fail("InsertWebhook"); err != nil {
		return err
	}
	if f.st.hooks.Hooks == nil {
		f.st.hooks.Hooks = map[uuid.UUID]service.WebhookRecord{}
	}
	w.ProjectIDs = slices.Clone(w.ProjectIDs)
	w.Events = slices.Clone(w.Events)
	f.st.hooks.Hooks[w.ID] = w
	return nil
}

func (f *Fake) UpdateWebhook(_ context.Context, w service.WebhookRecord) error {
	if err := f.fail("UpdateWebhook"); err != nil {
		return err
	}
	if _, ok := f.hook(w.ID); !ok {
		return nil
	}
	w.LastDelivery = nil
	f.st.hooks.Hooks[w.ID] = w
	return nil
}

func (f *Fake) DeleteWebhook(_ context.Context, id uuid.UUID) error {
	if err := f.fail("DeleteWebhook"); err != nil {
		return err
	}
	if _, ok := f.hook(id); !ok {
		return nil
	}
	delete(f.st.hooks.Hooks, id)
	f.st.hooks.Deliveries = slices.DeleteFunc(f.st.hooks.Deliveries, func(d DeliveryRow) bool { return d.WebhookID == id })
	return nil
}

func (f *Fake) MissingProjects(_ context.Context, ids []uuid.UUID) ([]uuid.UUID, error) {
	var out []uuid.UUID
	for _, id := range ids {
		if p, ok := f.st.Projects[id]; !ok || p.OrgID != f.org {
			out = append(out, id)
		}
	}
	return out, f.fail("MissingProjects")
}

func (f *Fake) InsertWebhookDelivery(_ context.Context, d service.NewWebhookDelivery) error {
	if err := f.fail("InsertWebhookDelivery"); err != nil {
		return err
	}
	t := service.Time(d.CreatedAt)
	f.st.hooks.Deliveries = append(f.st.hooks.Deliveries, DeliveryRow{OrgID: d.OrgID, WebhookID: d.WebhookID,
		Payload: d.Payload, WebhookDelivery: service.WebhookDelivery{ID: d.ID, Type: d.Type, State: "pending",
			CreatedAt: t, NextAttemptAt: &t}})
	return nil
}

func (f *Fake) WebhookTestsSince(_ context.Context, webhookID uuid.UUID, since time.Time) (int, time.Time, error) {
	n, oldest := 0, time.Time{}
	for _, d := range f.st.hooks.Deliveries {
		if d.WebhookID == webhookID && d.OrgID == f.org && d.Type == "webhook.test" && d.CreatedAt.T().After(since) {
			n++
			if oldest.IsZero() || d.CreatedAt.T().Before(oldest) {
				oldest = d.CreatedAt.T()
			}
		}
	}
	return n, oldest, f.fail("WebhookTestsSince")
}

func (f *Fake) WebhookDeliveries(_ context.Context, webhookID uuid.UUID, since time.Time, state string, after *service.DeliveryCursor, limit int) ([]service.WebhookDelivery, error) {
	if err := f.fail("WebhookDeliveries"); err != nil {
		return nil, err
	}
	var out []service.WebhookDelivery
	for _, d := range f.st.hooks.Deliveries {
		if d.WebhookID == webhookID && d.OrgID == f.org && !d.CreatedAt.T().Before(since) && (state == "" || d.State == state) {
			out = append(out, d.WebhookDelivery)
		}
	}
	key := func(d service.WebhookDelivery) (time.Time, string) { return d.CreatedAt.T(), d.ID.String() }
	slices.SortFunc(out, func(a, b service.WebhookDelivery) int {
		at, aid := key(a)
		bt, bid := key(b)
		if c := bt.Compare(at); c != 0 {
			return c
		}
		return strings.Compare(bid, aid)
	})
	if after != nil {
		out = slices.DeleteFunc(out, func(d service.WebhookDelivery) bool {
			t, id := key(d)
			return t.After(after.CreatedAt) || (t.Equal(after.CreatedAt) && id >= after.ID.String())
		})
	}
	if len(out) > limit {
		out = out[:limit]
	}
	return out, nil
}
