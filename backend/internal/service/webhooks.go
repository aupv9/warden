package service

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"net/http"
	"slices"
	"strconv"
	"strings"
	"time"
	"unicode/utf8"

	apperrors "github.com/aupv9/common-go/errors"
	"github.com/google/uuid"

	"github.com/aupv9/warden/backend/internal/domain/rbac"
	"github.com/aupv9/warden/backend/internal/ids"
	"github.com/aupv9/warden/backend/internal/notify"
	"github.com/aupv9/warden/backend/internal/secretbox"
	"github.com/aupv9/warden/backend/internal/webhook"
)

// Webhooks and Slack (v0.4 wave 2), managed by org admins and security leads
// (manage_integrations): they send org data out of Warden. The URL and signing
// secret are stored encrypted (webhook.Seal); the URL is never returned, only
// its hint, and the secret only when it is created or rotated. Audit entries
// never contain either.

// WebhookConfig is what the webhook routes need from the server.
type WebhookConfig struct {
	// Keys (secrets.key): nil makes webhooks unavailable.
	Keys *secretbox.Keyring
	// Checker validates URLs; nil checks with the default policy and DNS.
	Checker *webhook.Checker
}

const (
	maxWebhookName     = 80
	maxWebhookProjects = 100
	webhookTestsPerHr  = 10
	maxDeliveryLimit   = 100
)

type WebhookLastDelivery struct {
	At         Time   `json:"at"`
	State      string `json:"state"`
	StatusCode *int   `json:"status_code"`
}

// Webhook is a webhook as the API shows it: never its URL or secret.
type Webhook struct {
	ID                  uuid.UUID            `json:"id"`
	Kind                string               `json:"kind"`
	Name                string               `json:"name"`
	URLHint             string               `json:"url_hint"`
	Events              []string             `json:"events"`
	ProjectIDs          []uuid.UUID          `json:"project_ids"`
	MinSeverity         *string              `json:"min_severity"`
	Enabled             bool                 `json:"enabled"`
	DisabledReason      *string              `json:"disabled_reason"`
	ConsecutiveFailures int                  `json:"consecutive_failures"`
	LastDelivery        *WebhookLastDelivery `json:"last_delivery"`
	CreatedBy           UserRef              `json:"created_by"`
	CreatedAt           Time                 `json:"created_at"`
	UpdatedAt           Time                 `json:"updated_at"`
}

// WebhookRecord is a webhook row with its encrypted columns.
type WebhookRecord struct {
	Webhook
	OrgID  uuid.UUID
	Sealed webhook.Sealed
}

type WebhookList struct {
	Items []Webhook `json:"items"`
	// Available is false without secrets.key.
	Available bool `json:"available"`
}

// CreatedWebhook carries the signing secret, once (nil for Slack).
type CreatedWebhook struct {
	Webhook Webhook `json:"webhook"`
	Secret  *string `json:"secret"`
}

type WebhookSecret struct {
	Secret string `json:"secret"`
}

type WebhookDelivery struct {
	ID            uuid.UUID `json:"id"`
	Type          string    `json:"type"`
	State         string    `json:"state"`
	Attempts      int       `json:"attempts"`
	StatusCode    *int      `json:"status_code"`
	Error         *string   `json:"error"`
	CreatedAt     Time      `json:"created_at"`
	LastAttemptAt *Time     `json:"last_attempt_at"`
	NextAttemptAt *Time     `json:"next_attempt_at"`
	DeliveredAt   *Time     `json:"delivered_at"`
}

type NewWebhookDelivery struct {
	ID        uuid.UUID
	OrgID     uuid.UUID
	WebhookID uuid.UUID
	Type      string
	Payload   []byte
	CreatedAt time.Time
}

type DeliveryCursor struct {
	CreatedAt time.Time `json:"t"`
	ID        uuid.UUID `json:"id"`
}

// WebhookRepo is the webhook part of Repo. Every method runs under the org's
// app.org_id (webhook and webhook_delivery have forced RLS).
type WebhookRepo interface {
	// Webhooks lists the org's webhooks, oldest first, with their last delivery.
	Webhooks(ctx context.Context) ([]WebhookRecord, error)
	// Webhook returns one, locked when forUpdate; ErrNotFound if there is none.
	Webhook(ctx context.Context, id uuid.UUID, forUpdate bool) (WebhookRecord, error)
	// LockWebhooks serializes webhook creation per org, so the cap holds.
	LockWebhooks(ctx context.Context, orgID uuid.UUID) error
	CountWebhooks(ctx context.Context) (int, error)
	InsertWebhook(ctx context.Context, w WebhookRecord) error
	// UpdateWebhook writes every mutable column of w.
	UpdateWebhook(ctx context.Context, w WebhookRecord) error
	// DeleteWebhook deletes it and its deliveries.
	DeleteWebhook(ctx context.Context, id uuid.UUID) error
	// MissingProjects returns those of ids that aren't the org's projects.
	MissingProjects(ctx context.Context, ids []uuid.UUID) ([]uuid.UUID, error)
	// InsertWebhookDelivery queues a delivery (and kicks the sender).
	InsertWebhookDelivery(ctx context.Context, d NewWebhookDelivery) error
	// WebhookTestsSince counts the webhook's test deliveries created after
	// since and returns the oldest one's time (zero if none).
	WebhookTestsSince(ctx context.Context, webhookID uuid.UUID, since time.Time) (int, time.Time, error)
	// WebhookDeliveries lists deliveries created at or after since, newest
	// first, in one state ("" for any).
	WebhookDeliveries(ctx context.Context, webhookID uuid.UUID, since time.Time, state string, after *DeliveryCursor, limit int) ([]WebhookDelivery, error)
}

// Optional is a PATCH field that may be absent, null or a value.
type Optional[T any] struct {
	Set   bool
	Value *T
}

func (o *Optional[T]) UnmarshalJSON(b []byte) error {
	o.Set = true
	if string(b) == "null" {
		o.Value = nil
		return nil
	}
	var v T
	if err := json.Unmarshal(b, &v); err != nil {
		return err
	}
	o.Value = &v
	return nil
}

type CreateWebhookInput struct {
	Kind        string   `json:"kind"`
	Name        string   `json:"name"`
	URL         string   `json:"url"`
	Events      []string `json:"events"`
	ProjectIDs  []string `json:"project_ids"`
	MinSeverity *string  `json:"min_severity"`
}

type UpdateWebhookInput struct {
	Name        *string          `json:"name"`
	URL         *string          `json:"url"`
	Events      []string         `json:"events"`
	ProjectIDs  []string         `json:"project_ids"`
	MinSeverity Optional[string] `json:"min_severity"`
	Enabled     *bool            `json:"enabled"`
}

// errWebhooksUnavailable and errWebhookLimit have their own codes so a client
// can tell "ask your operator" from "delete one first" without parsing text.
func errWebhooksUnavailable() error {
	return apperrors.Conflict("SECRETS_KEY_MISSING", "webhooks are unavailable: the server has no secrets.key (ask your operator)")
}

func errWebhookLimit() error {
	return apperrors.Conflict("WEBHOOK_LIMIT", fmt.Sprintf("an organization can have at most %d webhooks", webhook.MaxPerOrg))
}

func errWebhookKey() error {
	return errConflict("the server can't read this webhook's stored URL or secret with its current keys; delete the webhook and add it again")
}

// integrations checks manage_integrations. API tokens never get here (the
// API's allow-list has no webhook route); the check is repeated anyway.
func integrations(a *Actor) error {
	if a.Token != nil || !rbac.Can(rbac.ManageIntegrations, a.OrgRole, "", false) {
		return errForbidden()
	}
	return nil
}

func (s *Service) webhookChecker() *webhook.Checker {
	if s.cfg.Webhooks.Checker != nil {
		return s.cfg.Webhooks.Checker
	}
	return &webhook.Checker{}
}

func validWebhookName(fe fieldErrors, name string) string {
	name = strings.TrimSpace(name)
	if name == "" || utf8.RuneCountInString(name) > maxWebhookName || !validText(name) || strings.ContainsFunc(name, isControl) {
		fe.add("name", "must be 1-80 characters")
	}
	return name
}

func validWebhookEvents(fe fieldErrors, events []string) {
	if len(events) == 0 {
		fe.add("events", "must list at least one event")
	}
	for i, e := range events {
		if !slices.Contains(notify.WebhookTypes, e) || slices.Contains(events[:i], e) {
			fe.add("events", "must be distinct events from: "+strings.Join(notify.WebhookTypes, ", "))
		}
	}
}

func validWebhookProjects(fe fieldErrors, raw []string) []uuid.UUID {
	out := make([]uuid.UUID, 0, len(raw))
	if len(raw) > maxWebhookProjects {
		fe.add("project_ids", "must list at most 100 projects")
		return out
	}
	for _, s := range raw {
		id, err := uuid.Parse(s)
		if err != nil || slices.Contains(out, id) {
			fe.add("project_ids", "must be distinct project ids")
			return out
		}
		out = append(out, id)
	}
	return out
}

func validMinSeverity(fe fieldErrors, sev *string) {
	if sev != nil && !slices.Contains(severities, *sev) {
		fe.add("min_severity", "must be critical, high, medium, low, info or null")
	}
}

// checkURL runs the URL checks and maps a refusal onto the url field.
func (s *Service) checkURL(ctx context.Context, fe fieldErrors, kind, raw string) string {
	hint, err := s.webhookChecker().Check(ctx, kind, raw)
	var ue *webhook.URLError
	switch {
	case errors.As(err, &ue):
		fe.add("url", ue.Msg)
	case err != nil:
		s.log.WarnContext(ctx, "webhook url check failed", "err", err)
		fe.add("url", webhook.MsgNoResolve)
	}
	return hint
}

func checkProjects(ctx context.Context, r Repo, fe fieldErrors, ids []uuid.UUID) error {
	if len(ids) == 0 {
		return nil
	}
	missing, err := r.MissingProjects(ctx, ids)
	if err != nil {
		return err
	}
	if len(missing) > 0 {
		fe.add("project_ids", "unknown project "+missing[0].String())
	}
	return nil
}

// Webhooks lists the org's webhooks.
func (s *Service) Webhooks(ctx context.Context, a *Actor) (WebhookList, error) {
	out := WebhookList{Items: []Webhook{}, Available: s.cfg.Webhooks.Keys.Available()}
	err := s.inOrg(ctx, a, func(r Repo) error {
		if err := integrations(a); err != nil {
			return err
		}
		list, err := r.Webhooks(ctx)
		for _, w := range list {
			out.Items = append(out.Items, w.Webhook)
		}
		return err
	})
	return out, err
}

// Webhook returns one webhook.
func (s *Service) Webhook(ctx context.Context, a *Actor, id uuid.UUID) (Webhook, error) {
	var out Webhook
	err := s.inOrg(ctx, a, func(r Repo) error {
		if err := integrations(a); err != nil {
			return err
		}
		w, err := r.Webhook(ctx, id, false)
		out = w.Webhook
		return notFound(err)
	})
	return out, err
}

// CreateWebhook adds a webhook; a generic one gets a signing secret, returned
// only here.
func (s *Service) CreateWebhook(ctx context.Context, a *Actor, in CreateWebhookInput) (CreatedWebhook, error) {
	var out CreatedWebhook
	err := s.inOrg(ctx, a, func(r Repo) error {
		if err := integrations(a); err != nil {
			return err
		}
		keys := s.cfg.Webhooks.Keys
		if !keys.Available() {
			return errWebhooksUnavailable()
		}
		fe := fieldErrors{}
		if in.Kind != webhook.KindGeneric && in.Kind != webhook.KindSlack {
			fe.add("kind", "must be generic or slack")
		}
		name := validWebhookName(fe, in.Name)
		validWebhookEvents(fe, in.Events)
		projects := validWebhookProjects(fe, in.ProjectIDs)
		validMinSeverity(fe, in.MinSeverity)
		if err := checkProjects(ctx, r, fe, projects); err != nil {
			return err
		}
		var hint string
		if _, bad := fe["kind"]; !bad {
			hint = s.checkURL(ctx, fe, in.Kind, in.URL)
		}
		if err := fe.err(); err != nil {
			return err
		}
		if err := r.LockWebhooks(ctx, a.OrgID); err != nil {
			return err
		}
		if n, err := r.CountWebhooks(ctx); err != nil {
			return err
		} else if n >= webhook.MaxPerOrg {
			return errWebhookLimit()
		}
		id := ids.New()
		var raw []byte
		if in.Kind == webhook.KindGeneric {
			var shown string
			var err error
			if raw, shown, err = webhook.NewSecret(); err != nil {
				return fmt.Errorf("generate webhook secret: %w", err)
			}
			out.Secret = &shown
		}
		sealed, err := webhook.Seal(keys, a.OrgID, id, in.URL, raw)
		if err != nil {
			return err
		}
		now := Time(s.now().UTC())
		w := WebhookRecord{OrgID: a.OrgID, Sealed: sealed, Webhook: Webhook{
			ID: id, Kind: in.Kind, Name: name, URLHint: hint, Events: in.Events, ProjectIDs: projects,
			MinSeverity: in.MinSeverity, Enabled: true, CreatedBy: UserRef{ID: a.UserID}, CreatedAt: now, UpdatedAt: now,
		}}
		if err := r.InsertWebhook(ctx, w); err != nil {
			return err
		}
		stored, err := r.Webhook(ctx, id, false)
		if err != nil {
			return err
		}
		out.Webhook = stored.Webhook
		return s.audit(ctx, r, a, "webhook.created", "webhook", id.String(), map[string]any{
			"name": name, "kind": in.Kind, "url_hint": hint, "events": in.Events, "project_ids": len(projects),
			"min_severity": in.MinSeverity,
		})
	})
	return out, err
}

// UpdateWebhook changes the fields sent. A new URL is checked like on create
// and re-encrypted (with the secret) under the active key; enabled:true also
// clears the failure count and the reason Warden turned it off.
func (s *Service) UpdateWebhook(ctx context.Context, a *Actor, id uuid.UUID, in UpdateWebhookInput) (Webhook, error) {
	var out Webhook
	err := s.inOrg(ctx, a, func(r Repo) error {
		if err := integrations(a); err != nil {
			return err
		}
		w, err := r.Webhook(ctx, id, true)
		if err != nil {
			return notFound(err)
		}
		fe := fieldErrors{}
		var changed []string
		if in.Name == nil && in.URL == nil && in.Events == nil && in.ProjectIDs == nil && !in.MinSeverity.Set && in.Enabled == nil {
			fe.add("body", "must change at least one field")
		}
		if in.Name != nil {
			if name := validWebhookName(fe, *in.Name); name != w.Name {
				w.Name, changed = name, append(changed, "name")
			}
		}
		if in.Events != nil {
			validWebhookEvents(fe, in.Events)
			if !slices.Equal(in.Events, w.Events) {
				w.Events, changed = in.Events, append(changed, "events")
			}
		}
		if in.ProjectIDs != nil {
			projects := validWebhookProjects(fe, in.ProjectIDs)
			if err := checkProjects(ctx, r, fe, projects); err != nil {
				return err
			}
			if !slices.Equal(projects, w.ProjectIDs) {
				w.ProjectIDs, changed = projects, append(changed, "project_ids")
			}
		}
		if in.MinSeverity.Set {
			validMinSeverity(fe, in.MinSeverity.Value)
			if !equalPtr(in.MinSeverity.Value, w.MinSeverity) {
				w.MinSeverity, changed = in.MinSeverity.Value, append(changed, "min_severity")
			}
		}
		if in.URL != nil {
			w.URLHint = s.checkURL(ctx, fe, w.Kind, *in.URL)
			changed = append(changed, "url")
		}
		if err := fe.err(); err != nil {
			return err
		}
		if in.URL != nil {
			keys := s.cfg.Webhooks.Keys
			if !keys.Available() {
				return errWebhooksUnavailable()
			}
			// The secret stays; it moves to the active key with the URL (one
			// key_id per row).
			var secret []byte
			if w.Sealed.Secret != nil {
				if _, secret, err = webhook.Open(keys, a.OrgID, id, w.Sealed); err != nil {
					return errWebhookKey()
				}
			}
			if w.Sealed, err = webhook.Seal(keys, a.OrgID, id, *in.URL, secret); err != nil {
				return err
			}
		}
		if in.Enabled != nil {
			on := *in.Enabled
			if on != w.Enabled || (on && (w.ConsecutiveFailures > 0 || w.DisabledReason != nil)) {
				changed = append(changed, "enabled")
			}
			w.Enabled, w.DisabledReason = on, nil
			if on {
				w.ConsecutiveFailures = 0
			}
		}
		if len(changed) == 0 {
			out = w.Webhook
			return nil
		}
		w.UpdatedAt = Time(s.now().UTC())
		if err := r.UpdateWebhook(ctx, w); err != nil {
			return err
		}
		stored, err := r.Webhook(ctx, id, false)
		if err != nil {
			return err
		}
		out = stored.Webhook
		data := map[string]any{"name": w.Name, "changed": changed}
		if in.URL != nil {
			data["url_hint"] = w.URLHint
		}
		if in.Enabled != nil {
			data["enabled"] = w.Enabled
		}
		return s.audit(ctx, r, a, "webhook.updated", "webhook", id.String(), data)
	})
	return out, err
}

func equalPtr[T comparable](a, b *T) bool {
	return (a == nil) == (b == nil) && (a == nil || *a == *b)
}

// DeleteWebhook deletes a webhook and its delivery log.
func (s *Service) DeleteWebhook(ctx context.Context, a *Actor, id uuid.UUID) error {
	return s.inOrg(ctx, a, func(r Repo) error {
		if err := integrations(a); err != nil {
			return err
		}
		w, err := r.Webhook(ctx, id, true)
		if err != nil {
			return notFound(err)
		}
		if err := r.DeleteWebhook(ctx, id); err != nil {
			return err
		}
		return s.audit(ctx, r, a, "webhook.deleted", "webhook", id.String(), map[string]any{
			"name": w.Name, "kind": w.Kind, "url_hint": w.URLHint,
		})
	})
}

// RotateWebhookSecret replaces a generic webhook's signing secret; the old
// one stops working at once.
func (s *Service) RotateWebhookSecret(ctx context.Context, a *Actor, id uuid.UUID) (WebhookSecret, error) {
	var out WebhookSecret
	err := s.inOrg(ctx, a, func(r Repo) error {
		if err := integrations(a); err != nil {
			return err
		}
		w, err := r.Webhook(ctx, id, true)
		if err != nil {
			return notFound(err)
		}
		if w.Kind != webhook.KindGeneric {
			return errInvalidTransition("Slack webhooks have no signing secret")
		}
		keys := s.cfg.Webhooks.Keys
		if !keys.Available() {
			return errWebhooksUnavailable()
		}
		url, _, err := webhook.Open(keys, a.OrgID, id, w.Sealed)
		if err != nil {
			return errWebhookKey()
		}
		raw, shown, err := webhook.NewSecret()
		if err != nil {
			return fmt.Errorf("generate webhook secret: %w", err)
		}
		if w.Sealed, err = webhook.Seal(keys, a.OrgID, id, url, raw); err != nil {
			return err
		}
		w.UpdatedAt = Time(s.now().UTC())
		if err := r.UpdateWebhook(ctx, w); err != nil {
			return err
		}
		out.Secret = shown
		return s.audit(ctx, r, a, "webhook.secret_rotated", "webhook", id.String(), map[string]any{"name": w.Name})
	})
	return out, err
}

// TestWebhook queues a webhook.test delivery (org only, sent once, even when
// the webhook is off), at most 10 per webhook per hour.
func (s *Service) TestWebhook(ctx context.Context, a *Actor, id uuid.UUID) (WebhookDelivery, error) {
	var out WebhookDelivery
	err := s.inOrg(ctx, a, func(r Repo) error {
		if err := integrations(a); err != nil {
			return err
		}
		w, err := r.Webhook(ctx, id, true) // the lock serializes the rate check
		if err != nil {
			return notFound(err)
		}
		now := s.now().UTC()
		n, oldest, err := r.WebhookTestsSince(ctx, id, now.Add(-time.Hour))
		if err != nil {
			return err
		}
		if n >= webhookTestsPerHr {
			return errTestRateLimited(oldest.Add(time.Hour).Sub(now))
		}
		org, err := r.Org(ctx, a.OrgID)
		if err != nil {
			return err
		}
		did := ids.New()
		body, err := webhook.Body(w.Kind, webhook.NewEvent(did, notify.WebhookTest, webhook.TestFacts(a.OrgID, org.Name, now), ""))
		if err != nil {
			return err
		}
		if err := r.InsertWebhookDelivery(ctx, NewWebhookDelivery{ID: did, OrgID: a.OrgID, WebhookID: id,
			Type: notify.WebhookTest, Payload: body, CreatedAt: now}); err != nil {
			return err
		}
		t := Time(now)
		out = WebhookDelivery{ID: did, Type: notify.WebhookTest, State: "pending", CreatedAt: t, NextAttemptAt: &t}
		return nil
	})
	return out, err
}

func errTestRateLimited(retryAfter time.Duration) error {
	secs := max(int64((retryAfter+time.Second-1)/time.Second), 1)
	return apperrors.Invalid("RATE_LIMITED", "you've sent "+strconv.Itoa(webhookTestsPerHr)+" tests in the last hour; try again later").
		WithHTTPStatus(http.StatusTooManyRequests).WithMetadata("retry_after", secs)
}

// DeliveryFilter is the raw query of GET /webhooks/{id}/deliveries.
type DeliveryFilter struct {
	// State: "" (any), pending, delivered or failed.
	State string
	PageParams
}

// WebhookDeliveries lists a webhook's deliveries of the last 30 days, newest
// first, optionally only those in one state.
func (s *Service) WebhookDeliveries(ctx context.Context, a *Actor, id uuid.UUID, f DeliveryFilter) (Page[WebhookDelivery], error) {
	var out Page[WebhookDelivery]
	p := f.PageParams
	limit := DefaultLimit
	if p.Limit != "" {
		n, err := strconv.Atoi(p.Limit)
		if err != nil || n < 1 || n > maxDeliveryLimit {
			return out, errField("limit", "must be an integer between 1 and 100")
		}
		limit = n
	}
	var after *DeliveryCursor
	if p.Cursor != "" {
		after = &DeliveryCursor{}
		if err := decodeCursor(p.Cursor, after); err != nil {
			return out, err
		}
	}
	err := s.inOrg(ctx, a, func(r Repo) error {
		if err := integrations(a); err != nil {
			return err
		}
		switch f.State {
		case "", "pending", "delivered", "failed":
		default:
			return errField("state", "must be pending, delivered or failed")
		}
		if _, err := r.Webhook(ctx, id, false); err != nil {
			return notFound(err)
		}
		rows, err := r.WebhookDeliveries(ctx, id, s.now().UTC().Add(-webhook.Retention), f.State, after, limit+1)
		if err != nil {
			return err
		}
		out.Items, out.NextCursor = page(rows, limit, func(d WebhookDelivery) any {
			return DeliveryCursor{CreatedAt: d.CreatedAt.T(), ID: d.ID}
		})
		return nil
	})
	return out, err
}
