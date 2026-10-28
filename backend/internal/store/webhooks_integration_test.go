//go:build integration

package store_test

import (
	"context"
	"crypto/rand"
	"encoding/base64"
	"net"
	"net/netip"
	"slices"
	"strings"
	"testing"
	"time"

	"github.com/google/uuid"
	"github.com/jackc/pgx/v5"

	"github.com/aupv9/warden/backend/internal/db"
	"github.com/aupv9/warden/backend/internal/secretbox"
	"github.com/aupv9/warden/backend/internal/service"
	"github.com/aupv9/warden/backend/internal/store"
	"github.com/aupv9/warden/backend/internal/webhook"
)

type publicDNS struct{}

func (publicDNS) LookupNetIP(_ context.Context, _, host string) ([]netip.Addr, error) {
	if host == "hooks.example.com" {
		return []netip.Addr{netip.MustParseAddr("93.184.216.34")}, nil
	}
	return nil, &net.DNSError{Err: "no such host", Name: host, IsNotFound: true}
}

// The webhook routes against the real schema: encryption at rest, RLS between
// orgs, the delivery log and its cursor, the test rate limit and the audit
// trail (which never holds the URL or the secret).
func TestWebhooksAgainstSchema(t *testing.T) {
	w := newWorld(t)
	raw := make([]byte, 32)
	_, _ = rand.Read(raw)
	keys, err := secretbox.Parse("k1:"+base64.StdEncoding.EncodeToString(raw), "")
	if err != nil {
		t.Fatal(err)
	}
	clock := time.Now().UTC()
	svc := service.New(w.db, w.objs, service.Config{Webhooks: service.WebhookConfig{Keys: keys,
		Checker: &webhook.Checker{Resolver: publicDNS{}}}}, nil)
	svc.SetClock(func() time.Time { return clock })
	a, b := w.org("WHA"), w.org("WHB")
	admin, otherAdmin := w.actor("WHAadmin", a.id), w.actor("WHBadmin", b.id)

	url := "https://hooks.example.com/in/" + strings.Repeat("s", 20)
	created, err := svc.CreateWebhook(ctx, admin, service.CreateWebhookInput{Kind: "generic", Name: "SIEM", URL: url,
		Events: []string{"issue.assigned"}, ProjectIDs: []string{a.project.String()}})
	if err != nil || created.Secret == nil || created.Webhook.CreatedBy.Email == "" || created.Webhook.ProjectIDs[0] != a.project {
		t.Fatal(created, err)
	}
	id := created.Webhook.ID
	// Another org's project is unknown; another org's admin sees nothing.
	_, err = svc.CreateWebhook(ctx, admin, service.CreateWebhookInput{Kind: "generic", Name: "x", URL: url,
		Events: []string{"issue.assigned"}, ProjectIDs: []string{b.project.String()}})
	if code(err) != "VALIDATION_FAILED" {
		t.Fatal(err)
	}
	if _, err := svc.Webhook(ctx, otherAdmin, id); code(err) != "NOT_FOUND" {
		t.Fatal(err)
	}
	if l, err := svc.Webhooks(ctx, otherAdmin); err != nil || len(l.Items) != 0 || !l.Available {
		t.Fatal(l, err)
	}

	// At rest: ciphertext only, and it opens for this row alone.
	var urlEnc, secretEnc []byte
	var keyID string
	ownerOne(t, a.id, `SELECT url_enc, secret_enc, key_id FROM webhook WHERE id = $1`, []any{id}, &urlEnc, &secretEnc, &keyID)
	if strings.Contains(string(urlEnc), "hooks.example.com") || keyID != "k1" {
		t.Fatal("stored in clear")
	}
	got, sec, err := webhook.Open(keys, a.id, id, webhook.Sealed{URL: urlEnc, Secret: secretEnc, KeyID: keyID})
	if err != nil || got != url || webhook.FormatSecret(sec) != *created.Secret {
		t.Fatal(err)
	}

	up, err := svc.UpdateWebhook(ctx, admin, id, service.UpdateWebhookInput{Name: ptr("SIEM 2"),
		MinSeverity: service.Optional[string]{Set: true, Value: ptr("high")}})
	if err != nil || up.Name != "SIEM 2" || *up.MinSeverity != "high" {
		t.Fatal(up, err)
	}
	if _, err := svc.RotateWebhookSecret(ctx, admin, id); err != nil {
		t.Fatal(err)
	}

	// Tests: 10 an hour, then 429; the log pages newest first.
	for i := range 10 {
		if _, err := svc.TestWebhook(ctx, admin, id); err != nil {
			t.Fatal(i, err)
		}
		clock = clock.Add(time.Second)
	}
	if _, err := svc.TestWebhook(ctx, admin, id); code(err) != "RATE_LIMITED" {
		t.Fatal(err)
	}
	page1, err := svc.WebhookDeliveries(ctx, admin, id, service.PageParams{Limit: "6"})
	if err != nil || len(page1.Items) != 6 || page1.NextCursor == nil || page1.Items[0].NextAttemptAt == nil {
		t.Fatal(page1, err)
	}
	page2, err := svc.WebhookDeliveries(ctx, admin, id, service.PageParams{Limit: "6", Cursor: *page1.NextCursor})
	if err != nil || len(page2.Items) != 4 || page2.NextCursor != nil || !page2.Items[0].CreatedAt.T().Before(page1.Items[5].CreatedAt.T()) {
		t.Fatal(page2, err)
	}
	one, err := svc.Webhook(ctx, admin, id)
	if err != nil || one.LastDelivery == nil || one.LastDelivery.State != "pending" {
		t.Fatal(one, err)
	}
	// Each test also queued a send_webhooks job in its transaction.
	var jobs int
	if err := w.pool.QueryRow(ctx, `SELECT count(*) FROM river_job WHERE kind = 'send_webhooks'`).Scan(&jobs); err != nil || jobs < 10 {
		t.Fatal(jobs, err)
	}

	// RLS: org B can't see org A's deliveries even by id.
	var seen int
	if err := db.WithOrg(ctx, w.pool, b.id, func(tx pgx.Tx) error {
		return tx.QueryRow(ctx, `SELECT count(*) FROM webhook_delivery WHERE webhook_id = $1`, id).Scan(&seen)
	}); err != nil || seen != 0 {
		t.Fatal(seen, err)
	}

	// Key rotation: with k2 active and k1 old, warden-admin secrets rotate
	// moves the row to k2, after which k1 can go.
	raw2 := make([]byte, 32)
	_, _ = rand.Read(raw2)
	k2 := "k2:" + base64.StdEncoding.EncodeToString(raw2)
	rotated, err := secretbox.Parse(k2, "k1:"+base64.StdEncoding.EncodeToString(raw))
	if err != nil {
		t.Fatal(err)
	}
	n, unreadable, err := store.ReencryptWebhooks(ctx, w.db, rotated)
	if err != nil || n < 1 || slices.Contains(unreadable, id) {
		t.Fatal(n, unreadable, err)
	}
	ownerOne(t, a.id, `SELECT url_enc, secret_enc, key_id FROM webhook WHERE id = $1`, []any{id}, &urlEnc, &secretEnc, &keyID)
	onlyK2, _ := secretbox.Parse(k2, "")
	if got, _, err := webhook.Open(onlyK2, a.id, id, webhook.Sealed{URL: urlEnc, Secret: secretEnc, KeyID: keyID}); err != nil || got != url {
		t.Fatal(keyID, err)
	}

	if err := svc.DeleteWebhook(ctx, admin, id); err != nil {
		t.Fatal(err)
	}
	ownerOne(t, a.id, `SELECT count(*) FROM webhook_delivery WHERE webhook_id = $1`, []any{id}, &seen)
	if seen != 0 {
		t.Fatal("deliveries left behind")
	}

	// The audit trail: every action, never the URL or a secret.
	var actions, data string
	ownerOne(t, a.id, `SELECT string_agg(action, ',' ORDER BY id), string_agg(data::text, ' ') FROM audit_log
		WHERE org_id = $1 AND action LIKE 'webhook.%'`, []any{a.id}, &actions, &data)
	if actions != "webhook.created,webhook.updated,webhook.secret_rotated,webhook.reencrypted,webhook.deleted" ||
		strings.Contains(data, strings.Repeat("s", 20)) || strings.Contains(data, "whsec_") {
		t.Fatal(actions, data)
	}
}

func ownerOne(t *testing.T, org uuid.UUID, q string, args []any, dest ...any) {
	t.Helper()
	conn, err := pgx.Connect(ctx, ownerURL)
	if err != nil {
		t.Fatal(err)
	}
	defer conn.Close(ctx)
	if err := pgx.BeginFunc(ctx, conn, func(tx pgx.Tx) error {
		if _, err := tx.Exec(ctx, "SELECT set_config('app.org_id', $1, true)", org.String()); err != nil {
			return err
		}
		return tx.QueryRow(ctx, q, args...).Scan(dest...)
	}); err != nil {
		t.Fatalf("%s: %v", q, err)
	}
}
