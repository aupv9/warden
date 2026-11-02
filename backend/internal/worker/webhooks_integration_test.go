//go:build integration

package worker

import (
	"context"
	"crypto/rand"
	"encoding/base64"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"net/http/httptest"
	"strconv"
	"strings"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	"github.com/google/uuid"
	"github.com/jackc/pgx/v5"

	"github.com/aupv9/warden/backend/internal/db"
	"github.com/aupv9/warden/backend/internal/notify"
	"github.com/aupv9/warden/backend/internal/secretbox"
	"github.com/aupv9/warden/backend/internal/webhook"
)

type hookReq struct {
	header http.Header
	body   []byte
}

// hookReceiver is a webhook endpoint on 127.0.0.1 (in webhook.allow_hosts).
type hookReceiver struct {
	*httptest.Server
	mu     sync.Mutex
	got    []hookReq
	status atomic.Int32
}

func newHookReceiver(t *testing.T) *hookReceiver {
	r := &hookReceiver{}
	r.status.Store(200)
	r.Server = httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, req *http.Request) {
		b, _ := io.ReadAll(req.Body)
		r.mu.Lock()
		r.got = append(r.got, hookReq{header: req.Header.Clone(), body: b})
		r.mu.Unlock()
		w.WriteHeader(int(r.status.Load()))
	}))
	t.Cleanup(r.Close)
	return r
}

func (r *hookReceiver) requests() []hookReq {
	r.mu.Lock()
	defer r.mu.Unlock()
	return append([]hookReq(nil), r.got...)
}

type hookTest struct {
	*itest
	keys  *secretbox.Keyring
	clock time.Time
	issue uuid.UUID
}

func newHookTest(t *testing.T) *hookTest {
	h := &hookTest{itest: newITest(t), clock: time.Now().UTC().Truncate(time.Second)}
	raw := make([]byte, 32)
	_, _ = rand.Read(raw)
	var err error
	if h.keys, err = secretbox.Parse("k1:"+base64.StdEncoding.EncodeToString(raw), ""); err != nil {
		t.Fatal(err)
	}
	h.env.Now = func() time.Time { return h.clock }
	h.env.PublicBaseURL = "https://warden.example"
	h.env.Webhooks = WebhookSettings{Keys: h.keys, FailureLimit: 2,
		Client: webhook.NewClient(webhook.Policy{AllowHosts: []string{"127.0.0.1"}}, webhook.ClientOptions{})}
	scanID, _ := h.scan("completed", fmt.Sprintf("%064d", 0), 0, "opengrep")
	h.issue = uuid.New()
	owner(t, h.org,
		fmt.Sprintf(`INSERT INTO org_member (org_id, user_id, role) VALUES ('%s', '%s', 'org_admin')`, h.org, h.user),
		fmt.Sprintf(`INSERT INTO issue (id, org_id, project_id, number, fingerprint, tool, rule_id, title, severity, status,
				first_seen_scan_id, last_seen_scan_id, file_path, snippet, description)
			VALUES ('%s', '%s', '%s', 7, '%064d', 'opengrep', 'python.sqli', 'SQL <!channel> injection', 'high', 'open',
				'%s', '%s', 'app/secret_dir/db.py', 'SNIPPET-NEVER-SENT', 'DESCRIPTION-NEVER-SENT')`,
			h.issue, h.org, h.project, 7, scanID, scanID))
	return h
}

type hookOpts struct {
	kind     string
	events   string
	projects string
	minSev   string
	enabled  bool
}

// addWebhook stores a webhook as the API would (sealed URL and secret).
func (h *hookTest) addWebhook(url string, o hookOpts) (uuid.UUID, []byte) {
	h.t.Helper()
	id := uuid.New()
	var secret []byte
	if o.kind == webhook.KindGeneric {
		secret, _, _ = webhook.NewSecret()
	}
	s, err := webhook.Seal(h.keys, h.org, id, url, secret)
	if err != nil {
		h.t.Fatal(err)
	}
	if o.projects == "" {
		o.projects = "{}"
	}
	var minSev any
	if o.minSev != "" {
		minSev = o.minSev
	}
	err = db.WithOrg(context.Background(), appPool, h.org, func(tx pgx.Tx) error {
		_, err := tx.Exec(context.Background(), `INSERT INTO webhook (id, org_id, kind, name, url_hint, url_enc, secret_enc, key_id,
				events, project_ids, min_severity, enabled, created_by)
			VALUES ($1, $2, $3, 'hook', 'http://127.0.0.1', $4, $5, $6, $7::text[], $8::uuid[], $9::severity, $10, $11)`,
			id, h.org, o.kind, s.URL, s.Secret, s.KeyID, o.events, o.projects, minSev, o.enabled, h.user)
		return err
	})
	if err != nil {
		h.t.Fatal(err)
	}
	return id, secret
}

func (h *hookTest) event(typ string) {
	h.t.Helper()
	err := db.WithOrg(context.Background(), appPool, h.org, func(tx pgx.Tx) error {
		return notify.Insert(context.Background(), tx, notify.Event{OrgID: h.org, Type: typ,
			Payload: notify.Payload{IssueID: notify.ID(h.issue), ActorID: notify.ID(h.user), UserID: notify.ID(h.user)}})
	})
	if err != nil {
		h.t.Fatal(err)
	}
}

func (h *hookTest) dispatch() {
	h.t.Helper()
	if err := h.env.DispatchNotifications(context.Background()); err != nil {
		h.t.Fatal(err)
	}
}

func (h *hookTest) send() {
	h.t.Helper()
	if err := h.env.SendWebhooks(context.Background()); err != nil {
		h.t.Fatal(err)
	}
}

type deliveryRow struct {
	id                uuid.UUID
	state, errCode    string
	attempts, status  int
	pending, failures int
	enabled           bool
	reason            string
}

func (h *hookTest) delivery(webhookID uuid.UUID) deliveryRow {
	h.t.Helper()
	var d deliveryRow
	h.q(fmt.Sprintf(`SELECT d.id, d.state, coalesce(d.error, ''), d.attempts, coalesce(d.status_code, 0),
			(SELECT count(*) FROM webhook_delivery x WHERE x.webhook_id = w.id AND x.state = 'pending'),
			w.consecutive_failures, w.enabled, coalesce(w.disabled_reason, '')
		FROM webhook w JOIN webhook_delivery d ON d.webhook_id = w.id WHERE w.id = '%s' ORDER BY d.created_at DESC, d.id DESC LIMIT 1`, webhookID),
		&d.id, &d.state, &d.errCode, &d.attempts, &d.status, &d.pending, &d.failures, &d.enabled, &d.reason)
	return d
}

// q runs as warden_app under the test's org, so RLS scopes it (the owner in
// the test container is a superuser and would see every test's rows).
func (h *hookTest) q(q string, dest ...any) {
	h.t.Helper()
	if err := db.WithOrg(context.Background(), appPool, h.org, func(tx pgx.Tx) error {
		return tx.QueryRow(context.Background(), q).Scan(dest...)
	}); err != nil {
		h.t.Fatalf("%s: %v", q, err)
	}
}

func (h *hookTest) count(q string) int {
	h.t.Helper()
	var n int
	h.q(q, &n)
	return n
}

// Dispatch writes one delivery per matching webhook, idempotently; the sender
// posts the stored body, signed (generic) or as a Slack message, built from
// the allow-listed columns only.
func TestWebhookDeliveryEndToEnd(t *testing.T) {
	h := newHookTest(t)
	r := newHookReceiver(t)
	generic, secret := h.addWebhook(r.URL+"/generic", hookOpts{kind: "generic", events: "{issue.assigned,scan.finished}", enabled: true})
	slack, _ := h.addWebhook(r.URL+"/services/T/B/x", hookOpts{kind: "slack", events: "{issue.assigned}", minSev: "high", enabled: true})
	// None of these get the event.
	h.addWebhook(r.URL+"/other-event", hookOpts{kind: "generic", events: "{scan.finished}", enabled: true})
	h.addWebhook(r.URL+"/off", hookOpts{kind: "generic", events: "{issue.assigned}", enabled: false})
	h.addWebhook(r.URL+"/other-project", hookOpts{kind: "generic", events: "{issue.assigned}", projects: "{" + uuid.NewString() + "}", enabled: true})
	h.addWebhook(r.URL+"/critical-only", hookOpts{kind: "generic", events: "{issue.assigned}", minSev: "critical", enabled: true})

	h.event(notify.IssueAssigned)
	h.dispatch()
	if n := h.count(`SELECT count(*) FROM webhook_delivery`); n != 2 {
		t.Fatal(n)
	}
	// A dispatch retried after a crash (the event re-read) adds nothing.
	var eventID int64
	h.q(`SELECT max(id) FROM outbox_event`, &eventID)
	err := db.WithOrg(context.Background(), appPool, h.org, func(tx pgx.Tx) error {
		return h.env.webhookQueue().Enqueue(context.Background(), tx, h.org, eventID, notify.IssueAssigned,
			[]byte(fmt.Sprintf(`{"issue_id":"%s"}`, h.issue)))
	})
	if err != nil || h.count(`SELECT count(*) FROM webhook_delivery`) != 2 {
		t.Fatal(err)
	}

	h.send()
	reqs := r.requests()
	if len(reqs) != 2 {
		t.Fatal(len(reqs))
	}
	for _, req := range reqs {
		body := string(req.body)
		for _, never := range []string{"SNIPPET-NEVER-SENT", "DESCRIPTION-NEVER-SENT", "secret_dir", "@x.test"} {
			if len(body) == 0 || strings.Contains(body, never) {
				t.Fatalf("%q sent: %s", never, body)
			}
		}
		if req.header.Get("webhook-signature") == "" {
			// Slack: a message with the title escaped.
			var m map[string]any
			if err := json.Unmarshal(req.body, &m); err != nil || !strings.Contains(body, `SQL &lt;!channel&gt; injection`) {
				t.Fatalf("slack: %s", body)
			}
			continue
		}
		id, ts := req.header.Get("webhook-id"), req.header.Get("webhook-timestamp")
		n, _ := strconv.ParseInt(ts, 10, 64)
		if want := webhook.Sign(secret, id, n, req.body); req.header.Get("webhook-signature") != want {
			t.Fatal("bad signature")
		}
		var ev webhook.Event
		if err := json.Unmarshal(req.body, &ev); err != nil || ev.ID.String() != id || ev.Type != "issue.assigned" ||
			ev.Issue == nil || ev.Issue.Key != "WEB-7" || ev.Issue.Title != "SQL <!channel> injection" || ev.Actor == nil ||
			ev.Issue.URL != "https://warden.example/orgs/"+h.org.String()+"/issues/"+h.issue.String() || ev.Project.Key != "WEB" {
			t.Fatalf("%v %s", err, body)
		}
	}
	for _, id := range []uuid.UUID{generic, slack} {
		if d := h.delivery(id); d.state != "delivered" || d.attempts != 1 || d.status != 200 || d.errCode != "" || d.failures != 0 {
			t.Fatalf("%+v", d)
		}
	}
	// Nothing is sent twice.
	h.send()
	if len(r.requests()) != 2 {
		t.Fatal(len(r.requests()))
	}
}

// 5xx is retried on the schedule; a delivery that runs out of retries counts
// as a failure; at the limit (2 here) the webhook is turned off, admins are
// told, and the audit log says Warden did it. A delivery still queued then
// fails as "disabled" without being sent.
func TestWebhookRetriesAndDisable(t *testing.T) {
	h := newHookTest(t)
	r := newHookReceiver(t)
	r.status.Store(503)
	id, _ := h.addWebhook(r.URL+"/x", hookOpts{kind: "generic", events: "{issue.reopened}", enabled: true})

	exhaust := func() {
		t.Helper()
		h.event(notify.IssueReopened)
		h.dispatch()
		for i, wait := range append(append([]time.Duration(nil), webhook.Retries...), 0) {
			h.send()
			d := h.delivery(id)
			if d.attempts != i+1 || d.status != 503 || d.errCode != "http_status" {
				t.Fatalf("attempt %d: %+v", i+1, d)
			}
			if wait > 0 {
				var next time.Time
				h.q(fmt.Sprintf(`SELECT next_at FROM webhook_delivery WHERE id = '%s'`, d.id), &next)
				if d.state != "pending" || !next.Equal(h.clock.Add(wait)) {
					t.Fatalf("attempt %d: %+v next %v", i+1, d, next)
				}
				h.send() // not due yet: nothing happens
				if h.delivery(id).attempts != i+1 {
					t.Fatal("sent before next_at")
				}
				h.clock = h.clock.Add(wait)
			}
		}
	}
	exhaust()
	if d := h.delivery(id); d.state != "failed" || d.attempts != 7 || d.failures != 1 || !d.enabled {
		t.Fatalf("%+v", d)
	}
	if len(r.requests()) != 7 {
		t.Fatal(len(r.requests()))
	}

	// A second exhausted delivery reaches the limit.
	exhaust()
	d := h.delivery(id)
	if d.failures != 2 || d.enabled || d.reason != "failures" {
		t.Fatalf("%+v", d)
	}
	sent := len(r.requests())
	if n := h.count(`SELECT count(*) FROM outbox_event WHERE type = 'webhook.disabled' AND payload->>'webhook_id' = '` + id.String() + `'`); n != 1 {
		t.Fatal(n)
	}
	if n := h.count(`SELECT count(*) FROM audit_log WHERE org_id = current_setting('app.org_id')::uuid AND action = 'webhook.disabled' AND actor_id IS NULL AND target_id = '` + id.String() + `'
		AND data->>'reason' = 'failures' AND NOT (data::text LIKE '%127.0.0.1/x%')`); n != 1 {
		t.Fatal(n)
	}
	h.dispatch() // the admin is told
	if n := h.count(`SELECT count(*) FROM notification WHERE type = 'webhook.disabled' AND link LIKE '%/integrations' AND email_state = 'pending'`); n != 1 {
		t.Fatal(n)
	}
	// A delivery queued before it went off is failed, not sent.
	err := db.WithOrg(context.Background(), appPool, h.org, func(tx pgx.Tx) error {
		_, err := tx.Exec(context.Background(), `INSERT INTO webhook_delivery (id, org_id, webhook_id, type, payload, next_at)
			VALUES ($1, $2, $3, 'issue.reopened', '{}', $4)`, uuid.New(), h.org, id, h.clock)
		return err
	})
	if err != nil {
		t.Fatal(err)
	}
	h.send()
	var pendingFailed int
	h.q(`SELECT count(*) FROM webhook_delivery WHERE state = 'failed' AND error = 'disabled' AND attempts = 0`, &pendingFailed)
	if pendingFailed != 1 || len(r.requests()) != sent {
		t.Fatal(pendingFailed, len(r.requests()), sent)
	}
	// While off, events don't queue deliveries.
	before := h.count(`SELECT count(*) FROM webhook_delivery`)
	h.event(notify.IssueReopened)
	h.dispatch()
	if h.count(`SELECT count(*) FROM webhook_delivery`) != before {
		t.Fatal("delivery queued for an off webhook")
	}
}

// 410 Gone turns the webhook off at once; other 4xx fail without retry; a
// test is tried once, even when the webhook is off, and never counts; a URL
// the server can't decrypt fails as key_unavailable without being sent.
func TestWebhookGoneTestAndKeys(t *testing.T) {
	h := newHookTest(t)
	h.env.Webhooks.FailureLimit = 10
	r := newHookReceiver(t)
	id, _ := h.addWebhook(r.URL+"/x", hookOpts{kind: "generic", events: "{issue.assigned}", enabled: true})

	r.status.Store(400)
	h.event(notify.IssueAssigned)
	h.dispatch()
	h.send()
	if d := h.delivery(id); d.state != "failed" || d.attempts != 1 || d.status != 400 || d.failures != 1 || !d.enabled {
		t.Fatalf("%+v", d)
	}

	r.status.Store(410)
	h.event(notify.IssueAssigned)
	h.dispatch()
	h.send()
	if d := h.delivery(id); d.state != "failed" || d.status != 410 || d.enabled || d.reason != "failures" || d.failures != 2 {
		t.Fatalf("%+v", d)
	}
	if n := h.count(`SELECT count(*) FROM audit_log WHERE org_id = current_setting('app.org_id')::uuid AND action = 'webhook.disabled' AND data->>'reason' = 'gone'`); n != 1 {
		t.Fatal(n)
	}

	// A test on the off webhook: sent once, failure not counted.
	r.status.Store(500)
	test := uuid.New()
	err := db.WithOrg(context.Background(), appPool, h.org, func(tx pgx.Tx) error {
		_, err := tx.Exec(context.Background(), `INSERT INTO webhook_delivery (id, org_id, webhook_id, type, payload, next_at)
			VALUES ($1, $2, $3, 'webhook.test', '{"type":"webhook.test"}', $4)`, test, h.org, id, h.clock)
		return err
	})
	if err != nil {
		t.Fatal(err)
	}
	n := len(r.requests())
	h.send()
	if d := h.delivery(id); d.id != test || d.state != "failed" || d.attempts != 1 || d.status != 500 || d.failures != 2 {
		t.Fatalf("%+v", d)
	}
	if len(r.requests()) != n+1 {
		t.Fatal("test not sent once")
	}

	// Keys: the URL was sealed under k1; a server with another key can't read it.
	other := newHookTest(t)
	h.env.Webhooks.Keys = other.keys
	h.addWebhook(r.URL+"/y", hookOpts{kind: "generic", events: "{issue.assigned}", enabled: true}) // sealed under h.keys
	h.event(notify.IssueAssigned)
	h.dispatch()
	n = len(r.requests())
	h.send()
	if c := h.count(`SELECT count(*) FROM webhook_delivery WHERE error = 'key_unavailable' AND attempts = 0 AND state = 'failed'`); c != 1 ||
		len(r.requests()) != n {
		t.Fatal(c, len(r.requests()))
	}
	h.env.Webhooks.Keys = nil // no secrets.key at all
	h.event(notify.IssueAssigned)
	h.dispatch()
	h.send()
	if c := h.count(`SELECT count(*) FROM webhook_delivery WHERE error = 'key_unavailable'`); c != 2 || len(r.requests()) != n {
		t.Fatal(c)
	}
}

// Webhook rows and deliveries are invisible across orgs, and old deliveries
// are pruned.
func TestWebhookRLSAndPrune(t *testing.T) {
	a, b := newHookTest(t), newHookTest(t)
	r := newHookReceiver(t)
	hookB, _ := b.addWebhook(r.URL+"/b", hookOpts{kind: "generic", events: "{issue.assigned}", enabled: true})
	var seen int
	err := db.WithOrg(context.Background(), appPool, a.org, func(tx pgx.Tx) error {
		return tx.QueryRow(context.Background(), `SELECT count(*) FROM webhook WHERE id = $1`, hookB).Scan(&seen)
	})
	if err != nil || seen != 0 {
		t.Fatal(seen, err)
	}
	// Org A's event never reaches org B's webhook.
	a.event(notify.IssueAssigned)
	a.dispatch()
	if n := b.count(`SELECT count(*) FROM webhook_delivery`); n != 0 {
		t.Fatal(n)
	}
	b.event(notify.IssueAssigned)
	b.dispatch()
	b.send()
	if n := b.count(`SELECT count(*) FROM webhook_delivery WHERE state = 'delivered'`); n != 1 {
		t.Fatal(n)
	}
	b.clock = b.clock.Add(31 * 24 * time.Hour)
	b.env.Now = func() time.Time { return b.clock }
	if err := b.env.PruneWebhookDeliveries(context.Background()); err != nil {
		t.Fatal(err)
	}
	if n := b.count(`SELECT count(*) FROM webhook_delivery`); n != 0 {
		t.Fatal(n)
	}
}
