package api

import (
	"context"
	"crypto/rand"
	"encoding/base64"
	"encoding/json"
	"fmt"
	"net"
	"net/netip"
	"regexp"
	"strings"
	"testing"
	"time"

	"github.com/google/uuid"

	"github.com/aupv9/warden/backend/internal/secretbox"
	"github.com/aupv9/warden/backend/internal/service"
	"github.com/aupv9/warden/backend/internal/service/servicetest"
	"github.com/aupv9/warden/backend/internal/webhook"
)

type dnsStub map[string]string

func (d dnsStub) LookupNetIP(_ context.Context, _, host string) ([]netip.Addr, error) {
	if a, ok := d[host]; ok {
		return []netip.Addr{netip.MustParseAddr(a)}, nil
	}
	return nil, &net.DNSError{Err: "no such host", Name: host, IsNotFound: true}
}

func testKeys(t *testing.T) *secretbox.Keyring {
	t.Helper()
	raw := make([]byte, 32)
	_, _ = rand.Read(raw)
	k, err := secretbox.Parse("k1:"+base64.StdEncoding.EncodeToString(raw), "")
	if err != nil {
		t.Fatal(err)
	}
	return k
}

// Slack URLs are credentials: built at test time, never committed.
var slackURL = "https://hooks.slack.com/services/T" + strings.Repeat("0", 8) + "/B" + strings.Repeat("1", 8) + "/" + strings.Repeat("x", 24)

const genericURL = "https://hooks.example.com/in/very-secret-path?token=abc"

func webhookEnv(t *testing.T, keys *secretbox.Keyring) *env {
	return newEnv(t, func(c *service.Config) {
		c.Webhooks = service.WebhookConfig{Keys: keys, Checker: &webhook.Checker{Resolver: dnsStub{
			"hooks.example.com": "93.184.216.34", "hooks.slack.com": "34.226.36.50", "intranet.example.com": "10.1.2.3",
			"metadata.example.com": "169.254.169.254",
		}}}
	})
}

func genericBody() map[string]any {
	return map[string]any{"kind": "generic", "name": "SIEM", "url": genericURL, "events": []string{"issue.assigned", "scan.finished"}}
}

// No response, audit entry or delivery ever contains the URL or the secret.
func (e *env) assertNoLeak(secrets ...string) {
	e.t.Helper()
	raw, _ := json.Marshal(e.f.AuditLog())
	for _, s := range append(secrets, "very-secret-path", "token=abc", strings.Repeat("x", 24)) {
		if s != "" && strings.Contains(string(raw), s) {
			e.t.Fatalf("audit log contains %q", s)
		}
	}
}

func TestWebhookPermissions(t *testing.T) {
	e := webhookEnv(t, testKeys(t))
	r := e.do("POST", "/webhooks", admin, genericBody())
	e.expect(r, 201, "")
	id := r.obj()["webhook"].(map[string]any)["id"].(string)
	for _, who := range []string{owner, dev, viewer, outsider} {
		e.expect(e.do("GET", "/webhooks", who, nil), 403, "FORBIDDEN")
		e.expect(e.do("POST", "/webhooks", who, genericBody()), 403, "FORBIDDEN")
		e.expect(e.do("GET", "/webhooks/"+id, who, nil), 403, "FORBIDDEN")
		e.expect(e.do("PATCH", "/webhooks/"+id, who, map[string]any{"enabled": false}), 403, "FORBIDDEN")
		e.expect(e.do("DELETE", "/webhooks/"+id, who, nil), 403, "FORBIDDEN")
		e.expect(e.do("POST", "/webhooks/"+id+"/rotate-secret", who, nil), 403, "FORBIDDEN")
		e.expect(e.do("POST", "/webhooks/"+id+"/test", who, nil), 403, "FORBIDDEN")
		e.expect(e.do("GET", "/webhooks/"+id+"/deliveries", who, nil), 403, "FORBIDDEN")
	}
	e.expect(e.do("GET", "/webhooks", stranger, nil), 404, "NOT_FOUND")
	e.expect(e.do("GET", "/webhooks", lead, nil), 200, "")
	e.expect(e.do("GET", "/webhooks/"+uuid.NewString(), lead, nil), 404, "NOT_FOUND")
	e.expect(e.do("GET", "/webhooks/nope", lead, nil), 404, "NOT_FOUND")

	// API tokens can't reach any webhook route, whatever the scope and creator.
	_, scanTok := e.newToken(owner, e.web, "scan:write", "issues:read")
	for _, c := range [][2]string{
		{"GET", "/webhooks"}, {"POST", "/webhooks"}, {"GET", "/webhooks/" + id}, {"PATCH", "/webhooks/" + id},
		{"DELETE", "/webhooks/" + id}, {"POST", "/webhooks/" + id + "/rotate-secret"}, {"POST", "/webhooks/" + id + "/test"},
		{"GET", "/webhooks/" + id + "/deliveries"},
	} {
		e.expect(e.doTok(c[0], c[1], scanTok, genericBody()), 403, "TOKEN_SCOPE")
	}
}

func TestWebhooksUnavailableWithoutKey(t *testing.T) {
	e := webhookEnv(t, nil)
	r := e.do("GET", "/webhooks", admin, nil)
	e.expect(r, 200, "")
	if r.obj()["available"] != false || len(r.items()) != 0 {
		t.Fatal(r.body)
	}
	e.expect(e.do("POST", "/webhooks", admin, genericBody()), 409, "SECRETS_KEY_MISSING")
	// The permission check comes first: others learn nothing about the server.
	e.expect(e.do("POST", "/webhooks", owner, genericBody()), 403, "FORBIDDEN")
}

func TestCreateWebhook(t *testing.T) {
	e := webhookEnv(t, testKeys(t))
	r := e.do("POST", "/webhooks", lead, genericBody())
	e.expect(r, 201, "")
	secret, _ := r.obj()["secret"].(string)
	if !regexp.MustCompile(`^whsec_[A-Za-z0-9+/]{43}=$`).MatchString(secret) {
		t.Fatal(r.body)
	}
	w := r.obj()["webhook"].(map[string]any)
	if w["url_hint"] != "https://hooks.example.com/…" || w["enabled"] != true || w["kind"] != "generic" ||
		w["last_delivery"] != nil || w["min_severity"] != nil || len(w["project_ids"].([]any)) != 0 ||
		w["created_by"].(map[string]any)["email"] != lead || strings.Contains(r.body, "very-secret-path") {
		t.Fatal(r.body)
	}
	// Stored encrypted under the org, row and column.
	stored, _ := e.f.StoredWebhook(uuid.MustParse(w["id"].(string)))
	if strings.Contains(string(stored.Sealed.URL), "hooks.example.com") || stored.Sealed.KeyID != "k1" || stored.Sealed.Secret == nil {
		t.Fatal("not sealed")
	}

	slack := e.do("POST", "/webhooks", admin, map[string]any{"kind": "slack", "name": "#security", "url": slackURL,
		"events": []string{"component.malicious"}, "project_ids": []string{e.web.String()}, "min_severity": "high"})
	e.expect(slack, 201, "")
	if slack.obj()["secret"] != nil || slack.obj()["webhook"].(map[string]any)["url_hint"] != "https://hooks.slack.com/…" ||
		strings.Contains(slack.body, strings.Repeat("x", 24)) {
		t.Fatal(slack.body)
	}

	list := e.do("GET", "/webhooks", admin, nil)
	if list.obj()["available"] != true || len(list.items()) != 2 || list.items()[0].(map[string]any)["name"] != "SIEM" ||
		strings.Contains(list.body, "very-secret-path") || strings.Contains(list.body, strings.Repeat("x", 24)) {
		t.Fatal(list.body)
	}
	got := e.do("GET", "/webhooks/"+w["id"].(string), admin, nil)
	if strings.Contains(got.body, "secret") && strings.Contains(got.body, secret) {
		t.Fatal(got.body)
	}

	a := e.f.AuditLog()
	if last := a[len(a)-1]; last.Action != "webhook.created" || last.Data["url_hint"] != "https://hooks.slack.com/…" {
		t.Fatalf("%+v", last)
	}
	e.assertNoLeak(secret)
}

func TestCreateWebhookValidation(t *testing.T) {
	e := webhookEnv(t, testKeys(t))
	body := func(over map[string]any) map[string]any {
		b := genericBody()
		for k, v := range over {
			b[k] = v
		}
		return b
	}
	for _, c := range []struct {
		over  map[string]any
		field string
		msg   string
	}{
		{map[string]any{"url": "http://hooks.example.com/x"}, "url", "must use https"},
		{map[string]any{"url": "https://intranet.example.com/x"}, "url", "resolves to a private address"},
		{map[string]any{"url": "https://metadata.example.com/latest"}, "url", "resolves to a private address"},
		{map[string]any{"url": "https://169.254.169.254/latest"}, "url", "resolves to a private address"},
		{map[string]any{"url": "https://[::ffff:10.0.0.1]/x"}, "url", "resolves to a private address"},
		{map[string]any{"url": "https://unknown.example.com/x"}, "url", "the host name doesn't resolve"},
		{map[string]any{"url": "https://u:p@hooks.example.com/x"}, "url", "must not contain a user name or password"},
		{map[string]any{"url": "https://2130706433/x"}, "url", "must be a valid URL"},
		{map[string]any{"kind": "slack"}, "url", "Slack URLs start with https://hooks.slack.com/services/"},
		{map[string]any{"kind": "teams"}, "kind", "must be generic or slack"},
		{map[string]any{"name": " "}, "name", "must be 1-80 characters"},
		{map[string]any{"name": strings.Repeat("n", 81)}, "name", "must be 1-80 characters"},
		{map[string]any{"name": "a\nb"}, "name", "must be 1-80 characters"},
		{map[string]any{"events": []string{}}, "events", "must list at least one event"},
		{map[string]any{"events": []string{"sla.overdue"}}, "events", ""},
		{map[string]any{"events": []string{"webhook.disabled"}}, "events", ""},
		{map[string]any{"events": []string{"scan.finished", "scan.finished"}}, "events", ""},
		{map[string]any{"project_ids": []string{"x"}}, "project_ids", ""},
		{map[string]any{"project_ids": []string{uuid.NewString()}}, "project_ids", ""},
		{map[string]any{"min_severity": "urgent"}, "min_severity", ""},
		{map[string]any{"secret": "mine"}, "secret", "unknown field"},
	} {
		r := e.do("POST", "/webhooks", admin, body(c.over))
		e.expect(r, 422, "VALIDATION_FAILED")
		fields, _ := r.Error.Metadata["fields"].(map[string]any)
		if msg, ok := fields[c.field].(string); !ok || (c.msg != "" && msg != c.msg) {
			t.Errorf("%v: %s", c.over, r.body)
		}
	}
	// Another org's project is unknown here.
	other := e.f.AddOrg("Other")
	e.expect(e.do("POST", "/webhooks", admin, body(map[string]any{"project_ids": []string{e.f.AddProject(other, "OTH").String()}})),
		422, "VALIDATION_FAILED")

	// At most 20 per org.
	for i := range 20 {
		e.expect(e.do("POST", "/webhooks", admin, body(map[string]any{"name": fmt.Sprint("hook ", i)})), 201, "")
	}
	e.expect(e.do("POST", "/webhooks", admin, genericBody()), 409, "WEBHOOK_LIMIT")
}

func TestUpdateWebhook(t *testing.T) {
	e := webhookEnv(t, testKeys(t))
	r := e.do("POST", "/webhooks", admin, genericBody())
	id := r.obj()["webhook"].(map[string]any)["id"].(string)
	secret := r.obj()["secret"].(string)
	wid := uuid.MustParse(id)
	path := "/webhooks/" + id

	e.expect(e.do("PATCH", path, admin, map[string]any{}), 422, "VALIDATION_FAILED")
	e.expect(e.do("PATCH", path, admin, map[string]any{"kind": "slack"}), 422, "VALIDATION_FAILED")
	e.expect(e.do("PATCH", path, admin, map[string]any{"url": "https://intranet.example.com/x"}), 422, "VALIDATION_FAILED")
	e.expect(e.do("PATCH", path, admin, map[string]any{"events": []string{}}), 422, "VALIDATION_FAILED")

	r = e.do("PATCH", path, lead, map[string]any{"name": "SIEM 2", "min_severity": "critical", "project_ids": []string{e.web.String()}})
	e.expect(r, 200, "")
	if r.obj()["name"] != "SIEM 2" || r.obj()["min_severity"] != "critical" || len(r.obj()["project_ids"].([]any)) != 1 {
		t.Fatal(r.body)
	}
	a := e.f.AuditLog()
	if last := a[len(a)-1]; last.Action != "webhook.updated" || fmt.Sprint(last.Data["changed"]) != "[name project_ids min_severity]" {
		t.Fatalf("%+v", last)
	}
	// null clears min_severity; absent leaves it.
	if r = e.do("PATCH", path, lead, map[string]any{"min_severity": nil}); r.obj()["min_severity"] != nil {
		t.Fatal(r.body)
	}
	if r = e.do("PATCH", path, lead, map[string]any{"name": "SIEM 3"}); r.obj()["min_severity"] != nil || r.obj()["name"] != "SIEM 3" {
		t.Fatal(r.body)
	}

	// Turned off by Warden after failures; enabled:true resets the count and reason.
	e.f.SetWebhook(wid, func(w *service.WebhookRecord) {
		reason := "failures"
		w.Enabled, w.DisabledReason, w.ConsecutiveFailures = false, &reason, 10
	})
	r = e.do("PATCH", path, admin, map[string]any{"enabled": true})
	if r.obj()["enabled"] != true || r.obj()["disabled_reason"] != nil || r.obj()["consecutive_failures"] != float64(0) {
		t.Fatal(r.body)
	}
	if r = e.do("PATCH", path, admin, map[string]any{"enabled": false}); r.obj()["enabled"] != false || r.obj()["disabled_reason"] != nil {
		t.Fatal(r.body)
	}

	// A new URL: re-checked, re-encrypted, and the secret kept.
	before, _ := e.f.StoredWebhook(wid)
	r = e.do("PATCH", path, admin, map[string]any{"url": "https://hooks.example.com/other"})
	e.expect(r, 200, "")
	after, _ := e.f.StoredWebhook(wid)
	if string(after.Sealed.URL) == string(before.Sealed.URL) || after.URLHint != "https://hooks.example.com/…" {
		t.Fatal("url not replaced")
	}
	a = e.f.AuditLog()
	if last := a[len(a)-1]; fmt.Sprint(last.Data["changed"]) != "[url]" {
		t.Fatalf("%+v", last)
	}
	e.assertNoLeak(secret, "/other")
}

func TestRotateDeleteWebhook(t *testing.T) {
	keys := testKeys(t)
	e := webhookEnv(t, keys)
	r := e.do("POST", "/webhooks", admin, genericBody())
	id := r.obj()["webhook"].(map[string]any)["id"].(string)
	old := r.obj()["secret"].(string)
	slack := e.do("POST", "/webhooks", admin, map[string]any{"kind": "slack", "name": "s", "url": slackURL, "events": []string{"scan.finished"}})
	sid := slack.obj()["webhook"].(map[string]any)["id"].(string)

	e.expect(e.do("POST", "/webhooks/"+sid+"/rotate-secret", admin, nil), 422, "INVALID_TRANSITION")
	r = e.do("POST", "/webhooks/"+id+"/rotate-secret", lead, nil)
	e.expect(r, 200, "")
	fresh := r.obj()["secret"].(string)
	if fresh == old || !strings.HasPrefix(fresh, "whsec_") {
		t.Fatal(r.body)
	}
	stored, _ := e.f.StoredWebhook(uuid.MustParse(id))
	url, sec, err := webhook.Open(keys, e.org, stored.ID, stored.Sealed)
	if err != nil || url != genericURL || webhook.FormatSecret(sec) != fresh {
		t.Fatal(url, err)
	}
	e.assertNoLeak(old, fresh)

	e.expect(e.do("DELETE", "/webhooks/"+id, admin, nil), 204, "")
	e.expect(e.do("GET", "/webhooks/"+id, admin, nil), 404, "NOT_FOUND")
	e.expect(e.do("DELETE", "/webhooks/"+id, admin, nil), 404, "NOT_FOUND")
	a := e.f.AuditLog()
	if last := a[len(a)-1]; last.Action != "webhook.deleted" || last.Data["name"] != "SIEM" {
		t.Fatalf("%+v", last)
	}
}

func TestWebhookTestAndDeliveries(t *testing.T) {
	e := webhookEnv(t, testKeys(t))
	r := e.do("POST", "/webhooks", admin, genericBody())
	id := r.obj()["webhook"].(map[string]any)["id"].(string)
	// Off webhooks can still be tested.
	e.expect(e.do("PATCH", "/webhooks/"+id, admin, map[string]any{"enabled": false}), 200, "")

	for i := range 10 {
		r = e.do("POST", "/webhooks/"+id+"/test", admin, nil)
		e.expect(r, 202, "")
		if r.obj()["type"] != "webhook.test" || r.obj()["state"] != "pending" || r.obj()["attempts"] != float64(0) {
			t.Fatal(i, r.body)
		}
		e.f.Now = e.f.Now.Add(time.Minute)
	}
	r = e.do("POST", "/webhooks/"+id+"/test", admin, nil)
	e.expect(r, 429, "RATE_LIMITED")
	if ra := r.header.Get("Retry-After"); ra != "3000" { // the first test was 50 minutes ago
		t.Fatal(ra)
	}
	e.f.Now = e.f.Now.Add(50 * time.Minute)
	e.expect(e.do("POST", "/webhooks/"+id+"/test", admin, nil), 202, "")

	// The test payload carries the org and nothing else.
	d := e.f.Deliveries(uuid.MustParse(id))
	var body map[string]any
	if err := json.Unmarshal(d[0].Payload, &body); err != nil {
		t.Fatal(err)
	}
	if body["id"] != d[0].ID.String() || body["org"].(map[string]any)["name"] != "Acme" || body["project"] != nil || body["issue"] != nil {
		t.Fatal(string(d[0].Payload))
	}

	// Newest first, 4 per page, then the rest.
	r = e.do("GET", "/webhooks/"+id+"/deliveries?limit=4", lead, nil)
	e.expect(r, 200, "")
	cursor, _ := r.obj()["next_cursor"].(string)
	if len(r.items()) != 4 || cursor == "" || r.items()[0].(map[string]any)["id"] != d[len(d)-1].ID.String() {
		t.Fatal(r.body)
	}
	seen := 4
	for cursor != "" {
		r = e.do("GET", "/webhooks/"+id+"/deliveries?limit=4&cursor="+cursor, lead, nil)
		seen += len(r.items())
		cursor, _ = r.obj()["next_cursor"].(string)
	}
	if seen != 11 {
		t.Fatal(seen)
	}
	e.expect(e.do("GET", "/webhooks/"+id+"/deliveries?limit=101", lead, nil), 422, "VALIDATION_FAILED")
	e.expect(e.do("GET", "/webhooks/"+id+"/deliveries?cursor=!!!", lead, nil), 422, "VALIDATION_FAILED")

	// ?state= filters; anything but the three states is a 422.
	delivered := service.Time(e.f.Now.Add(-2 * time.Hour)) // older than the tests: last_delivery stays theirs
	e.f.AddDelivery(servicetest.DeliveryRow{OrgID: e.org, WebhookID: uuid.MustParse(id), WebhookDelivery: service.WebhookDelivery{
		ID: uuid.New(), Type: "scan.finished", State: "delivered", Attempts: 1, CreatedAt: delivered, DeliveredAt: &delivered}})
	for state, n := range map[string]int{"pending": 11, "delivered": 1, "failed": 0} {
		r = e.do("GET", "/webhooks/"+id+"/deliveries?limit=100&state="+state, lead, nil)
		e.expect(r, 200, "")
		if len(r.items()) != n {
			t.Fatal(state, r.body)
		}
		for _, d := range r.items() {
			if d.(map[string]any)["state"] != state {
				t.Fatal(state, r.body)
			}
		}
	}
	for _, bad := range []string{"bogus", "PENDING", "pending,failed", "%00"} {
		e.expect(e.do("GET", "/webhooks/"+id+"/deliveries?state="+bad, lead, nil), 422, "VALIDATION_FAILED")
	}
	// The permission check comes before the validation.
	e.expect(e.do("GET", "/webhooks/"+id+"/deliveries?state=bogus", owner, nil), 403, "FORBIDDEN")

	// The last 30 days only.
	e.f.Now = e.f.Now.Add(31 * 24 * time.Hour)
	if r = e.do("GET", "/webhooks/"+id+"/deliveries", lead, nil); len(r.items()) != 0 {
		t.Fatal(r.body)
	}
	// last_delivery reflects the newest one.
	if w := e.do("GET", "/webhooks/"+id, lead, nil); w.obj()["last_delivery"].(map[string]any)["state"] != "pending" {
		t.Fatal(w.body)
	}
}
