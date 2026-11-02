package metrics_test

import (
	"errors"
	"fmt"
	"io"
	"log/slog"
	"net/http/httptest"
	"strings"
	"testing"
	"time"

	"github.com/prometheus/client_golang/prometheus"

	"github.com/aupv9/warden/backend/internal/metrics"
	"github.com/aupv9/warden/backend/internal/worker/dbtest"
)

func TestCountersIncrement(t *testing.T) {
	l := func(kv ...string) map[string]string {
		m := map[string]string{}
		for i := 0; i < len(kv); i += 2 {
			m[kv[i]] = kv[i+1]
		}
		return m
	}
	for _, c := range []struct {
		name   string
		labels map[string]string
		record func()
	}{
		{"warden_scans_total", l("status", "partial", "kind", "image"), func() { metrics.ScanFinished("image", "partial", time.Minute) }},
		{"warden_scan_duration_seconds", l("kind", "image"), func() { metrics.ScanFinished("image", "completed", time.Second) }},
		{"warden_tool_runs_total", l("tool", "trivy", "status", "timeout"), func() { metrics.ToolRun("trivy", "timeout") }},
		{"warden_webhook_deliveries_total", l("status", "retrying"), func() { metrics.WebhookDelivery("retrying") }},
		{"warden_notifications_sent_total", l("channel", "email"), func() { metrics.NotificationsSent(metrics.ChannelEmail, 1) }},
		// Unknown values can't grow the label set.
		{"warden_scans_total", l("status", "other", "kind", "other"), func() { metrics.ScanFinished("org-1234", "weird", 0) }},
		{"warden_tool_runs_total", l("tool", "other", "status", "other"), func() { metrics.ToolRun("../../etc", "?") }},
	} {
		before := metrics.Value(c.name, c.labels)
		c.record()
		if got := metrics.Value(c.name, c.labels); got != before+1 {
			t.Errorf("%s%v: %v -> %v", c.name, c.labels, before, got)
		}
	}
	before := metrics.Value("warden_notifications_sent_total", l("channel", "in_app"))
	metrics.NotificationsSent(metrics.ChannelInApp, 3)
	metrics.NotificationsSent(metrics.ChannelInApp, 0)
	if got := metrics.Value("warden_notifications_sent_total", l("channel", "in_app")); got != before+3 {
		t.Fatal(got)
	}
}

func TestHandlerServesText(t *testing.T) {
	metrics.ToolRun("gitleaks", "succeeded")
	rec := httptest.NewRecorder()
	metrics.Handler().ServeHTTP(rec, httptest.NewRequest("GET", "/metrics", nil))
	body := rec.Body.String()
	for _, want := range []string{`warden_tool_runs_total{status="succeeded",tool="gitleaks"}`, "go_goroutines"} {
		if !strings.Contains(body, want) {
			t.Errorf("missing %s", want)
		}
	}
}

func gather(t *testing.T, c prometheus.Collector) string {
	t.Helper()
	reg := prometheus.NewRegistry()
	reg.MustRegister(c)
	families, err := reg.Gather()
	if err != nil {
		t.Fatal(err)
	}
	var b strings.Builder
	for _, f := range families {
		for _, m := range f.GetMetric() {
			b.WriteString(f.GetName())
			for _, l := range m.GetLabel() {
				b.WriteString(" " + l.GetName() + "=" + l.GetValue())
			}
			fmt.Fprintf(&b, " %g\n", m.GetGauge().GetValue())
		}
	}
	return b.String()
}

func TestDBGauges(t *testing.T) {
	now := time.Date(2026, 11, 2, 12, 0, 0, 0, time.UTC)
	db := dbtest.Loose(t,
		dbtest.Step{Prefix: "SELECT count(*) FROM river_job WHERE queue = 'scan'", Rows: [][]any{{int64(4)}}},
		dbtest.Step{Prefix: "SELECT name, coalesce(loaded_at, updated_at) FROM vuln_intel_source", Rows: [][]any{
			{"kev", now.Add(-90 * time.Second)}, {"epss", now.Add(-time.Hour)},
		}},
	)
	g := metrics.NewDBGauges(db, slog.New(slog.NewTextHandler(io.Discard, nil)))
	g.Now = func() time.Time { return now }
	out := gather(t, g)
	for _, want := range []string{"warden_scan_queue_depth 4", "warden_intel_feed_age_seconds source=kev 90", "warden_intel_feed_age_seconds source=epss 3600"} {
		if !strings.Contains(out, want) {
			t.Errorf("missing %q in\n%s", want, out)
		}
	}
	// Cached: a second scrape within the TTL doesn't query, but ages advance.
	now = now.Add(10 * time.Second)
	out = gather(t, g)
	if n := len(db.Calls("SELECT count(*)")); n != 1 {
		t.Fatalf("queried %d times", n)
	}
	if !strings.Contains(out, "source=kev 100") {
		t.Fatal(out)
	}
	now = now.Add(time.Minute)
	gather(t, g)
	if n := len(db.Calls("SELECT count(*)")); n != 2 {
		t.Fatalf("not refreshed after the TTL: %d", n)
	}
}

func TestDBGaugesDropFailedQueries(t *testing.T) {
	db := dbtest.Loose(t,
		dbtest.Step{Prefix: "SELECT count(*)", Err: errors.New("down")},
		dbtest.Step{Prefix: "SELECT name", Err: errors.New("down")},
	)
	g := metrics.NewDBGauges(db, slog.New(slog.NewTextHandler(io.Discard, nil)))
	if out := gather(t, g); out != "" {
		t.Fatalf("stale or zero values reported: %s", out)
	}
}
