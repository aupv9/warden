// Package metrics holds Warden's Prometheus metrics, served at /metrics on the
// admin listener (admin.addr) of both binaries.
//
// It uses client_golang directly rather than common-go's observability: that
// module only builds a meter provider together with an OTLP trace exporter
// (Otel.Enabled turns on both), and Warden must not send traces nobody asked
// for. client_golang also keeps the metric names exactly as documented.
//
// Labels are fixed, small sets (status, kind, tool, channel, feed source):
// never an org, project, user or anything from an upload, so the series count
// is bounded and /metrics reveals nothing about tenants. Values outside a
// label's set are recorded as "other".
package metrics

import (
	"net/http"
	"slices"
	"time"

	"github.com/prometheus/client_golang/prometheus"
	"github.com/prometheus/client_golang/prometheus/collectors"
	"github.com/prometheus/client_golang/prometheus/promhttp"
	dto "github.com/prometheus/client_model/go"
)

// Registry is what /metrics serves: Warden's metrics plus the Go runtime and
// process collectors.
var Registry = prometheus.NewRegistry()

var (
	scans = prometheus.NewCounterVec(prometheus.CounterOpts{
		Name: "warden_scans_total",
		Help: "Scans finished by a worker, by final status and kind.",
	}, []string{"status", "kind"})
	scanDuration = prometheus.NewHistogramVec(prometheus.HistogramOpts{
		Name: "warden_scan_duration_seconds",
		Help: "Wall time of a scan job on the worker, from pickup to its final status.",
		// Scans take seconds to scan.timeout (30m by default).
		Buckets: []float64{5, 15, 30, 60, 120, 300, 600, 900, 1800, 3600},
	}, []string{"kind"})
	toolRuns = prometheus.NewCounterVec(prometheus.CounterOpts{
		Name: "warden_tool_runs_total",
		Help: "Scanner runs, by tool and outcome.",
	}, []string{"tool", "status"})
	webhookDeliveries = prometheus.NewCounterVec(prometheus.CounterOpts{
		Name: "warden_webhook_deliveries_total",
		Help: "Webhook delivery attempts, by outcome (delivered, retrying, failed).",
	}, []string{"status"})
	notifications = prometheus.NewCounterVec(prometheus.CounterOpts{
		Name: "warden_notifications_sent_total",
		Help: "Notifications sent, by channel (in_app, email, webhook).",
	}, []string{"channel"})
)

func init() {
	Registry.MustRegister(scans, scanDuration, toolRuns, webhookDeliveries, notifications,
		collectors.NewGoCollector(), collectors.NewProcessCollector(collectors.ProcessCollectorOpts{}))
}

// Handler serves Registry in the Prometheus text format.
func Handler() http.Handler {
	return promhttp.HandlerFor(Registry, promhttp.HandlerOpts{})
}

// Label sets. Anything else is recorded as "other".
var (
	scanStatuses = []string{"completed", "partial", "failed", "cancelled"}
	scanKinds    = []string{"source", "image", "history", "import"}
	tools        = []string{"gitleaks", "opengrep", "trivy", "checkov"}
	toolStatuses = []string{"succeeded", "failed", "timeout", "skipped"}
	// Delivery outcomes: delivered, a failure that will be retried, and a
	// final failure (including deliveries not sent: webhook off, key missing).
	deliveryStatuses = []string{"delivered", "retrying", "failed"}
)

// Notification channels.
const (
	ChannelInApp   = "in_app"
	ChannelEmail   = "email"
	ChannelWebhook = "webhook"
)

var channels = []string{ChannelInApp, ChannelEmail, ChannelWebhook}

func bounded(v string, set []string) string {
	if slices.Contains(set, v) {
		return v
	}
	return "other"
}

// ScanFinished records a scan's final status and how long its job ran.
func ScanFinished(kind, status string, took time.Duration) {
	kind = bounded(kind, scanKinds)
	scans.WithLabelValues(bounded(status, scanStatuses), kind).Inc()
	scanDuration.WithLabelValues(kind).Observe(took.Seconds())
}

// ToolRun records one scanner run's outcome.
func ToolRun(tool, status string) {
	toolRuns.WithLabelValues(bounded(tool, tools), bounded(status, toolStatuses)).Inc()
}

// WebhookDelivery records one webhook delivery attempt's outcome.
func WebhookDelivery(status string) {
	webhookDeliveries.WithLabelValues(bounded(status, deliveryStatuses)).Inc()
}

// NotificationsSent records n notifications sent over channel.
func NotificationsSent(channel string, n int) {
	if n > 0 {
		notifications.WithLabelValues(bounded(channel, channels)).Add(float64(n))
	}
}

// Value reads a metric from Registry for tests and diagnostics: a counter's
// or gauge's value, or a histogram's sample count, of the series whose labels
// equal labels exactly (0 when there is none).
func Value(name string, labels map[string]string) float64 {
	families, _ := Registry.Gather()
	for _, f := range families {
		if f.GetName() != name {
			continue
		}
		for _, m := range f.GetMetric() {
			if !sameLabels(m.GetLabel(), labels) {
				continue
			}
			switch {
			case m.Counter != nil:
				return m.GetCounter().GetValue()
			case m.Gauge != nil:
				return m.GetGauge().GetValue()
			case m.Histogram != nil:
				return float64(m.GetHistogram().GetSampleCount())
			}
		}
	}
	return 0
}

func sameLabels(got []*dto.LabelPair, want map[string]string) bool {
	if len(got) != len(want) {
		return false
	}
	for _, l := range got {
		if v, ok := want[l.GetName()]; !ok || v != l.GetValue() {
			return false
		}
	}
	return true
}
