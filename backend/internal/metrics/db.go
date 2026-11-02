package metrics

import (
	"context"
	"log/slog"
	"sync"
	"time"

	"github.com/jackc/pgx/v5"
	"github.com/prometheus/client_golang/prometheus"
)

var (
	queueDepthDesc = prometheus.NewDesc("warden_scan_queue_depth",
		"Scan jobs waiting or running (River queue \"scan\": available, scheduled, running).", nil, nil)
	feedAgeDesc = prometheus.NewDesc("warden_intel_feed_age_seconds",
		"Seconds since each vulnerability-intel feed was last loaded (for trivy_db, which is read in place, since its own build date).",
		[]string{"source"}, nil)
)

// DB is the part of a pool the gauges need. The queries read tables without
// row-level security (River's job table, vuln_intel_source), so no org scope
// is needed.
type DB interface {
	QueryRow(ctx context.Context, sql string, args ...any) pgx.Row
	Query(ctx context.Context, sql string, args ...any) (pgx.Rows, error)
}

// DBGauges reports the queue depth and feed ages from the database. Values
// are cached for TTL so frequent scrapes (or several scrapers) cost at most
// two small queries per TTL. A failed query drops that metric from the scrape
// instead of reporting a stale value.
type DBGauges struct {
	DB  DB
	TTL time.Duration
	Log *slog.Logger
	Now func() time.Time

	mu      sync.Mutex
	fetched time.Time
	queue   *float64
	feeds   map[string]time.Time
}

// NewDBGauges returns gauges refreshed at most every 30 seconds.
func NewDBGauges(db DB, log *slog.Logger) *DBGauges {
	return &DBGauges{DB: db, TTL: 30 * time.Second, Log: log, Now: time.Now}
}

func (g *DBGauges) Describe(ch chan<- *prometheus.Desc) {
	ch <- queueDepthDesc
	ch <- feedAgeDesc
}

func (g *DBGauges) Collect(ch chan<- prometheus.Metric) {
	g.mu.Lock()
	defer g.mu.Unlock()
	now := g.Now()
	if g.fetched.IsZero() || now.Sub(g.fetched) >= g.TTL {
		g.refresh()
		g.fetched = now
	}
	if g.queue != nil {
		ch <- prometheus.MustNewConstMetric(queueDepthDesc, prometheus.GaugeValue, *g.queue)
	}
	for name, at := range g.feeds {
		ch <- prometheus.MustNewConstMetric(feedAgeDesc, prometheus.GaugeValue, max(now.Sub(at).Seconds(), 0), name)
	}
}

func (g *DBGauges) refresh() {
	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()
	var n int64
	// Served by River's (state, queue, …) index.
	if err := g.DB.QueryRow(ctx, `SELECT count(*) FROM river_job
		WHERE queue = 'scan' AND state IN ('available', 'scheduled', 'running')`).Scan(&n); err != nil {
		g.Log.Warn("metrics: scan queue depth unavailable", "err", err)
		g.queue = nil
	} else {
		v := float64(n)
		g.queue = &v
	}
	feeds, err := g.feedTimes(ctx)
	if err != nil {
		g.Log.Warn("metrics: intel feed ages unavailable", "err", err)
	}
	g.feeds = feeds
}

// feedTimes: loaded_at changes only when a feed's content changes, so its age
// grows when the mirror stops syncing.
func (g *DBGauges) feedTimes(ctx context.Context) (map[string]time.Time, error) {
	rows, err := g.DB.Query(ctx, `SELECT name, coalesce(loaded_at, updated_at) FROM vuln_intel_source
		WHERE coalesce(loaded_at, updated_at) IS NOT NULL`)
	if err != nil {
		return nil, err
	}
	out := map[string]time.Time{}
	var (
		name string
		at   time.Time
	)
	if _, err := pgx.ForEachRow(rows, []any{&name, &at}, func() error { out[name] = at; return nil }); err != nil {
		return nil, err
	}
	return out, nil
}
