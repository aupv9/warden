//go:build integration

package migrations_test

import (
	"context"
	"errors"
	"io"
	"log/slog"
	"strconv"
	"strings"
	"testing"

	"github.com/jackc/pgx/v5/pgxpool"
	"github.com/prometheus/client_golang/prometheus"

	"github.com/aupv9/warden/backend/internal/app"
	"github.com/aupv9/warden/backend/internal/metrics"
	"github.com/aupv9/warden/backend/internal/migrations"
)

// The schema gate as the API and worker run it: warden_app reads the version
// (grants.sql) and compares it with the embedded migrations.
func TestSchemaGateAsApp(t *testing.T) {
	ctx := context.Background()
	pool, err := pgxpool.New(ctx, appURL)
	if err != nil {
		t.Fatal(err)
	}
	defer pool.Close()
	owner := connect(t, ownerURL)
	latest := migrations.Latest()
	gate := &app.SchemaGate{DB: pool, Latest: latest, Log: slog.New(slog.NewTextHandler(io.Discard, nil))}

	// Equal.
	if cur, err := migrations.Current(ctx, pool); err != nil || cur != latest {
		t.Fatalf("current %d, latest %d: %v", cur, latest, err)
	}
	if err := gate.Startup(ctx); err != nil {
		t.Fatal(err)
	}
	if err := gate.Checker().Check(ctx); err != nil {
		t.Fatal(err)
	}

	// Newer: a later release migrated the database.
	if _, err := owner.Exec(ctx, `INSERT INTO goose_db_version (version_id, is_applied) VALUES ($1, true)`, latest+1); err != nil {
		t.Fatal(err)
	}
	err = gate.Startup(ctx)
	var se *app.SchemaError
	if !errors.As(err, &se) || !se.Newer || !strings.Contains(err.Error(), "upgrade Warden") {
		t.Fatalf("newer schema: %v", err)
	}
	if _, err := owner.Exec(ctx, `DELETE FROM goose_db_version WHERE version_id = $1`, latest+1); err != nil {
		t.Fatal(err)
	}

	// Older: the binary was upgraded before warden-migrate ran. It starts, is
	// not ready, and recovers once the migration is back, without a restart.
	if _, err := owner.Exec(ctx, `UPDATE goose_db_version SET version_id = $1 WHERE version_id = $2`, -latest, latest); err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() {
		_, _ = owner.Exec(context.Background(), `UPDATE goose_db_version SET version_id = $1 WHERE version_id = $2`, latest, -latest)
	})
	if err := gate.Startup(ctx); err != nil {
		t.Fatalf("older schema must not stop startup: %v", err)
	}
	want := "binary needs " + strconv.FormatInt(latest, 10) + ": run warden-migrate"
	if err := gate.Checker().Check(ctx); err == nil || !strings.HasSuffix(err.Error(), want) {
		t.Fatalf("older schema: %v", err)
	}
	if _, err := owner.Exec(ctx, `UPDATE goose_db_version SET version_id = $1 WHERE version_id = $2`, latest, -latest); err != nil {
		t.Fatal(err)
	}
	if err := gate.Checker().Check(ctx); err != nil {
		t.Fatalf("not ready after migrating: %v", err)
	}
	if err := gate.Wait(ctx, 0); err != nil {
		t.Fatal(err)
	}

	// Re-running migrations keeps the grant (grants.sql runs after every migrate).
	if err := migrations.Up(ctx, ownerURL); err != nil {
		t.Fatal(err)
	}
	if cur, err := migrations.Current(ctx, pool); err != nil || cur != latest {
		t.Fatalf("after re-run: %d %v", cur, err)
	}
}

// The metrics' database queries run as warden_app (no org scope needed).
func TestDBGaugesAsApp(t *testing.T) {
	ctx := context.Background()
	pool, err := pgxpool.New(ctx, appURL)
	if err != nil {
		t.Fatal(err)
	}
	defer pool.Close()
	owner := connect(t, ownerURL)
	if _, err := owner.Exec(ctx, `INSERT INTO vuln_intel_source (name, loaded_at) VALUES ('kev', now() - interval '1 hour')
		ON CONFLICT (name) DO UPDATE SET loaded_at = EXCLUDED.loaded_at`); err != nil {
		t.Fatal(err)
	}
	reg := prometheus.NewRegistry()
	reg.MustRegister(metrics.NewDBGauges(pool, slog.New(slog.NewTextHandler(io.Discard, nil))))
	families, err := reg.Gather()
	if err != nil {
		t.Fatal(err)
	}
	got := map[string]float64{}
	for _, f := range families {
		for _, m := range f.GetMetric() {
			key := f.GetName()
			for _, l := range m.GetLabel() {
				key += " " + l.GetValue()
			}
			got[key] = m.GetGauge().GetValue()
		}
	}
	if _, ok := got["warden_scan_queue_depth"]; !ok {
		t.Fatalf("no queue depth: %v", got)
	}
	if age := got["warden_intel_feed_age_seconds kev"]; age < 3500 || age > 3700 {
		t.Fatalf("kev age %v (%v)", age, got)
	}
}
