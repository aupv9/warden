package app

import (
	"context"
	"errors"
	"io"
	"log/slog"
	"net"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"

	"github.com/aupv9/common-go/health"
	"github.com/jackc/pgx/v5/pgconn"
	"go.uber.org/fx"
	"go.uber.org/fx/fxtest"

	"github.com/aupv9/warden/backend/internal/config"
	"github.com/aupv9/warden/backend/internal/worker/dbtest"
)

var quiet = slog.New(slog.NewTextHandler(io.Discard, nil))

func TestAdminRoutes(t *testing.T) {
	reg := health.NewRegistry("warden", "test")
	reg.Register(health.CheckerFunc{CheckerName: "x", CheckFn: func(context.Context) error { return errors.New("down") }})
	get := func(h http.Handler, method, path string) int {
		rec := httptest.NewRecorder()
		h.ServeHTTP(rec, httptest.NewRequest(method, path, nil))
		return rec.Code
	}
	api := AdminHandler(reg, false)
	worker := AdminHandler(reg, true)
	for _, c := range []struct {
		h            http.Handler
		method, path string
		want         int
	}{
		{api, "GET", "/metrics", 200},
		{api, "GET", "/healthz", 404},
		{api, "GET", "/readyz", 404},
		{api, "GET", "/", 404},
		{api, "GET", "/admin/loglevel", 404},
		{api, "GET", "/metrics/x", 404},
		{api, "POST", "/metrics", 405},
		{worker, "GET", "/metrics", 200},
		{worker, "GET", "/healthz", 200},
		{worker, "GET", "/readyz", 503},
		{worker, "GET", "/info", 404},
		{worker, "GET", "/debug/pprof/", 404},
	} {
		if got := get(c.h, c.method, c.path); got != c.want {
			t.Errorf("%s %s (health=%v): %d, want %d", c.method, c.path, c.h == worker, got, c.want)
		}
	}
}

func TestAdminListenerBindsExactlyTheAddress(t *testing.T) {
	// Find a free loopback port, then ask for exactly it.
	l, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	addr := l.Addr().String()
	l.Close()

	cfg := &config.Config{}
	cfg.Admin.Addr = addr
	app := fxtest.New(t,
		fx.Supply(cfg, health.NewRegistry("warden", "test"), quiet, AdminHealth(true)),
		fx.Invoke(runAdmin),
	)
	app.RequireStart()
	if code := ProbeAdmin(addr); code != 0 {
		t.Fatalf("probe: %d", code)
	}
	_, port, _ := net.SplitHostPort(addr)
	if code := ProbeAdmin(":" + port); code != 0 {
		t.Fatal("wildcard host not probed on loopback")
	}
	app.RequireStop()
	if code := ProbeAdmin(addr); code != 1 {
		t.Fatal("probe passed after stop")
	}

	// A taken port fails startup instead of falling back to another.
	busy, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	defer busy.Close()
	cfg2 := &config.Config{}
	cfg2.Admin.Addr = busy.Addr().String()
	app2 := fx.New(fx.NopLogger, fx.Supply(cfg2, health.NewRegistry("warden", "test"), quiet), fx.Invoke(runAdmin))
	if err := app2.Start(context.Background()); err == nil {
		_ = app2.Stop(context.Background())
		t.Fatal("started on a taken port")
	}
}

func TestAdminListenerOffWhenUnset(t *testing.T) {
	app := fxtest.New(t, fx.Supply(&config.Config{}, health.NewRegistry("warden", "test"), quiet), fx.Invoke(runAdmin))
	app.RequireStart().RequireStop()
	if ProbeAdmin("") != 1 {
		t.Fatal("empty admin.addr must fail the healthcheck")
	}
}

func TestProbeAdminFailsWhenUnhealthy(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		http.Redirect(w, r, "http://example.com/healthz", http.StatusFound)
	}))
	defer srv.Close()
	if ProbeAdmin(strings.TrimPrefix(srv.URL, "http://")) != 1 {
		t.Fatal("redirect counted as healthy")
	}
	if ProbeAdmin("not an address") != 1 {
		t.Fatal("bad address")
	}
}

func gate(t *testing.T, latest int64, step dbtest.Step) *SchemaGate {
	step.Prefix = "SELECT max(version_id) FROM goose_db_version"
	return &SchemaGate{DB: dbtest.Loose(t, step), Latest: latest, Log: quiet}
}

func TestSchemaGate(t *testing.T) {
	ctx := context.Background()
	v := func(n int64) dbtest.Step { return dbtest.Step{Rows: [][]any{{&n}}} }

	// Equal: ready, starts.
	g := gate(t, 12, v(12))
	if err := g.Check(ctx); err != nil {
		t.Fatal(err)
	}
	if err := g.Startup(ctx); err != nil {
		t.Fatal(err)
	}

	// Newer: refuses to start, with the operator's message.
	g = gate(t, 12, v(13))
	err := g.Startup(ctx)
	if err == nil || err.Error() != "database schema 13 is newer than this binary (12); upgrade Warden" {
		t.Fatal(err)
	}

	// Older: starts, readiness fails with the advice.
	g = gate(t, 12, v(11))
	if err := g.Startup(ctx); err != nil {
		t.Fatal(err)
	}
	if err := g.Checker().Check(ctx); err == nil || err.Error() != "schema 11, binary needs 12: run warden-migrate" {
		t.Fatal(err)
	}

	// Unreadable (no grant yet, or never migrated): older.
	g = gate(t, 12, dbtest.Step{Err: &pgconn.PgError{Code: "42501"}})
	if err := g.Startup(ctx); err != nil {
		t.Fatal(err)
	}
	if err := g.Checker().Check(ctx); err == nil || !strings.Contains(err.Error(), "run warden-migrate") {
		t.Fatal(err)
	}

	// Any other error: startup stops, readiness says only "unavailable".
	g = gate(t, 12, dbtest.Step{Err: errors.New("conn refused to db.internal:5432 as warden_app")})
	if err := g.Startup(ctx); err == nil {
		t.Fatal("started without reading the version")
	}
	if err := g.Checker().Check(ctx); err == nil || err.Error() != "unavailable" {
		t.Fatal(err)
	}
}

func TestSchemaGateWaitRecovers(t *testing.T) {
	version := int64(11)
	db := dbtest.Loose(t, dbtest.Step{Prefix: "SELECT max(version_id)", Do: func([]any) dbtest.Step {
		v := version
		version++ // migrated after the first check
		return dbtest.Step{Rows: [][]any{{&v}}}
	}})
	g := &SchemaGate{DB: db, Latest: 12, Log: quiet}
	if err := g.Wait(context.Background(), 0); err != nil {
		t.Fatal(err)
	}
	if n := len(db.Calls("SELECT max")); n != 2 {
		t.Fatalf("%d checks", n)
	}
	ctx, cancel := context.WithCancel(context.Background())
	cancel()
	g = gate(t, 12, dbtest.Step{Rows: [][]any{{nil}}}) // empty table: version 0
	if err := g.Wait(ctx, 0); !errors.Is(err, context.Canceled) {
		t.Fatal(err)
	}
}
