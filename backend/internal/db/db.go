// Package db provides the warden_app pool and scopes transactions to one tenant.
package db

import (
	"context"
	"errors"
	"log/slog"

	cgconfig "github.com/aupv9/common-go/config"
	"github.com/aupv9/common-go/database"
	"github.com/aupv9/common-go/health"
	"github.com/google/uuid"
	"github.com/jackc/pgx/v5"
	"github.com/jackc/pgx/v5/pgxpool"
	"go.uber.org/fx"
)

// Connect opens a pool with common-go's pool settings (and query tracing when
// OpenTelemetry is enabled) and pings it.
func Connect(ctx context.Context, cfg *cgconfig.AppConfig) (*pgxpool.Pool, error) {
	d := cfg.Database
	return database.New(ctx, database.Config{
		DSN: d.DSN, Host: d.Host, Port: d.Port, User: d.User, Password: d.Password, Name: d.Name,
		SSLMode: d.SSLMode, MaxConns: d.MaxConns, MinConns: d.MinConns,
		MaxConnLifetime: d.MaxConnLifetime, MaxConnIdleTime: d.MaxConnIdleTime, ConnectTimeout: d.ConnectTimeout,
		AppName: cfg.App.Name, Tracing: cfg.Otel.Enabled,
	})
}

// Module provides *pgxpool.Pool. It replaces common-go's database.Module, whose
// readiness check returns the raw connection error (user, database and host) on
// the unauthenticated /readyz endpoint, and which would run golang-migrate.
var Module = fx.Module("db",
	fx.Provide(func(lc fx.Lifecycle, cfg *cgconfig.AppConfig) (*pgxpool.Pool, error) {
		pool, err := Connect(context.Background(), cfg)
		if err != nil {
			return nil, err
		}
		lc.Append(fx.StopHook(pool.Close))
		return pool, nil
	}),
	fx.Invoke(func(reg *health.Registry, pool *pgxpool.Pool, log *slog.Logger) {
		reg.Register(Checker(pool, log))
	}),
)

var errUnavailable = errors.New("unavailable")

// Checker pings the database and reports only "unavailable"; details are logged.
func Checker(p interface{ Ping(context.Context) error }, log *slog.Logger) health.Checker {
	return health.CheckerFunc{CheckerName: "database", CheckFn: func(ctx context.Context) error {
		if err := p.Ping(ctx); err != nil {
			log.Warn("database readiness check failed", slog.Any("error", err))
			return errUnavailable
		}
		return nil
	}}
}

// WithOrg runs fn in a transaction with app.org_id set for RLS. With uuid.Nil the
// setting stays unset and every RLS-protected table reads as empty (fail closed).
func WithOrg(ctx context.Context, pool *pgxpool.Pool, orgID uuid.UUID, fn func(pgx.Tx) error) error {
	return pgx.BeginFunc(ctx, pool, func(tx pgx.Tx) error {
		if orgID != uuid.Nil {
			if _, err := tx.Exec(ctx, "SELECT set_config('app.org_id', $1, true)", orgID.String()); err != nil {
				return err
			}
		}
		return fn(tx)
	})
}
