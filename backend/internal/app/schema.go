package app

import (
	"context"
	"errors"
	"fmt"
	"log/slog"
	"time"

	"github.com/aupv9/common-go/health"
	"github.com/jackc/pgx/v5/pgxpool"

	"github.com/aupv9/warden/backend/internal/migrations"
)

// SchemaGate compares the database's schema version with the one this binary
// embeds. A newer database means this binary is older than the data: running
// would read and write it wrongly, so the binary refuses to start. An older
// database means warden-migrate has not run yet: the process starts but is
// not ready, and becomes ready by itself once the migration is applied.
type SchemaGate struct {
	DB     migrations.Querier
	Latest int64
	Log    *slog.Logger
}

// SchemaError is a version mismatch. Its message tells an operator what to
// do and holds version numbers only (the same information /info's version
// gives), so /readyz may show it.
type SchemaError struct {
	Newer bool // the database is newer than the binary
	msg   string
}

func (e *SchemaError) Error() string { return e.msg }

var errSchemaUnavailable = errors.New("unavailable")

// NewSchemaGate checks the pool's schema against migrations.Latest.
func NewSchemaGate(pool *pgxpool.Pool, log *slog.Logger) *SchemaGate {
	return &SchemaGate{DB: pool, Latest: migrations.Latest(), Log: log}
}

// Check returns nil when the schema is exactly the binary's, a *SchemaError
// when it differs, and any other error when the version can't be read.
func (g *SchemaGate) Check(ctx context.Context) error {
	cur, err := migrations.Current(ctx, g.DB)
	switch {
	case errors.Is(err, migrations.ErrVersionUnreadable):
		return &SchemaError{msg: fmt.Sprintf("schema unknown, binary needs %d: run warden-migrate", g.Latest)}
	case err != nil:
		return err
	case cur > g.Latest:
		return &SchemaError{Newer: true, msg: fmt.Sprintf("database schema %d is newer than this binary (%d); upgrade Warden", cur, g.Latest)}
	case cur < g.Latest:
		return &SchemaError{msg: fmt.Sprintf("schema %d, binary needs %d: run warden-migrate", cur, g.Latest)}
	}
	return nil
}

// Checker is the "schema" readiness check. It queries on every probe (one
// max() over a table of a few dozen rows), so readiness recovers as soon as
// warden-migrate has run, without a restart. A database error reports only
// "unavailable"; the database check says more.
func (g *SchemaGate) Checker() health.Checker {
	return health.CheckerFunc{CheckerName: "schema", CheckFn: func(ctx context.Context) error {
		err := g.Check(ctx)
		var se *SchemaError
		if err == nil || errors.As(err, &se) {
			return err
		}
		g.Log.Warn("schema readiness check failed", slog.Any("error", err))
		return errSchemaUnavailable
	}}
}

// Startup refuses a database newer than the binary, and logs (but allows) an
// older one, which readiness then reports. An error reading the version stops
// startup too: the database was reachable a moment ago (db.Module pings it).
func (g *SchemaGate) Startup(ctx context.Context) error {
	ctx, cancel := context.WithTimeout(ctx, 15*time.Second)
	defer cancel()
	err := g.Check(ctx)
	var se *SchemaError
	switch {
	case errors.As(err, &se) && !se.Newer:
		g.Log.Warn("not ready until the database is migrated", "reason", se.Error())
		return nil
	case se != nil:
		return se
	case err != nil:
		return fmt.Errorf("read schema version: %w", err)
	}
	return nil
}

// Wait blocks until Check passes or ctx ends, checking every interval. The
// worker waits here before it takes jobs: on an older schema a scan could
// fail on a missing column.
func (g *SchemaGate) Wait(ctx context.Context, interval time.Duration) error {
	logged := ""
	for {
		err := g.Check(ctx)
		if err == nil {
			if logged != "" {
				g.Log.Info("database schema is current")
			}
			return nil
		}
		if msg := err.Error(); msg != logged {
			g.Log.Warn("waiting for the database schema", "reason", msg)
			logged = msg
		}
		select {
		case <-ctx.Done():
			return ctx.Err()
		case <-time.After(interval):
		}
	}
}
