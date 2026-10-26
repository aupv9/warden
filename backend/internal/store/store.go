// Package store implements service.Repo on Postgres (pgx). Every method runs on
// the transaction opened by DB.InOrg, which sets app.org_id for row-level
// security; queries also filter by org where a table has no RLS (audit_log) or
// where it's cheap to say so explicitly.
package store

import (
	"context"
	"errors"
	"strconv"

	"github.com/google/uuid"
	"github.com/jackc/pgx/v5"
	"github.com/jackc/pgx/v5/pgconn"
	"github.com/jackc/pgx/v5/pgxpool"
	"github.com/riverqueue/river"

	"github.com/aupv9/warden/backend/internal/db"
	"github.com/aupv9/warden/backend/internal/service"
)

// DB opens org-scoped transactions on the warden_app pool.
type DB struct {
	pool  *pgxpool.Pool
	river *river.Client[pgx.Tx]
}

// New returns a DB. jobs may be an insert-only River client; it's used to
// enqueue scans inside the caller's transaction.
func New(pool *pgxpool.Pool, jobs *river.Client[pgx.Tx]) *DB {
	return &DB{pool: pool, river: jobs}
}

var _ service.DB = (*DB)(nil)

func (d *DB) InOrg(ctx context.Context, orgID uuid.UUID, fn func(service.Repo) error) error {
	return db.WithOrg(ctx, d.pool, orgID, func(tx pgx.Tx) error {
		return fn(&Repo{tx: tx, river: d.river})
	})
}

// Repo is service.Repo bound to one transaction.
type Repo struct {
	tx    pgx.Tx
	river *river.Client[pgx.Tx]
	// dispatchQueued: this transaction already enqueued a notification dispatch.
	dispatchQueued bool
}

var _ service.Repo = (*Repo)(nil)

// NewRepo binds a Repo to an existing transaction (warden-admin, tests).
func NewRepo(tx pgx.Tx, jobs *river.Client[pgx.Tx]) *Repo { return &Repo{tx: tx, river: jobs} }

const uniqueViolation = "23505"

// mapErr turns driver errors the service cares about into its sentinels.
func mapErr(err error) error {
	if err == nil {
		return nil
	}
	if errors.Is(err, pgx.ErrNoRows) {
		return service.ErrNotFound
	}
	var pe *pgconn.PgError
	if errors.As(err, &pe) && pe.Code == uniqueViolation {
		return errors.Join(service.ErrConflict, err)
	}
	return err
}

// args builds positional parameters for dynamic queries.
type args []any

func (a *args) add(v any) string {
	*a = append(*a, v)
	return "$" + strconv.Itoa(len(*a))
}

func userRef(id *uuid.UUID, email, name *string) *service.UserRef {
	if id == nil {
		return nil
	}
	r := service.UserRef{ID: *id}
	if email != nil {
		r.Email = *email
	}
	if name != nil {
		r.DisplayName = *name
	}
	return &r
}

// activeStatuses mirrors issuestate.Active for SQL.
const activeStatuses = `('open','assigned','in_progress','reopened')`
