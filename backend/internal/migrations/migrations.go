// Package migrations applies the schema as warden_owner: goose SQL migrations,
// then River's queue tables, then the warden_app grants.
package migrations

import (
	"context"
	"database/sql"
	"embed"
	"errors"
	"fmt"
	"io/fs"
	"strconv"
	"strings"

	"github.com/jackc/pgx/v5"
	"github.com/jackc/pgx/v5/pgconn"
	"github.com/jackc/pgx/v5/pgxpool"
	_ "github.com/jackc/pgx/v5/stdlib" // database/sql driver for goose
	"github.com/pressly/goose/v3"
	"github.com/riverqueue/river/riverdriver/riverpgxv5"
	"github.com/riverqueue/river/rivermigrate"
)

//go:embed sql/*.sql
var sqlFiles embed.FS

//go:embed grants.sql
var grants string

// Up migrates the database at ownerURL to the latest version.
func Up(ctx context.Context, ownerURL string) error {
	db, err := sql.Open("pgx", ownerURL)
	if err != nil {
		return err
	}
	defer db.Close()
	fsys, err := fs.Sub(sqlFiles, "sql")
	if err != nil {
		return err
	}
	p, err := goose.NewProvider(goose.DialectPostgres, db, fsys)
	if err != nil {
		return err
	}
	if _, err := p.Up(ctx); err != nil {
		return fmt.Errorf("schema migrations: %w", err)
	}

	pool, err := pgxpool.New(ctx, ownerURL)
	if err != nil {
		return err
	}
	defer pool.Close()
	m, err := rivermigrate.New(riverpgxv5.New(pool), nil)
	if err != nil {
		return err
	}
	if _, err := m.Migrate(ctx, rivermigrate.DirectionUp, nil); err != nil {
		return fmt.Errorf("river migrations: %w", err)
	}

	if _, err := pool.Exec(ctx, grants); err != nil {
		return fmt.Errorf("grants: %w", err)
	}
	return nil
}

// Latest is the newest schema version embedded in this binary: the highest
// goose version among sql/*.sql. The API and worker compare it with Current.
func Latest() int64 {
	entries, err := fs.ReadDir(sqlFiles, "sql")
	if err != nil {
		panic("migrations: embedded sql directory: " + err.Error()) // compiled in; can't happen
	}
	var latest int64
	for _, e := range entries {
		num, _, ok := strings.Cut(e.Name(), "_")
		if !ok || !strings.HasSuffix(e.Name(), ".sql") {
			continue
		}
		if v, err := strconv.ParseInt(num, 10, 64); err == nil && v > latest {
			latest = v
		}
	}
	return latest
}

// ErrVersionUnreadable: the role can't read goose_db_version, or it doesn't
// exist yet. warden-migrate grants warden_app SELECT on it (grants.sql), so
// this means the database was never migrated by a release that has the
// schema gate: it is older than the binary.
var ErrVersionUnreadable = errors.New("schema version unreadable")

// PostgreSQL error codes Current maps to ErrVersionUnreadable.
const (
	undefinedTable        = "42P01"
	insufficientPrivilege = "42501"
)

// Querier is the part of a pool or connection Current needs.
type Querier interface {
	QueryRow(ctx context.Context, sql string, args ...any) pgx.Row
}

// Current is the database's schema version, read as warden_app with the query
// goose itself uses (the highest version recorded; 0 for an empty table).
func Current(ctx context.Context, db Querier) (int64, error) {
	var v *int64
	err := db.QueryRow(ctx, `SELECT max(version_id) FROM goose_db_version`).Scan(&v)
	var pe *pgconn.PgError
	if errors.As(err, &pe) && (pe.Code == undefinedTable || pe.Code == insufficientPrivilege) {
		return 0, ErrVersionUnreadable
	}
	if err != nil {
		return 0, err
	}
	if v == nil {
		return 0, nil
	}
	return *v, nil
}
