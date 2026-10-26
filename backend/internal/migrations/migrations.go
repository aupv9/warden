// Package migrations applies the schema as warden_owner: goose SQL migrations,
// then River's queue tables, then the warden_app grants.
package migrations

import (
	"context"
	"database/sql"
	"embed"
	"fmt"
	"io/fs"

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
