// warden-migrate applies migrations as the schema owner (WARDEN_MIGRATE__DSN).
// The API and worker connect as warden_app and can't change the schema.
//
//	warden-migrate          apply every migration (the default)
//	warden-migrate up       the same
//	warden-migrate status   print the database's schema version and this binary's
package main

import (
	"context"
	"errors"
	"fmt"
	"io"
	"os"
	"time"

	"github.com/jackc/pgx/v5"

	"github.com/aupv9/warden/backend/internal/config"
	"github.com/aupv9/warden/backend/internal/migrations"
)

func main() {
	cmd := "up"
	if len(os.Args) > 1 {
		cmd = os.Args[1]
	}
	if len(os.Args) > 2 || (cmd != "up" && cmd != "status") {
		fmt.Fprintln(os.Stderr, "usage: warden-migrate [up|status]")
		os.Exit(2)
	}
	cfg, err := config.Load()
	if err != nil {
		fmt.Fprintln(os.Stderr, err)
		os.Exit(2)
	}
	if cfg.Migrate.DSN == "" {
		fmt.Fprintln(os.Stderr, "WARDEN_MIGRATE__DSN is not set")
		os.Exit(2)
	}
	ctx := context.Background()
	if cmd == "status" {
		os.Exit(status(ctx, os.Stdout, cfg.Migrate.DSN.Reveal()))
	}
	if err := migrations.Up(ctx, cfg.Migrate.DSN.Reveal()); err != nil {
		fmt.Fprintln(os.Stderr, "warden-migrate:", err)
		os.Exit(1)
	}
	fmt.Println("migrations applied")
}

// status prints both versions. Exit 0 when they match, 1 when the database
// needs migrating or is newer than this binary, 2 when it can't be read.
func status(ctx context.Context, w io.Writer, dsn string) int {
	ctx, cancel := context.WithTimeout(ctx, 30*time.Second)
	defer cancel()
	conn, err := pgx.Connect(ctx, dsn)
	if err != nil {
		fmt.Fprintln(os.Stderr, "warden-migrate: connect:", err)
		return 2
	}
	defer conn.Close(context.Background())
	cur, err := migrations.Current(ctx, conn)
	if errors.Is(err, migrations.ErrVersionUnreadable) {
		cur, err = 0, nil // never migrated
	}
	if err != nil {
		fmt.Fprintln(os.Stderr, "warden-migrate:", err)
		return 2
	}
	latest := migrations.Latest()
	fmt.Fprintf(w, "database schema: %d\nbinary schema:   %d\n", cur, latest)
	switch {
	case cur < latest:
		fmt.Fprintln(w, "status: behind; run warden-migrate")
		return 1
	case cur > latest:
		fmt.Fprintln(w, "status: the database is newer than this binary; upgrade Warden")
		return 1
	}
	fmt.Fprintln(w, "status: up to date")
	return 0
}
