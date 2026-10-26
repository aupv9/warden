// warden-migrate applies migrations as the schema owner (WARDEN_MIGRATE__DSN).
// The API and worker connect as warden_app and can't change the schema.
package main

import (
	"context"
	"fmt"
	"os"

	"github.com/aupv9/warden/backend/internal/config"
	"github.com/aupv9/warden/backend/internal/migrations"
)

func main() {
	cfg, err := config.Load()
	if err != nil {
		fmt.Fprintln(os.Stderr, err)
		os.Exit(2)
	}
	if cfg.Migrate.DSN == "" {
		fmt.Fprintln(os.Stderr, "WARDEN_MIGRATE__DSN is not set")
		os.Exit(2)
	}
	if err := migrations.Up(context.Background(), cfg.Migrate.DSN.Reveal()); err != nil {
		fmt.Fprintln(os.Stderr, "warden-migrate:", err)
		os.Exit(1)
	}
	fmt.Println("migrations applied")
}
