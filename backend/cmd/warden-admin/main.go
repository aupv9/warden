// warden-admin is the operator CLI.
//
//	warden-admin org create --name "Acme" --admin you@example.com
//	warden-admin audit verify --org <org id>
//
// It connects with the runtime DSN (WARDEN_DATABASE__DSN, role warden_app), not
// the schema owner's: organization, org_member and app_user have no RLS and the
// app role may insert into them, and audit_log is append-only for it, which is
// all these commands need. The README's invariant is that only warden-migrate
// uses the owner role, and creating an org needs no DDL or RLS bypass.
package main

import (
	"context"
	"errors"
	"flag"
	"fmt"
	"io"
	"os"
	"time"

	"github.com/google/uuid"

	"github.com/aupv9/warden/backend/internal/config"
	"github.com/aupv9/warden/backend/internal/db"
	"github.com/aupv9/warden/backend/internal/store"
)

const usage = `usage:
  warden-admin org create --name NAME --admin EMAIL
  warden-admin audit verify --org ORG_ID`

func main() {
	os.Exit(run(os.Args[1:], os.Stdout, os.Stderr))
}

func run(args []string, stdout, stderr io.Writer) int {
	if len(args) < 2 {
		fmt.Fprintln(stderr, usage)
		return 2
	}
	ctx, cancel := context.WithTimeout(context.Background(), time.Minute)
	defer cancel()
	switch args[0] + " " + args[1] {
	case "org create":
		fs := flag.NewFlagSet("org create", flag.ContinueOnError)
		fs.SetOutput(stderr)
		name := fs.String("name", "", "organization name")
		admin := fs.String("admin", "", "email of the first org_admin (must have signed in once)")
		if err := fs.Parse(args[2:]); err != nil || *name == "" || *admin == "" {
			fmt.Fprintln(stderr, usage)
			return 2
		}
		d, closeDB, err := open(ctx)
		if err != nil {
			fmt.Fprintln(stderr, err)
			return 1
		}
		defer closeDB()
		id, err := store.CreateOrg(ctx, d, *name, *admin)
		if errors.Is(err, store.ErrAdminNotFound) {
			fmt.Fprintf(stderr, "%s: %v (ask them to sign in to the web UI first)\n", *admin, err)
			return 1
		}
		if err != nil {
			fmt.Fprintln(stderr, "create org:", err)
			return 1
		}
		fmt.Fprintf(stdout, "created organization %q: %s\n", *name, id)
		return 0
	case "audit verify":
		fs := flag.NewFlagSet("audit verify", flag.ContinueOnError)
		fs.SetOutput(stderr)
		org := fs.String("org", "", "organization id")
		if err := fs.Parse(args[2:]); err != nil {
			return 2
		}
		id, err := uuid.Parse(*org)
		if err != nil {
			fmt.Fprintln(stderr, usage)
			return 2
		}
		d, closeDB, err := open(ctx)
		if err != nil {
			fmt.Fprintln(stderr, err)
			return 1
		}
		defer closeDB()
		n, err := store.VerifyOrgAudit(ctx, d, id)
		if err != nil {
			fmt.Fprintf(stderr, "audit log of %s: %v (after %d good entries)\n", id, err, n)
			return 1
		}
		fmt.Fprintf(stdout, "audit log of %s: %d entries, chain intact\n", id, n)
		return 0
	}
	fmt.Fprintln(stderr, usage)
	return 2
}

func open(ctx context.Context) (*store.DB, func(), error) {
	cfg, err := config.Load()
	if err != nil {
		return nil, nil, err
	}
	pool, err := db.Connect(ctx, &cfg.AppConfig)
	if err != nil {
		return nil, nil, fmt.Errorf("connect: %w", err)
	}
	return store.New(pool, nil), pool.Close, nil
}
