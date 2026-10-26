//go:build integration

package migrations_test

import (
	"context"
	"fmt"
	"testing"

	"github.com/google/uuid"
	"github.com/jackc/pgx/v5"

	"github.com/aupv9/warden/backend/internal/db"
)

// Every table with an org_id column is under FORCEd row-level security, except
// two by design: the audit log (append-only, filtered by org explicitly) and
// org_member (membership is what decides which org a request may enter).
func TestEveryOrgTableHasForcedRLS(t *testing.T) {
	ctx := context.Background()
	conn := connect(t, ownerURL)
	rows, err := conn.Query(ctx, `SELECT c.relname, c.relrowsecurity, c.relforcerowsecurity
		FROM pg_class c JOIN pg_namespace n ON n.oid = c.relnamespace
		JOIN pg_attribute a ON a.attrelid = c.oid AND a.attname = 'org_id' AND NOT a.attisdropped
		WHERE n.nspname = 'public' AND c.relkind = 'r' AND c.relname NOT IN ('audit_log', 'org_member')`)
	if err != nil {
		t.Fatal(err)
	}
	seen := map[string]bool{}
	var (
		name          string
		rls, forceRLS bool
	)
	if _, err := pgx.ForEachRow(rows, []any{&name, &rls, &forceRLS}, func() error {
		seen[name] = true
		if !rls || !forceRLS {
			t.Errorf("%s: org_id without forced RLS", name)
		}
		return nil
	}); err != nil {
		t.Fatal(err)
	}
	for _, want := range []string{"notification", "outbox_event"} {
		if !seen[want] {
			t.Errorf("%s has no org_id", want)
		}
	}
}

// Notifications: org scope for the dispatcher, user scope (app.user_id) for
// the recipient, nothing without either; the app can't delete them.
func TestNotificationPolicies(t *testing.T) {
	ctx := context.Background()
	a, b := seedOrg(t, "NTA"), seedOrg(t, "NTB")
	user, other := uuid.New(), uuid.New()
	for _, org := range []uuid.UUID{a, b} {
		ownerExec(t, org,
			fmt.Sprintf("INSERT INTO app_user (id, keycloak_sub, email, display_name) VALUES ('%s', '%s', '%s@x.test', 'u') ON CONFLICT DO NOTHING", user, user, user),
			fmt.Sprintf("INSERT INTO app_user (id, keycloak_sub, email, display_name) VALUES ('%s', '%s', '%s@x.test', 'o') ON CONFLICT DO NOTHING", other, other, other),
			fmt.Sprintf("INSERT INTO outbox_event (org_id, type, payload) VALUES ('%s', 'issue.assigned', '{}')", org),
			fmt.Sprintf(`INSERT INTO notification (id, org_id, user_id, event_id, type, title, link, payload)
				SELECT '%s', org_id, '%s', id, type, 't', '/x', '{}' FROM outbox_event WHERE org_id = '%s'`, uuid.New(), user, org),
		)
	}
	pool := appPool(t)
	count := func(setting, value string) int {
		var n int
		err := pgx.BeginFunc(ctx, pool, func(tx pgx.Tx) error {
			if setting != "" {
				if _, err := tx.Exec(ctx, "SELECT set_config($1, $2, true)", setting, value); err != nil {
					return err
				}
			}
			return tx.QueryRow(ctx, "SELECT count(*) FROM notification WHERE user_id = $1", user).Scan(&n)
		})
		if err != nil {
			t.Fatal(err)
		}
		return n
	}
	if n := count("", ""); n != 0 {
		t.Fatal("visible without any scope", n)
	}
	if n := count("app.org_id", a.String()); n != 1 {
		t.Fatal(n)
	}
	if n := count("app.user_id", user.String()); n != 2 {
		t.Fatal("own notifications across orgs", n)
	}
	if n := count("app.user_id", other.String()); n != 0 {
		t.Fatal("someone else's notifications", n)
	}
	// User scope may mark read, but can't insert or reassign rows.
	err := pgx.BeginFunc(ctx, pool, func(tx pgx.Tx) error {
		if _, err := tx.Exec(ctx, "SELECT set_config('app.user_id', $1, true)", user.String()); err != nil {
			return err
		}
		if _, err := tx.Exec(ctx, "UPDATE notification SET read_at = now() WHERE user_id = $1", user); err != nil {
			return err
		}
		_, err := tx.Exec(ctx, "UPDATE notification SET user_id = $2 WHERE user_id = $1", user, other)
		return err
	})
	if pgCode(err) != insufficientPrivilege {
		t.Fatal("reassigned a notification", err)
	}
	err = db.WithOrg(ctx, pool, a, func(tx pgx.Tx) error {
		_, err := tx.Exec(ctx, "DELETE FROM notification")
		return err
	})
	if pgCode(err) != insufficientPrivilege {
		t.Fatal("app deleted notifications", err)
	}
	err = db.WithOrg(ctx, pool, a, func(tx pgx.Tx) error {
		_, err := tx.Exec(ctx, "DELETE FROM outbox_event")
		return err
	})
	if pgCode(err) != insufficientPrivilege {
		t.Fatal("app deleted outbox rows", err)
	}
	// Preferences are per user and writable by the app.
	err = db.WithOrg(ctx, pool, uuid.Nil, func(tx pgx.Tx) error {
		_, err := tx.Exec(ctx, "INSERT INTO notification_pref (user_id, type, email) VALUES ($1, 'scan.finished', true)", user)
		return err
	})
	if err != nil {
		t.Fatal(err)
	}
}
