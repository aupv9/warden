//go:build integration

package migrations_test

import (
	"context"
	"errors"
	"fmt"
	"os"
	"testing"
	"time"

	"github.com/google/uuid"
	"github.com/jackc/pgx/v5"
	"github.com/jackc/pgx/v5/pgconn"
	"github.com/jackc/pgx/v5/pgxpool"
	"github.com/testcontainers/testcontainers-go"
	tcpostgres "github.com/testcontainers/testcontainers-go/modules/postgres"
	"github.com/testcontainers/testcontainers-go/wait"

	"github.com/aupv9/warden/backend/internal/db"
	"github.com/aupv9/warden/backend/internal/migrations"
	"github.com/aupv9/warden/backend/internal/worker"
)

const appPassword = "app-test-pw"

var ownerURL, appURL string

func TestMain(m *testing.M) {
	ctx := context.Background()
	c, err := tcpostgres.Run(ctx, "postgres:16-alpine",
		tcpostgres.WithDatabase("warden"), tcpostgres.WithUsername("warden_owner"), tcpostgres.WithPassword("owner-test-pw"),
		testcontainers.WithWaitStrategy(wait.ForLog("database system is ready to accept connections").WithOccurrence(2).WithStartupTimeout(60*time.Second)),
	)
	if err != nil {
		fmt.Fprintln(os.Stderr, "start postgres:", err)
		os.Exit(1)
	}
	code := func() int {
		defer func() { _ = testcontainers.TerminateContainer(c) }()
		ownerURL, err = c.ConnectionString(ctx, "sslmode=disable")
		if err != nil {
			fmt.Fprintln(os.Stderr, err)
			return 1
		}
		conn, err := pgx.Connect(ctx, ownerURL)
		if err != nil {
			fmt.Fprintln(os.Stderr, err)
			return 1
		}
		_, err = conn.Exec(ctx, fmt.Sprintf("CREATE ROLE warden_app LOGIN PASSWORD '%s' NOSUPERUSER NOBYPASSRLS", appPassword))
		conn.Close(ctx)
		if err != nil {
			fmt.Fprintln(os.Stderr, err)
			return 1
		}
		if err := migrations.Up(ctx, ownerURL); err != nil {
			fmt.Fprintln(os.Stderr, err)
			return 1
		}
		// Re-running is a no-op (grants are idempotent).
		if err := migrations.Up(ctx, ownerURL); err != nil {
			fmt.Fprintln(os.Stderr, "second run:", err)
			return 1
		}
		host, _ := c.Host(ctx)
		port, _ := c.MappedPort(ctx, "5432/tcp")
		appURL = fmt.Sprintf("postgres://warden_app:%s@%s:%s/warden?sslmode=disable", appPassword, host, port.Port())
		return m.Run()
	}()
	os.Exit(code)
}

func connect(t *testing.T, url string) *pgx.Conn {
	t.Helper()
	conn, err := pgx.Connect(context.Background(), url)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { conn.Close(context.Background()) })
	return conn
}

// ownerExec runs statements as the owner with app.org_id set (the owner is also
// subject to FORCEd RLS).
func ownerExec(t *testing.T, org uuid.UUID, stmts ...string) {
	t.Helper()
	ctx := context.Background()
	conn := connect(t, ownerURL)
	tx, err := conn.Begin(ctx)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := tx.Exec(ctx, "SELECT set_config('app.org_id', $1, true)", org.String()); err != nil {
		t.Fatal(err)
	}
	for _, s := range stmts {
		if _, err := tx.Exec(ctx, s); err != nil {
			t.Fatalf("%s: %v", s, err)
		}
	}
	if err := tx.Commit(ctx); err != nil {
		t.Fatal(err)
	}
}

func seedOrg(t *testing.T, key string) uuid.UUID {
	org := uuid.New()
	ownerExec(t, org,
		fmt.Sprintf("INSERT INTO organization (id, name) VALUES ('%s', '%s')", org, key),
		fmt.Sprintf("INSERT INTO project (id, org_id, key, name) VALUES ('%s', '%s', '%s', '%s')", uuid.New(), org, key, key),
	)
	return org
}

func pgCode(err error) string {
	var pe *pgconn.PgError
	if errors.As(err, &pe) {
		return pe.Code
	}
	return ""
}

const (
	insufficientPrivilege = "42501"
	checkViolation        = "23514"
)

func appPool(t *testing.T) *pgxpool.Pool {
	t.Helper()
	pool, err := pgxpool.New(context.Background(), appURL)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(pool.Close)
	return pool
}

func TestRLSIsolatesOrgs(t *testing.T) {
	a := seedOrg(t, "AAA")
	seedOrg(t, "BBB")
	var keys []string
	err := db.WithOrg(context.Background(), appPool(t), a, func(tx pgx.Tx) error {
		rows, err := tx.Query(context.Background(), "SELECT key FROM project WHERE key IN ('AAA','BBB')")
		if err != nil {
			return err
		}
		keys, err = pgx.CollectRows(rows, pgx.RowTo[string])
		return err
	})
	if err != nil || len(keys) != 1 || keys[0] != "AAA" {
		t.Fatal(keys, err)
	}
}

func TestRLSFailsClosedWithoutOrg(t *testing.T) {
	seedOrg(t, "CCC")
	var n int
	err := db.WithOrg(context.Background(), appPool(t), uuid.Nil, func(tx pgx.Tx) error {
		return tx.QueryRow(context.Background(), "SELECT count(*) FROM project").Scan(&n)
	})
	if err != nil || n != 0 {
		t.Fatal(n, err)
	}
}

func TestRLSBlocksCrossOrgInsert(t *testing.T) {
	a, b := seedOrg(t, "DDD"), seedOrg(t, "EEE")
	err := db.WithOrg(context.Background(), appPool(t), a, func(tx pgx.Tx) error {
		_, err := tx.Exec(context.Background(), "INSERT INTO project (id, org_id, key, name) VALUES ($1, $2, 'EVIL', 'x')", uuid.New(), b)
		return err
	})
	if pgCode(err) != insufficientPrivilege {
		t.Fatalf("got %v", err)
	}
}

func TestAuditLogIsAppendOnlyForApp(t *testing.T) {
	ctx := context.Background()
	conn := connect(t, appURL)
	if _, err := conn.Exec(ctx, "INSERT INTO audit_log (action, hash) VALUES ('login', $1)", fmt.Sprintf("%064d", 0)); err != nil {
		t.Fatal(err)
	}
	for _, stmt := range []string{"UPDATE audit_log SET action = 'tampered'", "DELETE FROM audit_log", "TRUNCATE audit_log"} {
		if _, err := conn.Exec(ctx, stmt); pgCode(err) != insufficientPrivilege {
			t.Errorf("%s: %v", stmt, err)
		}
	}
}

func TestAppCannotTouchSchemaOrMigrations(t *testing.T) {
	ctx := context.Background()
	conn := connect(t, appURL)
	for _, stmt := range []string{
		"CREATE TABLE evil (id int)",
		"SELECT * FROM goose_db_version",
		"DELETE FROM river_migration",
		"ALTER TABLE project DISABLE ROW LEVEL SECURITY",
	} {
		if _, err := conn.Exec(ctx, stmt); err == nil {
			t.Errorf("%s: allowed", stmt)
		}
	}
	var bypass bool
	if err := conn.QueryRow(ctx, "SELECT rolbypassrls FROM pg_roles WHERE rolname = current_user").Scan(&bypass); err != nil || bypass {
		t.Fatal("warden_app has BYPASSRLS", err)
	}
}

func TestExceptionRequestConstraints(t *testing.T) {
	for _, c := range []struct {
		typ, expires string
		sameDecider  bool
	}{
		{"risk_accepted", "NULL", false},
		{"risk_accepted", "now() + interval '200 days'", false},
		{"false_positive", "NULL", true},
	} {
		org, user, other := uuid.New(), uuid.New(), uuid.New()
		project, scan, issue := uuid.New(), uuid.New(), uuid.New()
		key := "EXC"
		ownerExec(t, org,
			fmt.Sprintf("INSERT INTO organization (id, name) VALUES ('%s', 'o')", org),
			fmt.Sprintf("INSERT INTO app_user (id, keycloak_sub, email, display_name) VALUES ('%s', '%s', '%s@x.test', 'u')", user, user, user),
			fmt.Sprintf("INSERT INTO app_user (id, keycloak_sub, email, display_name) VALUES ('%s', '%s', '%s@x.test', 'u')", other, other, other),
			fmt.Sprintf("INSERT INTO project (id, org_id, key, name) VALUES ('%s', '%s', '%s', 'p')", project, org, key),
			fmt.Sprintf("INSERT INTO scan (id, org_id, project_id, created_by, file_name, tools) VALUES ('%s', '%s', '%s', '%s', 'a.zip', '{opengrep}')", scan, org, project, user),
			fmt.Sprintf("INSERT INTO issue (id, org_id, project_id, number, fingerprint, tool, rule_id, title, severity, first_seen_scan_id, last_seen_scan_id)"+
				" VALUES ('%s', '%s', '%s', 1, '%064d', 'opengrep', 'r', 't', 'high', '%s', '%s')", issue, org, project, 0, scan, scan),
		)
		decider := other
		if c.sameDecider {
			decider = user
		}
		err := db.WithOrg(context.Background(), appPool(t), org, func(tx pgx.Tx) error {
			_, err := tx.Exec(context.Background(), fmt.Sprintf(
				"INSERT INTO exception_request (id, org_id, issue_id, type, reason, requested_by, decided_by, expires_at)"+
					" VALUES ($1, $2, $3, $4, 'a sufficiently long justification', $5, $6, %s)", c.expires),
				uuid.New(), org, issue, c.typ, user, decider)
			return err
		})
		if pgCode(err) != checkViolation {
			t.Errorf("%+v: got %v", c, err)
		}
	}
}

func TestProjectKeyCheck(t *testing.T) {
	org := uuid.New()
	ownerExec(t, org, fmt.Sprintf("INSERT INTO organization (id, name) VALUES ('%s', 'o')", org))
	err := db.WithOrg(context.Background(), appPool(t), org, func(tx pgx.Tx) error {
		_, err := tx.Exec(context.Background(), "INSERT INTO project (id, org_id, key, name) VALUES ($1, $2, 'bad-key', 'x')", uuid.New(), org)
		return err
	})
	if pgCode(err) != checkViolation {
		t.Fatalf("got %v", err)
	}
}

// The app role must be able to run River (enqueue, lock, complete) without owner rights.
func TestWorkerRunsAsAppRole(t *testing.T) {
	ctx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
	defer cancel()
	client, err := worker.NewClient(appPool(t), worker.Options{ScanTimeout: time.Minute, ScanSlots: 1})
	if err != nil {
		t.Fatal(err)
	}
	if err := client.Start(ctx); err != nil {
		t.Fatal(err)
	}
	defer func() { _ = client.Stop(context.Background()) }()
	res, err := client.Insert(ctx, worker.ScanArgs{}, nil)
	if err != nil {
		t.Fatal(err)
	}
	for {
		job, err := client.JobGet(ctx, res.Job.ID)
		if err != nil {
			t.Fatal(err)
		}
		if job.FinalizedAt != nil {
			if job.State != "cancelled" { // placeholder worker cancels: not implemented yet
				t.Fatalf("state %s, errors %v", job.State, job.Errors)
			}
			return
		}
		select {
		case <-ctx.Done():
			t.Fatal("job not processed")
		case <-time.After(100 * time.Millisecond):
		}
	}
}
