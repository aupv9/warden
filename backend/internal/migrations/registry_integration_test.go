//go:build integration

package migrations_test

import (
	"context"
	"database/sql"
	"fmt"
	"os"
	"strings"
	"testing"

	"github.com/google/uuid"
	"github.com/jackc/pgx/v5"
	"github.com/pressly/goose/v3"

	"github.com/aupv9/warden/backend/internal/db"
)

// 00015: a registry credential has a well-formed host (no scheme, path or IP
// literal), one per (org, host), a known last_error; it is under forced RLS,
// and the app can change only the credential and its last outcome.
func TestRegistryCredentialConstraints(t *testing.T) {
	org, user, _ := seedUserProject(t, "REG")
	insert := func(org uuid.UUID, host, username string, enc []byte, lastError any) (uuid.UUID, error) {
		id := uuid.New()
		return id, appExec(t, org, `INSERT INTO registry_credential (id, org_id, host, username, password_enc, key_id, created_by, last_error)
			VALUES ($1, $2, $3, $4, $5, 'k1', $6, $7)`, id, org, host, username, enc, user, lastError)
	}
	enc := []byte("ciphertext")
	id, err := insert(org, "ghcr.io", "bot", enc, nil)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := insert(org, "registry.example.com:5000", "bot", enc, "unauthorized"); err != nil {
		t.Fatal(err)
	}
	if _, err := insert(org, "ghcr.io", "other", enc, nil); pgCode(err) != "23505" {
		t.Errorf("second credential for a host: got %v", err)
	}
	for _, c := range []struct {
		host, username string
		enc            []byte
		lastError      any
	}{
		{"GHCR.io", "u", enc, nil},
		{"https://ghcr.io", "u", enc, nil},
		{"ghcr.io/acme", "u", enc, nil},
		{"localhost", "u", enc, nil},
		{"[::1]", "u", enc, nil},
		{"u@ghcr.io", "u", enc, nil},
		{"ghcr.io:123456", "u", enc, nil},
		{strings.Repeat("a", 63) + "." + strings.Repeat("b", 63) + "." + strings.Repeat("c", 63) + "." + strings.Repeat("d", 63) + ".io", "u", enc, nil}, // over 253
		{"quay.io", "", enc, nil},
		{"quay.io", strings.Repeat("u", 257), enc, nil},
		{"quay.io", "u", []byte{}, nil},
		{"quay.io", "u", make([]byte, 16641), nil},
		{"quay.io", "u", enc, "timeout"},
	} {
		if _, err := insert(org, c.host, c.username, c.enc, c.lastError); pgCode(err) != checkViolation {
			t.Errorf("%.40q %q: got %v", c.host, c.lastError, err)
		}
	}

	// The app updates the credential and its outcome, never host, org or creator.
	if err := appExec(t, org, `UPDATE registry_credential SET username = 'bot2', password_enc = '\x01', key_id = 'k2',
		updated_at = now(), last_used_at = now(), last_error = 'blocked' WHERE id = $1`, id); err != nil {
		t.Fatal(err)
	}
	for _, stmt := range []string{
		"UPDATE registry_credential SET host = 'evil.example' WHERE id = $1",
		"UPDATE registry_credential SET created_by = created_by WHERE id = $1",
		"UPDATE registry_credential SET created_at = now() WHERE id = $1",
		"UPDATE registry_credential SET org_id = org_id WHERE id = $1",
	} {
		if err := appExec(t, org, stmt, id); pgCode(err) != insufficientPrivilege {
			t.Errorf("%s: got %v", stmt, err)
		}
	}
	if err := appExec(t, org, "TRUNCATE registry_credential"); pgCode(err) != insufficientPrivilege {
		t.Errorf("truncate: got %v", err)
	}

	// Another org sees none, can't write into this one, and RLS is forced.
	other, otherUser, _ := seedUserProject(t, "REH")
	var seen int
	err = db.WithOrg(context.Background(), appPool(t), other, func(tx pgx.Tx) error {
		return tx.QueryRow(context.Background(), "SELECT count(*) FROM registry_credential").Scan(&seen)
	})
	if err != nil || seen != 0 {
		t.Fatal(seen, err)
	}
	if err := appExec(t, other, "DELETE FROM registry_credential WHERE id = $1", id); err != nil {
		t.Fatal(err)
	}
	err = appExec(t, other, `INSERT INTO registry_credential (id, org_id, host, username, password_enc, key_id, created_by)
		VALUES ($1, $2, 'quay.io', 'u', '\x01', 'k1', $3)`, uuid.New(), org, otherUser)
	if pgCode(err) != insufficientPrivilege {
		t.Errorf("cross-org insert: got %v", err)
	}
	err = db.WithOrg(context.Background(), appPool(t), uuid.Nil, func(tx pgx.Tx) error {
		return tx.QueryRow(context.Background(), "SELECT count(*) FROM registry_credential").Scan(&seen)
	})
	if err != nil || seen != 0 {
		t.Fatal("visible without an org", seen, err)
	}
	var forced bool
	if err := connect(t, ownerURL).QueryRow(context.Background(),
		"SELECT relforcerowsecurity FROM pg_class WHERE relname = 'registry_credential'").Scan(&forced); err != nil || !forced {
		t.Fatal("RLS not forced", err)
	}
	if err := appExec(t, org, "DELETE FROM registry_credential WHERE id = $1", id); err != nil {
		t.Fatal(err)
	}
}

// 00015: only image scans with a reference are pulled; an issue's image layer
// is all three columns or none, well-formed, and only on image issues.
func TestPulledScanAndImageLayerConstraints(t *testing.T) {
	org, user, project := seedUserProject(t, "PUL")
	scan := func(kind, target, ref any, pulled bool) (uuid.UUID, error) {
		id := uuid.New()
		return id, appExec(t, org, `INSERT INTO scan (id, org_id, project_id, created_by, file_name, tools, kind, target, image_ref, pulled)
			VALUES ($1, $2, $3, $4, 'api.tar', '{trivy,gitleaks}', $5, $6, $7, $8)`, id, org, project, user, kind, target, ref, pulled)
	}
	ref := "ghcr.io/acme/api@sha256:" + strings.Repeat("ab", 32)
	scanID, err := scan("image", "ghcr.io/acme/api", ref, true)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := scan("image", "ghcr.io/acme/api", nil, false); err != nil {
		t.Fatal(err)
	}
	for _, c := range []struct {
		kind, target, ref any
	}{
		{"image", "ghcr.io/acme/api", nil},
		{"source", "", nil},
		{"history", "(history)", nil},
	} {
		if _, err := scan(c.kind, c.target, c.ref, true); pgCode(err) != checkViolation {
			t.Errorf("%+v: got %v", c, err)
		}
	}
	var pulled bool
	err = db.WithOrg(context.Background(), appPool(t), org, func(tx pgx.Tx) error {
		return tx.QueryRow(context.Background(), "SELECT pulled FROM scan WHERE id = $1", scanID).Scan(&pulled)
	})
	if err != nil || !pulled {
		t.Fatal(pulled, err)
	}

	n := 0
	issue := func(target string, digest, index, count any) error {
		n++
		return appExec(t, org, `INSERT INTO issue (id, org_id, project_id, number, fingerprint, tool, rule_id, title, severity,
			first_seen_scan_id, last_seen_scan_id, target, image_layer_digest, image_layer_index, image_layer_count)
			VALUES ($1, $2, $3, $4, $5, 'gitleaks', 'aws', 't', 'high', $6, $6, $7, $8, $9, $10)`,
			uuid.New(), org, project, n, fmt.Sprintf("%064d", n), scanID, target, digest, index, count)
	}
	digest := "sha256:" + strings.Repeat("0f", 32)
	if err := issue("ghcr.io/acme/api", digest, 0, 1); err != nil {
		t.Fatal(err)
	}
	if err := issue("ghcr.io/acme/api", digest, 7, 3); err != nil {
		t.Fatal(err)
	}
	if err := issue("ghcr.io/acme/api", nil, nil, nil); err != nil {
		t.Fatal(err)
	}
	for _, c := range []struct {
		target             string
		digest, index, cnt any
	}{
		{"", digest, 0, 1},                   // a source issue
		{"(history)", digest, 0, 1},          // a history issue
		{"ghcr.io/acme/api", digest, nil, 1}, // partial
		{"ghcr.io/acme/api", digest, 0, nil}, // partial
		{"ghcr.io/acme/api", nil, 0, 1},      // partial
		{"ghcr.io/acme/api", digest, -1, 1},  // negative index
		{"ghcr.io/acme/api", digest, 0, 0},   // no layer
		{"ghcr.io/acme/api", strings.ToUpper(digest), 0, 1},
		{"ghcr.io/acme/api", "sha512:" + strings.Repeat("0f", 32), 0, 1},
		{"ghcr.io/acme/api", digest[:70], 0, 1},
		{"ghcr.io/acme/api", digest + "\n", 0, 1},
	} {
		if err := issue(c.target, c.digest, c.index, c.cnt); pgCode(err) != checkViolation {
			t.Errorf("%+v: got %v", c, err)
		}
	}
}

// 00015 goes down and up again cleanly on a database with a credential and a
// pulled scan in it.
func TestRegistryMigrationDownUp(t *testing.T) {
	ctx := context.Background()
	if _, err := connect(t, ownerURL).Exec(ctx, `CREATE DATABASE downup_v07`); err != nil {
		t.Fatal(err)
	}
	url := strings.Replace(ownerURL, "/warden?", "/downup_v07?", 1)
	sqlDB, err := sql.Open("pgx", url)
	if err != nil {
		t.Fatal(err)
	}
	defer sqlDB.Close()
	p, err := goose.NewProvider(goose.DialectPostgres, sqlDB, os.DirFS("sql"))
	if err != nil {
		t.Fatal(err)
	}
	if _, err := p.Up(ctx); err != nil {
		t.Fatal(err)
	}
	org, user, project := uuid.New(), uuid.New(), uuid.New()
	conn := connect(t, url)
	for _, s := range []string{
		fmt.Sprintf("SELECT set_config('app.org_id', '%s', false)", org),
		fmt.Sprintf("INSERT INTO organization (id, name) VALUES ('%s', 'o')", org),
		fmt.Sprintf("INSERT INTO app_user (id, keycloak_sub, email, display_name) VALUES ('%s', 's', 'u@x.test', 'u')", user),
		fmt.Sprintf("INSERT INTO project (id, org_id, key, name) VALUES ('%s', '%s', 'PRJ', 'p')", project, org),
		fmt.Sprintf(`INSERT INTO registry_credential (id, org_id, host, username, password_enc, key_id, created_by)
			VALUES ('%s', '%s', 'ghcr.io', 'u', '\x01', 'k1', '%s')`, uuid.New(), org, user),
		fmt.Sprintf(`INSERT INTO scan (id, org_id, project_id, created_by, file_name, tools, kind, target, image_ref, pulled)
			VALUES ('%s', '%s', '%s', '%s', 'api.tar', '{trivy}', 'image', 'ghcr.io/acme/api', 'ghcr.io/acme/api@sha256:%s', true)`,
			uuid.New(), org, project, user, strings.Repeat("ab", 32)),
	} {
		if _, err := conn.Exec(ctx, s); err != nil {
			t.Fatalf("%s: %v", s, err)
		}
	}
	if _, err := p.DownTo(ctx, 14); err != nil {
		t.Fatal(err)
	}
	var n int
	if err := conn.QueryRow(ctx, `SELECT count(*) FROM information_schema.columns
		WHERE (table_name = 'scan' AND column_name = 'pulled') OR (table_name = 'issue' AND column_name LIKE 'image_layer_%')
		OR table_name = 'registry_credential'`).Scan(&n); err != nil || n != 0 {
		t.Fatal(n, err)
	}
	if _, err := p.Up(ctx); err != nil {
		t.Fatal(err)
	}
}
