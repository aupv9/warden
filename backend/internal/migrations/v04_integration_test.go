//go:build integration

package migrations_test

import (
	"context"
	"database/sql"
	"os"
	"strings"
	"testing"

	"github.com/google/uuid"
	"github.com/jackc/pgx/v5"
	_ "github.com/jackc/pgx/v5/stdlib"
	"github.com/pressly/goose/v3"
)

// 00009 backfills issue.license_category from license-issue titles
// ("pkg uses X (category)"); other issues, and titles without a known
// category, stay NULL. Run on a fresh database migrated to 00008 first.
func TestLicenseCategoryBackfill(t *testing.T) {
	ctx := context.Background()
	admin := connect(t, ownerURL)
	if _, err := admin.Exec(ctx, `CREATE DATABASE backfill_v04`); err != nil {
		t.Fatal(err)
	}
	url := strings.Replace(ownerURL, "/warden?", "/backfill_v04?", 1)
	sqlDB, err := sql.Open("pgx", url)
	if err != nil {
		t.Fatal(err)
	}
	defer sqlDB.Close()
	p, err := goose.NewProvider(goose.DialectPostgres, sqlDB, os.DirFS("sql"))
	if err != nil {
		t.Fatal(err)
	}
	if _, err := p.UpTo(ctx, 8); err != nil {
		t.Fatal(err)
	}

	org, project, user, scan := uuid.New(), uuid.New(), uuid.New(), uuid.New()
	conn := connect(t, url)
	titles := map[string]string{
		"license:GPL-3.0-only": "gpl-thing uses GPL-3.0-only (restricted)",
		"license:MIT":          "x uses MIT (notice)",
		"license:LicenseRef-x": "y uses LicenseRef-x (evil)",
		"CVE-2024-0001":        "lodash: prototype pollution (restricted)",
	}
	err = pgx.BeginFunc(ctx, conn, func(tx pgx.Tx) error {
		for _, s := range []string{"SELECT set_config('app.org_id', '" + org.String() + "', true)",
			"INSERT INTO organization (id, name) VALUES ('" + org.String() + "', 'o')",
			"INSERT INTO app_user (id, keycloak_sub, email, display_name) VALUES ('" + user.String() + "', 's', 'u@x.test', 'u')",
			"INSERT INTO project (id, org_id, key, name) VALUES ('" + project.String() + "', '" + org.String() + "', 'WEB', 'w')",
			"INSERT INTO scan (id, org_id, project_id, created_by, status, file_name, tools) VALUES ('" + scan.String() + "', '" +
				org.String() + "', '" + project.String() + "', '" + user.String() + "', 'completed', 'a.zip', '{trivy}')",
		} {
			if _, err := tx.Exec(ctx, s); err != nil {
				return err
			}
		}
		n := 0
		for rule, title := range titles {
			n++
			if _, err := tx.Exec(ctx, `INSERT INTO issue (id, org_id, project_id, number, fingerprint, tool, rule_id, title, severity,
				first_seen_scan_id, last_seen_scan_id) VALUES ($1, $2, $3, $4, $5, 'trivy', $6, $7, 'medium', $8, $8)`,
				uuid.New(), org, project, n, strings.Repeat(string(rune('a'+n)), 64), rule, title, scan); err != nil {
				return err
			}
		}
		return nil
	})
	if err != nil {
		t.Fatal(err)
	}
	if _, err := p.UpTo(ctx, 9); err != nil {
		t.Fatal(err)
	}
	got := map[string]string{}
	err = pgx.BeginFunc(ctx, conn, func(tx pgx.Tx) error {
		if _, err := tx.Exec(ctx, "SELECT set_config('app.org_id', $1, true)", org.String()); err != nil {
			return err
		}
		rows, err := tx.Query(ctx, `SELECT rule_id, coalesce(license_category, '-') FROM issue`)
		if err != nil {
			return err
		}
		defer rows.Close()
		for rows.Next() {
			var rule, cat string
			if err := rows.Scan(&rule, &cat); err != nil {
				return err
			}
			got[rule] = cat
		}
		return rows.Err()
	})
	if err != nil {
		t.Fatal(err)
	}
	if got["license:GPL-3.0-only"] != "restricted" || got["license:MIT"] != "notice" || got["license:LicenseRef-x"] != "-" ||
		got["CVE-2024-0001"] != "-" {
		t.Fatalf("%v", got)
	}
	// The table is FORCEd again after the backfill.
	var forced bool
	if err := conn.QueryRow(ctx, `SELECT relforcerowsecurity FROM pg_class WHERE relname = 'issue'`).Scan(&forced); err != nil || !forced {
		t.Fatal(forced, err)
	}
	// And the CHECK holds.
	err = pgx.BeginFunc(ctx, conn, func(tx pgx.Tx) error {
		_, err := tx.Exec(ctx, `UPDATE issue SET license_category = 'evil'`)
		return err
	})
	if pgCode(err) != checkViolation {
		t.Fatal(err)
	}
}
