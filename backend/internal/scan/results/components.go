package results

import (
	"context"
	"errors"
	"fmt"
	"slices"
	"strings"
	"unicode/utf8"

	"github.com/jackc/pgx/v5"

	"github.com/aupv9/warden/backend/internal/domain/ecosystem"
	"github.com/aupv9/warden/backend/internal/scan/trivyjson"
)

// Component inventory limits: the component table's CHECKs (00009), and at
// most as many rows per scan as trivyjson accepts packages.
const (
	MaxComponents         = trivyjson.MaxPackages
	maxComponentName      = 256
	maxComponentVersion   = 128
	maxComponentPURL      = 512
	maxComponentPath      = 2048
	maxComponentLicenses  = 64
	maxComponentLicenseID = 256
)

// ComponentStats says how a scan changed its (project, target)'s inventory.
// Skipped counts packages that couldn't be stored (shape or cap).
type ComponentStats struct {
	Added, Kept, Removed, Skipped int
}

type componentKey struct{ eco, matchName, version, path string }

// storable: valid UTF-8 without NUL (Postgres text rejects NUL), 1..max runes
// (or 0..max when empty is allowed). trivyjson already cleans and caps these;
// this is the last check before the CHECK constraints, so a bad package is
// skipped instead of failing the whole scan.
func storable(s string, allowEmpty bool, max int) bool {
	if s == "" {
		return allowEmpty
	}
	return utf8.ValidString(s) && !strings.ContainsRune(s, 0) && utf8.RuneCountInString(s) <= max
}

// componentRows turns the scan's packages into rows for component_in, one per
// unique key (licenses merged), and counts the packages it skipped.
func componentRows(pkgs []trivyjson.Package) ([][]any, int) {
	rows := make([][]any, 0, min(len(pkgs), MaxComponents))
	index := make(map[componentKey]int, len(pkgs))
	skipped := 0
	for _, p := range pkgs {
		if !ecosystem.Valid.MatchString(p.Ecosystem) || !storable(p.Name, false, maxComponentName) ||
			!storable(p.MatchName, false, maxComponentName) || !storable(p.Version, true, maxComponentVersion) ||
			!storable(p.FilePath, true, maxComponentPath) {
			skipped++
			continue
		}
		var licenses []string
		for _, l := range p.Licenses {
			if storable(l, false, maxComponentLicenseID) && !slices.Contains(licenses, l) && len(licenses) < maxComponentLicenses {
				licenses = append(licenses, l)
			}
		}
		k := componentKey{p.Ecosystem, p.MatchName, p.Version, p.FilePath}
		if i, ok := index[k]; ok {
			// Two Trivy targets can share a path (an image's OS packages).
			merged := rows[i][6].([]string)
			for _, l := range licenses {
				if !slices.Contains(merged, l) && len(merged) < maxComponentLicenses {
					merged = append(merged, l)
				}
			}
			rows[i][6] = merged
			continue
		}
		if len(rows) >= MaxComponents {
			skipped++
			continue
		}
		var purl *string
		if p.PURL != "" && storable(p.PURL, false, maxComponentPURL) {
			purl = &p.PURL
		}
		if licenses == nil {
			licenses = []string{}
		}
		index[k] = len(rows)
		rows = append(rows, []any{p.Ecosystem, p.Name, p.MatchName, p.Version, purl, p.FilePath, licenses})
	}
	return rows, skipped
}

// copier is the COPY support of a pgx transaction. It isn't part of DB so
// that unit-test fakes of DB stay small; like worker's intel loader, the
// inventory needs a real transaction (the integration tests cover it).
type copier interface {
	CopyFrom(ctx context.Context, table pgx.Identifier, columns []string, src pgx.CopyFromSource) (int64, error)
}

// replaceComponents makes the (project, target)'s inventory this scan's
// packages, in the results transaction: rows that are gone are deleted, new
// ones inserted (first_seen now), and rows that stay keep first_seen and point
// at this scan. Up to 200k rows, so the packages are COPYed into a temporary
// table (PUBLIC has the TEMPORARY privilege by default) and the diff is a few
// set-based statements, not a loop.
func replaceComponents(ctx context.Context, db DB, in Input) (*ComponentStats, error) {
	c, ok := db.(copier)
	if !ok {
		return nil, errors.New("components: database handle can't COPY")
	}
	rows, skipped := componentRows(in.Packages)
	stats := &ComponentStats{Skipped: skipped}
	// pg_temp: the table can't be shadowed by (or land in) a schema table.
	// IF NOT EXISTS and TRUNCATE make a second call in one transaction safe.
	if _, err := db.Exec(ctx, `CREATE TABLE IF NOT EXISTS pg_temp.component_in (ecosystem text NOT NULL, name text NOT NULL,
		match_name text NOT NULL, version text NOT NULL, purl text, path text NOT NULL, licenses text[] NOT NULL) ON COMMIT DROP`); err != nil {
		return nil, fmt.Errorf("components: temp table: %w", err)
	}
	if _, err := db.Exec(ctx, `TRUNCATE pg_temp.component_in`); err != nil {
		return nil, fmt.Errorf("components: temp table: %w", err)
	}
	if len(rows) > 0 {
		if _, err := c.CopyFrom(ctx, pgx.Identifier{"pg_temp", "component_in"},
			[]string{"ecosystem", "name", "match_name", "version", "purl", "path", "licenses"}, pgx.CopyFromRows(rows)); err != nil {
			return nil, fmt.Errorf("components: copy: %w", err)
		}
		// A fresh temp table has no statistics; without them the planner may
		// pick a nested loop over 200k rows for the anti-join below.
		if _, err := db.Exec(ctx, `ANALYZE pg_temp.component_in`); err != nil {
			return nil, fmt.Errorf("components: analyze: %w", err)
		}
	}
	tag, err := db.Exec(ctx, `DELETE FROM component c WHERE c.project_id = $1 AND c.target = $2
		AND NOT EXISTS (SELECT 1 FROM pg_temp.component_in n WHERE n.ecosystem = c.ecosystem AND n.match_name = c.match_name
			AND n.version = c.version AND n.path = c.path)`, in.ProjectID, in.Target)
	if err != nil {
		return nil, fmt.Errorf("components: delete: %w", err)
	}
	stats.Removed = int(tag.RowsAffected())
	// Every row left is in this scan: those are the kept ones.
	if err := db.QueryRow(ctx, `SELECT count(*) FROM component WHERE project_id = $1 AND target = $2`,
		in.ProjectID, in.Target).Scan(&stats.Kept); err != nil {
		return nil, fmt.Errorf("components: count: %w", err)
	}
	if len(rows) > 0 {
		if _, err := db.Exec(ctx, `INSERT INTO component AS c (org_id, project_id, target, scan_id, ecosystem, name, match_name,
				version, purl, path, licenses, first_seen)
			SELECT $1, $2, $3, $4, n.ecosystem, n.name, n.match_name, n.version, n.purl, n.path, n.licenses, $5 FROM pg_temp.component_in n
			ON CONFLICT (project_id, target, ecosystem, match_name, version, path)
			DO UPDATE SET scan_id = EXCLUDED.scan_id, name = EXCLUDED.name, purl = EXCLUDED.purl, licenses = EXCLUDED.licenses`,
			in.OrgID, in.ProjectID, in.Target, in.ScanID, in.Now); err != nil {
			return nil, fmt.Errorf("components: upsert: %w", err)
		}
	}
	stats.Added = len(rows) - stats.Kept
	return stats, nil
}
