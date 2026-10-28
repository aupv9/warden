package worker

import (
	"context"
	"crypto/sha256"
	"encoding/hex"
	"errors"
	"fmt"
	"io"
	"io/fs"
	"os"
	"path/filepath"
	"time"

	"github.com/google/uuid"
	"github.com/jackc/pgx/v5"
	"github.com/riverqueue/river"

	"github.com/aupv9/warden/backend/internal/domain/ecosystem"
	"github.com/aupv9/warden/backend/internal/intel"
)

// Exploit intelligence: the load_vuln_intel job reads the KEV and EPSS feeds
// from the mirror (scripts/sync-mirror.sh) into vuln_intel, and records the
// Trivy DB's date, so issues can be ranked by exploitation and the UI can say
// how fresh the data is. It also loads the OSV malicious-package advisories
// (one all.zip per ecosystem) into malicious_package and, when they changed,
// enqueues match_malicious for the component inventory (malicious.go).

type LoadVulnIntelArgs struct{}

func (LoadVulnIntelArgs) Kind() string { return "load_vuln_intel" }

// Parse errors are logged and never retried (the file won't change until the
// next sync, and the next hourly run tries again); a few attempts cover a
// database hiccup.
func (LoadVulnIntelArgs) InsertOpts() river.InsertOpts { return river.InsertOpts{MaxAttempts: 3} }

type LoadVulnIntelWorker struct {
	river.WorkerDefaults[LoadVulnIntelArgs]
	Env *Env
}

// Timeout: inflating and loading a full EPSS file takes seconds, but River's
// default of one minute is too tight on a busy database.
func (LoadVulnIntelWorker) Timeout(*river.Job[LoadVulnIntelArgs]) time.Duration {
	return 10 * time.Minute
}

func (w LoadVulnIntelWorker) Work(ctx context.Context, _ *river.Job[LoadVulnIntelArgs]) error {
	if w.Env == nil {
		return errNoEnv
	}
	return w.Env.LoadVulnIntel(ctx)
}

// Feed files in the mirror. Only these exact names are read: the sync script
// downloads to a temporary name and renames, so a half-written file is never
// picked up.
const (
	intelKEVFile  = "intel/kev.json"
	intelEPSSFile = "intel/epss.csv.gz"
	trivyMetaFile = "trivy/db/metadata.json"
	// intelOSVDir holds <ecosystem>.zip, OSV's all.zip of each ecosystem.
	intelOSVDir = "intel/osv"
)

const (
	sourceTrivyDB = "trivy_db"
	sourceKEV     = "kev"
	sourceEPSS    = "epss"

	// sourceOSVPrefix + ecosystem names an OSV malicious-package feed.
	sourceOSVPrefix = "osv_mal:"

	intelLoadLock  = "warden.load_vuln_intel" // advisory lock key
	msgFeedInvalid = "vulnerability feed rejected; keeping the previous data"
)

// feedSource is a file in the mirror and its parser: parse streams it,
// parseFile reads it in place (the OSV zips; one of the two is set).
type feedSource struct {
	name      string
	file      string
	maxSize   int64
	parse     func(io.Reader) (loadedFeed, error)
	parseFile func(f *os.File, size int64) (loadedFeed, error)
}

// loadedFeed is a parsed feed: the publisher's date (zero when unknown), the
// record count, and apply, which replaces the feed's data inside the load
// transaction (nil for trivy_db, which only records its date). unsupported
// is recorded for OSV feeds.
type loadedFeed struct {
	updatedAt   time.Time
	records     int
	unsupported *int
	apply       func(ctx context.Context, db DB) error
	// logAttrs are extra attributes for the "loaded" log line.
	logAttrs []any
}

// OSV all.zip caps: npm's is about 220 MB (2026), the others under 40 MB.
const (
	maxOSVNpmZip = 512 << 20
	maxOSVZip    = 128 << 20
)

// osvFeeds is one feed per ecosystem with an OSV malicious-package list.
func osvFeeds() []feedSource {
	var out []feedSource
	for _, eco := range ecosystem.OSV {
		max := int64(maxOSVZip)
		if eco == ecosystem.Npm {
			max = maxOSVNpmZip
		}
		out = append(out, feedSource{name: sourceOSVPrefix + eco, file: intelOSVDir + "/" + eco + ".zip", maxSize: max,
			parseFile: func(f *os.File, size int64) (loadedFeed, error) { return parseOSVFeed(f, size, eco) }})
	}
	return out
}

// LoadVulnIntel loads each feed whose file changed since the last load (by
// SHA-256). A feed that is missing or fails validation is skipped and its
// previous data stays; only database errors fail the job.
func (e *Env) LoadVulnIntel(ctx context.Context) error {
	feeds := []feedSource{
		{name: sourceKEV, file: intelKEVFile, maxSize: intel.MaxKEVBytes, parse: parseKEVFeed},
		{name: sourceEPSS, file: intelEPSSFile, maxSize: intel.MaxEPSSBytes, parse: parseEPSSFeed},
		{name: sourceTrivyDB, file: trivyMetaFile, maxSize: intel.MaxTrivyMetaBytes, parse: parseTrivyMeta},
	}
	feeds = append(feeds, osvFeeds()...)
	var errs []error
	for _, f := range feeds {
		if err := e.loadFeed(ctx, f); err != nil {
			errs = append(errs, fmt.Errorf("%s: %w", f.name, err))
		}
	}
	return errors.Join(errs...)
}

func (e *Env) loadFeed(ctx context.Context, f feedSource) error {
	path := filepath.Join(e.MirrorDir, f.file)
	file, size, sum, err := openFeed(path, f.maxSize)
	if errors.Is(err, fs.ErrNotExist) {
		e.Log.Info("vulnerability feed not in the mirror; run scripts/sync-mirror.sh", "feed", f.name, "path", path)
		return nil
	}
	if err != nil {
		e.Log.Error(msgFeedInvalid, "feed", f.name, "path", path, "err", err)
		return nil
	}
	defer file.Close()

	stored, err := e.feedSHA(ctx, f.name)
	if err != nil {
		return err
	}
	if stored == sum {
		return nil
	}
	var feed loadedFeed
	if f.parseFile != nil {
		feed, err = f.parseFile(file, size)
	} else {
		feed, err = f.parse(file)
	}
	if err != nil {
		e.Log.Error(msgFeedInvalid, "feed", f.name, "path", path, "sha256", sum, "err", err)
		return nil
	}
	now := e.Now().UTC()
	skipped := false
	err = e.Tx(ctx, uuid.Nil, func(db DB) error {
		// One loader at a time (two workers may both run the job on start); the
		// second sees the new hash and stops.
		if _, err := db.Exec(ctx, `SELECT pg_advisory_xact_lock(hashtext($1))`, intelLoadLock); err != nil {
			return err
		}
		var current *string
		if err := db.QueryRow(ctx, `SELECT sha256 FROM vuln_intel_source WHERE name = $1`, f.name).Scan(&current); err != nil && !errors.Is(err, pgx.ErrNoRows) {
			return err
		}
		if current != nil && *current == sum {
			skipped = true
			return nil
		}
		if feed.apply != nil {
			if err := feed.apply(ctx, db); err != nil {
				return err
			}
		}
		// Trivy reads its DB from the mirror directly: nothing is loaded, so
		// loaded_at and records stay null (the API contract says so).
		var loadedAt, updatedAt *time.Time
		var records *int
		if f.name != sourceTrivyDB {
			loadedAt, records = &now, &feed.records
		}
		if !feed.updatedAt.IsZero() {
			updatedAt = &feed.updatedAt
		}
		_, err := db.Exec(ctx, `INSERT INTO vuln_intel_source (name, updated_at, loaded_at, records, sha256, unsupported)
			VALUES ($1, $2, $3, $4, $5, $6)
			ON CONFLICT (name) DO UPDATE SET updated_at = EXCLUDED.updated_at, loaded_at = EXCLUDED.loaded_at,
				records = EXCLUDED.records, sha256 = EXCLUDED.sha256, unsupported = EXCLUDED.unsupported`,
			f.name, updatedAt, loadedAt, records, sum, feed.unsupported)
		return err
	})
	if err != nil {
		return err
	}
	if !skipped {
		e.Log.Info("loaded vulnerability feed", append([]any{"feed", f.name, "records", feed.records,
			"updated_at", feed.updatedAt.Format(time.RFC3339), "sha256", sum}, feed.logAttrs...)...)
	}
	return nil
}

func (e *Env) feedSHA(ctx context.Context, name string) (string, error) {
	var sum *string
	err := e.Tx(ctx, uuid.Nil, func(db DB) error {
		err := db.QueryRow(ctx, `SELECT sha256 FROM vuln_intel_source WHERE name = $1`, name).Scan(&sum)
		if errors.Is(err, pgx.ErrNoRows) {
			return nil
		}
		return err
	})
	if err != nil || sum == nil {
		return "", err
	}
	return *sum, nil
}

// openFeed opens a regular file of at most maxSize bytes and returns it,
// rewound, with its size and SHA-256. The same descriptor is hashed and
// parsed, so a sync replacing the file meanwhile can't make the two disagree.
func openFeed(path string, maxSize int64) (*os.File, int64, string, error) {
	f, err := os.Open(path)
	if err != nil {
		return nil, 0, "", err
	}
	ok := false
	defer func() {
		if !ok {
			f.Close()
		}
	}()
	fi, err := f.Stat()
	if err != nil {
		return nil, 0, "", err
	}
	if !fi.Mode().IsRegular() {
		return nil, 0, "", errors.New("not a regular file")
	}
	h := sha256.New()
	n, err := io.Copy(h, io.LimitReader(f, maxSize+1))
	if err != nil {
		return nil, 0, "", err
	}
	if n > maxSize {
		return nil, 0, "", fmt.Errorf("larger than %d bytes: %w", maxSize, intel.ErrTooLarge)
	}
	if _, err := f.Seek(0, io.SeekStart); err != nil {
		return nil, 0, "", err
	}
	ok = true
	// n, not the Stat size: what was hashed is what is parsed.
	return f, n, hex.EncodeToString(h.Sum(nil)), nil
}

// copier is the COPY support of a pgx transaction (results.DB doesn't need it).
type copier interface {
	CopyFrom(ctx context.Context, table pgx.Identifier, columns []string, src pgx.CopyFromSource) (int64, error)
}

// stage creates a transaction-local table and COPYs rows into it. It needs
// the TEMPORARY privilege on the database, which PUBLIC has by default.
func stage(ctx context.Context, db DB, ddl string, columns []string, rows [][]any) error {
	c, ok := db.(copier)
	if !ok {
		return errors.New("database handle can't COPY")
	}
	if _, err := db.Exec(ctx, `CREATE TEMP TABLE vuln_intel_stage (`+ddl+`) ON COMMIT DROP`); err != nil {
		return err
	}
	_, err := c.CopyFrom(ctx, pgx.Identifier{"vuln_intel_stage"}, columns, pgx.CopyFromRows(rows))
	return err
}

// Each feed owns its columns of vuln_intel: a load upserts them from the
// staged feed, clears them on CVEs that left the feed, and deletes rows that
// no feed mentions any more (the table's CHECK needs KEV or EPSS data). A row
// exists while either feed has the CVE, and each feed loads, fails or is
// skipped on its own: a broken EPSS file doesn't hold back a new KEV entry.
// Unchanged rows are left alone so their updated_at means something.

func parseKEVFeed(r io.Reader) (loadedFeed, error) {
	k, err := intel.ParseKEV(r)
	if err != nil {
		return loadedFeed{}, err
	}
	rows := make([][]any, len(k.Entries))
	for i, en := range k.Entries {
		var due *time.Time
		if !en.Due.IsZero() {
			due = &en.Due
		}
		rows[i] = []any{en.CVE, en.Added, due, en.Ransomware}
	}
	return loadedFeed{updatedAt: k.Released, records: len(rows), apply: func(ctx context.Context, db DB) error {
		if err := stage(ctx, db, `cve text PRIMARY KEY, kev_added date NOT NULL, kev_due date, kev_ransomware boolean NOT NULL`,
			[]string{"cve", "kev_added", "kev_due", "kev_ransomware"}, rows); err != nil {
			return err
		}
		_, err := db.Exec(ctx, `
			INSERT INTO vuln_intel AS v (cve, kev_added, kev_due, kev_ransomware, updated_at)
			SELECT cve, kev_added, kev_due, kev_ransomware, now() FROM vuln_intel_stage
			ON CONFLICT (cve) DO UPDATE SET kev_added = EXCLUDED.kev_added, kev_due = EXCLUDED.kev_due,
				kev_ransomware = EXCLUDED.kev_ransomware, updated_at = now()
			WHERE (v.kev_added, v.kev_due, v.kev_ransomware) IS DISTINCT FROM
				(EXCLUDED.kev_added, EXCLUDED.kev_due, EXCLUDED.kev_ransomware)`)
		if err != nil {
			return err
		}
		if _, err := db.Exec(ctx, `DELETE FROM vuln_intel v WHERE v.epss IS NULL
			AND NOT EXISTS (SELECT 1 FROM vuln_intel_stage s WHERE s.cve = v.cve)`); err != nil {
			return err
		}
		_, err = db.Exec(ctx, `UPDATE vuln_intel v SET kev_added = NULL, kev_due = NULL, kev_ransomware = false, updated_at = now()
			WHERE v.kev_added IS NOT NULL AND NOT EXISTS (SELECT 1 FROM vuln_intel_stage s WHERE s.cve = v.cve)`)
		return err
	}}, nil
}

func parseEPSSFeed(r io.Reader) (loadedFeed, error) {
	ep, err := intel.ParseEPSS(r)
	if err != nil {
		return loadedFeed{}, err
	}
	rows := make([][]any, len(ep.Scores))
	for i, s := range ep.Scores {
		rows[i] = []any{s.CVE, s.Score, s.Percentile}
	}
	return loadedFeed{updatedAt: ep.ScoreDate, records: len(rows), apply: func(ctx context.Context, db DB) error {
		if err := stage(ctx, db, `cve text PRIMARY KEY, epss real NOT NULL, epss_percentile real NOT NULL`,
			[]string{"cve", "epss", "epss_percentile"}, rows); err != nil {
			return err
		}
		_, err := db.Exec(ctx, `
			INSERT INTO vuln_intel AS v (cve, epss, epss_percentile, updated_at)
			SELECT cve, epss, epss_percentile, now() FROM vuln_intel_stage
			ON CONFLICT (cve) DO UPDATE SET epss = EXCLUDED.epss, epss_percentile = EXCLUDED.epss_percentile, updated_at = now()
			WHERE (v.epss, v.epss_percentile) IS DISTINCT FROM (EXCLUDED.epss, EXCLUDED.epss_percentile)`)
		if err != nil {
			return err
		}
		if _, err := db.Exec(ctx, `DELETE FROM vuln_intel v WHERE v.kev_added IS NULL
			AND NOT EXISTS (SELECT 1 FROM vuln_intel_stage s WHERE s.cve = v.cve)`); err != nil {
			return err
		}
		_, err = db.Exec(ctx, `UPDATE vuln_intel v SET epss = NULL, epss_percentile = NULL, updated_at = now()
			WHERE v.epss IS NOT NULL AND NOT EXISTS (SELECT 1 FROM vuln_intel_stage s WHERE s.cve = v.cve)`)
		return err
	}}, nil
}

func parseTrivyMeta(r io.Reader) (loadedFeed, error) {
	t, err := intel.ParseTrivyMeta(r)
	return loadedFeed{updatedAt: t}, err
}

// parseOSVFeed reads one ecosystem's OSV all.zip. Its apply diff-upserts that
// ecosystem's malicious_package rows (unchanged rows are left alone; ids that
// left the feed are deleted, while issues already created stay: feeds never
// fix one) and, in the load transaction, enqueues match_malicious for the
// names whose advisories are new or changed.
func parseOSVFeed(f *os.File, size int64, eco string) (loadedFeed, error) {
	res, err := intel.ParseOSVMalicious(f, size, eco)
	if err != nil {
		return loadedFeed{}, err
	}
	rows := make([][]any, len(res.Packages))
	for i, p := range res.Packages {
		versions := p.Versions
		if versions == nil {
			versions = []string{}
		}
		rows[i] = []any{p.ID, p.Ecosystem, p.Name, p.MatchName, p.AllVersions, versions, p.Summary, p.Published, p.Modified}
	}
	unsupported := res.Unsupported
	stats := []any{"advisories", res.Advisories, "withdrawn", res.Withdrawn, "unsupported", res.Unsupported,
		"partial", res.Partial, "other_ecosystem", res.OtherEcosystem, "invalid", res.Invalid}
	if len(res.InvalidSamples) > 0 {
		stats = append(stats, "invalid_samples", res.InvalidSamples)
	}
	return loadedFeed{updatedAt: res.Updated, records: len(rows), unsupported: &unsupported, logAttrs: stats,
		apply: func(ctx context.Context, db DB) error {
			if err := stage(ctx, db, `id text NOT NULL, ecosystem text NOT NULL, name text NOT NULL, match_name text NOT NULL,
				all_versions boolean NOT NULL, versions text[] NOT NULL, summary text NOT NULL, published timestamptz,
				modified timestamptz NOT NULL, PRIMARY KEY (id, match_name)`,
				[]string{"id", "ecosystem", "name", "match_name", "all_versions", "versions", "summary", "published", "modified"},
				rows); err != nil {
				return err
			}
			changed, err := db.Query(ctx, `WITH up AS (
					INSERT INTO malicious_package AS m (id, ecosystem, name, match_name, all_versions, versions, summary, published, modified)
					SELECT id, ecosystem, name, match_name, all_versions, versions, summary, published, modified FROM vuln_intel_stage
					ON CONFLICT (id, ecosystem, match_name) DO UPDATE SET name = EXCLUDED.name, all_versions = EXCLUDED.all_versions,
						versions = EXCLUDED.versions, summary = EXCLUDED.summary, published = EXCLUDED.published, modified = EXCLUDED.modified
					WHERE (m.name, m.all_versions, m.versions, m.summary, m.published, m.modified) IS DISTINCT FROM
						(EXCLUDED.name, EXCLUDED.all_versions, EXCLUDED.versions, EXCLUDED.summary, EXCLUDED.published, EXCLUDED.modified)
					RETURNING match_name)
				SELECT DISTINCT match_name FROM up ORDER BY 1`)
			if err != nil {
				return err
			}
			names, err := pgx.CollectRows(changed, pgx.RowTo[string])
			if err != nil {
				return err
			}
			if _, err := db.Exec(ctx, `DELETE FROM malicious_package m WHERE m.ecosystem = $1
				AND NOT EXISTS (SELECT 1 FROM vuln_intel_stage s WHERE s.id = m.id AND s.match_name = m.match_name)`, eco); err != nil {
				return err
			}
			if len(names) == 0 {
				return nil
			}
			args := MatchMaliciousArgs{Ecosystem: eco, Names: names}
			if len(names) > maxMatchNames {
				// The first load (or a large change): match the whole ecosystem
				// instead of carrying 200k names in the job's arguments.
				args = MatchMaliciousArgs{Ecosystem: eco, All: true}
			}
			return enqueueMatch(ctx, db, args)
		}}, nil
}
