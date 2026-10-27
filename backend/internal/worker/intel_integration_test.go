//go:build integration

package worker

import (
	"bytes"
	"compress/gzip"
	"context"
	"fmt"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/google/uuid"
	"github.com/jackc/pgx/v5"

	"github.com/aupv9/warden/backend/internal/db"
)

// Synthetic CVE ids, built at test time.
func feedCVE(n int) string { return fmt.Sprintf("CVE-2032-%05d", n) }

func kevFeed(released string, entries ...string) string {
	return `{"title":"t","catalogVersion":"x","dateReleased":"` + released + `","count":1,"vulnerabilities":[` +
		strings.Join(entries, ",") + `]}`
}

func kevItem(n int, added string, ransomware bool) string {
	r := "Unknown"
	if ransomware {
		r = "Known"
	}
	return fmt.Sprintf(`{"cveID":%q,"dateAdded":%q,"dueDate":"2032-12-01","knownRansomwareCampaignUse":%q,"product":"P"}`, feedCVE(n), added, r)
}

func epssFeed(t *testing.T, scoreDate string, rows ...string) string {
	t.Helper()
	var b bytes.Buffer
	z := gzip.NewWriter(&b)
	fmt.Fprintf(z, "#model_version:v2026.06.15,score_date:%s\ncve,epss,percentile\n%s\n", scoreDate, strings.Join(rows, "\n"))
	if err := z.Close(); err != nil {
		t.Fatal(err)
	}
	return b.String()
}

type intelRow struct {
	KEVAdded   *time.Time
	KEVDue     *time.Time
	Ransomware bool
	EPSS       *float32
	Percentile *float32
}

// String makes fmt print the values behind the pointers (comparisons below).
func (r intelRow) String() string {
	return fmt.Sprint(deref(r.KEVAdded), deref(r.KEVDue), r.Ransomware, deref(r.EPSS), deref(r.Percentile))
}

func (r intelSourceRow) String() string {
	return fmt.Sprint(deref(r.UpdatedAt), deref(r.LoadedAt), deref(r.Records), deref(r.SHA))
}

func deref[T any](p *T) any {
	if p == nil {
		return "<nil>"
	}
	return *p
}

func readIntel(t *testing.T) map[string]intelRow {
	t.Helper()
	out := map[string]intelRow{}
	err := db.WithOrg(context.Background(), ownerPool, uuid.Nil, func(tx pgx.Tx) error {
		rows, err := tx.Query(context.Background(), `SELECT cve, kev_added, kev_due, kev_ransomware, epss, epss_percentile
			FROM vuln_intel WHERE cve LIKE 'CVE-2032-%'`)
		if err != nil {
			return err
		}
		var cve string
		var r intelRow
		_, err = pgx.ForEachRow(rows, []any{&cve, &r.KEVAdded, &r.KEVDue, &r.Ransomware, &r.EPSS, &r.Percentile}, func() error {
			out[cve] = r
			return nil
		})
		return err
	})
	if err != nil {
		t.Fatal(err)
	}
	return out
}

type intelSourceRow struct {
	UpdatedAt *time.Time
	LoadedAt  *time.Time
	Records   *int
	SHA       *string
}

func readSources(t *testing.T) map[string]intelSourceRow {
	t.Helper()
	out := map[string]intelSourceRow{}
	err := db.WithOrg(context.Background(), ownerPool, uuid.Nil, func(tx pgx.Tx) error {
		rows, _ := tx.Query(context.Background(), `SELECT name, updated_at, loaded_at, records, sha256 FROM vuln_intel_source`)
		var name string
		var r intelSourceRow
		_, err := pgx.ForEachRow(rows, []any{&name, &r.UpdatedAt, &r.LoadedAt, &r.Records, &r.SHA}, func() error {
			out[name] = r
			return nil
		})
		return err
	})
	if err != nil {
		t.Fatal(err)
	}
	return out
}

// The loader runs as warden_app (appPool): this also proves the grants and
// the TEMPORARY privilege it needs are in place.
func TestLoadVulnIntelEndToEnd(t *testing.T) {
	ctx := context.Background()
	mirror := t.TempDir()
	clock := time.Date(2026, 10, 27, 12, 0, 0, 0, time.UTC)
	env := &Env{Tx: PoolTx(appPool), Now: func() time.Time { return clock }, Log: quietLog(), Settings: Settings{MirrorDir: mirror}}
	write := func(rel, content string) {
		p := filepath.Join(mirror, rel)
		if err := os.MkdirAll(filepath.Dir(p), 0o755); err != nil {
			t.Fatal(err)
		}
		// Replace atomically, as the sync script does.
		if err := os.WriteFile(p+".tmp", []byte(content), 0o644); err != nil {
			t.Fatal(err)
		}
		if err := os.Rename(p+".tmp", p); err != nil {
			t.Fatal(err)
		}
	}

	// 1, 2 in KEV; 2, 3 in EPSS: three merged rows.
	write(intelKEVFile, kevFeed("2026-10-26T22:24:24.6101Z", kevItem(1, "2024-03-01", true), kevItem(2, "2025-01-15", false)))
	write(intelEPSSFile, epssFeed(t, "2026-10-27T12:03:15Z", feedCVE(2)+",0.27183,0.98043", feedCVE(3)+",0.7,0.5"))
	write(trivyMetaFile, `{"Version":2,"UpdatedAt":"2026-10-25T12:57:48.463991102Z"}`)
	if err := env.LoadVulnIntel(ctx); err != nil {
		t.Fatal(err)
	}
	rows := readIntel(t)
	one, two, three := rows[feedCVE(1)], rows[feedCVE(2)], rows[feedCVE(3)]
	if len(rows) != 3 || one.KEVAdded.Format(time.DateOnly) != "2024-03-01" || !one.Ransomware || one.EPSS != nil ||
		two.KEVAdded == nil || *two.EPSS != float32(0.27183) || *two.Percentile != float32(0.98043) ||
		three.KEVAdded != nil || *three.EPSS != float32(0.7) || one.KEVDue.Format(time.DateOnly) != "2032-12-01" {
		t.Fatalf("%+v", rows)
	}
	src := readSources(t)
	if k := src["kev"]; !k.UpdatedAt.Equal(time.Date(2026, 10, 26, 22, 24, 24, 610100000, time.UTC)) || *k.Records != 2 || !k.LoadedAt.Equal(clock) {
		t.Fatalf("%+v", k)
	}
	if e := src["epss"]; !e.UpdatedAt.Equal(time.Date(2026, 10, 27, 12, 3, 15, 0, time.UTC)) || *e.Records != 2 {
		t.Fatalf("%+v", e)
	}
	if tr := src["trivy_db"]; tr.UpdatedAt == nil || tr.LoadedAt != nil || tr.Records != nil || tr.SHA == nil {
		t.Fatalf("%+v", tr)
	}

	// Unchanged files are skipped: loaded_at stays.
	clock = clock.Add(time.Hour)
	if err := env.LoadVulnIntel(ctx); err != nil {
		t.Fatal(err)
	}
	if k := readSources(t)["kev"]; !k.LoadedAt.Equal(clock.Add(-time.Hour)) {
		t.Fatalf("unchanged feed reloaded: %+v", k)
	}

	// A new catalog drops CVE 1 (KEV only: row deleted) and 2 (also in EPSS:
	// KEV columns cleared) and adds 3 (merged with its EPSS row).
	write(intelKEVFile, kevFeed("2026-10-28T10:00:00Z", kevItem(3, "2026-10-28", false)))
	if err := env.LoadVulnIntel(ctx); err != nil {
		t.Fatal(err)
	}
	rows = readIntel(t)
	two, three = rows[feedCVE(2)], rows[feedCVE(3)]
	if _, ok := rows[feedCVE(1)]; ok || len(rows) != 2 || two.KEVAdded != nil || two.KEVDue != nil || two.Ransomware || *two.EPSS != float32(0.27183) ||
		three.KEVAdded.Format(time.DateOnly) != "2026-10-28" || *three.EPSS != float32(0.7) {
		t.Fatalf("%+v", rows)
	}
	if k := readSources(t)["kev"]; *k.Records != 1 || !k.LoadedAt.Equal(clock) {
		t.Fatalf("%+v", k)
	}

	// Broken or hostile files keep the previous data and the job succeeds:
	// an out-of-range score, a gzip bomb, an empty catalog.
	before, beforeSrc := readIntel(t), readSources(t)
	bomb := func() string {
		var b bytes.Buffer
		z := gzip.NewWriter(&b)
		fmt.Fprintf(z, "#model_version:v1,score_date:2026-10-28T00:00:00Z\ncve,epss,percentile\n")
		zeros := make([]byte, 1<<20)
		for range 64 {
			_, _ = z.Write(zeros)
		}
		_ = z.Close()
		return b.String()
	}()
	for _, bad := range []struct{ file, content string }{
		{intelEPSSFile, epssFeed(t, "2026-10-28T12:00:00Z", feedCVE(2)+",1.5,0.9")},
		{intelEPSSFile, bomb},
		{intelKEVFile, kevFeed("2026-10-29T10:00:00Z")},
		{intelKEVFile, kevFeed("2026-10-29T10:00:00Z", kevItem(4, "2026-10-28", false), kevItem(4, "2026-10-28", false))},
	} {
		write(bad.file, bad.content)
		clock = clock.Add(time.Hour)
		if err := env.LoadVulnIntel(ctx); err != nil {
			t.Fatal(err)
		}
		if after := readIntel(t); fmt.Sprint(after) != fmt.Sprint(before) {
			t.Fatalf("%s: data changed: %+v", bad.file, after)
		}
		if after := readSources(t); fmt.Sprint(after) != fmt.Sprint(beforeSrc) {
			t.Fatalf("%s: sources changed: %+v", bad.file, after)
		}
	}

	// A fixed EPSS file loads again; the KEV columns are untouched by it.
	write(intelEPSSFile, epssFeed(t, "2026-10-29T12:00:00Z", feedCVE(3)+",0.5,0.4"))
	if err := env.LoadVulnIntel(ctx); err != nil {
		t.Fatal(err)
	}
	rows = readIntel(t)
	if _, ok := rows[feedCVE(2)]; ok || len(rows) != 1 || *rows[feedCVE(3)].EPSS != float32(0.5) || rows[feedCVE(3)].KEVAdded == nil {
		t.Fatalf("%+v", rows)
	}
}

// Real feeds from a synced mirror (WARDEN_TEST_MIRROR=.cache/mirror after
// scripts/sync-mirror.sh intel): load them and report what was loaded.
func TestLoadVulnIntelRealMirror(t *testing.T) {
	mirror := os.Getenv("WARDEN_TEST_MIRROR")
	if mirror == "" {
		t.Skip("WARDEN_TEST_MIRROR not set")
	}
	ctx := context.Background()
	env := &Env{Tx: PoolTx(appPool), Now: time.Now, Log: quietLog(), Settings: Settings{MirrorDir: mirror}}
	start := time.Now()
	if err := env.LoadVulnIntel(ctx); err != nil {
		t.Fatal(err)
	}
	took := time.Since(start)
	src := readSources(t)
	for _, name := range []string{"trivy_db", "kev", "epss"} {
		s, ok := src[name]
		if !ok {
			t.Errorf("%s not loaded", name)
			continue
		}
		rec := "-"
		if s.Records != nil {
			rec = fmt.Sprint(*s.Records)
		}
		t.Logf("%s: updated_at %s, records %s", name, s.UpdatedAt.Format(time.RFC3339), rec)
	}
	var total, kev, both int
	err := db.WithOrg(ctx, ownerPool, uuid.Nil, func(tx pgx.Tx) error {
		return tx.QueryRow(ctx, `SELECT count(*), count(*) FILTER (WHERE kev_added IS NOT NULL),
			count(*) FILTER (WHERE kev_added IS NOT NULL AND epss IS NOT NULL) FROM vuln_intel`).Scan(&total, &kev, &both)
	})
	if err != nil {
		t.Fatal(err)
	}
	t.Logf("vuln_intel: %d rows, %d in KEV, %d in KEV with an EPSS score; load took %s", total, kev, both, took.Round(time.Millisecond))
}
