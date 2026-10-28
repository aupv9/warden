package worker

import (
	"context"
	"crypto/sha256"
	"encoding/hex"
	"errors"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/google/uuid"

	"github.com/aupv9/warden/backend/internal/intel"
	"github.com/aupv9/warden/backend/internal/worker/dbtest"
)

const trivyMeta = `{"Version":2,"UpdatedAt":"2026-10-25T12:57:48.463991102Z"}`

func intelEnv(t *testing.T, mirror string, steps ...dbtest.Step) (*Env, *dbtest.DB) {
	db := dbtest.Loose(t, append([]dbtest.Step{
		{Prefix: "SELECT sha256 FROM vuln_intel_source"},
		{Prefix: "SELECT pg_advisory_xact_lock"},
		{Prefix: "INSERT INTO vuln_intel_source", Affected: 1},
	}, steps...)...)
	env := &Env{
		Tx: func(_ context.Context, org uuid.UUID, fn func(DB) error) error {
			if org != uuid.Nil {
				t.Errorf("intel load scoped to org %s", org)
			}
			return fn(db)
		},
		Now: func() time.Time { return time.Date(2026, 10, 27, 12, 0, 0, 0, time.UTC) }, Log: quietLog(),
		Settings: Settings{MirrorDir: mirror},
	}
	return env, db
}

func writeFile(t *testing.T, path, content string) string {
	t.Helper()
	if err := os.MkdirAll(filepath.Dir(path), 0o755); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(path, []byte(content), 0o644); err != nil {
		t.Fatal(err)
	}
	sum := sha256.Sum256([]byte(content))
	return hex.EncodeToString(sum[:])
}

func TestLoadVulnIntelWithoutFeedsDoesNothing(t *testing.T) {
	env, db := intelEnv(t, t.TempDir())
	if err := env.LoadVulnIntel(context.Background()); err != nil {
		t.Fatal(err)
	}
	if n := len(db.Calls("")); n != 0 {
		t.Fatalf("%d statements without any feed", n)
	}
}

// Invalid files are logged and skipped: nothing is written and the job
// succeeds, so River doesn't retry a file that won't change.
func TestLoadVulnIntelSkipsInvalidFeeds(t *testing.T) {
	mirror := t.TempDir()
	writeFile(t, filepath.Join(mirror, intelKEVFile), `{"dateReleased":"2026-10-26T22:24:24Z","vulnerabilities":[{"cveID":"CVE-1"}]}`)
	writeFile(t, filepath.Join(mirror, intelEPSSFile), "not gzip")
	writeFile(t, filepath.Join(mirror, trivyMetaFile), `{"UpdatedAt":"later"}`)
	env, db := intelEnv(t, mirror)
	if err := env.LoadVulnIntel(context.Background()); err != nil {
		t.Fatal(err)
	}
	if n := len(db.Calls("SELECT pg_advisory_xact_lock")) + len(db.Calls("INSERT")); n != 0 {
		t.Fatalf("%d writes for invalid feeds", n)
	}
}

func TestLoadVulnIntelRefusesOversizeAndSpecialFiles(t *testing.T) {
	mirror := t.TempDir()
	writeFile(t, filepath.Join(mirror, trivyMetaFile), `{"UpdatedAt":"2026-10-25T12:57:48Z","x":"`+strings.Repeat("a", intel.MaxTrivyMetaBytes)+`"}`)
	if err := os.MkdirAll(filepath.Join(mirror, intelKEVFile), 0o755); err != nil { // a directory, not a file
		t.Fatal(err)
	}
	env, db := intelEnv(t, mirror)
	if err := env.LoadVulnIntel(context.Background()); err != nil {
		t.Fatal(err)
	}
	if n := len(db.Calls("")); n != 0 {
		t.Fatalf("%d statements", n)
	}
	if _, _, err := openFeed(filepath.Join(mirror, trivyMetaFile), intel.MaxTrivyMetaBytes); !errors.Is(err, intel.ErrTooLarge) {
		t.Fatal(err)
	}
}

func TestLoadVulnIntelSkipsUnchangedFeeds(t *testing.T) {
	mirror := t.TempDir()
	sum := writeFile(t, filepath.Join(mirror, trivyMetaFile), trivyMeta)
	env, db := intelEnv(t, mirror, dbtest.Step{Prefix: "SELECT sha256 FROM vuln_intel_source", Rows: row(sum)})
	if err := env.LoadVulnIntel(context.Background()); err != nil {
		t.Fatal(err)
	}
	if n := len(db.Calls("SELECT pg_advisory_xact_lock")); n != 0 {
		t.Fatal("an unchanged feed was loaded")
	}
}

// trivy_db records the DB's date and hash; nothing is loaded, so loaded_at and
// records stay null.
func TestLoadVulnIntelRecordsTrivyDB(t *testing.T) {
	mirror := t.TempDir()
	sum := writeFile(t, filepath.Join(mirror, trivyMetaFile), trivyMeta)
	env, db := intelEnv(t, mirror)
	if err := env.LoadVulnIntel(context.Background()); err != nil {
		t.Fatal(err)
	}
	calls := db.Calls("INSERT INTO vuln_intel_source")
	if len(calls) != 1 {
		t.Fatalf("%d source updates", len(calls))
	}
	a := calls[0].Args
	if a[0] != sourceTrivyDB || !a[1].(time.Time).Equal(time.Date(2026, 10, 25, 12, 57, 48, 463991102, time.UTC)) ||
		a[2].(*time.Time) != nil || a[3].(*int) != nil || a[4] != sum {
		t.Fatalf("%v", a)
	}
}

// The KEV and EPSS loads need COPY, which only a real transaction has: the
// fake fails the load and the job reports it (integration tests cover COPY).
func TestLoadVulnIntelNeedsCopy(t *testing.T) {
	mirror := t.TempDir()
	writeFile(t, filepath.Join(mirror, intelKEVFile), `{"dateReleased":"2026-10-26T22:24:24Z","vulnerabilities":[
		{"cveID":"CVE-2024-00001","dateAdded":"2024-03-01","knownRansomwareCampaignUse":"Unknown"}]}`)
	env, db := intelEnv(t, mirror)
	err := env.LoadVulnIntel(context.Background())
	if err == nil || !strings.Contains(err.Error(), "COPY") {
		t.Fatal(err)
	}
	if n := len(db.Calls("INSERT INTO vuln_intel_source")); n != 0 {
		t.Fatal("source recorded although the load failed")
	}
}
