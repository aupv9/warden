//go:build integration

package results_test

import (
	"context"
	"strings"
	"testing"
	"time"

	"github.com/google/uuid"
	"github.com/jackc/pgx/v5"

	"github.com/aupv9/warden/backend/internal/db"
	"github.com/aupv9/warden/backend/internal/scan/redact"
	"github.com/aupv9/warden/backend/internal/scan/results"
	"github.com/aupv9/warden/backend/internal/scan/sarif"
	st "github.com/aupv9/warden/backend/internal/scan/scantest"
)

const imageTarget = "ghcr.io/acme/api"

func (f *fixture) imageScan() uuid.UUID {
	id := uuid.New()
	ownerTx(f.t, f.org, func(tx pgx.Tx) error {
		_, err := tx.Exec(context.Background(), `INSERT INTO scan (id, org_id, project_id, created_by, status, file_name, tools, kind, target)
			VALUES ($1, $2, $3, $4, 'running', 'i.tar', '{gitleaks,trivy}', 'image', $5)`, id, f.org, f.project, f.user, imageTarget)
		return err
	})
	return id
}

func (f *fixture) processImage(scanID uuid.UUID, fs []sarif.Finding) results.Plan {
	f.t.Helper()
	var plan results.Plan
	err := db.WithOrg(context.Background(), appPool, f.org, func(tx pgx.Tx) error {
		var err error
		plan, err = results.Process(context.Background(), tx, results.Input{
			OrgID: f.org, ProjectID: f.project, ScanID: scanID, Status: "completed", Target: imageTarget,
			Runs: ok("gitleaks"), Findings: map[string][]sarif.Finding{"gitleaks": fs}, GuardRatio: 0.5, Now: time.Now().UTC(),
		})
		return err
	})
	if err != nil {
		f.t.Fatal(err)
	}
	return plan
}

// imageFindings parses warden-layers' results the way the worker does.
func imageFindings(t *testing.T, layers []string, results ...any) []sarif.Finding {
	t.Helper()
	doc, err := redact.Doc(st.RoundTrip(st.Doc(results)), st.HMACKey)
	if err != nil {
		t.Fatal(err)
	}
	fs, err := sarif.Parse(st.RoundTrip(doc), "gitleaks", sarif.Options{ImageTarget: imageTarget, ImageLayers: layers})
	if err != nil {
		t.Fatal(err)
	}
	return fs
}

type layerRow struct {
	Digest       string
	Index, Count int
	Path, Status string
}

func (f *fixture) imageIssues() (rows []layerRow) {
	ownerTx(f.t, f.org, func(tx pgx.Tx) error {
		r, err := tx.Query(context.Background(), `SELECT image_layer_digest, image_layer_index, image_layer_count, file_path, status::text
			FROM issue WHERE project_id = $1 AND target = $2 ORDER BY number`, f.project, imageTarget)
		if err != nil {
			return err
		}
		rows, err = pgx.CollectRows(r, func(row pgx.CollectableRow) (layerRow, error) {
			var l layerRow
			return l, row.Scan(&l.Digest, &l.Index, &l.Count, &l.Path, &l.Status)
		})
		return err
	})
	return rows
}

// One issue per (rule, secret) in an image, at the lowest layer that holds
// it (also when a later layer deleted the file), with the layer count. A
// rebuilt image (new digests, the secret moved) keeps the issue; an image
// without it fixes the issue; a source scan never touches it.
func TestImageLayerProcessing(t *testing.T) {
	f := newFixture(t)
	digest := func(c byte) string { return "sha256:" + strings.Repeat(string(c), 64) }

	s1 := f.imageScan()
	p := f.processImage(s1, imageFindings(t, []string{digest('a'), digest('b'), digest('c')},
		st.ImageResult("aws-access-token", "/app/.env", 3, st.FakeSecret, 2),
		st.ImageResult("aws-access-token", "/app/.env", 3, st.FakeSecret, 1),
		st.ImageResult("aws-access-token", "/app/"+st.FakeSecret+".txt", 1, st.FakeSecret, 1),
	))
	if p.Stats != (results.Stats{New: 1, Total: 1}) || p.ToolCounts["gitleaks"] != 1 {
		t.Fatalf("%+v", p)
	}
	rows := f.imageIssues()
	if len(rows) != 1 || rows[0] != (layerRow{digest('b'), 1, 2, imageTarget + "::/app/.env", "open"}) {
		t.Fatalf("%+v", rows)
	}
	// No secret in the issue or its occurrence (a file named after it included).
	var dump string
	ownerTx(t, f.org, func(tx pgx.Tx) error {
		return tx.QueryRow(context.Background(), `SELECT string_agg(i::text, '') || (SELECT string_agg(o::text, '') FROM occurrence o WHERE o.scan_id = $2)
			FROM issue i WHERE project_id = $1`, f.project, s1).Scan(&dump)
	})
	if strings.Contains(dump, st.FakeSecret) {
		t.Fatal(dump)
	}

	// Rebuilt: other digests, the secret moved to another file in layer 0.
	s2 := f.imageScan()
	p = f.processImage(s2, imageFindings(t, []string{digest('d'), digest('e')},
		st.ImageResult("aws-access-token", "/srv/creds", 7, st.FakeSecret, 0),
	))
	if p.Stats.New != 0 || p.Stats.Fixed != 0 {
		t.Fatalf("%+v", p.Stats)
	}
	if rows := f.imageIssues(); len(rows) != 1 || rows[0] != (layerRow{digest('d'), 0, 1, imageTarget + "::/srv/creds", "open"}) {
		t.Fatalf("%+v", rows)
	}

	// A source scan doesn't touch it.
	if _, err := f.process(f.scan("gitleaks"), ok("gitleaks"), map[string][]sarif.Finding{"gitleaks": {}}); err != nil {
		t.Fatal(err)
	}
	if f.imageIssues()[0].Status != "open" {
		t.Fatal("source scan reached the image's issue")
	}

	// Gone from every layer: fixed.
	if p := f.processImage(f.imageScan(), nil); p.Stats.Fixed != 1 || f.imageIssues()[0].Status != "fixed" {
		t.Fatalf("%+v %+v", p.Stats, f.imageIssues())
	}
}
