package store

import (
	"strings"
	"testing"

	"github.com/google/uuid"

	"github.com/aupv9/warden/backend/internal/service"
)

// An import scan reads its import_* columns into Scan.Import (the counts stay
// nil until the worker sets them) and writes the three it is created with.
func TestRepoImportScan(t *testing.T) {
	org, user, proj, scan := uuid.New(), uuid.New(), uuid.New(), uuid.New()
	row := []any{scan, org, proj, "pending_upload", "codeql.sarif", int64(10), []string{"external"}, nil, service.ScanStats{},
		now, nil, nil, nil, "key", "sum", user, "a@b.c", "A", nil, nil, nil, "import", "(import) codeql /language:go/", nil,
		nil, nil, nil, nil, nil, nil, nil, nil, nil, service.ScanRuleRefs{}, false,
		"codeql", "/language:go/", "sarif", "2.19.0", 12, 1, nil}
	var inserted []any
	r, _ := repoWith(func(sql string, args []any) ([][]any, error) {
		if strings.HasPrefix(sql, "INSERT INTO scan") {
			inserted = args
			return nil, nil
		}
		return on(map[string][][]any{"FROM scan s JOIN app_user": {row}})(sql, args)
	})
	s, err := r.Scan(ctx, scan, false)
	if err != nil || s.Import == nil || s.Import.Tool != "codeql" || s.Import.Category != "/language:go/" || s.Import.Format != "sarif" ||
		*s.Import.ToolVersion != "2.19.0" || *s.Import.Results != 12 || *s.Import.Dropped != 1 || s.Import.Screened != nil {
		t.Fatal(s, err)
	}

	im := &service.NewScanImport{Tool: "codeql", Category: "", Format: "gitlab-sast"}
	if err := r.InsertScan(ctx, service.NewScan{ID: scan, Kind: service.KindImport, Import: im}); err != nil {
		t.Fatal(err)
	}
	tail := inserted[len(inserted)-3:]
	if p, ok := tail[1].(*string); !ok || *p != "" || *tail[0].(*string) != "codeql" || *tail[2].(*string) != "gitlab-sast" {
		t.Fatal(inserted)
	}
	// Any other scan leaves all three NULL (scan_import_fields).
	if err := r.InsertScan(ctx, service.NewScan{ID: scan}); err != nil {
		t.Fatal(err)
	}
	for _, v := range inserted[len(inserted)-3:] {
		if p, _ := v.(*string); p != nil {
			t.Fatal(inserted)
		}
	}
}
