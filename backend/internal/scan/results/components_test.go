package results

import (
	"context"
	"strconv"
	"strings"
	"testing"
	"time"

	"github.com/google/uuid"

	"github.com/aupv9/warden/backend/internal/scan/sandbox"
	"github.com/aupv9/warden/backend/internal/scan/trivyjson"
	"github.com/aupv9/warden/backend/internal/worker/dbtest"
)

func pkg(eco, name, version, path string, licenses ...string) trivyjson.Package {
	return trivyjson.Package{Ecosystem: eco, Name: name, MatchName: strings.ToLower(name), Version: version, FilePath: path,
		Licenses: licenses, PURL: "pkg:npm/" + name + "@" + version}
}

// Rows that would break the component table's CHECKs (or hold NUL) are
// skipped and counted; duplicates of a key merge their licenses.
func TestComponentRows(t *testing.T) {
	long := strings.Repeat("é", 257)
	rows, skipped := componentRows([]trivyjson.Package{
		pkg("npm", "lodash", "4.17.21", "package-lock.json", "MIT"),
		pkg("npm", "lodash", "4.17.21", "package-lock.json", "MIT", "ISC"), // same key: merged
		pkg("npm", "lodash", "4.17.21", "web/package-lock.json"),           // another path: its own row
		pkg("bad eco", "x", "1", "p"),
		pkg("", "x", "1", "p"),
		pkg("npm", "", "1", "p"),
		pkg("npm", long, "1", "p"),
		pkg("npm", "x", strings.Repeat("1", 129), "p"),
		pkg("npm", "x", "1", strings.Repeat("a/", 1025)),
		pkg("npm", "nul\x00name", "1", "p"),
		pkg("npm", "bad-utf8\xff", "1", "p"),
		pkg("apk", "musl", "", "", "MIT", "", "bad\x00license"), // empty version and path are fine
	})
	if skipped != 8 || len(rows) != 3 {
		t.Fatalf("%d skipped, rows %v", skipped, rows)
	}
	if l := rows[0][6].([]string); len(l) != 2 || l[0] != "MIT" || l[1] != "ISC" {
		t.Fatalf("licenses %v", l)
	}
	if l := rows[1][6].([]string); l == nil || len(l) != 0 {
		t.Fatalf("no licenses must be an empty array, not NULL: %#v", l)
	}
	if rows[2][1] != "musl" || rows[2][3] != "" || rows[2][5] != "" || len(rows[2][6].([]string)) != 1 {
		t.Fatalf("%v", rows[2])
	}
	if p := rows[0][4].(*string); p == nil || *p != "pkg:npm/lodash@4.17.21" {
		t.Fatalf("purl %v", rows[0][4])
	}
	// An oversized purl is dropped, not the row.
	p := pkg("npm", "x", "1", "p")
	p.PURL = "pkg:npm/" + strings.Repeat("x", 600)
	if rows, _ := componentRows([]trivyjson.Package{p}); len(rows) != 1 || rows[0][4].(*string) != nil {
		t.Fatalf("%v", rows)
	}
}

func TestComponentRowsCap(t *testing.T) {
	pkgs := make([]trivyjson.Package, MaxComponents+5)
	for i := range pkgs {
		pkgs[i] = trivyjson.Package{Ecosystem: "npm", Name: "p", MatchName: "p", Version: strconv.Itoa(i), FilePath: "package-lock.json"}
	}
	rows, skipped := componentRows(pkgs)
	if len(rows) != MaxComponents || skipped != 5 {
		t.Fatalf("%d rows, %d skipped", len(rows), skipped)
	}
}

// The inventory needs COPY: a handle without it fails the processing (and
// so the transaction), never silently keeps a stale inventory.
func TestReplaceComponentsNeedsCopy(t *testing.T) {
	db := dbtest.New(t)
	_, err := replaceComponents(context.Background(), db, Input{ProjectID: uuid.New(), Packages: []trivyjson.Package{pkg("npm", "a", "1", "p")},
		Runs: []sandbox.ToolRun{{Tool: "trivy", Status: sandbox.Succeeded}}, Now: time.Now()})
	if err == nil || !strings.Contains(err.Error(), "COPY") {
		t.Fatal(err)
	}
	db.Done()
}
