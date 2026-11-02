package migrations

import (
	"io/fs"
	"testing"
)

func TestLatestIsTheHighestEmbeddedVersion(t *testing.T) {
	files, err := fs.Glob(sqlFiles, "sql/*.sql")
	if err != nil || len(files) == 0 {
		t.Fatal(files, err)
	}
	// Versions are numbered 1, 2, … without gaps.
	if got := Latest(); got != int64(len(files)) {
		t.Fatalf("Latest() = %d with %d migrations", got, len(files))
	}
}
