package sandboxio

import (
	"archive/tar"
	"bytes"
	"io/fs"
	"os"
	"path/filepath"
	"strings"
	"testing"
)

func seedStreams(f *testing.F) {
	f.Add(tarOf(f, entry{name: "src/", typ: tar.TypeDir}, entry{name: "src/a.go", body: "package a"}))
	f.Add(tarOf(f, entry{name: "result.sarif", body: "{}"}, entry{name: "trivy.json", body: "[]"}))
	f.Add(tarOf(f, entry{name: "../evil", body: "x"}))
	f.Add(tarOf(f, entry{name: "l", typ: tar.TypeSymlink, linkname: "/etc"}, entry{name: "l/x", body: "x"}))
	f.Add(tarOf(f, entry{name: "h", typ: tar.TypeLink, linkname: "/etc/passwd"}))
	f.Add(tarOf(f, entry{name: "a", body: "1"}, entry{name: "a", body: "2"}))
	f.Add(tarOf(f, entry{name: "a", body: "x", pax: map[string]string{"path": "../../b"}}))
	f.Add([]byte{})
}

// checkTree asserts what any stream may leave in dir: only regular files and
// directories, nothing beside dir in parent, totals within l and, with
// l.Files, only those names, top-level, each within its cap.
func checkTree(t *testing.T, parent, dir string, l Limits) {
	t.Helper()
	assertContained(t, parent, dir)
	var total int64
	entries := 0
	err := filepath.WalkDir(dir, func(p string, d fs.DirEntry, err error) error {
		if err != nil || p == dir {
			return err
		}
		entries++
		rel, _ := filepath.Rel(dir, p)
		if d.IsDir() {
			if l.Files != nil {
				t.Fatalf("directory %q with Files set", rel)
			}
			return nil
		}
		fi, err := d.Info()
		if err != nil {
			return err
		}
		total += fi.Size()
		if l.Files != nil {
			limit, ok := l.Files[rel]
			if !ok || strings.ContainsRune(rel, filepath.Separator) {
				t.Fatalf("unexpected file %q", rel)
			}
			if fi.Size() > limit {
				t.Fatalf("%q: %d bytes over its cap %d", rel, fi.Size(), limit)
			}
		}
		return nil
	})
	if err != nil {
		t.Fatal(err)
	}
	if total > l.MaxBytes {
		t.Fatalf("wrote %d bytes, limit %d", total, l.MaxBytes)
	}
	// Directories made as parents of a file aren't entries of the stream,
	// but each needs a file (an entry) below it, so depth bounds them.
	if entries > l.MaxEntries*(1+50) {
		t.Fatalf("%d entries for a limit of %d", entries, l.MaxEntries)
	}
}

// FuzzReceive: whatever the stream (the worker's input direction), nothing
// leaves the target and the limits hold.
func FuzzReceive(f *testing.F) {
	seedStreams(f)
	f.Fuzz(func(t *testing.T, data []byte) {
		parent := t.TempDir()
		dir := filepath.Join(parent, "in")
		if err := os.Mkdir(dir, 0o755); err != nil {
			t.Fatal(err)
		}
		l := Limits{MaxBytes: 4096, MaxEntries: 8}
		_, _ = Receive(bytes.NewReader(data), dir, l)
		checkTree(t, parent, dir, l)
	})
}

// FuzzReceiveResults: a Pod's /out coming back to the worker. Only the named
// files, each within its cap, ever reach the worker's disk.
func FuzzReceiveResults(f *testing.F) {
	seedStreams(f)
	f.Fuzz(func(t *testing.T, data []byte) {
		parent := t.TempDir()
		dir := filepath.Join(parent, "out")
		if err := os.Mkdir(dir, 0o700); err != nil {
			t.Fatal(err)
		}
		l := Limits{MaxBytes: 3000, MaxEntries: 2, Files: map[string]int64{"result.sarif": 2048, "trivy.json": 64}}
		st, err := Receive(bytes.NewReader(data), dir, l)
		checkTree(t, parent, dir, l)
		if err == nil && (st.Dirs != 0 || st.Files > 2) {
			t.Fatalf("accepted %+v", st)
		}
	})
}

// FuzzSendFiles: the Pod's direction. Whatever /out holds (files of any size
// and name, symlinks), SendFiles sends only the named regular files within
// their caps, and the worker's Receive accepts exactly that.
func FuzzSendFiles(f *testing.F) {
	f.Add("result.sarif", []byte("{}"), "trivy.json", int64(10), true)
	f.Add("result.sarif", bytes.Repeat([]byte("x"), 100), "../x", int64(-1), false)
	f.Add("a", []byte(""), "b", int64(0), true)
	f.Fuzz(func(t *testing.T, name string, body []byte, other string, cap int64, link bool) {
		out := t.TempDir()
		if c, err := cleanName(name); err != nil || c != name || name == "" || strings.Contains(name, "/") {
			t.Skip()
		}
		if err := os.WriteFile(filepath.Join(out, name), body, 0o644); err != nil {
			t.Skip() // a name the file system can't hold
		}
		if link && other != "" && !strings.Contains(other, "/") && other != "." && other != ".." {
			_ = os.Symlink("/etc/passwd", filepath.Join(out, other))
		}
		caps := map[string]int64{name: max(cap, 0)}
		// Not a case variant: on a case-insensitive file system (macOS) it
		// would name the same file.
		if other != "" && !strings.EqualFold(other, name) {
			caps[other] = 1 << 20
		}
		var buf bytes.Buffer
		st, err := SendFiles(&buf, out, caps)
		if err != nil {
			return // a bad name in caps
		}
		if st.Files > 1 {
			t.Fatalf("sent %d files; only %q is a regular file", st.Files, name)
		}
		wantSent := int64(len(body)) <= max(cap, 0)
		if (st.Files == 1) != wantSent {
			t.Fatalf("sent %+v for a %d byte file under cap %d", st, len(body), cap)
		}
		parent := t.TempDir()
		dir := filepath.Join(parent, "got")
		if err := os.Mkdir(dir, 0o700); err != nil {
			t.Fatal(err)
		}
		l := Limits{MaxBytes: 2 << 20, MaxEntries: len(caps), Files: caps}
		got, err := Receive(&buf, dir, l)
		if err != nil {
			t.Fatalf("own stream refused: %v", err)
		}
		if got.Files != st.Files || got.Bytes != st.Bytes {
			t.Fatalf("received %+v, sent %+v", got, st)
		}
		checkTree(t, parent, dir, l)
	})
}
