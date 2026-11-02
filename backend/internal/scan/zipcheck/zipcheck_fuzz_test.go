package zipcheck

import (
	"archive/zip"
	"bytes"
	"errors"
	"io/fs"
	"os"
	"path"
	"path/filepath"
	"strings"
	"testing"
)

// Fuzz limits: small, so one input stays well under a millisecond of I/O.
var fuzzLimits = Limits{MaxZipBytes: 1 << 16, MaxTotalBytes: 1 << 18, MaxEntries: 16}

// zipBytes builds an archive in memory. mode is the raw external attributes'
// high half (the Unix mode), as an attacker would write it.
func zipBytes(entries ...entry) []byte {
	var buf bytes.Buffer
	zw := zip.NewWriter(&buf)
	for _, e := range entries {
		h := &zip.FileHeader{Name: e.name, Method: zip.Deflate}
		if e.mode != 0 {
			h.SetMode(e.mode)
		}
		w, err := zw.CreateHeader(h)
		if err != nil {
			panic(err)
		}
		_, _ = w.Write(e.data)
	}
	_ = zw.Close()
	return buf.Bytes()
}

// checkExtract runs Extract on data in a fresh tree root/a/b/c/out and checks
// what it left on disk: nothing outside dest, only regular files and
// directories inside it, read-only on success, and the limits held.
func checkExtract(t *testing.T, data []byte) {
	t.Helper()
	root := t.TempDir()
	parent := filepath.Join(root, "a", "b", "c")
	if err := os.MkdirAll(parent, 0o755); err != nil {
		t.Fatal(err)
	}
	zp := filepath.Join(root, "in.zip")
	if err := os.WriteFile(zp, data, 0o600); err != nil {
		t.Fatal(err)
	}
	dest := filepath.Join(parent, "out")
	res, err := Extract(zp, dest, fuzzLimits)
	defer func() { _ = RemoveAll(dest) }()
	var rej *Rejected
	if err != nil && !errors.As(err, &rej) {
		t.Fatalf("error that isn't a *Rejected: %v", err)
	}

	// Nothing but in.zip and the a/b/c/out chain exists under root.
	want := map[string]bool{"in.zip": true, "a": true, "a/b": true, "a/b/c": true, "a/b/c/out": true}
	var files int
	var total int64
	_ = filepath.WalkDir(root, func(p string, d fs.DirEntry, werr error) error {
		if werr != nil {
			t.Fatalf("walk: %v", werr)
		}
		rel, _ := filepath.Rel(root, p)
		rel = filepath.ToSlash(rel)
		if rel == "." || want[rel] {
			return nil
		}
		if !strings.HasPrefix(rel, "a/b/c/out/") {
			t.Fatalf("written outside dest: %q", rel)
		}
		st, lerr := os.Lstat(p)
		if lerr != nil {
			t.Fatal(lerr)
		}
		switch {
		case st.IsDir():
			if err == nil && st.Mode().Perm() != 0o555 {
				t.Fatalf("%q: dir mode %v", rel, st.Mode())
			}
		case st.Mode().IsRegular():
			files++
			total += st.Size()
			if err == nil && st.Mode().Perm() != 0o444 {
				t.Fatalf("%q: file mode %v", rel, st.Mode())
			}
			for _, part := range strings.Split(strings.TrimPrefix(rel, "a/b/c/out/"), "/") {
				if part == ".." || strings.ContainsRune(part, 0) {
					t.Fatalf("unsafe name %q", rel)
				}
			}
		default:
			t.Fatalf("%q: not a regular file or directory (%v)", rel, st.Mode())
		}
		return nil
	})
	if err != nil {
		return
	}
	if res.Files != files || res.Files == 0 || res.Files > fuzzLimits.MaxEntries {
		t.Fatalf("Files=%d, %d on disk", res.Files, files)
	}
	if total > res.TotalBytes {
		t.Fatalf("%d bytes on disk, %d counted", total, res.TotalBytes)
	}
	if res.TotalBytes > fuzzLimits.MaxTotalBytes {
		t.Fatalf("TotalBytes %d over the limit", res.TotalBytes)
	}
	for safe := range res.Renamed {
		if _, err := os.Lstat(filepath.Join(dest, filepath.FromSlash(safe))); err != nil {
			t.Fatalf("renamed %q missing: %v", safe, err)
		}
	}
	if res.RootDir != "" && (strings.ContainsAny(res.RootDir, "/\\") || res.RootDir == ".." || path.Clean(res.RootDir) != res.RootDir) {
		t.Fatalf("RootDir %q", res.RootDir)
	}
}

// FuzzExtract mutates whole archives (headers, directory, data).
func FuzzExtract(f *testing.F) {
	seeds := [][]entry{
		{{name: "app-main/src/app.py", data: []byte("print(1)\n")}, {name: "app-main/README", data: []byte("x")}},
		{{name: "ok.py", data: []byte("1")}, {name: "../../etc/passwd", data: []byte("pwned")}},
		{{name: `a\..\..\x`, data: []byte("1")}},
		{{name: "lnk", data: []byte("/tmp"), mode: fs.ModeSymlink | 0o777}, {name: "lnk/pwned.txt", data: []byte("x")}},
		{{name: "a", data: []byte("1")}, {name: "a/b.py", data: []byte("2")}},
		{{name: "a.py", data: []byte("first")}, {name: "a.py", data: []byte("second")}},
		{{name: "node_modules/x/index.js", data: []byte("1")}, {name: "src/x.py", data: []byte("1")}},
		{{name: "bomb.txt", data: make([]byte, 1<<17)}},
		{{name: "inner.zip", data: zipBytes(entry{name: "x", data: []byte("y")})}},
		{{name: "caf\xe9.py", data: []byte("1")}, {name: "a\x1b[31m.py", data: []byte("1")}},
		{{name: "dev", data: nil, mode: fs.ModeDevice | 0o644}, {name: "d/", data: nil}, {name: "d/f", data: []byte{0, 1, 2}}},
	}
	for _, s := range seeds {
		f.Add(zipBytes(s...))
	}
	f.Add([]byte("PK\x03\x04"))
	f.Fuzz(func(t *testing.T, data []byte) {
		if len(data) > 8<<10 {
			return
		}
		checkExtract(t, data)
	})
}

// FuzzExtractNames keeps the archive well formed and fuzzes what matters for
// path safety: entry names, Unix modes and the order of entries.
func FuzzExtractNames(f *testing.F) {
	f.Add("ok.py", uint32(0), "../../etc/passwd", uint32(0), []byte("x"))
	f.Add("lnk", uint32(fs.ModeSymlink|0o777), "lnk/pwned", uint32(0), []byte("/tmp"))
	f.Add("/etc/passwd", uint32(0), `C:\Windows\x`, uint32(0), []byte("x"))
	f.Add("a/./b/../../../x", uint32(0), "a//b", uint32(0), []byte("x"))
	f.Add("dir/", uint32(fs.ModeDir|0o755), "dir", uint32(0), []byte("x"))
	f.Add("caf\xe9/../x", uint32(0), "a\x00b", uint32(0), []byte("x"))
	f.Add("x/\u202e/y", uint32(0), "x/\u202e/y", uint32(0), []byte("x"))
	f.Fuzz(func(t *testing.T, name1 string, mode1 uint32, name2 string, mode2 uint32, data []byte) {
		if len(name1)+len(name2)+len(data) > 4096 {
			return
		}
		checkExtract(t, zipBytes(
			entry{name: name1, data: data, mode: fs.FileMode(mode1)},
			entry{name: name2, data: data, mode: fs.FileMode(mode2)},
			entry{name: "keep.txt", data: []byte("k")},
		))
	})
}
