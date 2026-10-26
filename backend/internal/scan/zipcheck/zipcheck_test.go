package zipcheck

import (
	"archive/zip"
	"bytes"
	"crypto/rand"
	"crypto/sha256"
	"encoding/binary"
	"encoding/hex"
	"errors"
	"fmt"
	"io/fs"
	"os"
	"path/filepath"
	"strings"
	"testing"
)

type entry struct {
	name string
	data []byte
	mode fs.FileMode // 0 = regular file
}

func makeZip(t *testing.T, entries ...entry) string {
	t.Helper()
	var buf bytes.Buffer
	zw := zip.NewWriter(&buf)
	for _, e := range entries {
		h := &zip.FileHeader{Name: e.name, Method: zip.Deflate}
		if e.mode != 0 {
			h.SetMode(e.mode)
		}
		w, err := zw.CreateHeader(h)
		if err != nil {
			t.Fatal(err)
		}
		if _, err := w.Write(e.data); err != nil {
			t.Fatal(err)
		}
	}
	if err := zw.Close(); err != nil {
		t.Fatal(err)
	}
	return writeFile(t, buf.Bytes())
}

func writeFile(t *testing.T, data []byte) string {
	t.Helper()
	p := filepath.Join(t.TempDir(), "a.zip")
	if err := os.WriteFile(p, data, 0o600); err != nil {
		t.Fatal(err)
	}
	return p
}

func patchFile(t *testing.T, p string, fn func([]byte) []byte) {
	t.Helper()
	data, err := os.ReadFile(p)
	if err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(p, fn(data), 0o600); err != nil {
		t.Fatal(err)
	}
}

func randBytes(n int) []byte {
	b := make([]byte, n)
	_, _ = rand.Read(b)
	return b
}

func outDir(t *testing.T) string {
	t.Helper()
	d := filepath.Join(t.TempDir(), "out")
	t.Cleanup(func() { MakeWritable(d) })
	return d
}

func extract(t *testing.T, zp string, limits ...Limits) (*Result, string) {
	t.Helper()
	l := DefaultLimits()
	if len(limits) > 0 {
		l = limits[0]
	}
	out := outDir(t)
	res, err := Extract(zp, out, l)
	if err != nil {
		t.Fatalf("extract: %v", err)
	}
	return res, out
}

func rejected(t *testing.T, zp string, limits ...Limits) string {
	t.Helper()
	l := DefaultLimits()
	if len(limits) > 0 {
		l = limits[0]
	}
	_, err := Extract(zp, outDir(t), l)
	var r *Rejected
	if !errors.As(err, &r) {
		t.Fatalf("want *Rejected, got %v", err)
	}
	return r.Code
}

func hasWarning(res *Result, sub string) bool {
	for _, w := range res.Warnings {
		if strings.Contains(w, sub) {
			return true
		}
	}
	return false
}

func TestValidZipExtractsReadOnly(t *testing.T) {
	zp := makeZip(t, entry{name: "app-main/src/app.py", data: []byte("print(1)\n")}, entry{name: "app-main/README", data: []byte("x")})
	res, out := extract(t, zp)
	if res.Files != 2 || res.RootDir != "app-main" {
		t.Fatalf("files=%d root=%q", res.Files, res.RootDir)
	}
	f := filepath.Join(out, "app-main/src/app.py")
	if b, _ := os.ReadFile(f); string(b) != "print(1)\n" {
		t.Fatalf("content %q", b)
	}
	if st, _ := os.Stat(f); st.Mode().Perm() != 0o444 {
		t.Fatalf("file mode %v", st.Mode().Perm())
	}
	if st, _ := os.Stat(filepath.Join(out, "app-main/src")); st.Mode().Perm() != 0o555 {
		t.Fatalf("dir mode %v", st.Mode().Perm())
	}
}

func TestPathTraversal(t *testing.T) {
	for _, name := range []string{
		"../../etc/passwd", "a/../../x", "/etc/passwd", "C:/Windows/x", `C:\evil`, `..\..\x`, `a\..\..\x`,
	} {
		t.Run(name, func(t *testing.T) {
			zp := makeZip(t, entry{name: "ok.py", data: []byte("1")}, entry{name: name, data: []byte("pwned")})
			if code := rejected(t, zp); code != "ZIP_PATH_TRAVERSAL" {
				t.Fatalf("code %s", code)
			}
			if _, err := os.Stat(filepath.Join(filepath.Dir(zp), "etc")); err == nil {
				t.Fatal("file written outside dest")
			}
		})
	}
}

func TestPathTooDeepOrTooLong(t *testing.T) {
	for _, name := range []string{strings.Repeat("d/", 51) + "f.py", strings.Repeat("a", 1025)} {
		if code := rejected(t, makeZip(t, entry{name: name, data: []byte("1")})); code != "ZIP_PATH_TRAVERSAL" {
			t.Fatalf("code %s", code)
		}
	}
}

func TestNULInName(t *testing.T) {
	zp := makeZip(t, entry{name: "aXb.py", data: []byte("1")})
	patchFile(t, zp, func(b []byte) []byte { return bytes.ReplaceAll(b, []byte("aXb.py"), []byte("a\x00b.py")) })
	if code := rejected(t, zp); code != "ZIP_PATH_TRAVERSAL" {
		t.Fatalf("code %s", code)
	}
}

func TestNotAZip(t *testing.T) {
	if code := rejected(t, writeFile(t, []byte("\x7fELF not a zip"))); code != "ZIP_INVALID" {
		t.Fatalf("code %s", code)
	}
}

func TestTruncatedZip(t *testing.T) {
	zp := makeZip(t, entry{name: "a.py", data: bytes.Repeat([]byte("x"), 1000)})
	patchFile(t, zp, func(b []byte) []byte { return b[:len(b)/2] })
	if code := rejected(t, zp); code != "ZIP_INVALID" {
		t.Fatalf("code %s", code)
	}
}

func TestCorruptDataFailsCRC(t *testing.T) {
	data := randBytes(50_000)
	var buf bytes.Buffer
	zw := zip.NewWriter(&buf)
	w, _ := zw.CreateHeader(&zip.FileHeader{Name: "a.bin", Method: zip.Store})
	_, _ = w.Write(data)
	_ = zw.Close()
	raw := buf.Bytes()
	raw[30+len("a.bin")+100] ^= 0xff // flip a byte inside the stored payload
	if code := rejected(t, writeFile(t, raw)); code != "ZIP_INVALID" {
		t.Fatalf("code %s", code)
	}
}

func TestTooLarge(t *testing.T) {
	zp := makeZip(t, entry{name: "a.py", data: randBytes(4096)})
	l := DefaultLimits()
	l.MaxZipBytes = 1024
	if code := rejected(t, zp, l); code != "ZIP_TOO_LARGE" {
		t.Fatalf("code %s", code)
	}
}

func TestTooManyFiles(t *testing.T) {
	var es []entry
	for i := range 11 {
		es = append(es, entry{name: fmt.Sprintf("f%d.py", i), data: []byte("1")})
	}
	l := DefaultLimits()
	l.MaxEntries = 10
	if code := rejected(t, makeZip(t, es...), l); code != "ZIP_TOO_MANY_FILES" {
		t.Fatalf("code %s", code)
	}
}

func TestRatioBomb(t *testing.T) {
	zp := makeZip(t, entry{name: "bomb.txt", data: make([]byte, 8<<20)})
	if code := rejected(t, zp); code != "ZIP_BOMB" {
		t.Fatalf("code %s", code)
	}
}

func TestTotalSizeBombCountsRealBytes(t *testing.T) {
	var es []entry
	for i := range 4 {
		es = append(es, entry{name: fmt.Sprintf("f%d.txt", i), data: randBytes(300_000)})
	}
	l := DefaultLimits()
	l.MaxTotalBytes = 1_000_000
	if code := rejected(t, makeZip(t, es...), l); code != "ZIP_BOMB" {
		t.Fatalf("code %s", code)
	}
}

// The central directory claims 1 byte; the real entry is 200 kB. Neither the
// limit nor the size check may trust the header.
func TestLyingHeaderSizesDoNotBypassLimit(t *testing.T) {
	zp := makeZip(t, entry{name: "a.txt", data: randBytes(200_000)})
	patchFile(t, zp, func(b []byte) []byte {
		cd := bytes.Index(b, []byte("PK\x01\x02"))
		binary.LittleEndian.PutUint32(b[cd+24:], 1)
		return b
	})
	l := DefaultLimits()
	l.MaxTotalBytes = 100_000
	rejected(t, zp, l)
}

func TestEncrypted(t *testing.T) {
	zp := makeZip(t, entry{name: "a.py", data: []byte("secret")})
	patchFile(t, zp, func(b []byte) []byte {
		for _, sig := range []struct {
			magic string
			off   int
		}{{"PK\x03\x04", 6}, {"PK\x01\x02", 8}} {
			i := bytes.Index(b, []byte(sig.magic))
			flags := binary.LittleEndian.Uint16(b[i+sig.off:])
			binary.LittleEndian.PutUint16(b[i+sig.off:], flags|0x1)
		}
		return b
	})
	if code := rejected(t, zp); code != "ZIP_ENCRYPTED" {
		t.Fatalf("code %s", code)
	}
}

func TestEmptyAfterFiltering(t *testing.T) {
	zp := makeZip(t, entry{name: "node_modules/x/index.js", data: []byte("1")}, entry{name: ".git/config", data: []byte("1")})
	if code := rejected(t, zp); code != "ZIP_EMPTY" {
		t.Fatalf("code %s", code)
	}
}

func TestSymlinkSkipped(t *testing.T) {
	zp := makeZip(t, entry{name: "ok.py", data: []byte("1")}, entry{name: "evil", data: []byte("/etc/passwd"), mode: fs.ModeSymlink | 0o777})
	res, out := extract(t, zp)
	if _, err := os.Lstat(filepath.Join(out, "evil")); err == nil {
		t.Fatal("symlink extracted")
	}
	if !hasWarning(res, "symlink") {
		t.Fatal(res.Warnings)
	}
}

// A symlink entry followed by a file "through" it must not write outside dest.
func TestSymlinkThenFileThroughIt(t *testing.T) {
	zp := makeZip(t,
		entry{name: "lnk", data: []byte("/tmp"), mode: fs.ModeSymlink | 0o777},
		entry{name: "lnk/pwned.txt", data: []byte("x")},
	)
	res, out := extract(t, zp)
	if st, err := os.Lstat(filepath.Join(out, "lnk")); err != nil || !st.IsDir() {
		t.Fatalf("lnk should be a real directory: %v", err)
	}
	if res.Files != 1 {
		t.Fatalf("files=%d", res.Files)
	}
}

func TestSkipDependencyDirs(t *testing.T) {
	zp := makeZip(t,
		entry{name: "app/main.py", data: []byte("1")},
		entry{name: "app/node_modules/x.js", data: []byte("1")},
		entry{name: "app/vendor/y.go", data: []byte("1")},
		entry{name: "app/.venv/z.py", data: []byte("1")},
		entry{name: "app/package-lock.json", data: []byte("{}")},
	)
	res, out := extract(t, zp)
	if res.Files != 2 {
		t.Fatalf("files=%d", res.Files)
	}
	if _, err := os.Stat(filepath.Join(out, "app/node_modules")); err == nil {
		t.Fatal("node_modules extracted")
	}
}

func TestLargeBinarySkipped(t *testing.T) {
	blob := append([]byte{0, 1, 2}, randBytes(6<<20)...)
	res, out := extract(t, makeZip(t, entry{name: "main.py", data: []byte("1")}, entry{name: "big.bin", data: blob}))
	if _, err := os.Stat(filepath.Join(out, "big.bin")); err == nil {
		t.Fatal("binary kept")
	}
	if !hasWarning(res, "binary") {
		t.Fatal(res.Warnings)
	}
}

func TestNestedZipNotExtracted(t *testing.T) {
	var inner bytes.Buffer
	zw := zip.NewWriter(&inner)
	w, _ := zw.Create("inner.py")
	_, _ = w.Write([]byte("1"))
	_ = zw.Close()
	res, out := extract(t, makeZip(t, entry{name: "main.py", data: []byte("1")}, entry{name: "lib.zip", data: inner.Bytes()}))
	if _, err := os.Stat(filepath.Join(out, "inner.py")); err == nil {
		t.Fatal("nested zip extracted")
	}
	if !hasWarning(res, "nested") {
		t.Fatal(res.Warnings)
	}
}

func TestDuplicateEntriesDoNotOverwrite(t *testing.T) {
	res, out := extract(t, makeZip(t, entry{name: "a.py", data: []byte("first")}, entry{name: "a.py", data: []byte("second")}))
	if b, _ := os.ReadFile(filepath.Join(out, "a.py")); string(b) != "first" {
		t.Fatalf("content %q", b)
	}
	if !hasWarning(res, "duplicate") {
		t.Fatal(res.Warnings)
	}
}

func TestFileThenDirSameNameIsConflict(t *testing.T) {
	zp := makeZip(t, entry{name: "a", data: []byte("1")}, entry{name: "a/b.py", data: []byte("2")})
	if code := rejected(t, zp); code != "ZIP_PATH_TRAVERSAL" {
		t.Fatalf("code %s", code)
	}
}

func TestNonUTF8NameRenamed(t *testing.T) {
	zp := makeZip(t, entry{name: "cafX.py", data: []byte("1")})
	patchFile(t, zp, func(b []byte) []byte { return bytes.ReplaceAll(b, []byte("cafX.py"), []byte("caf\xe9.py")) })
	res, out := extract(t, zp)
	if res.Files != 1 || len(res.Renamed) != 1 {
		t.Fatalf("files=%d renamed=%v", res.Files, res.Renamed)
	}
	for safe, original := range res.Renamed {
		if original != "cafΘ.py" { // 0xE9 in CP437
			t.Fatalf("original %q", original)
		}
		if !strings.HasPrefix(safe, "caf_.py.") {
			t.Fatalf("safe %q", safe)
		}
		if _, err := os.Stat(filepath.Join(out, safe)); err != nil {
			t.Fatal(err)
		}
	}
}

func TestControlCharNameRenamed(t *testing.T) {
	res, _ := extract(t, makeZip(t, entry{name: "a\x1b[31m.py", data: []byte("1")}))
	if len(res.Renamed) != 1 {
		t.Fatalf("renamed=%v", res.Renamed)
	}
}

func TestDestMustNotExist(t *testing.T) {
	zp := makeZip(t, entry{name: "a.py", data: []byte("1")})
	if _, err := Extract(zp, t.TempDir(), DefaultLimits()); err == nil {
		t.Fatal("extracted into existing dir")
	}
}

func TestChecksum(t *testing.T) {
	zp := makeZip(t, entry{name: "a.py", data: []byte("1")})
	data, _ := os.ReadFile(zp)
	sum := sha256.Sum256(data)
	if err := VerifyChecksum(zp, strings.ToUpper(hex.EncodeToString(sum[:]))); err != nil {
		t.Fatal(err)
	}
	err := VerifyChecksum(zp, strings.Repeat("0", 64))
	var r *Rejected
	if !errors.As(err, &r) || r.Code != "CHECKSUM_MISMATCH" {
		t.Fatalf("got %v", err)
	}
}

func TestRemoveAllHandlesReadOnlyTree(t *testing.T) {
	zp := makeZip(t, entry{name: "a/b/c.py", data: []byte("1")})
	root := filepath.Join(t.TempDir(), "scan")
	_ = os.Mkdir(root, 0o700)
	if _, err := Extract(zp, filepath.Join(root, "src"), DefaultLimits()); err != nil {
		t.Fatal(err)
	}
	if err := RemoveAll(root); err != nil {
		t.Fatal(err)
	}
	if _, err := os.Stat(root); err == nil {
		t.Fatal("not removed")
	}
}
