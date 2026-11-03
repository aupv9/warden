package sandboxio

import (
	"archive/tar"
	"bytes"
	"errors"
	"io"
	"io/fs"
	"os"
	"path/filepath"
	"slices"
	"strings"
	"testing"
)

type entry struct {
	name     string
	typ      byte
	body     string
	size     int64 // header size when it should differ from len(body)
	linkname string
	pax      map[string]string
}

func tarOf(t testing.TB, es ...entry) []byte {
	t.Helper()
	var buf bytes.Buffer
	tw := tar.NewWriter(&buf)
	for _, e := range es {
		typ := e.typ
		if typ == 0 {
			typ = tar.TypeReg
		}
		size := int64(len(e.body))
		if e.size != 0 {
			size = e.size
		}
		if typ != tar.TypeReg {
			size = 0
		}
		h := &tar.Header{Name: e.name, Typeflag: typ, Size: size, Mode: 0o644, Linkname: e.linkname, PAXRecords: e.pax}
		if typ == tar.TypeChar || typ == tar.TypeBlock {
			h.Devmajor, h.Devminor = 1, 3
		}
		if err := tw.WriteHeader(h); err != nil {
			t.Fatal(err)
		}
		if typ == tar.TypeReg && e.body != "" {
			if _, err := io.WriteString(tw, e.body); err != nil && e.size == 0 {
				t.Fatal(err)
			}
		}
	}
	if err := tw.Close(); err != nil && !errors.Is(err, tar.ErrWriteTooLong) {
		// A deliberately short entry makes Close complain; the bytes are what matter.
		_ = err
	}
	return buf.Bytes()
}

var roomy = Limits{MaxBytes: 1 << 20, MaxEntries: 100}

// receiveIn extracts into a fresh dir inside a parent, so an escape would be
// visible as something next to dir.
func receiveIn(t *testing.T, data []byte, l Limits) (string, Stats, error) {
	t.Helper()
	parent := t.TempDir()
	dir := filepath.Join(parent, "dest")
	if err := os.Mkdir(dir, 0o755); err != nil {
		t.Fatal(err)
	}
	st, err := Receive(bytes.NewReader(data), dir, l)
	assertContained(t, parent, dir)
	return dir, st, err
}

// assertContained: parent holds only dir, and dir holds only regular files
// and directories.
func assertContained(t testing.TB, parent, dir string) {
	t.Helper()
	ents, err := os.ReadDir(parent)
	if err != nil {
		t.Fatal(err)
	}
	if len(ents) != 1 || ents[0].Name() != filepath.Base(dir) {
		var names []string
		for _, e := range ents {
			names = append(names, e.Name())
		}
		t.Fatalf("something escaped next to the target: %v", names)
	}
	err = filepath.WalkDir(dir, func(p string, d fs.DirEntry, err error) error {
		if err != nil {
			return err
		}
		if !d.IsDir() && !d.Type().IsRegular() {
			t.Fatalf("non-regular entry %s (%v)", p, d.Type())
		}
		return nil
	})
	if err != nil {
		t.Fatal(err)
	}
}

func code(err error) string {
	var r *Rejected
	if errors.As(err, &r) {
		return r.Code
	}
	if err == nil {
		return ""
	}
	return "error: " + err.Error()
}

func TestReceiveTree(t *testing.T) {
	data := tarOf(t,
		entry{name: "src/", typ: tar.TypeDir},
		entry{name: "src/a/b.txt", body: "hello"},
		entry{name: "./src/c.txt", body: "x"},
		entry{name: "secrets/hmac", body: "key"},
		entry{name: "empty/", typ: tar.TypeDir},
	)
	dir, st, err := receiveIn(t, data, roomy)
	if err != nil {
		t.Fatal(err)
	}
	if st.Files != 3 || st.Bytes != 9 || st.Dirs != 2 {
		t.Fatalf("stats %+v", st)
	}
	b, err := os.ReadFile(filepath.Join(dir, "src/a/b.txt"))
	if err != nil || string(b) != "hello" {
		t.Fatalf("b.txt = %q, %v", b, err)
	}
	if fi, err := os.Stat(filepath.Join(dir, "empty")); err != nil || !fi.IsDir() {
		t.Fatal("empty dir missing")
	}
}

// A directory that already exists (a volume's mount point) is kept.
func TestReceiveIntoExistingDirectories(t *testing.T) {
	parent := t.TempDir()
	dir := filepath.Join(parent, "in")
	if err := os.MkdirAll(filepath.Join(dir, "src"), 0o755); err != nil {
		t.Fatal(err)
	}
	data := tarOf(t, entry{name: "src/", typ: tar.TypeDir}, entry{name: "src/f", body: "1"})
	if _, err := Receive(bytes.NewReader(data), dir, roomy); err != nil {
		t.Fatal(err)
	}
}

func TestReceiveAttacks(t *testing.T) {
	big := strings.Repeat("A", 2048)
	for _, c := range []struct {
		name string
		data func(t *testing.T) []byte
		lim  Limits
		want string
	}{
		{"dot-dot traversal", func(t *testing.T) []byte { return tarOf(t, entry{name: "../evil", body: "x"}) }, roomy, "IO_PATH"},
		{"nested traversal", func(t *testing.T) []byte { return tarOf(t, entry{name: "a/../../evil", body: "x"}) }, roomy, "IO_PATH"},
		{"absolute path", func(t *testing.T) []byte { return tarOf(t, entry{name: "/etc/passwd", body: "x"}) }, roomy, "IO_PATH"},
		{"backslash", func(t *testing.T) []byte { return tarOf(t, entry{name: `..\evil`, body: "x"}) }, roomy, "IO_PATH"},
		{"long component", func(t *testing.T) []byte { return tarOf(t, entry{name: strings.Repeat("n", 256), body: "x"}) }, roomy, "IO_PATH"},
		{"long path", func(t *testing.T) []byte { return tarOf(t, entry{name: strings.Repeat("d/", 600) + "f", body: "x"}) }, roomy, "IO_PATH"},
		{"symlink", func(t *testing.T) []byte {
			return tarOf(t, entry{name: "link", typ: tar.TypeSymlink, linkname: "/etc"})
		}, roomy, "IO_TYPE"},
		{"symlink then write through it", func(t *testing.T) []byte {
			return tarOf(t, entry{name: "link", typ: tar.TypeSymlink, linkname: ".."}, entry{name: "link/evil", body: "x"})
		}, roomy, "IO_TYPE"},
		{"hard link", func(t *testing.T) []byte {
			return tarOf(t, entry{name: "f", body: "x"}, entry{name: "h", typ: tar.TypeLink, linkname: "/etc/shadow"})
		}, roomy, "IO_TYPE"},
		{"char device", func(t *testing.T) []byte { return tarOf(t, entry{name: "null", typ: tar.TypeChar}) }, roomy, "IO_TYPE"},
		{"block device", func(t *testing.T) []byte { return tarOf(t, entry{name: "sda", typ: tar.TypeBlock}) }, roomy, "IO_TYPE"},
		{"fifo", func(t *testing.T) []byte { return tarOf(t, entry{name: "p", typ: tar.TypeFifo}) }, roomy, "IO_TYPE"},
		{"duplicate file", func(t *testing.T) []byte {
			return tarOf(t, entry{name: "f", body: "1"}, entry{name: "./f", body: "2"})
		}, roomy, "IO_DUPLICATE"},
		{"duplicate dir", func(t *testing.T) []byte {
			return tarOf(t, entry{name: "d/", typ: tar.TypeDir}, entry{name: "d", typ: tar.TypeDir})
		}, roomy, "IO_DUPLICATE"},
		{"file then dir of the same name", func(t *testing.T) []byte {
			return tarOf(t, entry{name: "x", body: "1"}, entry{name: "x/y", body: "2"})
		}, roomy, "IO_PATH"},
		{"oversize total", func(t *testing.T) []byte {
			return tarOf(t, entry{name: "a", body: big}, entry{name: "b", body: big})
		}, Limits{MaxBytes: 3000, MaxEntries: 10}, "IO_TOO_LARGE"},
		{"oversize single", func(t *testing.T) []byte { return tarOf(t, entry{name: "a", body: big}) }, Limits{MaxBytes: 100, MaxEntries: 10}, "IO_TOO_LARGE"},
		{"too many files", func(t *testing.T) []byte {
			var es []entry
			for i := range 5 {
				es = append(es, entry{name: string(rune('a' + i)), body: "x"})
			}
			return tarOf(t, es...)
		}, Limits{MaxBytes: 100, MaxEntries: 4}, "IO_TOO_MANY"},
		{"too many dirs", func(t *testing.T) []byte {
			var es []entry
			for i := range 5 {
				es = append(es, entry{name: string(rune('a'+i)) + "/", typ: tar.TypeDir})
			}
			return tarOf(t, es...)
		}, Limits{MaxBytes: 100, MaxEntries: 4}, "IO_TOO_MANY"},
		{"truncated entry", func(t *testing.T) []byte {
			b := tarOf(t, entry{name: "a", body: big})
			return b[:512+100]
		}, roomy, "IO_INVALID"},
		{"garbage", func(t *testing.T) []byte { return bytes.Repeat([]byte{0xff}, 1024) }, roomy, "IO_INVALID"},
	} {
		t.Run(c.name, func(t *testing.T) {
			_, _, err := receiveIn(t, c.data(t), c.lim)
			if err == nil {
				t.Fatal("accepted")
			}
			if c.want != "" && code(err) != c.want {
				t.Fatalf("got %v, want %s", err, c.want)
			}
		})
	}
}

// A stream of framing alone (PAX records) can't run on forever.
func TestReceiveBoundsFraming(t *testing.T) {
	var es []entry
	for i := range 4 {
		es = append(es, entry{name: string(rune('a' + i)), body: "x",
			pax: map[string]string{"comment": strings.Repeat("c", 900<<10)}})
	}
	data := tarOf(t, es...)
	// 4 entries of ~900 KiB framing each, but a budget for 1.
	_, _, err := receiveIn(t, data, Limits{MaxBytes: 10, MaxEntries: 0})
	if err == nil {
		t.Fatal("accepted")
	}
	if code(err) != "IO_TOO_LARGE" && code(err) != "IO_TOO_MANY" {
		t.Fatalf("got %v", err)
	}
	r := &limitedReader{r: bytes.NewReader(data), n: 1024}
	if _, err := io.Copy(io.Discard, r); err == nil {
		t.Fatal("limitedReader didn't stop")
	}
}

func TestReceiveFilesMode(t *testing.T) {
	files := Limits{MaxBytes: 300, MaxEntries: 2, Files: map[string]int64{"result.sarif": 200, "trivy.json": 100}}
	ok := tarOf(t, entry{name: "result.sarif", body: "{}"}, entry{name: "trivy.json", body: "[]"})
	dir, _, err := receiveIn(t, ok, files)
	if err != nil {
		t.Fatal(err)
	}
	if names, _ := FileNames(dir); !slices.Equal(names, []string{"result.sarif", "trivy.json"}) {
		t.Fatalf("files %v", names)
	}
	for _, c := range []struct {
		name string
		es   []entry
		want string
	}{
		{"unexpected name", []entry{{name: "raw.sarif", body: "secret"}}, "IO_UNEXPECTED"},
		{"nested name", []entry{{name: "x/result.sarif", body: "{}"}}, "IO_UNEXPECTED"},
		{"directory", []entry{{name: "d/", typ: tar.TypeDir}}, "IO_UNEXPECTED"},
		{"over its cap", []entry{{name: "trivy.json", body: strings.Repeat("x", 101)}}, "IO_TOO_LARGE"},
		{"symlink to a host file", []entry{{name: "result.sarif", typ: tar.TypeSymlink, linkname: "/etc/passwd"}}, "IO_TYPE"},
		{"hard link", []entry{{name: "result.sarif", typ: tar.TypeLink, linkname: "/etc/passwd"}}, "IO_TYPE"},
		{"duplicate", []entry{{name: "result.sarif", body: "{}"}, {name: "result.sarif", body: "{}"}}, "IO_DUPLICATE"},
		{"traversal", []entry{{name: "../result.sarif", body: "{}"}}, "IO_PATH"},
	} {
		t.Run(c.name, func(t *testing.T) {
			_, _, err := receiveIn(t, tarOf(t, c.es...), files)
			if code(err) != c.want {
				t.Fatalf("got %v, want %s", err, c.want)
			}
		})
	}
}

func TestSendTreeRoundTrip(t *testing.T) {
	root := t.TempDir()
	must(t, os.MkdirAll(filepath.Join(root, "src/a/b"), 0o755))
	must(t, os.WriteFile(filepath.Join(root, "src/a/b/f.go"), []byte("package b"), 0o444))
	must(t, os.WriteFile(filepath.Join(root, "src/top"), nil, 0o444))
	must(t, os.Symlink("/etc/passwd", filepath.Join(root, "src/link")))
	must(t, os.MkdirAll(filepath.Join(root, "secrets"), 0o700))
	must(t, os.WriteFile(filepath.Join(root, "secrets/hmac"), []byte("k"), 0o400))
	must(t, os.WriteFile(filepath.Join(root, "secrets/other"), []byte("not sent"), 0o400))

	plan, disk, err := Plan(root, []string{"src", "secrets/hmac"})
	if err != nil {
		t.Fatal(err)
	}
	if plan.Files != 3 || plan.Bytes != 10 || disk < 3*4096 {
		t.Fatalf("plan %+v disk %d", plan, disk)
	}
	var buf bytes.Buffer
	st, skipped, err := SendTree(&buf, root, []string{"src", "secrets/hmac"}, Limits{MaxBytes: plan.Bytes, MaxEntries: plan.Entries()})
	if err != nil {
		t.Fatal(err)
	}
	if skipped != 1 || st.Files != 3 || st.Bytes != plan.Bytes || st.Entries() != plan.Entries() {
		t.Fatalf("sent %+v skipped %d, plan %+v", st, skipped, plan)
	}
	dir, got, err := receiveIn(t, buf.Bytes(), Limits{MaxBytes: plan.Bytes, MaxEntries: plan.Entries()})
	if err != nil {
		t.Fatal(err)
	}
	if got != st {
		t.Fatalf("received %+v, sent %+v", got, st)
	}
	if _, err := os.Lstat(filepath.Join(dir, "src/link")); !errors.Is(err, fs.ErrNotExist) {
		t.Fatal("symlink was sent")
	}
	if _, err := os.Lstat(filepath.Join(dir, "secrets/other")); !errors.Is(err, fs.ErrNotExist) {
		t.Fatal("an unnamed file was sent")
	}

	// The sender refuses what the receiver would.
	if _, _, err := SendTree(io.Discard, root, []string{"src"}, Limits{MaxBytes: 5, MaxEntries: 100}); code(err) != "IO_TOO_LARGE" {
		t.Fatalf("over MaxBytes: %v", err)
	}
	if _, _, err := SendTree(io.Discard, root, []string{"src"}, Limits{MaxBytes: 100, MaxEntries: 2}); code(err) != "IO_TOO_MANY" {
		t.Fatalf("over MaxEntries: %v", err)
	}
	if _, _, err := SendTree(io.Discard, root, []string{"../x"}, roomy); err == nil {
		t.Fatal("traversal name accepted")
	}
}

func TestSendFiles(t *testing.T) {
	out := t.TempDir()
	must(t, os.WriteFile(filepath.Join(out, "result.sarif"), []byte("{}"), 0o644))
	must(t, os.WriteFile(filepath.Join(out, "trivy.json"), []byte(strings.Repeat("x", 50)), 0o644))
	must(t, os.Symlink("/etc/passwd", filepath.Join(out, "sbom.cdx.json")))
	must(t, os.WriteFile(filepath.Join(out, "raw.sarif"), []byte("secret"), 0o644))
	caps := map[string]int64{"result.sarif": 10, "trivy.json": 10 /* too small */, "sbom.cdx.json": 100, "missing": 1}
	var buf bytes.Buffer
	st, err := SendFiles(&buf, out, caps)
	if err != nil {
		t.Fatal(err)
	}
	if st.Files != 1 {
		t.Fatalf("sent %+v", st)
	}
	dir, _, err := receiveIn(t, buf.Bytes(), Limits{MaxBytes: 1000, MaxEntries: 4, Files: caps})
	if err != nil {
		t.Fatal(err)
	}
	if names, _ := FileNames(dir); !slices.Equal(names, []string{"result.sarif"}) {
		t.Fatalf("received %v", names)
	}
	for _, bad := range []string{"../x", "a/b", ""} {
		if _, err := SendFiles(io.Discard, out, map[string]int64{bad: 1}); err == nil {
			t.Fatalf("name %q accepted", bad)
		}
	}
}

func must(t testing.TB, err error) {
	t.Helper()
	if err != nil {
		t.Fatal(err)
	}
}
