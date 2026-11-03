package layerscan

import (
	"archive/tar"
	"bytes"
	"compress/gzip"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"io/fs"
	"os"
	"path/filepath"
	"slices"
	"strconv"
	"strings"
	"testing"

	"github.com/klauspost/compress/zstd"
)

// ent is one entry of a layer (or of the image tarball).
type ent struct {
	name string
	typ  byte
	body string
	link string
}

func file(name, body string) ent { return ent{name: name, typ: tar.TypeReg, body: body} }

func tarOf(t testing.TB, entries ...ent) []byte {
	t.Helper()
	var buf bytes.Buffer
	tw := tar.NewWriter(&buf)
	for _, e := range entries {
		h := &tar.Header{Name: e.name, Typeflag: e.typ, Mode: 0o644, Linkname: e.link, Size: int64(len(e.body)), Format: tar.FormatPAX}
		if e.typ != tar.TypeReg {
			h.Size = 0
		}
		if err := tw.WriteHeader(h); err != nil {
			t.Fatal(err)
		}
		if _, err := tw.Write([]byte(e.body)); err != nil {
			t.Fatal(err)
		}
	}
	if err := tw.Close(); err != nil {
		t.Fatal(err)
	}
	return buf.Bytes()
}

func gz(t testing.TB, b []byte) []byte {
	var buf bytes.Buffer
	w := gzip.NewWriter(&buf)
	_, _ = w.Write(b)
	if err := w.Close(); err != nil {
		t.Fatal(err)
	}
	return buf.Bytes()
}

func zst(t testing.TB, b []byte) []byte {
	w, err := zstd.NewWriter(nil)
	if err != nil {
		t.Fatal(err)
	}
	defer w.Close()
	return w.EncodeAll(b, nil)
}

func digestOf(b []byte) string {
	s := sha256.Sum256(b)
	return "sha256:" + hex.EncodeToString(s[:])
}

// imageTar is a `docker save` tarball (Docker 25+ names: blobs/sha256/<hex>)
// of the given layer blobs, in order; a blob given twice is stored once and
// listed twice.
func imageTar(t testing.TB, layers ...[]byte) []byte {
	t.Helper()
	cfg := []byte(`{"os":"linux"}`)
	entries := []ent{file("blobs/sha256/"+digestOf(cfg)[7:], string(cfg))}
	var names []string
	seen := map[string]bool{}
	for _, l := range layers {
		name := "blobs/sha256/" + digestOf(l)[7:]
		names = append(names, name)
		if !seen[name] {
			seen[name] = true
			entries = append(entries, file(name, string(l)))
		}
	}
	m, _ := json.Marshal([]any{map[string]any{"Config": entries[0].name, "Layers": names}})
	return tarOf(t, append(entries, file("manifest.json", string(m)))...)
}

func writeImage(t testing.TB, b []byte) string {
	t.Helper()
	p := filepath.Join(t.TempDir(), "image.tar")
	if err := os.WriteFile(p, b, 0o600); err != nil {
		t.Fatal(err)
	}
	return p
}

// seen is a file Gitleaks would have read: its layer directory, path in the
// layer and content.
type seen struct {
	layer int
	path  string
	body  string
}

// collect is a scan that records every file of every batch, and checks the
// batch holds nothing but directories and regular files under numbered
// layer directories.
func collect(t *testing.T, got *[]seen, batches *int) func(Batch) error {
	return func(b Batch) error {
		*batches++
		return filepath.WalkDir(b.Dir, func(p string, d fs.DirEntry, err error) error {
			if err != nil {
				return err
			}
			rel, _ := filepath.Rel(b.Dir, p)
			if !d.IsDir() && !d.Type().IsRegular() {
				t.Errorf("%s is neither a directory nor a regular file (%v)", rel, d.Type())
				return nil
			}
			if d.IsDir() {
				return nil
			}
			num, inLayer, _ := strings.Cut(filepath.ToSlash(rel), "/")
			n, err := strconv.Atoi(num)
			if err != nil || b.Layers[n] == nil {
				t.Errorf("file %s outside a layer directory", rel)
			}
			body, err := os.ReadFile(p)
			*got = append(*got, seen{n, inLayer, string(body)})
			return err
		})
	}
}

func extract(t *testing.T, image []byte, l Limits) (*Report, []seen, int, error) {
	t.Helper()
	var got []seen
	n := 0
	dir := filepath.Join(t.TempDir(), "layers")
	rep, err := Extract(writeImage(t, image), dir, l, collect(t, &got, &n))
	if err == nil {
		if entries, rerr := os.ReadDir(dir); rerr != nil || len(entries) != 0 {
			t.Fatalf("dir not emptied: %v %v", entries, rerr)
		}
	}
	return rep, got, n, err
}

func testLimits() Limits {
	l := DefaultLimits(64 << 20)
	l.MaxFileBytes = 1 << 10
	return l
}

func has(got []seen, s seen) bool { return slices.Contains(got, s) }

func TestExtractLayers(t *testing.T) {
	base := tarOf(t, ent{name: "etc/", typ: tar.TypeDir}, file("etc/os-release", "ID=test"))
	add := tarOf(t, file("./app/.env", "TOKEN=one"), file("/app/abs.txt", "abs"))
	del := tarOf(t, file("app/.wh..env", ""), file("app/.wh..wh..opq", ""), file("app/new.txt", "new"))
	rep, got, batches, err := extract(t, imageTar(t, base, gz(t, add), zst(t, del)), testLimits())
	if err != nil {
		t.Fatal(err)
	}
	// Digests are the uncompressed layers' (diff IDs), whatever the compression.
	if !slices.Equal(rep.Layers, []string{digestOf(base), digestOf(add), digestOf(del)}) {
		t.Fatal(rep.Layers)
	}
	for _, s := range []seen{{0, "etc/os-release", "ID=test"}, {1, "app/.env", "TOKEN=one"}, {1, "app/abs.txt", "abs"}, {2, "app/new.txt", "new"}} {
		if !has(got, s) {
			t.Errorf("missing %+v in %+v", s, got)
		}
	}
	// The deleted file is still read (layer 1); the whiteouts deleted nothing.
	if len(got) != 4 || rep.Whiteouts != 2 || rep.Unsafe != 0 || rep.Skipped != 0 || batches != 1 {
		t.Fatalf("%+v %+v %d", rep, got, batches)
	}
}

// A layer the image lists twice is read once and reported at both indexes.
func TestExtractRepeatedLayer(t *testing.T) {
	a, b := tarOf(t, file("a", "x")), tarOf(t, file("b", "y"))
	var layers map[int][]int
	rep, err := Extract(writeImage(t, imageTar(t, a, b, a)), filepath.Join(t.TempDir(), "l"), testLimits(), func(bt Batch) error {
		layers = bt.Layers
		return nil
	})
	if err != nil {
		t.Fatal(err)
	}
	if !slices.Equal(rep.Layers, []string{digestOf(a), digestOf(b), digestOf(a)}) || !slices.Equal(layers[0], []int{0, 2}) ||
		!slices.Equal(layers[1], []int{1}) || len(layers) != 2 {
		t.Fatal(rep.Layers, layers)
	}
}

// Names that leave the layer's directory, links, devices and FIFOs are never
// written; a file "under" a symlink lands in a real directory inside the
// layer, never through the link. Nothing appears outside dir.
func TestExtractHostileEntries(t *testing.T) {
	layer := tarOf(t,
		file("../../escape.txt", "x"),
		file("a/../../escape2.txt", "x"),
		file("ok/../in.txt", "x"), // also has "..": skipped, not resolved
		ent{name: "lnk", typ: tar.TypeSymlink, link: "/"},
		file("lnk/write-through.txt", "through"),
		ent{name: "up", typ: tar.TypeSymlink, link: "../../.."},
		file("up/escape3.txt", "x"),
		ent{name: "hl", typ: tar.TypeLink, link: "../../../etc/passwd"},
		ent{name: "dev", typ: tar.TypeChar},
		ent{name: "blk", typ: tar.TypeBlock},
		ent{name: "fifo", typ: tar.TypeFifo},
		file(strings.Repeat("d/", 60)+"deep", "x"),
		file("good.txt", "good"),
	)
	parent := t.TempDir()
	dir := filepath.Join(parent, "work", "layers")
	if err := os.Mkdir(filepath.Dir(dir), 0o700); err != nil {
		t.Fatal(err)
	}
	var got []seen
	n := 0
	rep, err := Extract(writeImage(t, imageTar(t, layer)), dir, testLimits(), collect(t, &got, &n))
	if err != nil {
		t.Fatal(err)
	}
	if !has(got, seen{0, "good.txt", "good"}) || !has(got, seen{0, "lnk/write-through.txt", "through"}) ||
		!has(got, seen{0, "up/escape3.txt", "x"}) || len(got) != 3 {
		t.Fatalf("%+v", got)
	}
	// "..": 3, links: 3, devices and FIFOs: 3, depth: 1. (NUL: TestEntryPath;
	// tar can't write one.)
	if rep.Unsafe != 10 {
		t.Fatalf("%+v", rep)
	}
	entries, _ := os.ReadDir(filepath.Dir(dir))
	if len(entries) != 1 || entries[0].Name() != "layers" {
		t.Fatalf("written outside the layers directory: %v", entries)
	}
	if _, err := os.Lstat(filepath.Join(parent, "escape.txt")); !errors.Is(err, fs.ErrNotExist) {
		t.Fatal("escaped")
	}
}

func TestEntryPath(t *testing.T) {
	for name, want := range map[string]string{
		"a/b": "a/b", "./a//b/": "a/b", "/etc/passwd": "etc/passwd", "///x": "x", ".": "", "/": "",
	} {
		if got, ok := EntryPath(name); !ok || got != want {
			t.Errorf("%q: %q %v", name, got, ok)
		}
	}
	for _, name := range []string{"..", "../x", "a/../b", "a/..", "x\x00", "\xff", strings.Repeat("a/", 51) + "b", strings.Repeat("a", 1025)} {
		if _, ok := EntryPath(name); ok {
			t.Errorf("%q accepted", name)
		}
	}
}

// gnuSparse is a GNU sparse entry (type 'S') whose real size is huge and
// whose data is empty: Go's tar reader reads it as a file of zeros.
func gnuSparse(name string, realSize int64) []byte {
	var blk [512]byte
	copy(blk[0:], name)
	copy(blk[100:], "0000644\x00")
	copy(blk[108:], "0000000\x00")
	copy(blk[116:], "0000000\x00")
	copy(blk[124:], "00000000000\x00") // physical size 0
	copy(blk[136:], "00000000000\x00")
	blk[156] = 'S'
	copy(blk[257:], "ustar  \x00")
	// One sparse entry: offset realSize, 0 bytes (all holes); real size.
	copy(blk[386:], strconv.FormatInt(realSize, 8))
	copy(blk[398:], "00000000000")
	copy(blk[483:], strconv.FormatInt(realSize, 8))
	copy(blk[148:], "        ")
	sum := 0
	for _, b := range blk {
		sum += int(b)
	}
	copy(blk[148:], strconv.FormatInt(int64(sum), 8)+"\x00 ")
	return blk[:]
}

// Huge files are skipped unread: a regular file over the cap, and a sparse
// one claiming a terabyte (which would be a terabyte of zeros to write).
func TestExtractHugeAndSparseFiles(t *testing.T) {
	var layer bytes.Buffer
	layer.Write(gnuSparse("sparse.bin", 1<<40))
	rest := tarOf(t, file("big.bin", strings.Repeat("z", 4<<10)), file("small.txt", "s"))
	layer.Write(rest)
	rep, got, _, err := extract(t, imageTar(t, layer.Bytes()), testLimits())
	if err != nil {
		t.Fatal(err)
	}
	if rep.Skipped != 2 || len(got) != 1 || got[0].path != "small.txt" {
		t.Fatalf("%+v %+v", rep, got)
	}
}

func TestExtractLimits(t *testing.T) {
	many := make([]ent, 20)
	for i := range many {
		many[i] = file("f"+strconv.Itoa(i), "x")
	}
	l := testLimits()
	l.MaxEntries = 10
	if _, _, _, err := extract(t, imageTar(t, tarOf(t, many...)), l); !errors.Is(err, ErrTooLarge) {
		t.Fatalf("too many entries: %v", err)
	}
	// A gzip bomb: 8 MB of zeros in a few KB.
	bomb := gz(t, tarOf(t, file("zeros", strings.Repeat("\x00", 8<<20))))
	l = testLimits()
	l.MaxExpanded = 1 << 20
	if _, _, _, err := extract(t, imageTar(t, bomb), l); !errors.Is(err, ErrTooLarge) {
		t.Fatalf("bomb: %v", err)
	}
	// Written bytes count too (sparse files are written out whole).
	l = testLimits()
	l.MaxExpanded = 8 << 10
	l.MaxFileBytes = 64 << 10
	var layer bytes.Buffer
	layer.Write(gnuSparse("sparse.bin", 32<<10))
	layer.Write(tarOf(t))
	if _, _, _, err := extract(t, imageTar(t, layer.Bytes()), l); !errors.Is(err, ErrTooLarge) {
		t.Fatalf("sparse: %v", err)
	}
}

func TestExtractUnreadableLayers(t *testing.T) {
	for name, layer := range map[string][]byte{
		"not a tar":   []byte(strings.Repeat("garbage!", 100)),
		"broken gzip": append(gz(t, tarOf(t, file("a", "b")))[:20], 0, 1, 2),
		"bad zstd":    append([]byte{0x28, 0xb5, 0x2f, 0xfd}, bytes.Repeat([]byte{0xff}, 64)...),
		"truncated":   tarOf(t, file("a", strings.Repeat("b", 2048)))[:1024],
	} {
		if _, _, _, err := extract(t, imageTar(t, layer), testLimits()); !errors.Is(err, ErrUnreadable) {
			t.Errorf("%s: %v", name, err)
		}
	}
	// Not an image at all.
	if _, _, _, err := extract(t, tarOf(t, file("x", "y")), testLimits()); !errors.Is(err, ErrUnreadable) {
		t.Errorf("no manifest: %v", err)
	}
}

// Batches bound /tmp; an entry that replaces an earlier one of its layer is
// written after the earlier one was scanned, so both are read.
func TestExtractBatches(t *testing.T) {
	l := testLimits()
	l.BatchFiles = 2
	layer := tarOf(t, file("a", "1"), file("b", "2"), file("c", "3"), file("d", "4"), file("e", "5"))
	_, got, batches, err := extract(t, imageTar(t, layer), l)
	if err != nil || len(got) != 5 || batches != 3 {
		t.Fatal(got, batches, err)
	}
	l = testLimits()
	l.BatchBytes = 4
	_, got, batches, err = extract(t, imageTar(t, tarOf(t, file("a", "12"), file("b", "34"), file("c", "5"))), l)
	if err != nil || len(got) != 3 || batches != 2 {
		t.Fatal(got, batches, err)
	}
	replaced := tarOf(t, file("app/key", "OLD"), file("app/key", "NEW"), file("x", "x"), file("x/y", "under a file"))
	rep, got, batches, err := extract(t, imageTar(t, replaced), testLimits())
	if err != nil || !has(got, seen{0, "app/key", "OLD"}) || !has(got, seen{0, "app/key", "NEW"}) ||
		!has(got, seen{0, "x/y", "under a file"}) || batches != 3 || rep.Skipped != 0 {
		t.Fatal(got, batches, err)
	}
	l = testLimits()
	l.MaxReplaceScans = 1
	rep, got, _, err = extract(t, imageTar(t, tarOf(t, file("k", "1"), file("k", "2"), file("k", "3"))), l)
	if err != nil || len(got) != 2 || rep.Skipped != 1 {
		t.Fatal(got, rep, err)
	}
	// An empty image still gets one (empty) batch: Gitleaks runs once.
	_, got, batches, err = extract(t, imageTar(t, tarOf(t)), testLimits())
	if err != nil || len(got) != 0 || batches != 1 {
		t.Fatal(got, batches, err)
	}
}

func TestExtractStopsOnScanError(t *testing.T) {
	boom := errors.New("gitleaks failed")
	_, err := Extract(writeImage(t, imageTar(t, tarOf(t, file("a", "b")))), filepath.Join(t.TempDir(), "l"), testLimits(),
		func(Batch) error { return boom })
	if !errors.Is(err, boom) {
		t.Fatal(err)
	}
}

// The OCI layout (no manifest.json) is read too.
func TestExtractOCILayout(t *testing.T) {
	layer := gz(t, tarOf(t, file("f", "x")))
	cfg := []byte("{}")
	mf, _ := json.Marshal(map[string]any{"config": map[string]any{"digest": digestOf(cfg)}, "layers": []any{map[string]any{"digest": digestOf(layer)}}})
	idx, _ := json.Marshal(map[string]any{"manifests": []any{map[string]any{"digest": digestOf(mf)}}})
	img := tarOf(t, file("oci-layout", "{}"), file("index.json", string(idx)), file("blobs/sha256/"+digestOf(mf)[7:], string(mf)),
		file("blobs/sha256/"+digestOf(cfg)[7:], string(cfg)), file("blobs/sha256/"+digestOf(layer)[7:], string(layer)))
	rep, got, _, err := extract(t, img, testLimits())
	if err != nil || len(got) != 1 || len(rep.Layers) != 1 {
		t.Fatal(rep, got, err)
	}
}
