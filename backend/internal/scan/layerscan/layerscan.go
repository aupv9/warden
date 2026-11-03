// Package layerscan runs inside the Gitleaks sandbox (cmd/warden-layers),
// never in the worker: it unpacks an image's layers for Gitleaks, a batch at
// a time, and maps what Gitleaks found back onto the image (the path in the
// image and the layer).
//
// The tarball and every layer in it are hostile. imagecheck has validated
// the tarball outside the sandbox and validates it again here; the layers
// themselves are only ever read here. Only regular files are written, under
// <dir>/<layer>/ and through an os.Root: no link, device or FIFO is created
// or followed, and a name that would leave the layer's directory is skipped.
// Whiteouts are recorded but delete nothing: a file a later layer deletes is
// still in the image, and so is any secret in it. So is an entry a later
// entry of the same layer replaces: the batch is scanned before the
// replacement is written.
//
// Each layer's digest is the sha256 of its uncompressed tar (its diff ID, as
// `docker inspect` lists it under RootFS.Layers), computed while reading it.
package layerscan

import (
	"archive/tar"
	"bufio"
	"bytes"
	"compress/gzip"
	"crypto/sha256"
	"encoding/hex"
	"errors"
	"fmt"
	"io"
	"math"
	"os"
	"path"
	"path/filepath"
	"strconv"
	"strings"
	"unicode/utf8"

	"github.com/klauspost/compress/zstd"

	"github.com/aupv9/warden/backend/internal/scan/archpath"
	"github.com/aupv9/warden/backend/internal/scan/imagecheck"
)

// Errors that end a scan of the image (warden-layers' exit codes 5 and 6,
// sandbox.ExitImageTooLarge and ExitImageUnreadable).
var (
	ErrTooLarge   = errors.New("the image's layers expand past the limits")
	ErrUnreadable = errors.New("a layer of the image can't be read")
)

// Limits bound the work one image can cause. Only MaxExpanded depends on the
// image limit; batches keep /tmp (a tmpfs, counted as memory) to about
// BatchBytes whatever the image's size.
type Limits struct {
	// MaxExpanded caps the uncompressed bytes of all layers together, and
	// separately the bytes written for Gitleaks (a sparse file is written
	// out in full).
	MaxExpanded int64
	// MaxEntries caps the tar entries of all layers together.
	MaxEntries int
	// MaxFileBytes: larger files are skipped (Report.Skipped), unread.
	MaxFileBytes int64
	// BatchBytes and BatchFiles: Gitleaks runs over what was written once
	// either would be passed.
	BatchBytes int64
	BatchFiles int
	// MaxReplaceScans bounds the extra batches that entries replacing an
	// earlier entry of the same layer cause; past it, they are skipped
	// (Report.Skipped).
	MaxReplaceScans int
}

// DefaultLimits are warden-layers' limits for a given MaxExpanded.
func DefaultLimits(maxExpanded int64) Limits {
	return Limits{
		MaxExpanded:     maxExpanded,
		MaxEntries:      1_000_000,
		MaxFileBytes:    64 << 20,
		BatchBytes:      256 << 20,
		BatchFiles:      20_000,
		MaxReplaceScans: 64,
	}
}

// Report is what warden-layers writes to /out/layers.json
// (sandbox.ArtifactLayers): the digest of every layer by index (0 = the
// base layer) and what was not scanned.
type Report struct {
	Layers []string `json:"layers"`
	// Skipped: regular files not scanned (over MaxFileBytes, or replacing an
	// earlier entry past MaxReplaceScans).
	Skipped int `json:"skipped_files"`
	// Whiteouts: deletions by a layer; nothing was deleted.
	Whiteouts int `json:"whiteouts"`
	// Unsafe: entries never written: links, devices, FIFOs, names that leave
	// the layer, and files whose place an earlier entry holds.
	Unsafe int `json:"unsafe_entries"`
}

// Batch is one directory Gitleaks reads: Dir/<n>/<path in the image> are the
// files of layer n, and Layers[n] every index the same layer is at (an
// image may list one layer twice).
type Batch struct {
	Dir    string
	Layers map[int][]int
}

// Extract unpacks the layers of the image tarball at image under dir (which
// must not exist yet), calling scan on each full batch and once at the end
// (also when nothing was written, so Gitleaks always runs once). dir is empty
// again when Extract returns.
func Extract(image, dir string, l Limits, scan func(Batch) error) (*Report, error) {
	res, err := imagecheck.Check(image, imagecheck.Limits{MaxBytes: math.MaxInt64})
	if err != nil {
		return nil, fmt.Errorf("%w: %v", ErrUnreadable, err)
	}
	if err := os.Mkdir(dir, 0o700); err != nil {
		return nil, err
	}
	x := &extractor{dir: dir, l: l, scan: scan, layers: map[int][]int{}, rep: &Report{Layers: make([]string, len(res.LayerFiles))}}
	defer x.close()
	at := map[string][]int{} // tarball entry -> image indexes
	for i, name := range res.LayerFiles {
		at[name] = append(at[name], i)
	}
	for _, idx := range at {
		x.layers[idx[0]] = idx
	}

	f, err := os.Open(image)
	if err != nil {
		return nil, err
	}
	defer f.Close()
	tr := tar.NewReader(f)
	for {
		hdr, err := tr.Next()
		if errors.Is(err, io.EOF) {
			break
		}
		if err != nil {
			return nil, fmt.Errorf("%w: %v", ErrUnreadable, err)
		}
		parts, err := archpath.Clean(hdr.Name)
		if err != nil || hdr.Typeflag != tar.TypeReg {
			continue
		}
		idx, ok := at[path.Join(parts...)]
		if !ok {
			continue
		}
		delete(at, path.Join(parts...))
		digest, err := x.layer(tr, idx[0])
		if err != nil {
			return nil, err
		}
		for _, i := range idx {
			x.rep.Layers[i] = digest
		}
	}
	if len(at) > 0 {
		return nil, fmt.Errorf("%w: a layer the manifest lists is missing", ErrUnreadable)
	}
	if x.files > 0 || x.batches == 0 {
		if err := x.flush(); err != nil {
			return nil, err
		}
	}
	return x.rep, nil
}

type extractor struct {
	dir    string
	l      Limits
	scan   func(Batch) error
	layers map[int][]int
	rep    *Report

	expanded, written int64 // against l.MaxExpanded
	entries           int
	batchBytes        int64
	files             int // in the current batch
	batches           int
	replaceScans      int
	over              bool // the expanded cap was hit (whatever error tar made of it)

	root  *os.Root // dir/<rootN>, open while the batch holds files of that layer
	rootN int
}

func (x *extractor) close() {
	if x.root != nil {
		x.root.Close()
		x.root = nil
	}
}

// flush runs scan over the batch and empties dir.
func (x *extractor) flush() error {
	x.close()
	err := x.scan(Batch{Dir: x.dir, Layers: x.layers})
	x.batches++
	x.batchBytes, x.files = 0, 0
	if rerr := os.RemoveAll(x.dir); rerr != nil && err == nil {
		err = rerr
	}
	if merr := os.Mkdir(x.dir, 0o700); merr != nil && err == nil {
		err = merr
	}
	return err
}

// layerRoot is dir/<n>, created when missing.
func (x *extractor) layerRoot(n int) (*os.Root, error) {
	if x.root != nil && x.rootN == n {
		return x.root, nil
	}
	x.close()
	p := filepath.Join(x.dir, strconv.Itoa(n))
	if err := os.Mkdir(p, 0o700); err != nil && !errors.Is(err, os.ErrExist) {
		return nil, err
	}
	r, err := os.OpenRoot(p)
	if err != nil {
		return nil, err
	}
	x.root, x.rootN = r, n
	return r, nil
}

// counter counts the uncompressed bytes of all layers against MaxExpanded.
type counter struct {
	r io.Reader
	x *extractor
}

func (c counter) Read(p []byte) (int, error) {
	if c.x.expanded >= c.x.l.MaxExpanded {
		c.x.over = true
		return 0, ErrTooLarge
	}
	if left := c.x.l.MaxExpanded - c.x.expanded; int64(len(p)) > left {
		p = p[:left]
	}
	n, err := c.r.Read(p)
	c.x.expanded += int64(n)
	return n, err
}

var (
	gzipMagic = []byte{0x1f, 0x8b}
	zstdMagic = []byte{0x28, 0xb5, 0x2f, 0xfd}
)

// zstd's window is how much the decoder holds; images use the default 8 MB.
const zstdMaxWindow = 128 << 20

// fail turns a read error into ErrTooLarge when the cap caused it (tar may
// report it as a short read), else ErrUnreadable.
func (x *extractor) fail(err error) error {
	if x.over || errors.Is(err, ErrTooLarge) {
		return ErrTooLarge
	}
	return fmt.Errorf("%w: %v", ErrUnreadable, err)
}

// layer unpacks one layer (uncompressed, gzip or zstd) into the batch as
// directory n and returns its digest.
func (x *extractor) layer(r io.Reader, n int) (string, error) {
	br := bufio.NewReaderSize(r, 64<<10)
	magic, _ := br.Peek(4)
	var dec io.Reader = br
	switch {
	case bytes.HasPrefix(magic, gzipMagic):
		zr, err := gzip.NewReader(br)
		if err != nil {
			return "", x.fail(err)
		}
		defer zr.Close()
		dec = zr
	case bytes.HasPrefix(magic, zstdMagic):
		zr, err := zstd.NewReader(br, zstd.WithDecoderConcurrency(1), zstd.WithDecoderMaxWindow(zstdMaxWindow),
			zstd.WithDecoderMaxMemory(zstdMaxWindow))
		if err != nil {
			return "", x.fail(err)
		}
		defer zr.Close()
		dec = zr
	}
	h := sha256.New()
	stream := io.TeeReader(counter{r: dec, x: x}, h)
	tr := tar.NewReader(stream)
	for {
		hdr, err := tr.Next()
		if errors.Is(err, io.EOF) {
			break
		}
		if err != nil {
			return "", x.fail(err)
		}
		if x.entries++; x.entries > x.l.MaxEntries {
			return "", ErrTooLarge
		}
		if err := x.entry(tr, hdr, n); err != nil {
			return "", err
		}
	}
	// The end-of-archive blocks and any padding are part of the layer (and
	// of its digest); gzip checks its CRC at the end.
	if _, err := io.Copy(io.Discard, stream); err != nil {
		return "", x.fail(err)
	}
	return "sha256:" + hex.EncodeToString(h.Sum(nil)), nil
}

// EntryPath is where a layer entry goes under the layer's directory, or ok
// false for a name that can't be written safely: one with "..", NUL or
// invalid UTF-8, or longer or deeper than archpath allows. A leading "/" is
// dropped, as Docker applies layers.
func EntryPath(name string) (rel string, ok bool) {
	if strings.ContainsRune(name, 0) || !utf8.ValidString(name) || utf8.RuneCountInString(name) > archpath.MaxPathLen {
		return "", false
	}
	var parts []string
	for _, p := range strings.Split(name, "/") {
		switch p {
		case "", ".":
		case "..":
			return "", false
		default:
			parts = append(parts, p)
		}
	}
	if len(parts) > archpath.MaxPathDepth {
		return "", false
	}
	return strings.Join(parts, "/"), true
}

// whiteout: an OCI/AUFS deletion marker (".wh.<name>", ".wh..wh..opq").
func whiteout(rel string) bool { return strings.HasPrefix(path.Base(rel), ".wh.") }

func (x *extractor) entry(tr *tar.Reader, hdr *tar.Header, n int) error {
	rel, ok := EntryPath(hdr.Name)
	switch {
	case !ok:
		x.rep.Unsafe++
		return nil
	case rel == "":
		return nil
	case whiteout(rel):
		x.rep.Whiteouts++
		return nil
	}
	switch hdr.Typeflag {
	case tar.TypeReg, tar.TypeGNUSparse:
	case tar.TypeDir:
		return nil // made for the files in it
	default:
		// Links, devices, FIFOs: never created, so never followed.
		x.rep.Unsafe++
		return nil
	}
	if hdr.Size > x.l.MaxFileBytes {
		x.rep.Skipped++
		return nil
	}
	if hdr.Size == 0 {
		return nil // nothing to find
	}
	if x.written+hdr.Size > x.l.MaxExpanded {
		return ErrTooLarge
	}
	if x.batchBytes+hdr.Size > x.l.BatchBytes || x.files >= x.l.BatchFiles {
		if err := x.flush(); err != nil {
			return err
		}
	}
	f, err := x.create(rel, n)
	if f == nil || err != nil {
		return err
	}
	_, err = io.Copy(f, tr)
	if cerr := f.Close(); err == nil && cerr != nil {
		return cerr
	}
	if err != nil {
		return x.fail(err)
	}
	x.written += hdr.Size
	x.batchBytes += hdr.Size
	x.files++
	return nil
}

// create makes rel in layer n's directory. When the place is taken (an
// earlier entry of the layer at the same name, or a file where a directory
// must go), the batch is scanned first, so the earlier entry is read too; nil
// and no error means the entry is skipped.
func (x *extractor) create(rel string, n int) (*os.File, error) {
	for attempt := 0; ; attempt++ {
		root, err := x.layerRoot(n)
		if err != nil {
			return nil, err
		}
		if d := path.Dir(rel); d != "." {
			err = root.MkdirAll(d, 0o700)
		}
		var f *os.File
		if err == nil {
			f, err = root.OpenFile(rel, os.O_WRONLY|os.O_CREATE|os.O_EXCL, 0o600)
		}
		if err == nil {
			return f, nil
		}
		if attempt > 0 || x.files == 0 {
			// Not a clash with this batch: a name the OS refuses.
			x.rep.Unsafe++
			return nil, nil
		}
		if x.replaceScans >= x.l.MaxReplaceScans {
			x.rep.Skipped++
			return nil, nil
		}
		x.replaceScans++
		if err := x.flush(); err != nil {
			return nil, err
		}
	}
}
