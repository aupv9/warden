// Package zipcheck validates and extracts uploaded archives. It is the
// only place in Warden allowed to extract an archive.
package zipcheck

import (
	"archive/zip"
	"bytes"
	"crypto/sha256"
	"encoding/hex"
	"errors"
	"fmt"
	"io"
	"io/fs"
	"os"
	"path"
	"path/filepath"
	"regexp"
	"slices"
	"strings"
	"syscall"
	"unicode/utf8"

	"golang.org/x/text/encoding/charmap"

	"github.com/aupv9/warden/backend/internal/scan/archpath"
)

const (
	chunk          = 64 * 1024
	MaxRatio       = 100
	RatioFloor     = 1024 * 1024
	MaxBinaryBytes = 5 * 1024 * 1024

	flagEncrypted = 0x1
	flagUTF8      = 0x800
	unixTypeMask  = 0o170000
	unixRegular   = 0o100000
)

var zipMagic = []byte("PK\x03\x04")

var SkipDirs = []string{"node_modules", "vendor", "dist", "build", ".git", ".venv"}

var (
	unsafeNameChars = regexp.MustCompile(`[^A-Za-z0-9._\-]`)
)

// Rejected carries a stable error code (ZIP_PATH_TRAVERSAL, ZIP_BOMB, ...).
type Rejected struct {
	Code   string
	Detail string
}

func (e *Rejected) Error() string { return e.Code + ": " + e.Detail }

func reject(code, format string, args ...any) *Rejected {
	return &Rejected{Code: code, Detail: fmt.Sprintf(format, args...)}
}

type Limits struct {
	MaxZipBytes   int64
	MaxTotalBytes int64
	MaxEntries    int
}

func DefaultLimits() Limits {
	return Limits{MaxZipBytes: 200 << 20, MaxTotalBytes: 1 << 30, MaxEntries: 100_000}
}

type Result struct {
	Files      int
	TotalBytes int64
	Warnings   []string
	Renamed    map[string]string // safe path -> original entry name
	RootDir    string            // the single top-level directory, if there is one
}

func SHA256File(p string) (string, error) {
	f, err := os.Open(p)
	if err != nil {
		return "", err
	}
	defer f.Close()
	h := sha256.New()
	if _, err := io.Copy(h, f); err != nil {
		return "", err
	}
	return hex.EncodeToString(h.Sum(nil)), nil
}

func VerifyChecksum(p, expected string) error {
	got, err := SHA256File(p)
	if err != nil {
		return err
	}
	if got != strings.ToLower(expected) {
		return reject("CHECKSUM_MISMATCH", "uploaded file does not match recorded SHA-256")
	}
	return nil
}

// decodeName returns the entry name to use, the original name for display, and
// whether it had to be renamed. Names that aren't valid UTF-8 or contain control
// characters get a safe ASCII name.
func decodeName(f *zip.File) (name, original string, renamed bool) {
	name = f.Name
	if !utf8.ValidString(name) {
		if f.Flags&flagUTF8 == 0 {
			if dec, err := charmap.CodePage437.NewDecoder().String(name); err == nil {
				name = dec
			}
		}
		name = strings.ToValidUTF8(name, "�")
		return safeRename(name), name, true
	}
	for _, r := range name {
		if r < 0x20 && r != 0 {
			return safeRename(name), name, true
		}
	}
	return name, name, false
}

func safeRename(name string) string {
	sum := sha256.Sum256([]byte(name))
	digest := hex.EncodeToString(sum[:])[:8]
	var parts []string
	for _, p := range strings.Split(strings.ReplaceAll(name, `\`, "/"), "/") {
		if p == "" || p == "." {
			continue
		}
		p = unsafeNameChars.ReplaceAllString(p, "_")
		parts = append(parts, p)
	}
	if len(parts) == 0 {
		return "_" + digest
	}
	parts[len(parts)-1] += "." + digest
	return strings.Join(parts, "/")
}

// validatePath returns the cleaned relative parts of an entry name, or an empty
// slice for the archive root itself (the rules are shared with imagecheck).
func validatePath(name string) ([]string, error) {
	parts, err := archpath.Clean(name)
	if err != nil {
		return nil, reject("ZIP_PATH_TRAVERSAL", "%v", err)
	}
	return parts, nil
}

func openZip(zipPath string, limits Limits) (*zip.ReadCloser, error) {
	st, err := os.Stat(zipPath)
	if err != nil {
		return nil, err
	}
	if st.Size() > limits.MaxZipBytes {
		return nil, reject("ZIP_TOO_LARGE", "archive is %d bytes", st.Size())
	}
	f, err := os.Open(zipPath)
	if err != nil {
		return nil, err
	}
	head := make([]byte, 4)
	_, err = io.ReadFull(f, head)
	f.Close()
	if err != nil || !bytes.Equal(head, zipMagic) {
		return nil, reject("ZIP_INVALID", `missing PK\x03\x04 signature`)
	}
	zr, err := zip.OpenReader(zipPath)
	// ErrInsecurePath (GODEBUG zipinsecurepath=0) still returns a usable reader;
	// validatePath reports those entries with the precise error code.
	if errors.Is(err, zip.ErrInsecurePath) {
		err = nil
	}
	if err != nil {
		if zr != nil {
			zr.Close()
		}
		return nil, reject("ZIP_INVALID", "unreadable central directory: %v", err)
	}
	return zr, nil
}

// Extract validates zipPath and extracts it into dest, which must not exist yet.
// On success the tree is read-only (files 0444, directories 0555). On error the
// caller must remove dest.
func Extract(zipPath, dest string, limits Limits) (*Result, error) {
	if err := os.Mkdir(dest, 0o755); err != nil {
		return nil, err
	}
	destReal, err := filepath.EvalSymlinks(dest)
	if err != nil {
		return nil, err
	}
	res := &Result{Renamed: map[string]string{}}

	zr, err := openZip(zipPath, limits)
	if err != nil {
		return nil, err
	}
	defer zr.Close()
	if len(zr.File) > limits.MaxEntries {
		return nil, reject("ZIP_TOO_MANY_FILES", "%d entries", len(zr.File))
	}

	topLevels := map[string]bool{}
	madeDirs := map[string]bool{destReal: true}

	for _, f := range zr.File {
		if f.Flags&flagEncrypted != 0 {
			return nil, reject("ZIP_ENCRYPTED", "entry %q is encrypted", f.Name)
		}
		name, original, renamed := decodeName(f)
		parts, err := validatePath(name)
		if err != nil {
			return nil, err
		}
		if len(parts) == 0 {
			continue
		}
		topLevels[parts[0]] = true

		isDir := strings.HasSuffix(name, "/")
		dirParts := parts[:len(parts)-1]
		if isDir {
			dirParts = parts
		}
		if slices.ContainsFunc(dirParts, func(p string) bool { return slices.Contains(SkipDirs, p) }) {
			continue
		}
		if isDir {
			continue
		}

		if ftype := (f.ExternalAttrs >> 16) & unixTypeMask; ftype != 0 && ftype != unixRegular {
			res.Warnings = append(res.Warnings, fmt.Sprintf("skipped non-regular entry %q (symlink/device)", name))
			continue
		}
		rel := path.Join(parts...)
		if strings.EqualFold(path.Ext(rel), ".zip") {
			res.Warnings = append(res.Warnings, fmt.Sprintf("nested archive %q not extracted", name))
		}

		target := filepath.Join(destReal, filepath.FromSlash(rel))
		if !strings.HasPrefix(target, destReal+string(filepath.Separator)) {
			return nil, reject("ZIP_PATH_TRAVERSAL", "entry %q escapes the archive root", name)
		}
		if err := mkdirs(filepath.Dir(target), madeDirs); err != nil {
			return nil, err
		}
		kept, err := extractEntry(f, target, name, limits, res)
		if err != nil {
			return nil, err
		}
		if !kept {
			continue
		}
		res.Files++
		if renamed {
			res.Renamed[rel] = original
		}
	}

	if res.Files == 0 {
		return nil, reject("ZIP_EMPTY", "no source files left after filtering")
	}
	if len(topLevels) == 1 {
		for only := range topLevels {
			if st, err := os.Lstat(filepath.Join(destReal, only)); err == nil && st.IsDir() {
				res.RootDir = only
			}
		}
	}
	return res, makeReadOnly(destReal)
}

// mkdirs creates the missing parents of p one level at a time and refuses to
// walk through anything that isn't a real directory.
func mkdirs(p string, made map[string]bool) error {
	var missing []string
	for d := p; !made[d]; d = filepath.Dir(d) {
		missing = append(missing, d)
	}
	for i := len(missing) - 1; i >= 0; i-- {
		d := missing[i]
		if err := os.Mkdir(d, 0o755); err != nil {
			if !errors.Is(err, fs.ErrExist) {
				return err
			}
			st, err := os.Lstat(d)
			if err != nil || !st.IsDir() {
				return reject("ZIP_PATH_TRAVERSAL", "path conflict at %q", filepath.Base(d))
			}
		}
		made[d] = true
	}
	return nil
}

// extractEntry writes one entry, counting the bytes actually decompressed (header
// sizes are attacker-controlled). It returns false if the entry was skipped.
func extractEntry(f *zip.File, target, name string, limits Limits, res *Result) (kept bool, err error) {
	out, err := os.OpenFile(target, os.O_WRONLY|os.O_CREATE|os.O_EXCL|syscall.O_NOFOLLOW, 0o644)
	if err != nil {
		if errors.Is(err, fs.ErrExist) {
			res.Warnings = append(res.Warnings, fmt.Sprintf("duplicate entry %q skipped", name))
			return false, nil
		}
		return false, err
	}
	defer func() {
		if cerr := out.Close(); cerr != nil && err == nil {
			err = cerr
		}
		if !kept || err != nil {
			os.Remove(target)
			kept = false
		}
	}()

	src, err := f.Open()
	if err != nil {
		return false, reject("ZIP_INVALID", "cannot decompress %q: %v", name, err)
	}
	defer src.Close()

	compressed := max(int64(f.CompressedSize64), 1)
	var written int64
	binaryChecked, isBinary := false, false
	buf := make([]byte, chunk)
	for {
		n, rerr := fill(src, buf)
		if n > 0 {
			if !binaryChecked {
				binaryChecked = true
				isBinary = bytes.IndexByte(buf[:min(n, 8192)], 0) >= 0
			}
			written += int64(n)
			res.TotalBytes += int64(n)
			if res.TotalBytes > limits.MaxTotalBytes {
				return false, reject("ZIP_BOMB", "uncompressed content exceeds limit")
			}
			if written > RatioFloor && written > MaxRatio*compressed {
				return false, reject("ZIP_BOMB", "entry %q exceeds %d:1 ratio", name, MaxRatio)
			}
			if isBinary && written > MaxBinaryBytes {
				res.Warnings = append(res.Warnings, fmt.Sprintf("binary file %q > 5 MB skipped", name))
				return false, nil
			}
			if _, err := out.Write(buf[:n]); err != nil {
				return false, err
			}
		}
		if rerr == io.EOF {
			break
		}
		if rerr != nil { // CRC/size mismatch (ErrChecksum, ErrFormat) or truncated data
			return false, reject("ZIP_INVALID", "cannot decompress %q: %v", name, rerr)
		}
	}
	if err := out.Chmod(0o444); err != nil {
		return false, err
	}
	return true, nil
}

// fill reads until buf is full or the reader fails. Unlike io.ReadFull it passes
// the reader's error through unchanged, so a truncated stream
// (io.ErrUnexpectedEOF from the decompressor) isn't mistaken for a clean end.
func fill(r io.Reader, buf []byte) (int, error) {
	n := 0
	for n < len(buf) {
		m, err := r.Read(buf[n:])
		n += m
		if err != nil {
			return n, err
		}
	}
	return n, nil
}

func makeReadOnly(root string) error {
	var dirs []string
	err := filepath.WalkDir(root, func(p string, d fs.DirEntry, err error) error {
		if err != nil {
			return err
		}
		if d.IsDir() {
			dirs = append(dirs, p)
		}
		return nil
	})
	if err != nil {
		return err
	}
	for i := len(dirs) - 1; i >= 0; i-- {
		if err := os.Chmod(dirs[i], 0o555); err != nil {
			return err
		}
	}
	return nil
}

// MakeWritable undoes makeReadOnly so a scan directory can be removed.
func MakeWritable(root string) {
	_ = filepath.WalkDir(root, func(p string, d fs.DirEntry, err error) error {
		if err == nil && d.IsDir() {
			_ = os.Chmod(p, 0o700)
		}
		return nil
	})
}

// RemoveAll deletes a scan directory, including the read-only extracted tree.
func RemoveAll(root string) error {
	if _, err := os.Lstat(root); errors.Is(err, fs.ErrNotExist) {
		return nil
	}
	MakeWritable(root)
	return os.RemoveAll(root)
}
