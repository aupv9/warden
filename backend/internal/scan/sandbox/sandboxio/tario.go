// Package sandboxio moves files into and out of a kubernetes scanner Pod as
// tar streams over the pods/exec API (sandbox/kube): the Pod has no network
// and shares no volume with the worker. Both ends are here, so the
// warden-sandbox-io binary in the Pod and the worker apply the same rules.
//
// Receiving takes regular files and directories only: no links, devices,
// FIFOs or sparse files; names are cleaned like archive entries (archpath)
// and written through an os.Root, so nothing lands outside the target
// directory and no symlink is ever followed. Totals (bytes, entries) are
// checked against the limits before anything is written. What comes back from
// a Pod's /out is hostile input (a scanner wrote it): the worker receives it
// with Limits.Files, which admits only the tool's SARIF and artifacts, each
// within its own cap.
package sandboxio

import (
	"archive/tar"
	"errors"
	"fmt"
	"io"
	"io/fs"
	"os"
	"path"
	"path/filepath"
	"slices"
	"sort"
	"strings"
	"syscall"

	"github.com/aupv9/warden/backend/internal/scan/archpath"
)

// MaxNameBytes is the longest path component Linux file systems take (NAME_MAX).
const MaxNameBytes = 255

// headerBudget bounds the tar framing read per entry besides its content:
// archive/tar accepts PAX and GNU long-name records of up to 1 MiB each, and
// a run of them before one entry. The stream as a whole is capped at
// MaxBytes plus this per entry, so framing can't be used to stream forever.
const headerBudget = 2<<20 + 4096

// Rejected is a refused stream; Code is stable (IO_PATH, IO_TYPE, ...).
type Rejected struct {
	Code   string
	Detail string
}

func (e *Rejected) Error() string { return e.Code + ": " + e.Detail }

func reject(code, format string, args ...any) *Rejected {
	return &Rejected{Code: code, Detail: fmt.Sprintf(format, args...)}
}

// Limits bound one stream.
type Limits struct {
	// MaxBytes is the total content of all files.
	MaxBytes int64
	// MaxEntries counts files and directories.
	MaxEntries int
	// Files, when set, is everything a stream may hold: top-level regular
	// files by name, each at most its cap; no directories. Used for a Pod's
	// /out (the SARIF and the tool's artifacts).
	Files map[string]int64
}

// Stats describe a stream.
type Stats struct {
	Files, Dirs int
	Bytes       int64
}

// Receive extracts the tar stream r into dir, which must exist. Directories
// that already exist (mount points) are kept; a file is never overwritten.
// On error, what was written so far stays; the caller removes it.
func Receive(r io.Reader, dir string, l Limits) (Stats, error) {
	var st Stats
	if l.MaxBytes < 0 || l.MaxEntries < 0 {
		return st, errors.New("sandboxio: negative limits")
	}
	root, err := os.OpenRoot(dir)
	if err != nil {
		return st, err
	}
	defer root.Close()

	budget := l.MaxBytes + int64(l.MaxEntries+1)*headerBudget
	tr := tar.NewReader(&limitedReader{r: r, n: budget})
	seen := map[string]bool{}
	entries := 0
	for {
		hdr, err := tr.Next()
		if errors.Is(err, io.EOF) {
			return st, nil
		}
		if err != nil {
			var lr *errStreamTooLong
			if errors.As(err, &lr) {
				return st, reject("IO_TOO_LARGE", "stream exceeds its limit")
			}
			return st, reject("IO_INVALID", "unreadable tar stream: %v", err)
		}
		if entries++; entries > l.MaxEntries {
			return st, reject("IO_TOO_MANY", "more than %d entries", l.MaxEntries)
		}
		name, err := cleanName(hdr.Name)
		if err != nil {
			return st, err
		}
		if name == "" {
			if hdr.Typeflag == tar.TypeDir {
				continue // the stream's root: dir itself
			}
			return st, reject("IO_PATH", "entry without a name")
		}
		if seen[name] {
			return st, reject("IO_DUPLICATE", "entry %q appears twice", name)
		}
		seen[name] = true

		switch hdr.Typeflag {
		case tar.TypeDir:
			if l.Files != nil {
				return st, reject("IO_UNEXPECTED", "directory %q where only files are expected", name)
			}
			if err := mkdirs(root, name); err != nil {
				return st, err
			}
			st.Dirs++
		case tar.TypeReg:
			if err := checkFile(l, name, hdr.Size, st.Bytes); err != nil {
				return st, err
			}
			if err := writeFile(root, name, tr, hdr.Size); err != nil {
				return st, err
			}
			st.Files++
			st.Bytes += hdr.Size
		default:
			return st, reject("IO_TYPE", "entry %q is not a regular file or directory (type %q)", name, hdr.Typeflag)
		}
	}
}

// cleanName applies the archive entry rules (archpath) plus NAME_MAX per
// component, and returns the slash-separated relative name ("" for the root).
func cleanName(raw string) (string, error) {
	if strings.Contains(raw, `\`) {
		// archpath would take it as a separator; a sender never writes one,
		// and on Linux it is a legal name character: refuse the ambiguity.
		return "", reject("IO_PATH", "entry %q contains a backslash", raw)
	}
	parts, err := archpath.Clean(raw)
	if err != nil {
		return "", reject("IO_PATH", "%v", err)
	}
	for _, p := range parts {
		if len(p) > MaxNameBytes {
			return "", reject("IO_PATH", "entry name component longer than %d bytes", MaxNameBytes)
		}
	}
	return path.Join(parts...), nil
}

func checkFile(l Limits, name string, size, sofar int64) error {
	if size < 0 {
		return reject("IO_INVALID", "entry %q has a negative size", name)
	}
	if l.Files != nil {
		limit, ok := l.Files[name]
		if !ok {
			return reject("IO_UNEXPECTED", "unexpected file %q", name)
		}
		if size > limit {
			return reject("IO_TOO_LARGE", "file %q is %d bytes, over its %d byte cap", name, size, limit)
		}
	}
	if size > l.MaxBytes-sofar {
		return reject("IO_TOO_LARGE", "content exceeds %d bytes", l.MaxBytes)
	}
	return nil
}

// mkdirs creates name and its missing parents under root; anything in the way
// that is not a directory is refused (os.Root never follows a symlink out).
func mkdirs(root *os.Root, name string) error {
	parts := strings.Split(name, "/")
	for i := range parts {
		p := strings.Join(parts[:i+1], "/")
		err := root.Mkdir(p, 0o755)
		if err == nil {
			continue
		}
		if !errors.Is(err, fs.ErrExist) {
			return pathErr(name, err)
		}
		fi, err := root.Lstat(p)
		if err != nil || !fi.IsDir() {
			return reject("IO_PATH", "path conflict at %q", p)
		}
	}
	return nil
}

func writeFile(root *os.Root, name string, r io.Reader, size int64) (err error) {
	if dir := path.Dir(name); dir != "." {
		if err := mkdirs(root, dir); err != nil {
			return err
		}
	}
	f, err := root.OpenFile(name, os.O_WRONLY|os.O_CREATE|os.O_EXCL|syscall.O_NOFOLLOW, 0o644)
	if err != nil {
		if errors.Is(err, fs.ErrExist) {
			// A case-insensitive file system folds two names into one.
			return reject("IO_DUPLICATE", "entry %q collides with an earlier one", name)
		}
		return pathErr(name, err)
	}
	defer func() {
		if cerr := f.Close(); cerr != nil && err == nil {
			err = cerr
		}
	}()
	n, err := io.CopyN(f, r, size)
	if err != nil {
		var lr *errStreamTooLong
		if errors.As(err, &lr) {
			return reject("IO_TOO_LARGE", "stream exceeds its limit")
		}
		return reject("IO_INVALID", "entry %q truncated after %d of %d bytes", name, n, size)
	}
	return nil
}

// pathErr makes a name the file system can't store a refusal rather than an
// internal error.
func pathErr(name string, err error) error {
	switch {
	case errors.Is(err, syscall.ENAMETOOLONG), errors.Is(err, syscall.EILSEQ):
		return reject("IO_PATH", "entry %q can't be stored", name)
	case errors.Is(err, fs.ErrPermission), errors.Is(err, syscall.EROFS):
		return reject("IO_PATH", "entry %q is outside the writable volumes", name)
	}
	var pe *fs.PathError
	if errors.As(err, &pe) && strings.Contains(pe.Err.Error(), "escapes") {
		return reject("IO_PATH", "entry %q escapes the directory", name)
	}
	return err
}

type errStreamTooLong struct{}

func (*errStreamTooLong) Error() string { return "stream exceeds its limit" }

// limitedReader fails (rather than reporting EOF) once more than n bytes
// were asked for, so a cut-off stream and an over-long one can be told apart.
type limitedReader struct {
	r io.Reader
	n int64
}

func (l *limitedReader) Read(p []byte) (int, error) {
	if l.n <= 0 {
		return 0, &errStreamTooLong{}
	}
	if int64(len(p)) > l.n {
		p = p[:l.n]
	}
	n, err := l.r.Read(p)
	l.n -= int64(n)
	return n, err
}

// SendTree writes the regular files and directories under root/names as a
// tar stream (names relative to root, slash-separated; parents of a nested
// name are written first). Symlinks and other non-regular entries are left
// out and counted in skipped. The worker sends a scan's input with it; the
// result is refused when it exceeds l, before the Pod would refuse it.
func SendTree(w io.Writer, root string, names []string, l Limits) (st Stats, skipped int, err error) {
	tw := tar.NewWriter(w)
	written := map[string]bool{}
	entries := 0
	addDir := func(name string) error {
		if written[name] {
			return nil
		}
		written[name] = true
		if entries++; entries > l.MaxEntries {
			return reject("IO_TOO_MANY", "more than %d entries", l.MaxEntries)
		}
		st.Dirs++
		return tw.WriteHeader(&tar.Header{Typeflag: tar.TypeDir, Name: name + "/", Mode: 0o755})
	}
	for _, n := range names {
		clean, err := cleanName(n)
		if err != nil || clean == "" {
			return st, skipped, fmt.Errorf("sandboxio: bad name %q", n)
		}
		parts := strings.Split(clean, "/")
		for i := 1; i < len(parts); i++ {
			if err := addDir(strings.Join(parts[:i], "/")); err != nil {
				return st, skipped, err
			}
		}
		base := filepath.Join(root, filepath.FromSlash(clean))
		err = filepath.WalkDir(base, func(p string, d fs.DirEntry, err error) error {
			if err != nil {
				return err
			}
			rel, err := filepath.Rel(root, p)
			if err != nil {
				return err
			}
			name := filepath.ToSlash(rel)
			switch {
			case d.IsDir():
				return addDir(name)
			case d.Type().IsRegular():
				if entries++; entries > l.MaxEntries {
					return reject("IO_TOO_MANY", "more than %d entries", l.MaxEntries)
				}
				n, err := sendFile(tw, p, name, l.MaxBytes-st.Bytes)
				if err != nil {
					return err
				}
				st.Files++
				st.Bytes += n
			default:
				skipped++
			}
			return nil
		})
		if err != nil {
			return st, skipped, err
		}
	}
	return st, skipped, tw.Close()
}

// sendFile writes one regular file of at most room bytes. It is opened
// without following a symlink and checked again after opening.
func sendFile(tw *tar.Writer, p, name string, room int64) (int64, error) {
	f, err := os.OpenFile(p, os.O_RDONLY|syscall.O_NOFOLLOW, 0)
	if err != nil {
		return 0, err
	}
	defer f.Close()
	fi, err := f.Stat()
	if err != nil {
		return 0, err
	}
	if !fi.Mode().IsRegular() {
		return 0, reject("IO_TYPE", "%q is not a regular file", name)
	}
	if fi.Size() > room {
		return 0, reject("IO_TOO_LARGE", "content exceeds the limit at %q", name)
	}
	if err := tw.WriteHeader(&tar.Header{Typeflag: tar.TypeReg, Name: name, Mode: 0o644, Size: fi.Size()}); err != nil {
		return 0, err
	}
	// Exactly the size in the header: a file that changed underneath fails
	// the stream instead of corrupting it.
	if _, err := io.CopyN(tw, f, fi.Size()); err != nil {
		return 0, err
	}
	return fi.Size(), nil
}

// SendFiles writes the named top-level regular files of dir, each at most its
// cap, as a tar stream: a Pod's /out going back to the worker. A missing,
// non-regular (a symlink is not followed) or oversized file is left out, as
// the docker backend leaves out such an artifact; the worker then finds no
// SARIF and fails the tool. Names are sent in sorted order.
func SendFiles(w io.Writer, dir string, files map[string]int64) (Stats, error) {
	var st Stats
	root, err := os.OpenRoot(dir)
	if err != nil {
		return st, err
	}
	defer root.Close()
	names := make([]string, 0, len(files))
	for n := range files {
		if c, err := cleanName(n); err != nil || n == "" || c != n || strings.Contains(n, "/") {
			return st, fmt.Errorf("sandboxio: bad file name %q", n)
		}
		names = append(names, n)
	}
	sort.Strings(names)
	tw := tar.NewWriter(w)
	for _, n := range names {
		f, err := root.OpenFile(n, os.O_RDONLY|syscall.O_NOFOLLOW, 0)
		if err != nil {
			continue // missing, or a symlink (ELOOP)
		}
		fi, err := f.Stat()
		if err != nil || !fi.Mode().IsRegular() || fi.Size() > files[n] {
			f.Close()
			continue
		}
		err = tw.WriteHeader(&tar.Header{Typeflag: tar.TypeReg, Name: n, Mode: 0o644, Size: fi.Size()})
		if err == nil {
			_, err = io.CopyN(tw, f, fi.Size())
		}
		f.Close()
		if err != nil {
			return st, err
		}
		st.Files++
		st.Bytes += fi.Size()
	}
	return st, tw.Close()
}

// Plan sizes what SendTree would send of root/names: the content, the entry
// count, and the space it takes on a file system with 4 KiB blocks (each file
// and directory rounded up), which is what an emptyDir's sizeLimit measures.
func Plan(root string, names []string) (st Stats, disk int64, err error) {
	const block = 4096
	for _, n := range names {
		clean, err := cleanName(n)
		if err != nil || clean == "" {
			return st, 0, fmt.Errorf("sandboxio: bad name %q", n)
		}
		st.Dirs += strings.Count(clean, "/")
		disk += int64(strings.Count(clean, "/")) * block
		err = filepath.WalkDir(filepath.Join(root, filepath.FromSlash(clean)), func(p string, d fs.DirEntry, err error) error {
			if err != nil {
				return err
			}
			switch {
			case d.IsDir():
				st.Dirs++
				disk += block
			case d.Type().IsRegular():
				fi, err := d.Info()
				if err != nil {
					return err
				}
				st.Files++
				st.Bytes += fi.Size()
				disk += (fi.Size() + block - 1) / block * block
				if fi.Size() == 0 {
					disk += block // the inode's share, roughly
				}
			}
			return nil
		})
		if err != nil {
			return st, 0, err
		}
	}
	return st, disk, nil
}

// Entries is Files + Dirs.
func (s Stats) Entries() int { return s.Files + s.Dirs }

// FileNames lists the top-level regular files directly in dir (Lstat: a
// symlink is not one), sorted. Tests and the worker use it to check what a
// Receive left.
func FileNames(dir string) ([]string, error) {
	ents, err := os.ReadDir(dir)
	if err != nil {
		return nil, err
	}
	var out []string
	for _, e := range ents {
		if e.Type().IsRegular() {
			out = append(out, e.Name())
		}
	}
	slices.Sort(out)
	return out, nil
}
