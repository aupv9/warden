// Package imagecheck validates an uploaded `docker save` tarball before Trivy
// reads it. The tarball is hostile input and is never extracted (zipcheck
// stays the only place that extracts): the tar is streamed, entries must be
// regular files or directories with safe names (archpath, the zip rules),
// and the manifest must describe exactly one image whose config and layers
// are all in the tarball.
//
// Two layouts are accepted: Docker's (manifest.json; layers as <id>/layer.tar
// or blobs/sha256/<hex>), and the OCI image layout (oci-layout, index.json and
// blobs/sha256/<hex>) used without a manifest.json. Docker 25+ writes both;
// then manifest.json, which Trivy reads first, is the one checked.
package imagecheck

import (
	"archive/tar"
	"bytes"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"os"
	"path"
	"regexp"

	"github.com/aupv9/warden/backend/internal/scan/archpath"
)

const (
	MaxEntries       = 4096
	MaxLayers        = 256
	MaxManifestBytes = 1 << 20
	// maxIndexDepth: index.json -> (manifest list ->) image manifest.
	maxIndexDepth = 2
)

// Error codes (scan.error_code).
const (
	// CodeInvalid: not a `docker save` tarball Warden accepts: unreadable tar,
	// unsafe or duplicate names, links or special files, a bad or oversized
	// manifest, or a config or layer missing from the tarball.
	CodeInvalid = "IMAGE_INVALID"
	// CodeTooLarge: over scan.image_upload_max_mb, or more than MaxEntries
	// entries or MaxLayers layers.
	CodeTooLarge = "IMAGE_TOO_LARGE"
	// CodeMultiple: the tarball holds more than one image (save one at a time).
	CodeMultiple = "IMAGE_MULTIPLE"
)

// Rejected carries a stable error code; Detail is for logs only.
type Rejected struct {
	Code   string
	Detail string
}

func (e *Rejected) Error() string { return e.Code + ": " + e.Detail }

func reject(code, format string, args ...any) *Rejected {
	return &Rejected{Code: code, Detail: fmt.Sprintf(format, args...)}
}

type Limits struct {
	MaxBytes int64
}

type Result struct {
	Layout string // "docker" or "oci"
	Layers int
}

var digest = regexp.MustCompile(`^sha256:([0-9a-f]{64})$`)

// entry is a regular file of the tarball.
type entry struct {
	size int64
}

// Check validates the tarball at p.
func Check(p string, limits Limits) (*Result, error) {
	st, err := os.Stat(p)
	if err != nil {
		return nil, err
	}
	if st.Size() > limits.MaxBytes {
		return nil, reject(CodeTooLarge, "tarball is %d bytes", st.Size())
	}
	small := map[string]bool{"manifest.json": true, "index.json": true, "oci-layout": true}
	files, contents, err := scan(p, small)
	if err != nil {
		return nil, err
	}
	if raw, ok := contents["manifest.json"]; ok {
		return checkDocker(raw, files)
	}
	if raw, ok := contents["index.json"]; ok {
		if _, ok := files["oci-layout"]; !ok {
			return nil, reject(CodeInvalid, "index.json without oci-layout")
		}
		return checkOCI(p, raw, files)
	}
	return nil, reject(CodeInvalid, "no manifest.json or index.json: not a docker save tarball")
}

// scan streams the tarball once: it checks every header and returns the
// regular files by cleaned name, plus the content of those in read (each at
// most MaxManifestBytes).
func scan(p string, read map[string]bool) (map[string]entry, map[string][]byte, error) {
	f, err := os.Open(p)
	if err != nil {
		return nil, nil, err
	}
	defer f.Close()
	tr := tar.NewReader(f)
	files := map[string]entry{}
	dirs := map[string]bool{}
	contents := map[string][]byte{}
	for n := 0; ; n++ {
		hdr, err := tr.Next()
		if errors.Is(err, io.EOF) {
			break
		}
		if err != nil {
			return nil, nil, reject(CodeInvalid, "unreadable tar: %v", err)
		}
		if n >= MaxEntries {
			return nil, nil, reject(CodeTooLarge, "more than %d entries", MaxEntries)
		}
		parts, err := archpath.Clean(hdr.Name)
		if err != nil {
			return nil, nil, reject(CodeInvalid, "%v", err)
		}
		name := path.Join(parts...)
		switch hdr.Typeflag {
		case tar.TypeDir:
			if name == "" {
				continue
			}
			if _, ok := files[name]; ok || dirs[name] {
				return nil, nil, reject(CodeInvalid, "duplicate entry %q", name)
			}
			dirs[name] = true
		case tar.TypeReg:
			if name == "" {
				return nil, nil, reject(CodeInvalid, "file entry without a name")
			}
			if _, ok := files[name]; ok || dirs[name] {
				return nil, nil, reject(CodeInvalid, "duplicate entry %q", name)
			}
			files[name] = entry{size: hdr.Size}
			if read[name] {
				if hdr.Size > MaxManifestBytes {
					return nil, nil, reject(CodeInvalid, "%s larger than %d bytes", name, MaxManifestBytes)
				}
				b, err := io.ReadAll(io.LimitReader(tr, MaxManifestBytes+1))
				if err != nil {
					return nil, nil, reject(CodeInvalid, "unreadable %s: %v", name, err)
				}
				contents[name] = b
			}
		default:
			// Symlinks and hard links could point Trivy at other entries (or
			// outside the image); devices and FIFOs have no place in a save.
			return nil, nil, reject(CodeInvalid, "entry %q is not a regular file or directory (type %q)", name, hdr.Typeflag)
		}
	}
	return files, contents, nil
}

// decode reads one JSON value of the expected shape; anything else is invalid.
func decode(raw []byte, v any, what string) error {
	dec := json.NewDecoder(bytes.NewReader(raw))
	if err := dec.Decode(v); err != nil {
		return reject(CodeInvalid, "%s: %v", what, err)
	}
	if _, err := dec.Token(); !errors.Is(err, io.EOF) {
		return reject(CodeInvalid, "%s: trailing data", what)
	}
	return nil
}

// present checks that a manifest's reference is a safe name of a regular file.
func present(files map[string]entry, ref, what string) error {
	parts, err := archpath.Clean(ref)
	if err != nil || len(parts) == 0 {
		return reject(CodeInvalid, "%s: bad path %q", what, ref)
	}
	if _, ok := files[path.Join(parts...)]; !ok {
		return reject(CodeInvalid, "%s %q is not in the tarball", what, ref)
	}
	return nil
}

func checkDocker(raw []byte, files map[string]entry) (*Result, error) {
	var manifest []struct {
		Config string   `json:"Config"`
		Layers []string `json:"Layers"`
	}
	if err := decode(raw, &manifest, "manifest.json"); err != nil {
		return nil, err
	}
	switch {
	case len(manifest) == 0:
		return nil, reject(CodeInvalid, "manifest.json lists no image")
	case len(manifest) > 1:
		return nil, reject(CodeMultiple, "manifest.json lists %d images", len(manifest))
	}
	m := manifest[0]
	if err := present(files, m.Config, "config"); err != nil {
		return nil, err
	}
	if err := checkLayers(len(m.Layers)); err != nil {
		return nil, err
	}
	for _, l := range m.Layers {
		if err := present(files, l, "layer"); err != nil {
			return nil, err
		}
	}
	return &Result{Layout: "docker", Layers: len(m.Layers)}, nil
}

func checkLayers(n int) error {
	if n == 0 {
		return reject(CodeInvalid, "the image has no layers")
	}
	if n > MaxLayers {
		return reject(CodeTooLarge, "the image has %d layers (at most %d)", n, MaxLayers)
	}
	return nil
}

type descriptor struct {
	Digest string `json:"digest"`
}

// ociDoc is an image index (manifests) or an image manifest (config, layers).
type ociDoc struct {
	Manifests []descriptor `json:"manifests"`
	Config    *descriptor  `json:"config"`
	Layers    []descriptor `json:"layers"`
}

func blobPath(d descriptor) (string, bool) {
	m := digest.FindStringSubmatch(d.Digest)
	if m == nil {
		return "", false
	}
	return "blobs/sha256/" + m[1], true
}

// checkOCI follows index.json to exactly one image manifest whose blobs are
// all present. A manifest list may name other platforms' manifests that
// docker save leaves out; exactly one of its entries must be present.
func checkOCI(p string, raw []byte, files map[string]entry) (*Result, error) {
	var doc ociDoc
	if err := decode(raw, &doc, "index.json"); err != nil {
		return nil, err
	}
	for depth := 0; ; depth++ {
		if doc.Config != nil {
			break // an image manifest
		}
		if depth >= maxIndexDepth {
			return nil, reject(CodeInvalid, "index nested deeper than %d", maxIndexDepth)
		}
		var here []string
		for _, d := range doc.Manifests {
			bp, ok := blobPath(d)
			if !ok {
				return nil, reject(CodeInvalid, "bad digest %q", d.Digest)
			}
			if _, ok := files[bp]; ok {
				here = append(here, bp)
			}
		}
		// The top-level index names each saved image; a manifest list names
		// platforms, of which docker save keeps one.
		if depth == 0 && len(doc.Manifests) > 1 {
			return nil, reject(CodeMultiple, "index.json lists %d images", len(doc.Manifests))
		}
		switch {
		case len(here) == 0:
			return nil, reject(CodeInvalid, "no manifest of the index is in the tarball")
		case len(here) > 1:
			return nil, reject(CodeMultiple, "the tarball holds %d image manifests", len(here))
		}
		if files[here[0]].size > MaxManifestBytes {
			return nil, reject(CodeInvalid, "manifest larger than %d bytes", MaxManifestBytes)
		}
		_, contents, err := scan(p, map[string]bool{here[0]: true})
		if err != nil {
			return nil, err
		}
		doc = ociDoc{}
		if err := decode(contents[here[0]], &doc, "manifest "+here[0]); err != nil {
			return nil, err
		}
	}
	bp, ok := blobPath(*doc.Config)
	if !ok {
		return nil, reject(CodeInvalid, "bad config digest %q", doc.Config.Digest)
	}
	if err := present(files, bp, "config"); err != nil {
		return nil, err
	}
	if err := checkLayers(len(doc.Layers)); err != nil {
		return nil, err
	}
	for _, l := range doc.Layers {
		bp, ok := blobPath(l)
		if !ok {
			return nil, reject(CodeInvalid, "bad layer digest %q", l.Digest)
		}
		if err := present(files, bp, "layer"); err != nil {
			return nil, err
		}
	}
	return &Result{Layout: "oci", Layers: len(doc.Layers)}, nil
}
