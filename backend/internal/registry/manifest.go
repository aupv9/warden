package registry

import (
	"bytes"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"mime"
	"regexp"
	"slices"
)

const (
	// MaxManifestBytes caps a manifest or index, and an image config (the
	// OCI distribution spec's suggested registry limit).
	MaxManifestBytes = 4 << 20
	// MaxLayers caps an image's layers (imagecheck allows 256 in an upload).
	MaxLayers = 128
	// maxBlobBytes bounds any descriptor's size before the pull budget is
	// applied, so sums of up to MaxLayers+1 sizes can't overflow.
	maxBlobBytes = 1 << 40
	// maxIndexEntries bounds a multi-platform index.
	maxIndexEntries = 1024
)

// Media types Warden pulls.
const (
	mtOCIIndex       = "application/vnd.oci.image.index.v1+json"
	mtDockerList     = "application/vnd.docker.distribution.manifest.list.v2+json"
	mtOCIManifest    = "application/vnd.oci.image.manifest.v1+json"
	mtDockerManifest = "application/vnd.docker.distribution.manifest.v2+json"
	mtOCIConfig      = "application/vnd.oci.image.config.v1+json"
	mtDockerConfig   = "application/vnd.docker.container.image.v1+json"
)

// manifestAccept is the Accept header of manifest requests: images and
// indexes, never Docker's schema 1 (signed, unverifiable by digest).
var manifestAccept = []string{mtOCIIndex, mtDockerList, mtOCIManifest, mtDockerManifest}

// layerTypes are the layer media types Warden pulls: tar, gzip and zstd.
// Foreign and non-distributable layers (fetched from URLs other than the
// registry) are refused.
var layerTypes = []string{
	"application/vnd.oci.image.layer.v1.tar",
	"application/vnd.oci.image.layer.v1.tar+gzip",
	"application/vnd.oci.image.layer.v1.tar+zstd",
	"application/vnd.docker.image.rootfs.diff.tar.gzip",
}

var sha256Digest = regexp.MustCompile(`^sha256:[0-9a-f]{64}$`)

type docKind int

const (
	kindImage docKind = iota + 1
	kindIndex
)

type platform struct {
	OS           string `json:"os"`
	Architecture string `json:"architecture"`
	Variant      string `json:"variant"`
}

type descriptor struct {
	MediaType string    `json:"mediaType"`
	Digest    string    `json:"digest"`
	Size      int64     `json:"size"`
	URLs      []string  `json:"urls"`
	Platform  *platform `json:"platform"`
}

// document is an image manifest or an index, as a registry sent it.
type document struct {
	SchemaVersion int          `json:"schemaVersion"`
	MediaType     string       `json:"mediaType"`
	Config        *descriptor  `json:"config"`
	Layers        []descriptor `json:"layers"`
	Manifests     []descriptor `json:"manifests"`
	kind          docKind
}

func isManifestType(mt string) bool { return mt == mtOCIManifest || mt == mtDockerManifest }
func isIndexType(mt string) bool    { return mt == mtOCIIndex || mt == mtDockerList }

// parseDocument reads a manifest or index. Its kind comes from its own
// mediaType, else the Content-Type, else its shape; the two may not disagree.
// An image manifest must be fully valid (checkImage); an index only well
// formed, since only the selected entry is fetched.
func parseDocument(raw []byte, contentType string) (*document, error) {
	var d document
	dec := json.NewDecoder(bytes.NewReader(raw))
	if err := dec.Decode(&d); err != nil {
		return nil, fmt.Errorf("manifest: %v", err)
	}
	if _, err := dec.Token(); !errors.Is(err, io.EOF) {
		return nil, errors.New("manifest: trailing data")
	}
	if d.SchemaVersion != 2 {
		return nil, fmt.Errorf("manifest: schemaVersion %d (only 2 is supported)", d.SchemaVersion)
	}
	ct, _, _ := mime.ParseMediaType(contentType)
	known := func(mt string) bool { return isManifestType(mt) || isIndexType(mt) }
	mt := d.MediaType
	switch {
	case mt != "" && !known(mt):
		return nil, fmt.Errorf("manifest: unsupported media type %q", mt)
	case mt != "" && known(ct) && ct != mt:
		return nil, fmt.Errorf("manifest: media type %q but Content-Type %q", mt, ct)
	case mt == "" && known(ct):
		mt = ct
	}
	switch {
	case isIndexType(mt) || (mt == "" && d.Manifests != nil && d.Config == nil):
		d.kind = kindIndex
	case isManifestType(mt) || (mt == "" && d.Config != nil && d.Manifests == nil):
		d.kind = kindImage
	default:
		return nil, errors.New("manifest: neither an image manifest nor an index")
	}
	if d.kind == kindIndex {
		if d.Config != nil || d.Layers != nil {
			return nil, errors.New("index: has config or layers")
		}
		if len(d.Manifests) == 0 || len(d.Manifests) > maxIndexEntries {
			return nil, fmt.Errorf("index: %d entries", len(d.Manifests))
		}
		return &d, nil
	}
	if d.Manifests != nil {
		return nil, errors.New("manifest: has manifests")
	}
	return &d, nil
}

// checkDescriptor: a sha256 digest, a size in (0, maxBlobBytes], no URLs.
func checkDescriptor(d descriptor, what string) error {
	if !sha256Digest.MatchString(d.Digest) {
		return fmt.Errorf("%s: unsupported digest %q", what, truncate(d.Digest))
	}
	if d.Size <= 0 || d.Size > maxBlobBytes {
		return fmt.Errorf("%s: size %d", what, d.Size)
	}
	if len(d.URLs) > 0 {
		return fmt.Errorf("%s: foreign layer (urls)", what)
	}
	return nil
}

// tooLarge marks a check failure that is about size (CodeTooLarge).
type tooLarge struct{ error }

// checkImage validates an image manifest: an image config, 1..MaxLayers
// layers of supported types, every descriptor well formed.
func checkImage(d *document) error {
	if d.kind != kindImage || d.Config == nil {
		return errors.New("not an image manifest")
	}
	if err := checkDescriptor(*d.Config, "config"); err != nil {
		return err
	}
	if d.Config.MediaType != mtOCIConfig && d.Config.MediaType != mtDockerConfig {
		return fmt.Errorf("config: media type %q is not an image config (an artifact?)", truncate(d.Config.MediaType))
	}
	if d.Config.Size > MaxManifestBytes {
		return tooLarge{fmt.Errorf("config: %d bytes", d.Config.Size)}
	}
	switch n := len(d.Layers); {
	case n == 0:
		return errors.New("the image has no layers")
	case n > MaxLayers:
		return tooLarge{fmt.Errorf("the image has %d layers (at most %d)", n, MaxLayers)}
	}
	for i, l := range d.Layers {
		what := fmt.Sprintf("layer %d", i)
		if err := checkDescriptor(l, what); err != nil {
			return err
		}
		if !slices.Contains(layerTypes, l.MediaType) {
			return fmt.Errorf("%s: unsupported media type %q", what, truncate(l.MediaType))
		}
	}
	return nil
}

// errNoPlatform: the index has no image for the platform (CodePlatform).
var errNoPlatform = errors.New("no image for the platform")

// selectPlatform picks the index entry for p: an image manifest whose
// platform matches exactly, else (no variant asked) the architecture's
// default variant.
func selectPlatform(d *document, p Platform) (descriptor, error) {
	var fallback *descriptor
	for i := range d.Manifests {
		m := d.Manifests[i]
		if !isManifestType(m.MediaType) || m.Platform == nil ||
			m.Platform.OS != p.OS || m.Platform.Architecture != p.Arch {
			continue
		}
		v := m.Platform.Variant
		if v == p.Variant {
			return m, checkDescriptor(m, "index entry")
		}
		if p.Variant == "" && v == defaultVariant[p.Arch] && fallback == nil {
			fallback = &d.Manifests[i]
		} else if p.Variant == defaultVariant[p.Arch] && v == "" && fallback == nil {
			fallback = &d.Manifests[i]
		}
	}
	if fallback != nil {
		return *fallback, checkDescriptor(*fallback, "index entry")
	}
	return descriptor{}, errNoPlatform
}

// defaultVariant: what an index entry without a variant means (and the
// reverse), as container runtimes read it.
var defaultVariant = map[string]string{"arm64": "v8", "arm": "v7"}

// truncate keeps hostile strings short in errors and logs.
func truncate(s string) string {
	const n = 80
	if len(s) > n {
		return s[:n] + "…"
	}
	return s
}
