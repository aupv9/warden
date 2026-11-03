package registry

import (
	"strings"
	"testing"
)

// FuzzParseDocument: whatever a registry sends, parsing never panics, and
// what it accepts holds the invariants the pull relies on.
func FuzzParseDocument(f *testing.F) {
	d := "sha256:" + strings.Repeat("ab", 32)
	f.Add([]byte(`{"schemaVersion":2,"mediaType":"`+mtDockerManifest+`","config":{"mediaType":"`+mtDockerConfig+`","digest":"`+d+`","size":10},"layers":[{"mediaType":"application/vnd.docker.image.rootfs.diff.tar.gzip","digest":"`+d+`","size":5}]}`), mtDockerManifest)
	f.Add([]byte(`{"schemaVersion":2,"manifests":[{"mediaType":"`+mtOCIManifest+`","digest":"`+d+`","size":10,"platform":{"os":"linux","architecture":"amd64"}}]}`), mtOCIIndex)
	f.Add([]byte(`{"schemaVersion":2,"config":{"digest":"`+d+`","size":-1},"layers":[{"urls":["http://x"]}]}`), "")
	f.Add([]byte(`{"schemaVersion":2,"mediaType":"`+mtOCIIndex+`","config":{}}`), mtDockerManifest+"; charset=utf-8")
	f.Add([]byte(`{"schemaVersion":1}`), "application/vnd.docker.distribution.manifest.v1+prettyjws")
	f.Fuzz(func(t *testing.T, raw []byte, ct string) {
		doc, err := parseDocument(raw, ct)
		if err != nil {
			return
		}
		switch doc.kind {
		case kindIndex:
			if doc.Config != nil || doc.Layers != nil || len(doc.Manifests) == 0 || len(doc.Manifests) > maxIndexEntries {
				t.Fatalf("bad index accepted: %+v", doc)
			}
			for _, p := range []Platform{{OS: "linux", Arch: "amd64"}, {OS: "linux", Arch: "arm64"}, {OS: "linux", Arch: "arm64", Variant: "v8"}} {
				m, err := selectPlatform(doc, p)
				if err != nil {
					continue
				}
				if !isManifestType(m.MediaType) || !sha256Digest.MatchString(m.Digest) || m.Size <= 0 || m.Size > maxBlobBytes ||
					m.Platform == nil || m.Platform.OS != p.OS || m.Platform.Architecture != p.Arch {
					t.Fatalf("bad entry selected for %v: %+v", p, m)
				}
			}
		case kindImage:
			if doc.Manifests != nil {
				t.Fatal("image with manifests")
			}
			if err := checkImage(doc); err != nil {
				return
			}
			if len(doc.Layers) == 0 || len(doc.Layers) > MaxLayers || doc.Config.Size > MaxManifestBytes {
				t.Fatalf("bad image accepted: %+v", doc)
			}
			var total int64
			for _, b := range append([]descriptor{*doc.Config}, doc.Layers...) {
				if !sha256Digest.MatchString(b.Digest) || b.Size <= 0 || b.Size > maxBlobBytes || len(b.URLs) > 0 {
					t.Fatalf("bad descriptor accepted: %+v", b)
				}
				total += b.Size
				if total < 0 {
					t.Fatal("size overflow")
				}
			}
			for _, b := range uniqueBlobs(doc) {
				if n := blobName(b.Digest); strings.Contains(n, "..") || !strings.HasPrefix(n, "blobs/sha256/") || len(n) != len("blobs/sha256/")+64 {
					t.Fatal(n)
				}
			}
		default:
			t.Fatalf("kind %d", doc.kind)
		}
	})
}

// FuzzParseChallenges: hostile WWW-Authenticate headers never panic and
// yield only named schemes.
func FuzzParseChallenges(f *testing.F) {
	f.Add(`Bearer realm="https://auth.docker.io/token",service="registry.docker.io"`)
	f.Add(`Basic realm="x", Negotiate abc==`)
	f.Add(`Bearer realm="\`)
	f.Fuzz(func(t *testing.T, h string) {
		for _, c := range parseChallenges([]string{h}) {
			if c.scheme == "" || c.params == nil {
				t.Fatalf("%+v", c)
			}
		}
	})
}
