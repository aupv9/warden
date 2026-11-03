package registry

import (
	"archive/tar"
	"context"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net/http"
	"os"
	"strings"
	"time"
)

// Limits bound one pull.
type Limits struct {
	// MaxBytes caps everything fetched from the registry, manifests and
	// blobs as sent (scan.pull_max_mb).
	MaxBytes int64
}

// Result describes a pulled image (for logs).
type Result struct {
	// Manifest is the digest of the image manifest written; it differs from
	// the reference's digest when that names an index.
	Manifest string
	// Platform is the index entry's platform, "" when the reference named an
	// image manifest.
	Platform string
	Layers   int
	// Bytes is what was fetched (manifests and blobs).
	Bytes int64
}

// TarOverhead bounds what the tarball adds to the pulled bytes (headers,
// padding, manifest.json), for imagecheck's size limit.
const TarOverhead = (MaxLayers+2)*2*512 + 64<<10

// Pull fetches ref (resolving an index to plat), verifies every manifest and
// blob against its digest, and writes a `docker save` tarball to dest, which
// must not exist: manifest.json naming the config and the layers, stored as
// blobs/sha256/<hex> exactly as sent (compressed; Warden never unpacks them,
// Trivy and Gitleaks read them in the sandbox). creds may be nil (anonymous).
// On error dest may be left partly written; the caller removes it (the
// scan's scratch directory).
func (c *Client) Pull(ctx context.Context, ref Ref, creds *Credentials, plat Platform, lim Limits, dest string) (*Result, error) {
	s := c.session(ref.Host, creds, "repository:"+ref.apiRepository()+":pull")
	defer s.close()
	p := &puller{s: s, repo: ref.apiRepository(), budget: lim.MaxBytes}

	top, n, err := p.manifest(ctx, ref.Digest, MaxManifestBytes)
	if err != nil {
		return nil, err
	}
	res := &Result{Manifest: ref.Digest}
	img := top
	if top.kind == kindIndex {
		d, err := selectPlatform(top, plat)
		if errors.Is(err, errNoPlatform) {
			return nil, fail(CodePlatform, "the index has no image for "+plat.String())
		}
		if err != nil {
			return nil, fail(CodeFailed, err.Error())
		}
		if d.Size > MaxManifestBytes {
			return nil, fail(CodeTooLarge, fmt.Sprintf("image manifest of %d bytes", d.Size))
		}
		var m int64
		if img, m, err = p.manifest(ctx, d.Digest, d.Size); err != nil {
			return nil, err
		}
		if m != d.Size {
			return nil, fail(CodeFailed, "image manifest size differs from the index")
		}
		if img.kind != kindImage {
			return nil, fail(CodeFailed, "the index entry is not an image manifest")
		}
		n += m
		res.Manifest, res.Platform = d.Digest, plat.String()
	}
	if err := checkImage(img); err != nil {
		var tl tooLarge
		if errors.As(err, &tl) {
			return nil, fail(CodeTooLarge, err.Error())
		}
		return nil, fail(CodeFailed, err.Error())
	}
	// Refuse what can't fit before fetching any of it.
	blobs := uniqueBlobs(img)
	total := n
	for _, b := range blobs {
		total += b.Size
	}
	if total > lim.MaxBytes {
		return nil, fail(CodeTooLarge, fmt.Sprintf("the image is %d bytes (at most %d)", total, lim.MaxBytes))
	}
	if err := p.write(ctx, img, blobs, dest); err != nil {
		return nil, err
	}
	res.Layers, res.Bytes = len(img.Layers), lim.MaxBytes-p.budget
	return res, nil
}

type puller struct {
	s      *session
	repo   string
	budget int64 // bytes still allowed
}

func (p *puller) take(n int64) error {
	if n > p.budget {
		return fail(CodeTooLarge, "over scan.pull_max_mb")
	}
	p.budget -= n
	return nil
}

// manifest fetches the manifest or index named by digest (at most limit
// bytes) and verifies it hashes to digest.
func (p *puller) manifest(ctx context.Context, digest string, limit int64) (*document, int64, error) {
	resp, err := p.s.get(ctx, "/v2/"+p.repo+"/manifests/"+digest, manifestAccept)
	if err != nil {
		return nil, 0, err
	}
	if resp.StatusCode != http.StatusOK {
		return nil, 0, p.s.statusError(resp, "manifest "+digest)
	}
	defer resp.Body.Close()
	if resp.ContentLength > limit {
		return nil, 0, fail(CodeTooLarge, fmt.Sprintf("manifest of %d bytes", resp.ContentLength))
	}
	raw, err := io.ReadAll(io.LimitReader(resp.Body, limit+1))
	if err != nil {
		return nil, 0, p.readError(ctx, "manifest", err)
	}
	if int64(len(raw)) > limit {
		return nil, 0, fail(CodeTooLarge, "manifest over "+fmt.Sprint(limit)+" bytes")
	}
	if err := p.take(int64(len(raw))); err != nil {
		return nil, 0, err
	}
	sum := sha256.Sum256(raw)
	if "sha256:"+hex.EncodeToString(sum[:]) != digest {
		return nil, 0, fail(CodeFailed, "manifest digest mismatch for "+digest)
	}
	d, err := parseDocument(raw, resp.Header.Get("Content-Type"))
	if err != nil {
		return nil, 0, fail(CodeFailed, err.Error())
	}
	return d, int64(len(raw)), nil
}

func (p *puller) readError(ctx context.Context, what string, err error) *Error {
	if ctx.Err() != nil {
		return fail(CodeFailed, what+": "+ctx.Err().Error())
	}
	if errors.Is(err, context.Canceled) {
		return fail(CodeFailed, what+": stalled (no data within the idle timeout)")
	}
	return fail(CodeFailed, what+": "+redactURLError(err).Error())
}

// uniqueBlobs: the config, then each distinct layer (an image may repeat
// one; the tarball holds it once).
func uniqueBlobs(img *document) []descriptor {
	seen := map[string]bool{}
	var out []descriptor
	for _, d := range append([]descriptor{*img.Config}, img.Layers...) {
		if !seen[d.Digest] {
			seen[d.Digest] = true
			out = append(out, d)
		}
	}
	return out
}

func blobName(digest string) string { return "blobs/sha256/" + strings.TrimPrefix(digest, "sha256:") }

// write creates the tarball: every blob, then manifest.json.
func (p *puller) write(ctx context.Context, img *document, blobs []descriptor, dest string) (err error) {
	f, err := os.OpenFile(dest, os.O_WRONLY|os.O_CREATE|os.O_EXCL, 0o600)
	if err != nil {
		return err
	}
	defer func() {
		if cerr := f.Close(); err == nil && cerr != nil {
			err = cerr
		}
	}()
	tw := tar.NewWriter(f)
	for _, b := range blobs {
		if err := p.blob(ctx, b, tw); err != nil {
			return err
		}
	}
	layers := make([]string, len(img.Layers))
	for i, l := range img.Layers {
		layers[i] = blobName(l.Digest)
	}
	manifest, err := json.Marshal([]struct {
		Config   string   `json:"Config"`
		RepoTags []string `json:"RepoTags"`
		Layers   []string `json:"Layers"`
	}{{Config: blobName(img.Config.Digest), RepoTags: []string{}, Layers: layers}})
	if err != nil {
		return err
	}
	if err := tw.WriteHeader(header("manifest.json", int64(len(manifest)))); err != nil {
		return err
	}
	if _, err := tw.Write(manifest); err != nil {
		return err
	}
	return tw.Close()
}

func header(name string, size int64) *tar.Header {
	return &tar.Header{Name: name, Typeflag: tar.TypeReg, Mode: 0o644, Size: size, ModTime: time.Unix(0, 0)}
}

// blob streams one blob into the tarball, hashing it on the way: exactly
// d.Size bytes that hash to d.Digest, or the pull fails.
func (p *puller) blob(ctx context.Context, d descriptor, tw *tar.Writer) error {
	if err := p.take(d.Size); err != nil {
		return err
	}
	resp, err := p.s.get(ctx, "/v2/"+p.repo+"/blobs/"+d.Digest, nil)
	if err != nil {
		return err
	}
	if resp.StatusCode != http.StatusOK {
		e := p.s.statusError(resp, "blob "+d.Digest)
		if e.Code == CodeNotFound {
			e.Code = CodeFailed // the manifest names it: the registry is broken
		}
		return e
	}
	defer resp.Body.Close()
	if resp.ContentLength >= 0 && resp.ContentLength != d.Size {
		return fail(CodeFailed, fmt.Sprintf("blob %s: %d bytes sent, descriptor says %d", d.Digest, resp.ContentLength, d.Size))
	}
	if err := tw.WriteHeader(header(blobName(d.Digest), d.Size)); err != nil {
		return err
	}
	h := sha256.New()
	n, err := io.Copy(io.MultiWriter(tw, h), io.LimitReader(resp.Body, d.Size))
	if err != nil {
		var e *Error
		if errors.As(err, &e) {
			return e
		}
		return p.readError(ctx, "blob "+d.Digest, err)
	}
	if n != d.Size {
		return fail(CodeFailed, fmt.Sprintf("blob %s: %d bytes, descriptor says %d", d.Digest, n, d.Size))
	}
	// Anything past the size is never read or written.
	if "sha256:"+hex.EncodeToString(h.Sum(nil)) != d.Digest {
		return fail(CodeFailed, "blob digest mismatch for "+d.Digest)
	}
	return nil
}
