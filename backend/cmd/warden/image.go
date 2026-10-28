package main

import (
	"context"
	"errors"
	"fmt"
	"os/exec"
	"path/filepath"
	"strings"
)

// Image scans: `warden scan --image REF` runs `docker save REF` and uploads
// the tarball; `--image-tar FILE --target REPO` uploads a tarball made
// elsewhere. Issues are tracked per target (the repository without tag or
// digest), so each image keeps its own issues, apart from the source's.

// dockerSave writes `docker save ref` to dest. ref is passed as one argv
// element (no shell), and refs starting with "-" are refused before this.
func dockerSave(ctx context.Context, ref, dest string) error {
	cmd := exec.CommandContext(ctx, "docker", "save", "--output", dest, ref)
	out, err := cmd.CombinedOutput()
	if err != nil {
		msg := strings.TrimSpace(string(out))
		if len(msg) > 300 {
			msg = msg[:300]
		}
		return fmt.Errorf("docker save: %w: %s", err, msg)
	}
	return nil
}

// imageTarget derives the target from an image reference: the tag and digest
// are dropped and Docker Hub names are written out in full, the way Docker
// resolves them ("alpine" and "docker.io/alpine" are docker.io/library/alpine;
// "acme/api" is docker.io/acme/api; index.docker.io is docker.io), so one image
// keeps one target however it is spelled. Other registries are kept as given.
func imageTarget(ref string) (string, error) {
	r := strings.TrimSpace(ref)
	if r == "" || strings.HasPrefix(r, "-") || strings.ContainsFunc(r, func(c rune) bool { return c <= ' ' || c == 0x7f }) {
		return "", errors.New("must be an image reference such as ghcr.io/acme/api:1.2")
	}
	if i := strings.IndexByte(r, '@'); i >= 0 {
		r = r[:i]
	}
	if i := strings.LastIndexByte(r, ':'); i > strings.LastIndexByte(r, '/') {
		r = r[:i] // a tag, not a registry port
	}
	parts := strings.Split(r, "/")
	first := parts[0]
	hasRegistry := len(parts) > 1 && (strings.ContainsAny(first, ".:") || first == "localhost")
	switch {
	case !hasRegistry:
		parts = append([]string{"docker.io"}, parts...)
	case first == "index.docker.io" || first == "registry-1.docker.io":
		parts[0] = "docker.io"
	}
	if parts[0] == "docker.io" && len(parts) == 2 {
		parts = []string{"docker.io", "library", parts[1]}
	}
	t := strings.ToLower(strings.Join(parts, "/"))
	if len(t) > 255 || strings.Contains(t, "//") {
		return "", errors.New("must be an image reference such as ghcr.io/acme/api:1.2")
	}
	return t, nil
}

// tarName is the upload's file name: the target's last component.
func tarName(target string) string {
	return archiveName(filepath.Base(target)) + ".tar"
}

// imageProblems checks the image flags; set names the flags given.
func (o *options) imageProblems(set map[string]bool) []string {
	var p []string
	switch {
	case o.image != "" && o.imageTar != "":
		return []string{"--image and --image-tar: give one"}
	case o.image == "" && o.imageTar == "":
		for _, f := range []string{"target", "image-ref"} {
			if set[f] {
				p = append(p, "--"+f+": only with --image or --image-tar")
			}
		}
		return p
	}
	if set["dir"] {
		p = append(p, "--dir: not with --image or --image-tar")
	}
	if o.image != "" {
		if set["image-ref"] {
			p = append(p, "--image-ref: only with --image-tar (--image is the reference)")
		}
		t, err := imageTarget(o.image)
		if err != nil {
			return append(p, "--image: "+err.Error())
		}
		o.imageRef = strings.TrimSpace(o.image)
		if o.target == "" {
			o.target = t
		}
	}
	if o.imageTar != "" && o.target == "" {
		p = append(p, "--target: required with --image-tar (the image repository, e.g. ghcr.io/acme/api)")
	}
	return p
}

// imageArtifact writes (or locates) the tarball to upload and the request
// fields that make the scan an image scan.
func (c client) imageArtifact(ctx context.Context, tmp string) (string, map[string]any, error) {
	p := c.o.imageTar
	if c.o.image != "" {
		p = filepath.Join(tmp, "image.tar")
		c.printf("==> docker save %s\n", clean(c.o.image))
		if err := c.d.save(ctx, c.o.image, p); err != nil {
			return "", nil, err
		}
	}
	body := map[string]any{"kind": "image", "file_name": tarName(c.o.target), "target": c.o.target}
	if c.o.imageRef != "" {
		body["image_ref"] = c.o.imageRef
	}
	return p, body, nil
}
