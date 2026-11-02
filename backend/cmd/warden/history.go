package main

import (
	"context"
	"errors"
	"fmt"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
)

// History scans: `warden scan --history` bundles every commit of the
// repository at --dir (`git bundle create --all`) and uploads it; the server
// runs Gitleaks over each commit, so a secret deleted long ago is found too.
// Issues are tracked under the target (history), apart from the source's.

// errShallow: a shallow clone lacks the older commits, and the server would
// refuse its bundle (BUNDLE_INCOMPLETE) after the upload; say so before.
var errShallow = errors.New("the repository is a shallow clone, so its history is incomplete; " +
	"fetch the full history first (GitHub Actions: actions/checkout with fetch-depth: 0; GitLab CI: GIT_DEPTH: 0; " +
	"elsewhere: git fetch --unshallow)")

// gitBundle writes a bundle of every ref of the repository at dir to dest.
// Arguments are separate argv elements (no shell); git, not Warden, reads the
// repository, as when the developer runs it.
func gitBundle(ctx context.Context, dir, dest string) error {
	out, err := gitOutput(ctx, dir, "rev-parse", "--is-shallow-repository")
	if err != nil {
		return err
	}
	if out == "true" {
		return errShallow
	}
	if _, err := gitOutput(ctx, dir, "bundle", "create", "--quiet", dest, "--all"); err != nil {
		return err
	}
	// The bundle holds the whole history: only this user may read it. Its
	// directory is the CLI's private temporary one (0700), removed after the upload.
	return os.Chmod(dest, 0o600)
}

func gitOutput(ctx context.Context, dir string, args ...string) (string, error) {
	cmd := exec.CommandContext(ctx, "git", append([]string{"-C", dir}, args...)...)
	var stderr strings.Builder
	cmd.Stderr = &stderr
	out, err := cmd.Output()
	if err != nil {
		msg := strings.TrimSpace(stderr.String())
		if len(msg) > 300 {
			msg = msg[:300]
		}
		return "", fmt.Errorf("git %s: %w: %s", args[0], err, msg)
	}
	return strings.TrimSpace(string(out)), nil
}

// historyProblems checks the flags that don't go with --history.
func (o *options) historyProblems(set map[string]bool) []string {
	if !o.history {
		return nil
	}
	var p []string
	if o.image != "" || o.imageTar != "" {
		p = append(p, "--history: not with --image or --image-tar")
	}
	if o.sbomOut != "" {
		p = append(p, "--sbom-out: history scans have no SBOM")
	}
	if set["tools"] && (len(o.tools) != 1 || o.tools[0] != "gitleaks") {
		p = append(p, "--tools: history scans run gitleaks only")
	}
	return p
}

// historyArtifact writes the bundle to upload and the request fields that
// make the scan a history scan.
func (c client) historyArtifact(ctx context.Context, tmp string) (string, map[string]any, error) {
	dir, err := filepath.Abs(c.o.dir)
	if err != nil {
		return "", nil, err
	}
	name := archiveName(dir)
	p := filepath.Join(tmp, name+".bundle")
	if err := c.d.bundle(ctx, dir, p); err != nil {
		return "", nil, err
	}
	c.printf("==> bundled the git history of %s\n", clean(dir))
	return p, map[string]any{"kind": "history", "file_name": name + ".bundle", "tools": []string{"gitleaks"}}, nil
}
