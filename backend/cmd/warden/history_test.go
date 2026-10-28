package main

import (
	"context"
	"errors"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"testing"
)

func TestHistoryScan(t *testing.T) {
	f := newFakeServer(t)
	d := testDeps()
	var bundled string
	d.bundle = func(_ context.Context, dir, dest string) error {
		bundled = dest
		return os.WriteFile(dest, []byte("bundle of "+filepath.Base(dir)), 0o600)
	}
	d.pack = func(string, string, string) (int, error) {
		t.Fatal("packed a directory for a history scan")
		return 0, nil
	}
	r := f.run(t, f.token, d, "--history", "--fail-on", "critical")
	if r.code != exitPass || string(f.uploaded) != "bundle of repo" {
		t.Fatalf("%+v", r)
	}
	c := f.created
	tools, _ := c["tools"].([]any)
	if c["kind"] != "history" || c["file_name"] != "repo.bundle" || len(tools) != 1 || tools[0] != "gitleaks" || c["target"] != nil {
		t.Fatal(c)
	}
	// The temporary bundle is gone once the scan is done.
	if _, err := os.Stat(bundled); !errors.Is(err, os.ErrNotExist) {
		t.Fatal(bundled, err)
	}
	// --tools gitleaks is accepted, as the server's only choice.
	if r := f.run(t, f.token, d, "--history", "--tools", "gitleaks"); r.code != exitPass {
		t.Fatalf("%+v", r)
	}
}

func TestHistoryFlagProblems(t *testing.T) {
	f := newFakeServer(t)
	for name, c := range map[string]struct {
		args []string
		want string
	}{
		"image":     {[]string{"--history", "--image", "alpine"}, "--history: not with --image"},
		"image-tar": {[]string{"--history", "--image-tar", "a.tar", "--target", "x"}, "--history: not with --image"},
		"tools":     {[]string{"--history", "--tools", "gitleaks,trivy"}, "--tools: history scans run gitleaks only"},
		"sbom":      {[]string{"--history", "--sbom-out", "bom.json"}, "--sbom-out: history scans have no SBOM"},
		"target":    {[]string{"--history", "--target", "x"}, "--target: only with"},
	} {
		d := testDeps()
		d.bundle = func(context.Context, string, string) error { t.Fatal("bundled"); return nil }
		if r := f.runImage(t, d, c.args...); r.code != exitError || !strings.Contains(r.stderr, c.want) {
			t.Errorf("%s: %+v", name, r)
		}
	}
	// A failed bundle (a shallow clone) stops before anything is created.
	d := testDeps()
	d.bundle = func(context.Context, string, string) error { return errShallow }
	f.created = nil
	if r := f.run(t, f.token, d, "--history"); r.code != exitError || !strings.Contains(r.stderr, "fetch-depth: 0") ||
		!strings.Contains(r.stderr, "GIT_DEPTH: 0") || f.created != nil {
		t.Fatalf("%+v", r)
	}
}

func git(t *testing.T, dir string, args ...string) {
	t.Helper()
	cmd := exec.Command("git", append([]string{"-C", dir}, args...)...)
	cmd.Env = append(os.Environ(), "GIT_CONFIG_GLOBAL=/dev/null", "GIT_CONFIG_SYSTEM=/dev/null",
		"GIT_AUTHOR_NAME=t", "GIT_AUTHOR_EMAIL=t@x.test", "GIT_COMMITTER_NAME=t", "GIT_COMMITTER_EMAIL=t@x.test")
	if out, err := cmd.CombinedOutput(); err != nil {
		t.Fatalf("git %v: %v\n%s", args, err, out)
	}
}

// The real git: a full clone bundles (0600, every ref), a shallow one is
// refused with the hint, and so is a directory that isn't a repository.
func TestGitBundle(t *testing.T) {
	if _, err := exec.LookPath("git"); err != nil {
		t.Skip("git not installed")
	}
	t.Setenv("GIT_CONFIG_GLOBAL", "/dev/null")
	t.Setenv("GIT_CONFIG_NOSYSTEM", "1")
	repo := t.TempDir()
	git(t, repo, "init", "-q", "-b", "main")
	for i, body := range []string{"a", "b"} {
		_ = os.WriteFile(filepath.Join(repo, "f"), []byte(body), 0o600)
		git(t, repo, "add", "f")
		git(t, repo, "commit", "-q", "-m", string(rune('1'+i)))
	}
	git(t, repo, "branch", "other")
	dest := filepath.Join(t.TempDir(), "r.bundle")
	if err := gitBundle(context.Background(), repo, dest); err != nil {
		t.Fatal(err)
	}
	st, err := os.Stat(dest)
	if err != nil || st.Mode().Perm() != 0o600 {
		t.Fatal(st, err)
	}
	head, _ := os.ReadFile(dest)
	if !strings.HasPrefix(string(head), "# v2 git bundle\n") || !strings.Contains(string(head), " refs/heads/other\n") {
		t.Fatalf("%.200q", head)
	}

	shallow := t.TempDir()
	git(t, shallow, "clone", "-q", "--depth=1", "--no-local", "file://"+repo, ".")
	if err := gitBundle(context.Background(), shallow, filepath.Join(t.TempDir(), "s.bundle")); !errors.Is(err, errShallow) {
		t.Fatal(err)
	}
	if err := gitBundle(context.Background(), t.TempDir(), filepath.Join(t.TempDir(), "n.bundle")); err == nil {
		t.Fatal("bundled a directory that isn't a repository")
	}
}
