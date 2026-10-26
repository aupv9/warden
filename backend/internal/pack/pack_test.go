package pack

import (
	"archive/zip"
	"os"
	"os/exec"
	"path/filepath"
	"slices"
	"testing"
)

func gitRepo(t *testing.T) string {
	t.Helper()
	if _, err := exec.LookPath("git"); err != nil {
		t.Skip("git not installed")
	}
	dir := t.TempDir()
	git := func(args ...string) {
		t.Helper()
		cmd := exec.Command("git", append([]string{"-C", dir}, args...)...)
		cmd.Env = append(os.Environ(), "GIT_CONFIG_GLOBAL=/dev/null", "GIT_CONFIG_SYSTEM=/dev/null")
		if out, err := cmd.CombinedOutput(); err != nil {
			t.Fatalf("git %v: %v: %s", args, err, out)
		}
	}
	write := func(rel, body string) {
		t.Helper()
		p := filepath.Join(dir, rel)
		if err := os.MkdirAll(filepath.Dir(p), 0o755); err != nil {
			t.Fatal(err)
		}
		if err := os.WriteFile(p, []byte(body), 0o644); err != nil {
			t.Fatal(err)
		}
	}
	git("init", "-q")
	write(".gitignore", "build/\n*.log\n")
	write("main.go", "package main\n")
	write("pkg/util.go", "package pkg\n")
	write("gone.txt", "x")
	git("add", ".")
	write("new.txt", "untracked, not ignored")
	write("build/out.bin", "ignored")
	write("debug.log", "ignored")
	if err := os.Remove(filepath.Join(dir, "gone.txt")); err != nil { // still in the index
		t.Fatal(err)
	}
	outside := filepath.Join(t.TempDir(), "secret.txt")
	if err := os.WriteFile(outside, []byte("outside the tree"), 0o600); err != nil {
		t.Fatal(err)
	}
	if err := os.Symlink(outside, filepath.Join(dir, "link.txt")); err != nil {
		t.Fatal(err)
	}
	return dir
}

func TestRepoPacksTrackedAndUntrackedRegularFiles(t *testing.T) {
	dir := gitRepo(t)
	dest := filepath.Join(t.TempDir(), "src.zip")
	n, err := Repo(dir, dest, "app/")
	if err != nil {
		t.Fatal(err)
	}
	zr, err := zip.OpenReader(dest)
	if err != nil {
		t.Fatal(err)
	}
	defer zr.Close()
	var names []string
	for _, f := range zr.File {
		names = append(names, f.Name)
	}
	slices.Sort(names)
	want := []string{"app/.gitignore", "app/main.go", "app/new.txt", "app/pkg/util.go"}
	if !slices.Equal(names, want) || n != len(want) {
		t.Fatalf("%d %v", n, names)
	}
	// The destination must be new.
	if _, err := Repo(dir, dest, ""); err == nil {
		t.Fatal("overwrote an existing file")
	}
}

func TestRepoNeedsGitTree(t *testing.T) {
	if _, err := exec.LookPath("git"); err != nil {
		t.Skip("git not installed")
	}
	dir := t.TempDir()
	t.Setenv("GIT_CEILING_DIRECTORIES", filepath.Dir(dir))
	if _, err := Repo(dir, filepath.Join(t.TempDir(), "x.zip"), ""); err == nil {
		t.Fatal("packed a directory that isn't a git tree")
	}
}
