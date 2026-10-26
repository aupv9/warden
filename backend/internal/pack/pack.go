// Package pack zips a git working tree the way a developer's upload looks:
// tracked files plus untracked files that aren't ignored, regular files only
// (symlinks, sockets and the like are skipped, so a link can't pull files from
// outside the tree into the archive). Used by selfscan and the warden CLI.
package pack

import (
	"archive/zip"
	"bytes"
	"errors"
	"fmt"
	"io"
	"os"
	"os/exec"
	"path/filepath"
)

// Repo writes the files of the git working tree at root into a new zip at dest
// (which must not exist), each under prefix (e.g. "warden/"; may be empty).
// It returns the number of files written.
func Repo(root, dest, prefix string) (int, error) {
	cmd := exec.Command("git", "-C", root, "ls-files", "-co", "--exclude-standard", "-z")
	var stderr bytes.Buffer
	cmd.Stderr = &stderr
	list, err := cmd.Output()
	if err != nil {
		return 0, fmt.Errorf("git ls-files in %s: %w: %s", root, err, bytes.TrimSpace(stderr.Bytes()))
	}
	f, err := os.OpenFile(dest, os.O_WRONLY|os.O_CREATE|os.O_EXCL, 0o600)
	if err != nil {
		return 0, err
	}
	defer f.Close()
	zw := zip.NewWriter(f)
	n := 0
	for _, rel := range bytes.Split(list, []byte{0}) {
		if len(rel) == 0 {
			continue
		}
		p := filepath.Join(root, string(rel))
		st, err := os.Lstat(p)
		if errors.Is(err, os.ErrNotExist) {
			continue // deleted but still in the index
		}
		if err != nil {
			return 0, err
		}
		if !st.Mode().IsRegular() {
			continue
		}
		if err := addFile(zw, p, prefix+filepath.ToSlash(string(rel))); err != nil {
			return 0, err
		}
		n++
	}
	if err := zw.Close(); err != nil {
		return 0, err
	}
	return n, f.Close()
}

func addFile(zw *zip.Writer, path, name string) error {
	src, err := os.Open(path)
	if err != nil {
		return err
	}
	defer src.Close()
	w, err := zw.CreateHeader(&zip.FileHeader{Name: name, Method: zip.Deflate})
	if err != nil {
		return err
	}
	_, err = io.Copy(w, src)
	return err
}
