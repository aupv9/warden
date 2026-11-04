// warden-layers runs inside the Gitleaks sandbox (warden-gitleaks image
// mode): it unpacks the image's layers a batch at a time
// (internal/scan/layerscan), runs Gitleaks over each batch and writes one
// raw SARIF for warden-redact, plus the layer report:
//
//	warden-layers -image /src/image.tar -dir /tmp/layers -max-bytes N \
//	  -sarif /tmp/raw.sarif -report /out/layers.json -- gitleaks dir FLAGS...
//
// The Gitleaks command (everything after "--") gets the batch directory and
// --report-path appended. Exit 5: the layers expand past the limits; exit 6:
// a layer can't be read (sandbox.ExitImageTooLarge, ExitImageUnreadable).
package main

import (
	"encoding/json"
	"errors"
	"flag"
	"fmt"
	"io"
	"os"
	"os/exec"
	"path/filepath"
	"slices"

	"github.com/aupv9/warden/backend/internal/scan/layerscan"
	"github.com/aupv9/warden/backend/internal/scan/sarif"
)

const (
	exitTooLarge   = 5
	exitUnreadable = 6
)

func main() {
	err := run(os.Args[1:])
	if err == nil {
		return
	}
	// Only Warden's own messages: no path from the image (which may hold a
	// secret) is printed.
	switch {
	case errors.Is(err, layerscan.ErrTooLarge):
		fmt.Fprintln(os.Stderr, "warden-layers:", layerscan.ErrTooLarge)
		os.Exit(exitTooLarge)
	case errors.Is(err, layerscan.ErrUnreadable):
		fmt.Fprintln(os.Stderr, "warden-layers:", layerscan.ErrUnreadable)
		os.Exit(exitUnreadable)
	}
	fmt.Fprintln(os.Stderr, "warden-layers:", err)
	os.Exit(1)
}

func run(args []string) error {
	fs := flag.NewFlagSet("warden-layers", flag.ContinueOnError)
	image := fs.String("image", "/src/image.tar", "the docker save tarball")
	dir := fs.String("dir", "/tmp/layers", "where batches are unpacked (must not exist)")
	maxBytes := fs.Int64("max-bytes", 0, "the most uncompressed bytes all layers may hold")
	out := fs.String("sarif", "/tmp/raw.sarif", "the merged raw SARIF (for warden-redact)")
	report := fs.String("report", "/out/layers.json", "the layer report")
	if err := fs.Parse(args); err != nil {
		return err
	}
	// The command after -- is always gitleaks: only its flags come from the
	// wrapper, and the program name is fixed here rather than taken from argv.
	cmd := fs.Args()
	if len(cmd) < 2 || cmd[0] != "gitleaks" || *maxBytes <= 0 {
		return errors.New("usage: warden-layers -max-bytes N [flags] -- gitleaks dir FLAGS")
	}
	gitleaks := cmd[1:]
	batchReport := filepath.Join(filepath.Dir(*out), "batch.sarif")
	var m layerscan.Merger
	rep, err := layerscan.Extract(*image, *dir, layerscan.DefaultLimits(*maxBytes), func(b layerscan.Batch) error {
		doc, err := runGitleaks(gitleaks, b.Dir, batchReport)
		if err != nil {
			return err
		}
		return m.Add(doc, b)
	})
	if err != nil {
		return err
	}
	if err := writeJSON(*out, m.Doc(), 0o600); err != nil {
		return err
	}
	return writeJSON(*report, rep, 0o644)
}

// runGitleaks runs Gitleaks with flags over one batch and reads its SARIF.
func runGitleaks(flags []string, dir, report string) (map[string]any, error) {
	cmd := exec.Command("gitleaks", append(slices.Clone(flags), dir, "--report-path", report)...)
	cmd.Stdout, cmd.Stderr = os.Stderr, os.Stderr
	if err := cmd.Run(); err != nil {
		return nil, fmt.Errorf("gitleaks: %w", err)
	}
	f, err := os.Open(report)
	if err != nil {
		return nil, err
	}
	v, err := sarif.Decode(io.LimitReader(f, sarif.MaxFileBytes))
	f.Close()
	if err != nil {
		return nil, fmt.Errorf("gitleaks SARIF: %w", err)
	}
	if err := os.Remove(report); err != nil {
		return nil, err
	}
	doc, ok := v.(map[string]any)
	if !ok {
		return nil, errors.New("gitleaks SARIF is not an object")
	}
	return doc, nil
}

func writeJSON(path string, v any, mode os.FileMode) error {
	f, err := os.OpenFile(path, os.O_WRONLY|os.O_CREATE|os.O_EXCL, mode)
	if err != nil {
		return err
	}
	enc := json.NewEncoder(f)
	enc.SetEscapeHTML(false)
	err = enc.Encode(v)
	if cerr := f.Close(); err == nil {
		err = cerr
	}
	if err != nil {
		os.Remove(path)
	}
	return err
}
