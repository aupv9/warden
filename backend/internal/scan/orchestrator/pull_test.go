package orchestrator

import (
	"context"
	"errors"
	"os"
	"path/filepath"
	"testing"

	"github.com/aupv9/warden/backend/internal/registry"
	"github.com/aupv9/warden/backend/internal/scan/sandbox"
	"github.com/aupv9/warden/backend/internal/scan/zipcheck"
)

// pullDeps pulls instead of downloading: it writes tar (or fails with err).
type pullDeps struct {
	*fakeDeps
	tar    []byte
	err    error
	pulled []string
}

func (d *pullDeps) Pull(_ context.Context, dest string) error {
	d.pulled = append(d.pulled, dest)
	if d.err != nil {
		_ = os.WriteFile(dest, []byte("partial"), 0o600) // left behind for cleanup
		return d.err
	}
	return os.WriteFile(dest, d.tar, 0o600)
}

func (d *pullDeps) Download(context.Context, string, string) error {
	return errors.New("a pulled scan has no upload")
}

func pulledJob() Job {
	return Job{ScanID: "scan-pulled", OrgID: "o", ProjectID: "p", Tools: []string{"trivy"}, Kind: KindImage,
		Target: "ghcr.io/acme/api", Pulled: true}
}

// A pulled image is checked and scanned like an upload, with no checksum or
// object: imagecheck still gates it, and only the scratch directory goes.
func TestPulledImageScan(t *testing.T) {
	data, _ := imageTar(t, `[{"Config":"c.json","Layers":["l/layer.tar"]}]`)
	d := &pullDeps{fakeDeps: newDeps(t, nil, map[string]sandbox.ToolStatus{"trivy": sandbox.Succeeded}), tar: data}
	d.trivyOut = map[string]string{"trivy.json": imageReport}
	d.limits = &Limits{Zip: zipcheck.DefaultLimits(), ImageMaxBytes: 1, PullMaxBytes: int64(len(data))}
	j := pulledJob()
	out, err := Execute(context.Background(), j, d)
	if err != nil || out.Status != Completed || !d.sawImage || len(d.pulled) != 1 {
		t.Fatal(out, err, d.sawImage, d.pulled)
	}
	if filepath.Base(d.pulled[0]) != "image.tar" {
		t.Fatal(d.pulled)
	}
	assertPulledCleaned(t, d, j)

	// imagecheck refuses a bad tarball from a registry like an upload's.
	bad, _ := imageTar(t, `[{"Config":"c.json","Layers":["missing.tar"]}]`)
	d = &pullDeps{fakeDeps: newDeps(t, nil, map[string]sandbox.ToolStatus{"trivy": sandbox.Succeeded}), tar: bad}
	out, err = Execute(context.Background(), j, d)
	if err != nil || out.Status != Failed || out.ErrorCode != "IMAGE_INVALID" || d.sawImage {
		t.Fatal(out, err)
	}
	assertPulledCleaned(t, d, j)
}

// A failed pull ends the scan with its PULL_* code; no scanner runs and the
// partial tarball goes with the scratch directory.
func TestPullFailure(t *testing.T) {
	for _, code := range []string{registry.CodeUnauthorized, registry.CodeBlocked, registry.CodeTooLarge} {
		d := &pullDeps{fakeDeps: newDeps(t, nil, map[string]sandbox.ToolStatus{"trivy": sandbox.Succeeded}),
			err: &registry.Error{Code: code, Detail: "x"}}
		j := pulledJob()
		out, err := Execute(context.Background(), j, d)
		if err != nil || out.Status != Failed || out.ErrorCode != code || d.sawImage {
			t.Fatal(code, out, err)
		}
		assertPulledCleaned(t, d, j)
	}
	// Deps without a puller can't run a pulled scan.
	d := newDeps(t, nil, nil)
	if _, err := Execute(context.Background(), pulledJob(), d); err == nil {
		t.Fatal("pulled without a puller")
	}
}

func assertPulledCleaned(t *testing.T, d *pullDeps, j Job) {
	t.Helper()
	if _, err := os.Stat(filepath.Join(d.root, j.ScanID)); err == nil {
		t.Fatal("scratch directory left behind")
	}
	if len(d.deleted) != 0 {
		t.Fatalf("deleted objects of a pulled scan: %v", d.deleted)
	}
}
