//go:build integration

package store_test

import (
	"strings"
	"testing"

	"github.com/aupv9/warden/backend/internal/service"
)

// An image scan is stored with its kind, target and reference (the schema's
// CHECKs agree with the service's validation) and its tarball key.
func TestImageScanRoundTrip(t *testing.T) {
	w := newWorld(t)
	f := w.org("IMG")
	w.svc = service.New(w.db, w.objs, service.Config{UploadMaxBytes: 1 << 20, ImageUploadMaxBytes: 1 << 30, RateLimitPerHour: 5}, nil)
	dev := w.actor("IMGdev", f.id)
	ref := "registry.example:5000/acme/api:1.2"
	target := "registry.example:5000/acme/api"
	created := must(w.svc.CreateScan(ctx, dev, f.project, service.CreateScanInput{Kind: "image", FileName: "api.tar", FileSize: 500 << 20,
		SHA256: strings.Repeat("d", 64), Target: &target, ImageRef: &ref}))
	sc := must(w.svc.Scan(ctx, dev, created.Scan.ID))
	if sc.Kind != "image" || sc.Target != target || sc.ImageRef == nil || *sc.ImageRef != ref || sc.Tools[0] != "trivy" || len(sc.Tools) != 1 ||
		sc.ObjectKey != "scans/"+f.id.String()+"/"+sc.ID.String()+".tar" {
		t.Fatalf("%+v", sc)
	}
	if src := must(w.svc.Scan(ctx, dev, f.scan)); src.Kind != "source" || src.Target != "" || src.ImageRef != nil {
		t.Fatalf("%+v", src)
	}
}
