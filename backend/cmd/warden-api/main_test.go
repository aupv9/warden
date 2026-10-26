package main

import (
	"testing"
	"time"

	"go.uber.org/fx"

	"github.com/aupv9/warden/backend/internal/config"
)

// The dependency graph is complete (no constructor runs, so no database is needed).
func TestAppGraph(t *testing.T) {
	cfg, err := config.Load()
	if err != nil {
		t.Fatal(err)
	}
	if err := fx.ValidateApp(appOptions(cfg)); err != nil {
		t.Fatal(err)
	}
	sc := ServiceConfig(cfg)
	if sc.UploadMaxBytes != int64(cfg.Scan.UploadMaxMB)<<20 || sc.UploadURLTTL != 15*time.Minute || sc.Limits.ScanTimeoutMinutes != 30 {
		t.Fatalf("%+v", sc)
	}
}
