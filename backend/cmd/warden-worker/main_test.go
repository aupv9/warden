package main

import (
	"testing"

	"go.uber.org/fx"

	"github.com/aupv9/warden/backend/internal/app"
	"github.com/aupv9/warden/backend/internal/config"
)

// The dependency graph is complete (no constructor runs, so no database is needed).
func TestAppGraph(t *testing.T) {
	t.Chdir(t.TempDir())
	cfg, err := config.Load()
	if err != nil {
		t.Fatal(err)
	}
	if err := fx.ValidateApp(appOptions(cfg)); err != nil {
		t.Fatal(err)
	}
}

func TestHealthcheckNeedsAdminAddr(t *testing.T) {
	if app.ProbeAdmin("") != 1 {
		t.Fatal("healthy without an admin listener")
	}
}
