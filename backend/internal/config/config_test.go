package config

import (
	"encoding/json"
	"fmt"
	"log/slog"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"
)

func TestSecretNeverPrints(t *testing.T) {
	s := Secret("hunter2-database-password")
	b, _ := json.Marshal(struct{ P Secret }{s})
	var logged strings.Builder
	slog.New(slog.NewJSONHandler(&logged, nil)).Info("x", "s", s)
	for _, out := range []string{fmt.Sprint(s), fmt.Sprintf("%v %+v %#v %s", s, s, s, s), string(b), logged.String()} {
		if strings.Contains(out, "hunter2") {
			t.Fatal(out)
		}
	}
	if s.Reveal() != "hunter2-database-password" {
		t.Fatal("reveal")
	}
}

func TestDefaults(t *testing.T) {
	t.Chdir(t.TempDir()) // no config.yaml
	c, err := Load()
	if err != nil {
		t.Fatal(err)
	}
	if c.App.Name != "warden" || c.Server.Port != 8010 || c.Scan.Timeout != 30*time.Minute ||
		c.OIDC.Audience != "warden-api" || c.Scan.SandboxRuntime != "runsc" {
		t.Fatalf("%+v", c)
	}
}

func TestEnvOverridesNestedKeys(t *testing.T) {
	t.Chdir(t.TempDir())
	t.Setenv("WARDEN_SERVER__PORT", "9999")
	t.Setenv("WARDEN_SCAN__TIMEOUT", "45m")
	t.Setenv("WARDEN_DATABASE__DSN", "postgres://a@b/c")
	t.Setenv("WARDEN_OIDC__ISSUER", "https://sso.example.com/realms/x")
	c, err := Load()
	if err != nil {
		t.Fatal(err)
	}
	if c.Server.Port != 9999 || c.Scan.Timeout != 45*time.Minute || c.Database.DSN != "postgres://a@b/c" ||
		c.OIDC.Issuer != "https://sso.example.com/realms/x" {
		t.Fatalf("%+v", c)
	}
}

func TestSecretsFromFiles(t *testing.T) {
	t.Chdir(t.TempDir())
	p := filepath.Join(t.TempDir(), "hmac")
	_ = os.WriteFile(p, []byte("from-a-file\n"), 0o600)
	t.Setenv("WARDEN_SCAN__HMAC_KEY", "file:"+p)
	c, err := Load()
	if err != nil {
		t.Fatal(err)
	}
	if c.Scan.HMACKey.Reveal() != "from-a-file" {
		t.Fatalf("%q", c.Scan.HMACKey.Reveal())
	}
	t.Setenv("WARDEN_SCAN__HMAC_KEY", "file:/does/not/exist")
	if _, err := Load(); err == nil {
		t.Fatal("missing secret file accepted")
	}
}

func TestYAMLFile(t *testing.T) {
	dir := t.TempDir()
	t.Chdir(dir)
	yaml := "scan:\n  images:\n    trivy: registry.internal/warden/trivy@sha256:" + strings.Repeat("a", 64) + "\n"
	_ = os.WriteFile(filepath.Join(dir, "config.yaml"), []byte(yaml), 0o600)
	c, err := Load()
	if err != nil {
		t.Fatal(err)
	}
	if !strings.HasSuffix(c.Scan.Images["trivy"], strings.Repeat("a", 64)) {
		t.Fatal(c.Scan.Images)
	}
}

func TestScannerImagesMustBePinned(t *testing.T) {
	dir := t.TempDir()
	t.Chdir(dir)
	for _, img := range []string{
		"trivy: aquasec/trivy:latest",
		"trivy: sha256:" + strings.Repeat("a", 63),
		"trivy: x sha256:" + strings.Repeat("a", 64),
		"trivy: aquasec/trivy:0.75.0",
		"evil: registry.internal/x@sha256:" + strings.Repeat("a", 64),
	} {
		_ = os.WriteFile(filepath.Join(dir, "config.yaml"), []byte("scan:\n  images:\n    "+img+"\n"), 0o600)
		if _, err := Load(); err == nil {
			t.Fatalf("%s accepted", img)
		}
	}
	// Accepted: a local image ID (content-addressed) and tag + digest (the digest decides).
	for _, img := range []string{
		"gitleaks: sha256:" + strings.Repeat("b", 64),
		"trivy: docker.io/aquasec/trivy:0.75.0@sha256:" + strings.Repeat("c", 64),
	} {
		_ = os.WriteFile(filepath.Join(dir, "config.yaml"), []byte("scan:\n  images:\n    "+img+"\n"), 0o600)
		if _, err := Load(); err != nil {
			t.Fatalf("%s: %v", img, err)
		}
	}
}

func TestInvalidValuesAreErrors(t *testing.T) {
	t.Chdir(t.TempDir())
	for k, v := range map[string]string{
		"WARDEN_SERVER__PORT":                "lots",
		"WARDEN_SCAN__SANDBOX_RUNTIME":       "privileged",
		"WARDEN_SCAN__TIMEOUT":               "10s",
		"WARDEN_OIDC__ISSUER":                "not a url",
		"WARDEN_LOG__LEVEL":                  "loud",
		"WARDEN_SCAN__AUTOCLOSE_GUARD_RATIO": "2",
	} {
		t.Run(k, func(t *testing.T) {
			t.Setenv(k, v)
			if _, err := Load(); err == nil {
				t.Fatalf("%s=%s accepted", k, v)
			}
		})
	}
}

func TestBrokenYAMLIsAnError(t *testing.T) {
	dir := t.TempDir()
	t.Chdir(dir)
	_ = os.WriteFile(filepath.Join(dir, "config.yaml"), []byte("scan: [unclosed\n"), 0o600)
	if _, err := Load(); err == nil {
		t.Fatal("broken config.yaml silently ignored")
	}
}
