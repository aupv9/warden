package main

import (
	"encoding/json"
	"io/fs"
	"log/slog"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"testing/fstest"

	"github.com/aupv9/common-go/transport/httpserver"

	"github.com/aupv9/warden/backend/internal/api"
	"github.com/aupv9/warden/backend/internal/auth"
	"github.com/aupv9/warden/backend/internal/config"
	"github.com/aupv9/warden/backend/internal/service"
	"github.com/aupv9/warden/backend/internal/service/servicetest"
	"github.com/aupv9/warden/backend/internal/storage"
)

func webServer(t *testing.T, c *config.Config, endpoints func() auth.BrowserEndpoints, dist fs.FS) http.Handler {
	t.Helper()
	objects, err := storage.New(storage.FromSection(c.Storage))
	if err != nil {
		t.Fatal(err)
	}
	opts, err := webOptions(c, objects, endpoints, dist)
	if err != nil {
		t.Fatal(err)
	}
	srv, err := httpserver.New(slog.New(slog.DiscardHandler), api.ServerOptions()...)
	if err != nil {
		t.Fatal(err)
	}
	api.Register(srv.Engine(), auth.NewVerifier(c.OIDC.Issuer, c.OIDC.Audience, auth.StaticKeys{}),
		service.New(servicetest.New(), nil, service.Config{}, nil), opts...)
	return srv.Engine()
}

func noEndpoints() auth.BrowserEndpoints { return auth.BrowserEndpoints{} }

func get(h http.Handler, path string) *httptest.ResponseRecorder {
	w := httptest.NewRecorder()
	h.ServeHTTP(w, httptest.NewRequest("GET", path, nil))
	return w
}

func loadConfig(t *testing.T, env map[string]string) *config.Config {
	t.Helper()
	env["WARDEN_STORAGE__ACCESS_KEY"], env["WARDEN_STORAGE__SECRET_KEY"] = "ak", "sk"
	for k, v := range env {
		t.Setenv(k, v)
	}
	c, err := config.Load()
	if err != nil {
		t.Fatal(err)
	}
	return c
}

// The UI's CSP is built from server configuration: the issuer and the public
// storage origin (never the internal endpoint).
func TestWebUIFromConfig(t *testing.T) {
	c := loadConfig(t, map[string]string{
		"WARDEN_OIDC__ISSUER":             "https://sso.warden.example/realms/warden",
		"WARDEN_STORAGE__ENDPOINT":        "http://s3:8333",
		"WARDEN_STORAGE__PUBLIC_ENDPOINT": "https://s3.warden.example",
		"WARDEN_WEB__OIDC_AUDIENCE":       "warden-api",
	})
	var discovered auth.BrowserEndpoints
	h := webServer(t, c, func() auth.BrowserEndpoints { return discovered }, fstest.MapFS{"index.html": {Data: []byte("<!doctype html>")}})
	w := get(h, "/projects")
	csp := w.Header().Get("Content-Security-Policy")
	if w.Code != 200 || w.Body.String() != "<!doctype html>" ||
		!strings.Contains(csp, "connect-src 'self' https://sso.warden.example https://s3.warden.example;") ||
		strings.Contains(csp, "s3:8333") {
		t.Fatalf("%d %q %s", w.Code, csp, w.Body)
	}
	// Once discovery has been read, the next response allows its endpoints.
	discovered = auth.BrowserEndpoints{Token: "https://tokens.warden.example/token", Authorization: "https://login.warden.example/auth"}
	csp = get(h, "/").Header().Get("Content-Security-Policy")
	if !strings.Contains(csp, "connect-src 'self' https://sso.warden.example https://tokens.warden.example https://s3.warden.example;") ||
		!strings.Contains(csp, "frame-src 'self' https://sso.warden.example https://login.warden.example;") {
		t.Fatal(csp)
	}
	w = get(h, "/api/v1/web-config")
	var body struct{ Data api.WebConfig }
	if err := json.Unmarshal(w.Body.Bytes(), &body); err != nil {
		t.Fatal(err)
	}
	d := body.Data
	if w.Code != 200 || d.Issuer != "https://sso.warden.example/realms/warden" || d.ClientID != "warden-web" ||
		d.Scope != "openid profile email" || d.Audience == nil || *d.Audience != "warden-api" {
		t.Fatalf("%d %s", w.Code, w.Body)
	}
}

func TestNoWebUIWithoutBundle(t *testing.T) {
	h := webServer(t, loadConfig(t, map[string]string{}), noEndpoints, nil)
	if w := get(h, "/"); w.Code != 404 || strings.Contains(w.Body.String(), "html") {
		t.Fatalf("%d %s", w.Code, w.Body)
	}
	if w := get(h, "/api/v1/web-config"); w.Code != 200 || !strings.Contains(w.Body.String(), `"audience":null`) {
		t.Fatalf("%d %s", w.Code, w.Body)
	}
}

// A configuration value that would add CSP directives stops the API at startup.
func TestWebUIRefusesUnsafeOrigins(t *testing.T) {
	c := loadConfig(t, map[string]string{})
	c.OIDC.Issuer = "https://sso.example.com;script-src *"
	objects, err := storage.New(storage.FromSection(c.Storage))
	if err != nil {
		t.Fatal(err)
	}
	if _, err := webOptions(c, objects, noEndpoints, fstest.MapFS{"index.html": {}}); err == nil {
		t.Fatal("issuer with a CSP directive accepted")
	}
}
