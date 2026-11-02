package api

import (
	"encoding/json"
	"net/http"
	"strings"
	"testing"
	"testing/fstest"

	"github.com/aupv9/warden/backend/internal/service"
	"github.com/aupv9/warden/backend/internal/service/servicetest"
	"github.com/aupv9/warden/backend/internal/webui"
)

const uiCSP = "default-src 'self'; frame-ancestors 'none'"

func uiServer(t *testing.T, opts ...Option) http.Handler {
	t.Helper()
	return serverWith(t, nil, service.New(servicetest.New(), nil, service.Config{}, nil), opts...)
}

func testUI(t *testing.T) Option {
	t.Helper()
	ui, err := webui.New(fstest.MapFS{
		"index.html":       {Data: []byte("<!doctype html><title>Warden</title>")},
		"assets/app-1.js":  {Data: []byte("x")},
		"healthz":          {Data: []byte("shadow")},
		"api/v1/me":        {Data: []byte("shadow")},
		"admin/loglevel":   {Data: []byte("shadow")},
		"metrics/anything": {Data: []byte("shadow")},
	}, uiCSP)
	if err != nil {
		t.Fatal(err)
	}
	return WithUI(ui)
}

func TestWebConfig(t *testing.T) {
	aud := "https://api.warden.example"
	for _, tc := range []struct {
		cfg  WebConfig
		want string
	}{
		{WebConfig{Issuer: "https://sso.example.com/realms/w", ClientID: "warden-web", Scope: "openid profile email"},
			`{"issuer":"https://sso.example.com/realms/w","client_id":"warden-web","scope":"openid profile email","audience":null}`},
		{WebConfig{Issuer: "https://tenant.auth0.com/", ClientID: "abc", Scope: "openid", Audience: &aud},
			`{"issuer":"https://tenant.auth0.com/","client_id":"abc","scope":"openid","audience":"https://api.warden.example"}`},
	} {
		// No Authorization header: the UI reads this before anyone signs in.
		w := do(uiServer(t, WithWebConfig(tc.cfg)), "GET", "/api/v1/web-config", "", nil)
		var body struct {
			Data  json.RawMessage `json:"data"`
			Error any             `json:"error"`
		}
		if err := json.Unmarshal(w.Body.Bytes(), &body); err != nil {
			t.Fatal(err)
		}
		if w.Code != 200 || string(body.Data) != tc.want || body.Error != nil {
			t.Fatalf("%d %s", w.Code, w.Body)
		}
		h := w.Header()
		if h.Get("Cache-Control") != "no-store" || h.Get("Content-Security-Policy") != "default-src 'none'; frame-ancestors 'none'" {
			t.Fatalf("%v", h)
		}
	}
}

// Without configuration it fails closed instead of sending an empty issuer.
func TestWebConfigUnset(t *testing.T) {
	w := do(uiServer(t), "GET", "/api/v1/web-config", "", nil)
	if e := decode(t, w); w.Code != 500 || e.Error == nil || e.Data != nil {
		t.Fatalf("%d %s", w.Code, w.Body)
	}
	if w := do(uiServer(t), "POST", "/api/v1/web-config", "", nil); w.Code != 405 {
		t.Fatalf("POST: %d", w.Code)
	}
}

func TestUIServedOutsideAPI(t *testing.T) {
	h := uiServer(t, testUI(t))
	for _, p := range []string{"/", "/projects/abc/issues"} {
		w := do(h, "GET", p, "", nil)
		if w.Code != 200 || !strings.Contains(w.Body.String(), "<title>Warden</title>") ||
			w.Header().Get("Content-Security-Policy") != uiCSP || w.Header().Get("Cache-Control") != "no-store" ||
			w.Header().Get("X-Frame-Options") != "DENY" || w.Header().Get("X-Content-Type-Options") != "nosniff" {
			t.Fatalf("%s: %d %v %s", p, w.Code, w.Header(), w.Body)
		}
	}
	if w := do(h, "GET", "/assets/app-1.js", "", nil); w.Code != 200 || w.Header().Get("Cache-Control") != "public, max-age=31536000, immutable" {
		t.Fatalf("asset: %d %v", w.Code, w.Header())
	}
	if w := do(h, "HEAD", "/", "", nil); w.Code != 200 || w.Body.Len() != 0 {
		t.Fatalf("HEAD: %d", w.Code)
	}
}

// API, health and admin paths never fall back to the UI, even when the
// bundle happens to hold a file of that name; and the API keeps its own CSP.
func TestUINeverShadowsReservedPaths(t *testing.T) {
	h := uiServer(t, testUI(t))
	for _, p := range []string{"/api/v1/nope", "/api/v2/x", "/api", "/api/", "/api/v1/me/x", "/healthz/x", "/admin/loglevel", "/admin/x",
		"/metrics/anything", "/readyz/x", "/info/x"} {
		w := do(h, "GET", p, "", nil)
		if w.Code != 404 || strings.Contains(w.Body.String(), "shadow") || strings.Contains(w.Body.String(), "Warden</title>") {
			t.Fatalf("%s: %d %s", p, w.Code, w.Body)
		}
		if strings.HasPrefix(p, "/api") {
			if e := decode(t, w); e.Error == nil || e.Error.Code != "NOT_FOUND" ||
				w.Header().Get("Content-Security-Policy") != "default-src 'none'; frame-ancestors 'none'" {
				t.Fatalf("%s: %v %s", p, w.Header(), w.Body)
			}
		}
	}
	if w := do(h, "GET", "/healthz", "", nil); w.Code != 200 || strings.Contains(w.Body.String(), "<") {
		t.Fatalf("healthz: %d %s", w.Code, w.Body)
	}
	// Writes to a UI path are JSON errors from the API, never the UI.
	if w := do(h, "POST", "/projects", "", nil); w.Code != 404 || strings.Contains(w.Body.String(), "Warden</title>") {
		t.Fatalf("POST: %d %s", w.Code, w.Body)
	}
}

func TestNoUIWithoutOption(t *testing.T) {
	w := do(uiServer(t), "GET", "/", "", nil)
	if e := decode(t, w); w.Code != 404 || e.Error == nil || e.Error.Code != "NOT_FOUND" {
		t.Fatalf("%d %s", w.Code, w.Body)
	}
}
