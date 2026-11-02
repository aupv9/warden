package webui

import (
	"bufio"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"testing/fstest"
)

const index = `<!doctype html><html><head><script type="module" src="/assets/index-abc.js"></script></head><body><div id="root"></div></body></html>`

func testUI(t *testing.T) http.Handler {
	t.Helper()
	h, err := New(fstest.MapFS{
		"index.html":           {Data: []byte(index)},
		"assets/index-abc.js":  {Data: []byte("console.log(1)")},
		"assets/app-def.css":   {Data: []byte("body{}")},
		"assets/font-1.woff2":  {Data: []byte("wOF2")},
		"assets/.secret":       {Data: []byte("dotfile")},
		".env":                 {Data: []byte("SECRET=1")},
		"robots.txt":           {Data: []byte("User-agent: *")},
		"assets/sub/deep-1.js": {Data: []byte("deep")},
	}, "default-src 'self'")
	if err != nil {
		t.Fatal(err)
	}
	return h
}

func get(h http.Handler, method, target string) *httptest.ResponseRecorder {
	// Parse a raw request line, as the server does: no dot-segment removal and
	// no reference resolution ("//host/x" stays a path).
	r, err := http.ReadRequest(bufio.NewReader(strings.NewReader(method + " " + target + " HTTP/1.1\r\nHost: warden.test\r\n\r\n")))
	if err != nil {
		panic(target + ": " + err.Error())
	}
	w := httptest.NewRecorder()
	h.ServeHTTP(w, r)
	return w
}

func TestServesIndexForClientRoutes(t *testing.T) {
	h := testUI(t)
	for _, p := range []string{"/", "/index.html", "/projects", "/projects/", "/projects/0b1c/issues/42", "/assets", "/settings/sign-in"} {
		w := get(h, "GET", p)
		if w.Code != 200 || w.Body.String() != index {
			t.Fatalf("%s: %d %q", p, w.Code, w.Body)
		}
		hdr := w.Header()
		if hdr.Get("Content-Type") != "text/html; charset=utf-8" || hdr.Get("Cache-Control") != "no-store" ||
			hdr.Get("Content-Security-Policy") != "default-src 'self'" {
			t.Fatalf("%s: %v", p, hdr)
		}
	}
}

func TestServesAssetsImmutable(t *testing.T) {
	h := testUI(t)
	for p, ct := range map[string]string{
		"/assets/index-abc.js":  "text/javascript; charset=utf-8",
		"/assets/app-def.css":   "text/css; charset=utf-8",
		"/assets/font-1.woff2":  "font/woff2",
		"/assets/sub/deep-1.js": "text/javascript; charset=utf-8",
	} {
		w := get(h, "GET", p)
		hdr := w.Header()
		if w.Code != 200 || hdr.Get("Content-Type") != ct || hdr.Get("Cache-Control") != "public, max-age=31536000, immutable" ||
			hdr.Get("Content-Security-Policy") != "default-src 'self'" {
			t.Fatalf("%s: %d %v", p, w.Code, hdr)
		}
	}
	if w := get(h, "GET", "/robots.txt"); w.Code != 200 || w.Header().Get("Cache-Control") != "no-cache" {
		t.Fatalf("robots.txt: %d %v", w.Code, w.Header())
	}
	w := get(h, "HEAD", "/assets/index-abc.js")
	if w.Code != 200 || w.Body.Len() != 0 || w.Header().Get("Content-Length") != "14" {
		t.Fatalf("HEAD: %d %v %q", w.Code, w.Header(), w.Body)
	}
}

// A missing hashed asset is a 404, not index.html with a year-long cache header.
func TestMissingAssetIsNotFound(t *testing.T) {
	w := get(testUI(t), "GET", "/assets/index-old.js")
	if w.Code != 404 || strings.Contains(w.Body.String(), "<html") || w.Header().Get("Cache-Control") != "no-store" {
		t.Fatalf("%d %v %q", w.Code, w.Header(), w.Body)
	}
}

// Traversal, encoded separators and dotfiles are refused outright: never the
// file, never index.html standing in for it.
func TestRefusesUnusualPaths(t *testing.T) {
	h := testUI(t)
	for _, p := range []string{
		"/../index.html",
		"/assets/../index.html",
		"/assets/./index-abc.js",
		"/%2e%2e/index.html",
		"/assets/%2e%2e/.env",
		"/assets%2findex-abc.js",
		"/assets%2Findex-abc.js",
		"/assets/sub%2fdeep-1.js",
		"/.env",
		"/%2eenv",
		"/assets/.secret",
		"/.git/config",
		"/.well-known/openid-configuration",
		"//evil.example/x",
		"/assets//index-abc.js",
		`/assets\index-abc.js`,
		"/assets/%5cindex-abc.js",
		"/a%00b",
		"/a%0d%0aSet-Cookie:x",
		"/%25",
	} {
		w := get(h, "GET", p)
		if w.Code != 404 || strings.Contains(w.Body.String(), "<html") || strings.Contains(w.Body.String(), "SECRET") ||
			strings.Contains(w.Body.String(), "dotfile") {
			t.Errorf("%s: %d %q", p, w.Code, w.Body)
		}
		if w.Header().Get("Content-Security-Policy") == "" {
			t.Errorf("%s: no CSP on the refusal", p)
		}
	}
}

func TestOnlyGetAndHead(t *testing.T) {
	h := testUI(t)
	for _, m := range []string{"POST", "PUT", "DELETE", "OPTIONS"} {
		if w := get(h, m, "/"); w.Code != 405 || w.Header().Get("Allow") != "GET, HEAD" {
			t.Fatalf("%s: %d", m, w.Code)
		}
	}
}

func TestNewRefusesIncompleteBuilds(t *testing.T) {
	if _, err := New(nil, "default-src 'self'"); err == nil {
		t.Fatal("nil FS accepted")
	}
	if _, err := New(fstest.MapFS{"assets/a.js": {}}, "default-src 'self'"); err == nil {
		t.Fatal("a build without index.html accepted")
	}
	if _, err := New(fstest.MapFS{"index.html": {}}, ""); err == nil {
		t.Fatal("empty CSP accepted")
	}
}

func TestCSP(t *testing.T) {
	got, err := CSP("https://SSO.example.com/realms/warden", "https://s3.example.com:8443", "", "https://sso.example.com")
	if err != nil {
		t.Fatal(err)
	}
	want := "default-src 'self'; script-src 'self'; style-src 'self'; img-src 'self' data:; font-src 'self' data:; " +
		"connect-src 'self' https://sso.example.com https://s3.example.com:8443; frame-ancestors 'none'; base-uri 'none'; " +
		"form-action 'self' https://sso.example.com; object-src 'none'"
	if got != want {
		t.Fatalf("\n got %s\nwant %s", got, want)
	}
	for _, s := range []string{"unsafe-inline", "unsafe-eval", "*", "blob:"} {
		if strings.Contains(got, s) {
			t.Fatalf("policy allows %s", s)
		}
	}
	if got, _ := CSP("http://[::1]:8180/realms/warden"); !strings.Contains(got, "connect-src 'self' http://[::1]:8180;") {
		t.Fatal(got)
	}
}

// Configuration values are pasted into a header: nothing may add a directive or a source.
func TestCSPRefusesInjection(t *testing.T) {
	for _, bad := range []string{
		"",
		"sso.example.com",
		"javascript:alert(1)",
		"ftp://sso.example.com",
		"https://sso.example.com; script-src *",
		"https://sso.example.com%3B%20script-src%20*",
		"https://sso.example.com,evil.example",
		"https://user:pw@sso.example.com",
		"https://*.example.com",
		"https://sso.example.com:99999999",
		"https://sso.example.com 'unsafe-inline'",
	} {
		if p, err := CSP(bad); err == nil {
			t.Errorf("issuer %q accepted: %s", bad, p)
		}
		if p, err := CSP("https://sso.example.com", bad); err == nil && bad != "" {
			t.Errorf("storage %q accepted: %s", bad, p)
		}
	}
}

func TestEmbeddedWithoutTagIsNil(t *testing.T) {
	if Embedded() != nil {
		t.Skip("built with -tags webui")
	}
}
