// Package webui serves the built web UI (frontend/dist) from warden-api's own
// listener, so a production install is one origin: the UI calls /api/v1 with
// no CORS, and its Content-Security-Policy can say 'self'.
//
// The UI is compiled in only with `-tags webui` (the Dockerfile and
// `make build-webui` copy frontend/dist to internal/webui/dist first);
// without the tag Embedded returns nil and the API serves no UI, so plain
// `go build` and `go test` work without Node.
package webui

import (
	"bytes"
	"errors"
	"fmt"
	"io/fs"
	"net/http"
	"net/url"
	"path"
	"regexp"
	"slices"
	"strings"
	"time"
)

// contentTypes is explicit rather than mime.TypeByExtension: the scratch image
// has no /etc/mime.types, and Go's built-in table lacks the font types.
var contentTypes = map[string]string{
	".html":        "text/html; charset=utf-8",
	".js":          "text/javascript; charset=utf-8",
	".mjs":         "text/javascript; charset=utf-8",
	".css":         "text/css; charset=utf-8",
	".json":        "application/json",
	".map":         "application/json",
	".svg":         "image/svg+xml",
	".png":         "image/png",
	".ico":         "image/x-icon",
	".webp":        "image/webp",
	".woff":        "font/woff",
	".woff2":       "font/woff2",
	".txt":         "text/plain; charset=utf-8",
	".webmanifest": "application/manifest+json",
}

const (
	// Vite names everything under assets/ by content hash, so a URL never
	// changes meaning and browsers may keep it for a year.
	cacheImmutable = "public, max-age=31536000, immutable"
	// index.html names the current hashes: always fetch it again, so an
	// upgrade takes effect on the next load.
	cacheNever = "no-store"
	// Anything else at the root (none today) is revalidated.
	cacheRevalidate = "no-cache"
)

type handler struct {
	files fs.FS
	index []byte
	csp   func() string
}

// New serves dist, which must hold index.html: a file that exists is served
// as itself, a missing file under assets/ is a 404, and any other path gets
// index.html (client-side routing). csp gives the Content-Security-Policy
// for each response (it follows the provider's discovery document); it is set
// on every response, because a dedicated worker script runs under the policy
// it was served with.
func New(dist fs.FS, csp func() string) (http.Handler, error) {
	if dist == nil {
		return nil, errors.New("webui: no UI bundled")
	}
	if csp == nil || csp() == "" {
		return nil, errors.New("webui: a Content-Security-Policy is required")
	}
	index, err := fs.ReadFile(dist, "index.html")
	if err != nil {
		return nil, fmt.Errorf("webui: %w", err)
	}
	return &handler{files: dist, index: index, csp: csp}, nil
}

func (h *handler) ServeHTTP(w http.ResponseWriter, r *http.Request) {
	hdr := w.Header()
	hdr.Set("Content-Security-Policy", h.csp())
	if r.Method != http.MethodGet && r.Method != http.MethodHead {
		hdr.Set("Allow", "GET, HEAD")
		http.Error(w, "method not allowed", http.StatusMethodNotAllowed)
		return
	}
	name, ok := fileName(r.URL)
	if !ok {
		notFound(w)
		return
	}
	if name != "" && name != "index.html" {
		if body, ok := h.read(name); ok {
			cache := cacheRevalidate
			if strings.HasPrefix(name, "assets/") {
				cache = cacheImmutable
			}
			serve(w, r, name, body, cache)
			return
		}
		// A stale or mistyped asset URL must not come back as HTML with a 200
		// (the browser would cache it for a year as "the script").
		if strings.HasPrefix(name, "assets/") {
			notFound(w)
			return
		}
	}
	serve(w, r, "index.html", h.index, cacheNever)
}

// read returns a regular file's content; directories and anything else are absent.
func (h *handler) read(name string) ([]byte, bool) {
	st, err := fs.Stat(h.files, name)
	if err != nil || !st.Mode().IsRegular() {
		return nil, false
	}
	b, err := fs.ReadFile(h.files, name)
	return b, err == nil
}

func serve(w http.ResponseWriter, r *http.Request, name string, body []byte, cache string) {
	hdr := w.Header()
	ct, ok := contentTypes[path.Ext(name)]
	if !ok {
		ct = "application/octet-stream"
	}
	hdr.Set("Content-Type", ct)
	hdr.Set("Cache-Control", cache)
	// ServeContent answers HEAD and Range; the zero time sends no Last-Modified.
	http.ServeContent(w, r, name, time.Time{}, bytes.NewReader(body))
}

func notFound(w http.ResponseWriter) {
	w.Header().Set("Cache-Control", cacheNever)
	http.Error(w, "not found", http.StatusNotFound)
}

// fileName maps a request path to a name inside dist ("" for the root). It
// refuses rather than normalizes anything unusual, so no two spellings reach
// the same file and nothing outside dist is ever named: escaped slashes or
// dots (RawPath is set only when the escaping differs from the canonical
// one), "." and ".." segments, dotfiles, empty segments, backslashes and
// control characters.
func fileName(u *url.URL) (string, bool) {
	p := u.Path
	if u.RawPath != "" || !strings.HasPrefix(p, "/") || strings.ContainsAny(p, `\%`) || hasControl(p) {
		return "", false
	}
	name := strings.TrimPrefix(p, "/")
	if name == "" {
		return "", true
	}
	segs := strings.Split(name, "/")
	for i, s := range segs {
		if s == "" && i == len(segs)-1 {
			continue // trailing slash: a client-side route such as /projects/
		}
		if s == "" || strings.HasPrefix(s, ".") {
			return "", false
		}
	}
	name = strings.TrimSuffix(name, "/")
	if !fs.ValidPath(name) {
		return "", false
	}
	return name, true
}

func hasControl(s string) bool {
	return strings.ContainsFunc(s, func(r rune) bool { return r < 0x20 || r == 0x7f })
}

// origin is the scheme://host[:port] of an http(s) URL, lower-cased. The host
// is checked character by character because it is pasted into a CSP header:
// a space, ';' or ',' would let a configuration value add directives.
var originHost = regexp.MustCompile(`^(\[[0-9a-f:.]+\]|[a-z0-9.-]+)(:[0-9]{1,5})?$`)

func origin(raw string) (string, error) {
	u, err := url.Parse(raw)
	if err != nil {
		return "", fmt.Errorf("webui: %q is not a URL", raw)
	}
	scheme, host := strings.ToLower(u.Scheme), strings.ToLower(u.Host)
	if (scheme != "https" && scheme != "http") || u.User != nil || !originHost.MatchString(host) {
		return "", fmt.Errorf("webui: %q must be an http(s) URL with a plain host", raw)
	}
	return scheme + "://" + host, nil
}

// Policy is what the web UI's CSP allows besides Warden itself. Every value
// comes from server configuration or the provider's discovery document, and
// only its origin is used: a CSP source with a path matches that exact path
// only, so the issuer URL itself would not cover its discovery document.
type Policy struct {
	Issuer  string // oidc.issuer (required)
	Storage string // where presigned URLs point (storage.public_endpoint, else endpoint)
	// The provider's endpoints from discovery (auth.BrowserEndpoints), empty
	// until it has been read; one that isn't a plain http(s) URL is left out.
	Authorization, Token, UserInfo, EndSession string
}

// CSP is the web UI's Content-Security-Policy. Scripts, styles and fonts come
// only from Warden itself: the build has no inline <script>, <style> or style
// attribute and inlines no font (bundle_test.go checks the embedded build),
// and React sets style props through the CSSOM, which style-src doesn't
// govern. Images may be data: URIs (Vite inlines small ones).
//
//   - connect-src: the issuer (discovery), the token, userinfo and end-session
//     endpoints (fetches by oidc-client-ts), and the object store (presigned
//     uploads are PUTs from the browser).
//   - frame-src: the issuer and authorization endpoint, for oidc-client-ts's
//     silent renewal in a hidden iframe when there is no refresh token; 'self'
//     for the page it redirects back to.
//   - form-action: the authorization and end-session endpoints, in case a
//     sign-in or sign-out step is a form post.
//
// Nothing may frame the UI (frame-ancestors 'none').
func (p Policy) CSP() (string, error) {
	iss, err := origin(p.Issuer)
	if err != nil {
		return "", err
	}
	var store string
	if p.Storage != "" {
		if store, err = origin(p.Storage); err != nil {
			return "", err
		}
	}
	discovered := func(raw string) string {
		if o, err := origin(raw); err == nil {
			return o
		}
		return ""
	}
	auth, token, userinfo, endSession := discovered(p.Authorization), discovered(p.Token), discovered(p.UserInfo), discovered(p.EndSession)
	return strings.Join([]string{
		"default-src 'self'",
		"script-src 'self'",
		"style-src 'self'",
		"img-src 'self' data:",
		"font-src 'self'",
		"connect-src " + sources(iss, token, userinfo, endSession, store),
		"frame-src " + sources(iss, auth),
		"frame-ancestors 'none'",
		"base-uri 'none'",
		"form-action " + sources(iss, auth, endSession),
		"object-src 'none'",
	}, "; "), nil
}

// sources is 'self' plus each distinct non-empty origin, in order.
func sources(origins ...string) string {
	out := []string{"'self'"}
	for _, o := range origins {
		if o != "" && !slices.Contains(out, o) {
			out = append(out, o)
		}
	}
	return strings.Join(out, " ")
}
