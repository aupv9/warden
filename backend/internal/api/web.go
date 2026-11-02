package api

import (
	"net/http"
	"strings"

	apperrors "github.com/aupv9/common-go/errors"
	"github.com/aupv9/common-go/response"
	"github.com/gin-gonic/gin"
)

// WebConfig is what the bundled web UI needs before anyone signs in
// (GET /api/v1/web-config, OpenAPI schema WebConfig). The issuer is always the
// server's oidc.issuer, so the UI can't be pointed at a provider the API
// doesn't trust.
type WebConfig struct {
	Issuer   string  `json:"issuer"`
	ClientID string  `json:"client_id"`
	Scope    string  `json:"scope"`
	Audience *string `json:"audience"` // null: not sent
}

// Option configures Register.
type Option func(*options)

type options struct {
	web WebConfig
	ui  http.Handler
}

// WithWebConfig sets the body of GET /api/v1/web-config.
func WithWebConfig(w WebConfig) Option { return func(o *options) { o.web = w } }

// WithUI serves the web UI (internal/webui) for GET and HEAD requests that no
// route matches, outside /api and the health and admin paths.
func WithUI(h http.Handler) Option { return func(o *options) { o.ui = h } }

// webConfig is public on purpose: no token exists before sign-in, and every
// value is one a browser sees during sign-in anyway. Same body for everyone,
// never cached (an operator who changes the client must not wait for caches).
func webConfig(w WebConfig) gin.HandlerFunc {
	return func(c *gin.Context) {
		if w.Issuer == "" || w.ClientID == "" || w.Scope == "" {
			response.Error(c.Writer, c.Request, apperrors.Internal("INTERNAL", "internal error"))
			return
		}
		response.OK(c.Writer, c.Request, w)
	}
}

// reservedPrefixes never fall back to the UI's index.html: a mistyped API path
// must stay a JSON 404, and the probes' paths must never answer 200 with HTML.
var reservedPrefixes = []string{Prefix, "/healthz", "/readyz", "/livez", "/info", "/admin", "/metrics"}

func isReserved(path string) bool {
	for _, p := range reservedPrefixes {
		if path == p || strings.HasPrefix(path, p+"/") {
			return true
		}
	}
	return path == "/api" || strings.HasPrefix(path, "/api/")
}

// noRoute answers what no route matched: the UI for GET/HEAD outside the
// reserved paths (when the binary bundles it), else the JSON 404.
func noRoute(ui http.Handler) gin.HandlerFunc {
	return func(c *gin.Context) {
		m := c.Request.Method
		if ui != nil && (m == http.MethodGet || m == http.MethodHead) && !isReserved(c.Request.URL.Path) {
			ui.ServeHTTP(c.Writer, c.Request)
			return
		}
		response.Error(c.Writer, c.Request, apperrors.NotFound("NOT_FOUND", "not found"))
	}
}
