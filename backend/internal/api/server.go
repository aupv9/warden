// Package api is the REST API under /api/v1. It runs on common-go's httpserver
// (gin) and answers with common-go's response envelope {data, error, meta}.
package api

import (
	_ "embed"
	"log/slog"
	"net/http"
	"strings"
	"time"

	cgauth "github.com/aupv9/common-go/auth"
	apperrors "github.com/aupv9/common-go/errors"
	"github.com/aupv9/common-go/logger"
	"github.com/aupv9/common-go/response"
	"github.com/aupv9/common-go/transport/httpserver"
	"github.com/gin-gonic/gin"

	"github.com/aupv9/warden/backend/internal/service"
)

const (
	Prefix       = "/api/v1"
	MaxBodyBytes = 1 << 20 // uploads go straight to object storage, not through the API
)

//go:embed openapi.json
var openAPI []byte

// ServerOptions are applied on top of the options common-go derives from config.
func ServerOptions() []httpserver.Option {
	return []httpserver.Option{
		httpserver.WithSecurityHeaders(false), // HSTS belongs to the TLS-terminating proxy
		httpserver.WithBodyLimit(MaxBodyBytes),
		httpserver.WithRequestTimeout(30 * time.Second),
		httpserver.WithMiddleware(apiHeaders()),
		// common-go mounts /admin/loglevel unauthenticated unless guarded.
		httpserver.WithAdminGuard(denyAll()),
	}
}

// apiHeaders adds what common-go's SecurityHeaders doesn't: a deny-all CSP and no caching.
func apiHeaders() gin.HandlerFunc {
	return func(c *gin.Context) {
		h := c.Writer.Header()
		h.Set("Content-Security-Policy", "default-src 'none'; frame-ancestors 'none'")
		h.Set("Cache-Control", "no-store")
		c.Next()
	}
}

func denyAll() gin.HandlerFunc {
	return func(c *gin.Context) {
		c.Abort()
		response.Error(c.Writer, c.Request, apperrors.NotFound("NOT_FOUND", "not found"))
	}
}

// ObjectStore and ErrObjectNotFound are the object-storage seam (presigned
// uploads, HEAD before a scan starts); see service.ObjectStore.
type ObjectStore = service.ObjectStore

var ErrObjectNotFound = service.ErrObjectNotFound

// Register mounts Warden's routes on the engine.
func Register(e *gin.Engine, v cgauth.Verifier, svc *service.Service) {
	e.HandleMethodNotAllowed = true
	// No proxy is trusted: X-Forwarded-For would otherwise let clients choose
	// the IP that gets logged. (The audit log uses the peer address regardless.)
	_ = e.SetTrustedProxies(nil)
	e.NoRoute(func(c *gin.Context) {
		response.Error(c.Writer, c.Request, apperrors.NotFound("NOT_FOUND", "not found"))
	})
	e.NoMethod(func(c *gin.Context) {
		response.Error(c.Writer, c.Request,
			apperrors.Invalid("METHOD_NOT_ALLOWED", "method not allowed").WithHTTPStatus(http.StatusMethodNotAllowed))
	})
	e.GET(Prefix+"/openapi.json", func(c *gin.Context) {
		c.Data(http.StatusOK, "application/json", openAPI)
	})

	v1 := e.Group(Prefix, Authenticate(v), identify(svc))
	handlers{svc: svc}.routes(v1)
}

// Authenticate requires a valid bearer token. Failures are 401 with a generic
// message; the reason is logged server-side only.
func Authenticate(v cgauth.Verifier) gin.HandlerFunc {
	return func(c *gin.Context) {
		scheme, token, _ := strings.Cut(c.GetHeader("Authorization"), " ")
		if !strings.EqualFold(scheme, "bearer") {
			token = ""
		}
		p, err := v.Verify(c.Request.Context(), strings.TrimSpace(token))
		if err != nil {
			if ae, ok := apperrors.As(err); ok && ae.Cause != nil {
				logger.FromContext(c.Request.Context()).Info("token rejected", slog.Any("reason", ae.Cause))
			}
			c.Header("WWW-Authenticate", `Bearer realm="warden"`)
			c.Abort()
			response.Error(c.Writer, c.Request, err)
			return
		}
		c.Request = c.Request.WithContext(cgauth.IntoContext(c.Request.Context(), p))
		c.Next()
	}
}
