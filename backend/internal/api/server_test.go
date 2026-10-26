package api

import (
	"context"
	"crypto/rand"
	"crypto/rsa"
	"encoding/json"
	"errors"
	"io"
	"log/slog"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"

	cgconfig "github.com/aupv9/common-go/config"
	"github.com/aupv9/common-go/health"
	"github.com/aupv9/common-go/logger"
	"github.com/aupv9/common-go/transport/httpserver"
	"github.com/gin-gonic/gin"
	"github.com/golang-jwt/jwt/v5"
	"go.uber.org/fx"

	"github.com/aupv9/warden/backend/internal/auth"
	"github.com/aupv9/warden/backend/internal/db"
	"github.com/aupv9/warden/backend/internal/service"
	"github.com/aupv9/warden/backend/internal/service/servicetest"
)

const (
	issuer   = "http://localhost:8180/realms/warden"
	audience = "warden-api"
)

var key, _ = rsa.GenerateKey(rand.Reader, 2048)

func verifier() *auth.Verifier {
	return auth.NewVerifier(issuer, audience, auth.StaticKeys{"k1": &key.PublicKey})
}

type pinger struct{ err error }

func (p pinger) Ping(context.Context) error { return p.err }

// server builds the same HTTP stack warden-api runs: common-go's httpserver
// module (health, /admin, middleware) plus Warden's routes, without listening.
func server(t *testing.T, dbErr error) http.Handler {
	t.Helper()
	return serverWith(t, dbErr, service.New(servicetest.New(), nil, service.Config{}, nil))
}

func serverWith(t *testing.T, dbErr error, svc *service.Service) http.Handler {
	t.Helper()
	var engine *gin.Engine
	app := fx.New(
		fx.NopLogger,
		fx.Supply(cgconfig.DefaultAppConfig(), slog.New(slog.DiscardHandler)),
		fx.Provide(func() *logger.LevelControl { _, l := logger.NewWithControl(logger.Config{Level: "info"}); return l }),
		health.Module,
		httpserver.Module(ServerOptions()...),
		fx.Invoke(func(reg *health.Registry) { reg.Register(db.Checker(pinger{dbErr}, slog.New(slog.DiscardHandler))) }),
		fx.Invoke(func(e *gin.Engine) { Register(e, verifier(), svc) }),
		fx.Populate(&engine),
	)
	if err := app.Err(); err != nil {
		t.Fatal(err)
	}
	return engine
}

func token(t *testing.T, over jwt.MapClaims) string {
	t.Helper()
	now := time.Now().Unix()
	c := jwt.MapClaims{"sub": "u-1", "iss": issuer, "aud": audience, "iat": now, "exp": now + 300,
		"email": "dev@example.com", "amr": []string{"pwd", "otp"}}
	for k, v := range over {
		c[k] = v
	}
	tok := jwt.NewWithClaims(jwt.SigningMethodRS256, c)
	tok.Header["kid"] = "k1"
	s, err := tok.SignedString(key)
	if err != nil {
		t.Fatal(err)
	}
	return s
}

func do(h http.Handler, method, path, authz string, body io.Reader) *httptest.ResponseRecorder {
	r := httptest.NewRequest(method, path, body)
	if authz != "" {
		r.Header.Set("Authorization", authz)
	}
	w := httptest.NewRecorder()
	h.ServeHTTP(w, r)
	return w
}

type envelope struct {
	Data  map[string]any `json:"data"`
	Error *struct {
		Code     string         `json:"code"`
		Message  string         `json:"message"`
		Metadata map[string]any `json:"metadata"`
	} `json:"error"`
	Meta *struct {
		RequestID string `json:"request_id"`
	} `json:"meta"`
}

func decode(t *testing.T, w *httptest.ResponseRecorder) envelope {
	t.Helper()
	var e envelope
	if err := json.Unmarshal(w.Body.Bytes(), &e); err != nil {
		t.Fatalf("%v: %s", err, w.Body)
	}
	return e
}

func TestHealthzHasSecurityHeaders(t *testing.T) {
	w := do(server(t, nil), "GET", "/healthz", "", nil)
	h := w.Header()
	if w.Code != 200 || h.Get("X-Content-Type-Options") != "nosniff" || h.Get("Cache-Control") != "no-store" ||
		h.Get("Content-Security-Policy") == "" || h.Get("X-Frame-Options") != "DENY" || h.Get("X-Request-ID") == "" {
		t.Fatalf("%d %v", w.Code, h)
	}
}

func TestReadyzDoesNotLeakDatabaseErrors(t *testing.T) {
	if w := do(server(t, nil), "GET", "/readyz", "", nil); w.Code != 200 {
		t.Fatal(w.Code)
	}
	w := do(server(t, errors.New("failed to connect to `user=warden_app database=warden`: 10.0.0.5:5432")), "GET", "/readyz", "", nil)
	if w.Code != 503 || strings.Contains(w.Body.String(), "warden_app") || strings.Contains(w.Body.String(), "10.0.0.5") {
		t.Fatalf("%d %s", w.Code, w.Body)
	}
}

func TestAdminEndpointsAreClosed(t *testing.T) {
	h := server(t, nil)
	for _, m := range []string{"GET", "PUT", "POST"} {
		w := do(h, m, "/admin/loglevel", "", strings.NewReader(`{"level":"debug"}`))
		if w.Code != 404 {
			t.Fatalf("%s /admin/loglevel: %d %s", m, w.Code, w.Body)
		}
	}
}

func TestMeRequiresToken(t *testing.T) {
	h := server(t, nil)
	for _, authz := range []string{"", "Basic dXNlcjpwYXNz", "Bearer", "Bearer   "} {
		w := do(h, "GET", "/api/v1/me", authz, nil)
		if w.Code != 401 || !strings.Contains(w.Header().Get("WWW-Authenticate"), "Bearer") {
			t.Fatalf("%q: %d %v", authz, w.Code, w.Header())
		}
		if e := decode(t, w); e.Error == nil || e.Error.Code != "UNAUTHORIZED" || e.Data != nil {
			t.Fatalf("%q: %s", authz, w.Body)
		}
	}
	// A Basic credential must not be fed to the JWT verifier as if it were a token.
	if w := do(h, "GET", "/api/v1/me", "Basic "+token(t, nil), nil); w.Code != 401 {
		t.Fatal(w.Code)
	}
}

func TestMeWithValidToken(t *testing.T) {
	w := do(server(t, nil), "GET", "/api/v1/me", "Bearer "+token(t, nil), nil)
	if w.Code != 200 {
		t.Fatalf("%d %s", w.Code, w.Body)
	}
	e := decode(t, w)
	want := map[string]any{"sub": "u-1", "email": "dev@example.com", "name": nil, "mfa": true}
	for k, v := range want {
		if e.Data[k] != v {
			t.Fatalf("%s: %s", k, w.Body)
		}
	}
	if e.Error != nil || e.Meta == nil || e.Meta.RequestID == "" {
		t.Fatalf("%s", w.Body)
	}
}

func TestRejectionsAreGeneric(t *testing.T) {
	h := server(t, nil)
	tok := jwt.NewWithClaims(jwt.SigningMethodHS256, jwt.MapClaims{"sub": "x", "iss": issuer, "aud": audience,
		"iat": time.Now().Unix(), "exp": time.Now().Unix() + 60})
	tok.Header["kid"] = "k1"
	forged, _ := tok.SignedString([]byte("secret"))
	for _, s := range []string{
		forged,
		token(t, jwt.MapClaims{"aud": "other-api"}),
		token(t, jwt.MapClaims{"iss": "https://evil/realms/x"}),
		token(t, jwt.MapClaims{"exp": time.Now().Unix() - 120}),
	} {
		w := do(h, "GET", "/api/v1/me", "Bearer "+s, nil)
		e := decode(t, w)
		if w.Code != 401 || e.Error.Message != "invalid or expired token" || len(e.Error.Metadata) != 0 {
			t.Fatalf("%d %s", w.Code, w.Body)
		}
	}
}

func TestOpenAPIAndUnknownRoutes(t *testing.T) {
	h := server(t, nil)
	if w := do(h, "GET", "/api/v1/openapi.json", "", nil); w.Code != 200 || !json.Valid(w.Body.Bytes()) {
		t.Fatal(w.Code)
	}
	w := do(h, "GET", "/docs", "", nil)
	if w.Code != 404 || decode(t, w).Error.Code != "NOT_FOUND" || w.Header().Get("Cache-Control") != "no-store" {
		t.Fatalf("%d %s", w.Code, w.Body)
	}
	w = do(h, "POST", "/healthz", "", nil)
	if w.Code != 405 || decode(t, w).Error.Code != "METHOD_NOT_ALLOWED" {
		t.Fatalf("%d %s", w.Code, w.Body)
	}
}

func TestPanicBecomesGeneric500(t *testing.T) {
	srv, err := httpserver.New(slog.New(slog.DiscardHandler), ServerOptions()...)
	if err != nil {
		t.Fatal(err)
	}
	srv.Engine().GET("/boom", func(*gin.Context) { panic("secret internal detail") })
	w := do(srv.Engine(), "GET", "/boom", "", nil)
	if w.Code != 500 || strings.Contains(w.Body.String(), "secret internal detail") {
		t.Fatalf("%d %s", w.Code, w.Body)
	}
}

func TestBodyLimit(t *testing.T) {
	srv, _ := httpserver.New(slog.New(slog.DiscardHandler), ServerOptions()...)
	srv.Engine().POST("/echo", func(c *gin.Context) {
		if _, err := io.ReadAll(c.Request.Body); err != nil {
			c.Status(http.StatusRequestEntityTooLarge)
			return
		}
		c.Status(http.StatusOK)
	})
	if w := do(srv.Engine(), "POST", "/echo", "", strings.NewReader(strings.Repeat("a", MaxBodyBytes+1))); w.Code != 413 {
		t.Fatal(w.Code)
	}
}
