package app

import (
	"context"
	"errors"
	"log/slog"
	"net"
	"net/http"
	"time"

	"github.com/aupv9/common-go/health"
	"go.uber.org/fx"

	"github.com/aupv9/warden/backend/internal/config"
	"github.com/aupv9/warden/backend/internal/metrics"
)

// AdminHealth, supplied as true by the worker, adds /healthz and /readyz to
// the admin listener. The API serves those on its main port already.
type AdminHealth bool

// AdminHandler serves the admin listener's routes and nothing else (404):
// GET /metrics, and with withHealth GET /healthz and /readyz.
func AdminHandler(reg *health.Registry, withHealth bool) http.Handler {
	mux := http.NewServeMux()
	mux.Handle("GET /metrics", metrics.Handler())
	if withHealth {
		mux.HandleFunc("GET /healthz", reg.LivenessHandler())
		mux.HandleFunc("GET /readyz", reg.ReadinessHandler())
	}
	return mux
}

// newAdminServer: timeouts sized for a scrape or a probe; nothing on this
// listener streams or takes a body.
func newAdminServer(h http.Handler) *http.Server {
	return &http.Server{
		Handler:           h,
		ReadHeaderTimeout: 5 * time.Second,
		ReadTimeout:       10 * time.Second,
		WriteTimeout:      30 * time.Second,
		IdleTimeout:       60 * time.Second,
		MaxHeaderBytes:    16 << 10,
	}
}

type adminParams struct {
	fx.In
	LC     fx.Lifecycle
	Cfg    *config.Config
	Reg    *health.Registry
	Log    *slog.Logger
	Health AdminHealth `optional:"true"`
}

// runAdmin starts the admin listener when admin.addr is set. It binds exactly
// that address (no fallback): a port that is taken fails startup.
func runAdmin(p adminParams) {
	addr := p.Cfg.Admin.Addr
	if addr == "" {
		return
	}
	srv := newAdminServer(AdminHandler(p.Reg, bool(p.Health)))
	p.LC.Append(fx.Hook{
		OnStart: func(context.Context) error {
			l, err := net.Listen("tcp", addr)
			if err != nil {
				return err
			}
			p.Log.Info("admin listener started", "addr", l.Addr().String())
			go func() {
				if err := srv.Serve(l); err != nil && !errors.Is(err, http.ErrServerClosed) {
					p.Log.Error("admin listener stopped", "err", err)
				}
			}()
			return nil
		},
		OnStop: srv.Shutdown,
	})
}

// ProbeAdmin GETs /healthz on the admin listener at addr and returns the exit
// code for -healthcheck: 0 when healthy, 1 otherwise (also when addr is empty,
// as the worker has no other HTTP server). A wildcard host is probed on
// loopback.
func ProbeAdmin(addr string) int {
	if addr == "" {
		return 1
	}
	host, port, err := net.SplitHostPort(addr)
	if err != nil {
		return 1
	}
	if ip := net.ParseIP(host); host == "" || (ip != nil && ip.IsUnspecified()) {
		host = "127.0.0.1"
		if ip != nil && ip.To4() == nil {
			host = "::1"
		}
	}
	c := &http.Client{Timeout: 3 * time.Second,
		// One request, no proxy (HTTP_PROXY must not see the probe), no pooled connection.
		Transport: &http.Transport{DisableKeepAlives: true},
		// Never follow a redirect away from the admin listener.
		CheckRedirect: func(*http.Request, []*http.Request) error { return http.ErrUseLastResponse }}
	resp, err := c.Get("http://" + net.JoinHostPort(host, port) + "/healthz")
	if err != nil {
		return 1
	}
	resp.Body.Close()
	if resp.StatusCode != http.StatusOK {
		return 1
	}
	return 0
}
