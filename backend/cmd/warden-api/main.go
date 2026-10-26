// warden-api serves the REST API. `warden-api -healthcheck` probes a running
// instance (the container image has no shell or curl).
package main

import (
	"flag"
	"fmt"
	"net"
	"net/http"
	"os"
	"strconv"
	"time"

	cgauth "github.com/aupv9/common-go/auth"
	"github.com/aupv9/common-go/transport/httpserver"
	"go.uber.org/fx"

	"github.com/aupv9/warden/backend/internal/api"
	"github.com/aupv9/warden/backend/internal/app"
	"github.com/aupv9/warden/backend/internal/auth"
	"github.com/aupv9/warden/backend/internal/config"
	"github.com/aupv9/warden/backend/internal/db"
)

func main() {
	healthcheck := flag.Bool("healthcheck", false, "GET /healthz on the configured port and exit 0 if healthy")
	flag.Parse()
	cfg, err := config.Load()
	if err != nil {
		fmt.Fprintln(os.Stderr, err)
		os.Exit(2)
	}
	if *healthcheck {
		os.Exit(probe(cfg.Server.Port))
	}
	fx.New(
		app.Core(cfg),
		db.Module,
		httpserver.Module(api.ServerOptions()...),
		fx.Provide(func(c *config.Config) cgauth.Verifier {
			return auth.NewVerifier(c.OIDC.Issuer, c.OIDC.Audience, auth.NewJWKS(c.OIDC.Issuer, c.OIDC.JWKSCache))
		}),
		fx.Invoke(api.Register),
	).Run()
}

func probe(port int) int {
	c := &http.Client{Timeout: 3 * time.Second}
	resp, err := c.Get("http://" + net.JoinHostPort("127.0.0.1", strconv.Itoa(port)) + "/healthz")
	if err != nil {
		return 1
	}
	resp.Body.Close()
	if resp.StatusCode != http.StatusOK {
		return 1
	}
	return 0
}
