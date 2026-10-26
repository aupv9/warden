// warden-api serves the REST API. `warden-api -healthcheck` probes a running
// instance (the container image has no shell or curl).
package main

import (
	"context"
	"errors"
	"flag"
	"fmt"
	"log/slog"
	"net"
	"net/http"
	"os"
	"strconv"
	"time"

	cgauth "github.com/aupv9/common-go/auth"
	"github.com/aupv9/common-go/transport/httpserver"
	"github.com/jackc/pgx/v5"
	"github.com/jackc/pgx/v5/pgxpool"
	"github.com/riverqueue/river"
	"go.uber.org/fx"

	"github.com/aupv9/warden/backend/internal/api"
	"github.com/aupv9/warden/backend/internal/app"
	"github.com/aupv9/warden/backend/internal/auth"
	"github.com/aupv9/warden/backend/internal/config"
	"github.com/aupv9/warden/backend/internal/db"
	"github.com/aupv9/warden/backend/internal/service"
	"github.com/aupv9/warden/backend/internal/store"
	"github.com/aupv9/warden/backend/internal/worker"
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
		// Insert-only River client: the API enqueues scans, workers run them.
		fx.Provide(func(pool *pgxpool.Pool) (*river.Client[pgx.Tx], error) {
			return worker.NewClient(pool, worker.Options{})
		}),
		fx.Provide(func() api.ObjectStore { return unwiredStore{} }),
		fx.Provide(func(c *config.Config, pool *pgxpool.Pool, jobs *river.Client[pgx.Tx], objects api.ObjectStore, log *slog.Logger) *service.Service {
			return service.New(store.New(pool, jobs), objects, ServiceConfig(c), log)
		}),
		fx.Invoke(api.Register),
	).Run()
}

// ServiceConfig maps the configuration to the service's settings.
func ServiceConfig(c *config.Config) service.Config {
	return service.Config{
		UploadMaxBytes:   int64(c.Scan.UploadMaxMB) << 20,
		RateLimitPerHour: c.Scan.RateLimitPerHour,
		UploadURLTTL:     15 * time.Minute,
		Limits: service.Limits{
			UploadMaxMB: c.Scan.UploadMaxMB, UnzipMaxMB: c.Scan.UnzipMaxMB, UnzipMaxFiles: c.Scan.UnzipMaxFiles,
			ScanTimeoutMinutes: int(c.Scan.Timeout / time.Minute), ScansPerHour: c.Scan.RateLimitPerHour,
		},
	}
}

// unwiredStore stands in until the S3 implementation (internal/storage) is
// wired: creating or starting a scan fails with a generic 500 (the reason is logged).
type unwiredStore struct{}

var errStorageNotWired = errors.New("object storage not wired")

func (unwiredStore) PresignPut(context.Context, string, int64, string, time.Duration) (string, map[string]string, error) {
	return "", nil, errStorageNotWired
}

func (unwiredStore) Head(context.Context, string) (int64, error) { return 0, errStorageNotWired }

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
