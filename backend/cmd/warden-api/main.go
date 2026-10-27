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
	"github.com/aupv9/warden/backend/internal/domain/rbac"
	"github.com/aupv9/warden/backend/internal/service"
	"github.com/aupv9/warden/backend/internal/storage"
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
	fx.New(appOptions(cfg)).Run()
}

// appOptions is the API's dependency graph.
func appOptions(cfg *config.Config) fx.Option {
	return fx.Options(
		app.Core(cfg),
		db.Module,
		httpserver.Module(api.ServerOptions()...),
		fx.Provide(func(c *config.Config) cgauth.Verifier {
			v := auth.NewVerifier(c.OIDC.Issuer, c.OIDC.Audience,
				auth.NewJWKS(c.OIDC.Issuer, c.OIDC.JWKSURL, c.OIDC.JWKSCache, c.OIDC.Algorithms))
			v.Algs = c.OIDC.Algorithms
			v.MFA = auth.MFAPolicy{AMR: c.OIDC.MFAAMR, ACR: c.OIDC.MFAACR}
			return v
		}),
		// Insert-only River client: the API enqueues scans, workers run them.
		fx.Provide(func(pool *pgxpool.Pool) (*river.Client[pgx.Tx], error) {
			return worker.NewClient(pool, worker.Options{})
		}),
		fx.Provide(func(c *config.Config) (api.ObjectStore, error) {
			client, err := storage.New(storage.FromSection(c.Storage))
			if err != nil {
				return nil, err
			}
			return objectStore{client}, nil
		}),
		fx.Provide(func(c *config.Config, pool *pgxpool.Pool, jobs *river.Client[pgx.Tx], objects api.ObjectStore, log *slog.Logger) *service.Service {
			return service.New(store.New(pool, jobs), objects, ServiceConfig(c), log)
		}),
		fx.Invoke(api.Register),
	)
}

// ServiceConfig maps the configuration to the service's settings.
func ServiceConfig(c *config.Config) service.Config {
	return service.Config{
		UploadMaxBytes:   int64(c.Scan.UploadMaxMB) << 20,
		RateLimitPerHour: c.Scan.RateLimitPerHour,
		UploadURLTTL:     15 * time.Minute,
		RequireMFARoles:  roles(c.OIDC.RequireMFARoles),
		Limits: service.Limits{
			UploadMaxMB: c.Scan.UploadMaxMB, UnzipMaxMB: c.Scan.UnzipMaxMB, UnzipMaxFiles: c.Scan.UnzipMaxFiles,
			ScanTimeoutMinutes: int(c.Scan.Timeout / time.Minute), ScansPerHour: c.Scan.RateLimitPerHour,
		},
	}
}

func roles(names []string) []rbac.Role {
	out := make([]rbac.Role, 0, len(names))
	for _, n := range names {
		out = append(out, rbac.Role(n))
	}
	return out
}

// objectStore adapts the S3 client to the service's ObjectStore, which has its
// own not-found sentinel so the service doesn't depend on the storage package.
type objectStore struct{ *storage.Client }

func (o objectStore) Head(ctx context.Context, key string) (int64, error) {
	size, err := o.Client.Head(ctx, key)
	if errors.Is(err, storage.ErrNotFound) {
		return 0, service.ErrObjectNotFound
	}
	return size, err
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
