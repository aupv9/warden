// Package app wires the common-go modules shared by warden-api and warden-worker.
package app

import (
	"log/slog"

	cgconfig "github.com/aupv9/common-go/config"
	"github.com/aupv9/common-go/health"
	"github.com/aupv9/common-go/logger"
	"github.com/aupv9/common-go/observability"
	"go.uber.org/fx"
	"go.uber.org/fx/fxevent"

	"github.com/aupv9/warden/backend/internal/config"
)

// Core provides *config.Config and the common-go *config.AppConfig it embeds,
// plus logger, observability (off unless WARDEN_OTEL__ENABLED=true) and the
// health registry. It replaces foundation.Core, which would load config with
// the APP_ prefix and import every transport (Kafka, gRPC, Redis).
func Core(cfg *config.Config) fx.Option {
	return fx.Options(
		fx.Supply(cfg),
		fx.Provide(func(c *config.Config) *cgconfig.AppConfig { return &c.AppConfig }),
		logger.Module,
		observability.Module,
		health.Module,
		fx.WithLogger(func(l *slog.Logger) fxevent.Logger { return &fxevent.SlogLogger{Logger: l} }),
	)
}
