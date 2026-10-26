// Package config loads Warden's settings with common-go/config: defaults →
// optional YAML file (WARDEN_CONFIG_FILE, default config.yaml) → environment.
//
// Environment variables use the WARDEN_ prefix and "__" for nesting:
//
//	WARDEN_DATABASE__DSN=postgres://warden_app:...@db:5432/warden
//	WARDEN_OIDC__ISSUER=https://sso.example.com/realms/warden
//	WARDEN_SCAN__SANDBOX_RUNTIME=runsc
//
// Any secret may be given as "file:/run/secrets/name" (Docker/Kubernetes secrets).
package config

import (
	"fmt"
	"log/slog"
	"os"
	"regexp"
	"slices"
	"time"

	cgconfig "github.com/aupv9/common-go/config"
)

const EnvPrefix = "WARDEN_"

var Scanners = []string{"gitleaks", "opengrep", "trivy", "checkov"}

// digestPinned: a registry reference pinned by digest (a tag may precede the digest,
// as in scanners/images.lock.json; the digest decides), or a local image ID (content
// addressed, so just as immutable; used for scanner images built from scanners/).
var digestPinned = regexp.MustCompile(`^([a-z0-9.\-]+(:\d+)?(/[a-z0-9._\-]+)+(:[A-Za-z0-9_][A-Za-z0-9._\-]{0,127})?@sha256:[0-9a-f]{64}|sha256:[0-9a-f]{64})$`)

// Secret never prints its value (logs, %v, JSON).
type Secret string

func (Secret) String() string               { return "****" }
func (Secret) GoString() string             { return "****" }
func (Secret) MarshalJSON() ([]byte, error) { return []byte(`"****"`), nil }
func (Secret) LogValue() slog.Value         { return slog.StringValue("****") }
func (s Secret) Reveal() string             { return string(s) }

// Config is common-go's AppConfig (App, Log, Server, Otel, Database; its Auth,
// GRPC, EventBus and Cache sections are unused) plus Warden's own Settings.
type Config struct {
	cgconfig.AppConfig
	Settings
}

type Settings struct {
	OIDC    OIDCSection    `koanf:"oidc"`
	Migrate MigrateSection `koanf:"migrate"`
	Storage StorageSection `koanf:"storage"`
	SMTP    SMTPSection    `koanf:"smtp"`
	Scan    ScanSection    `koanf:"scan"`
}

type OIDCSection struct {
	Issuer    string        `koanf:"issuer" validate:"required,url"`
	Audience  string        `koanf:"audience" validate:"required"`
	JWKSCache time.Duration `koanf:"jwks_cache"`
}

// MigrateSection: only warden-migrate connects as the schema owner.
type MigrateSection struct {
	DSN Secret `koanf:"dsn"`
}

type StorageSection struct {
	Endpoint  string `koanf:"endpoint"`
	Bucket    string `koanf:"bucket"`
	AccessKey Secret `koanf:"access_key"`
	SecretKey Secret `koanf:"secret_key"`
}

type SMTPSection struct {
	Host          string `koanf:"host"`
	Port          int    `koanf:"port"`
	From          string `koanf:"from"`
	PublicBaseURL string `koanf:"public_base_url"`
}

type ScanSection struct {
	UploadMaxMB         int               `koanf:"upload_max_mb" validate:"min=1"`
	UnzipMaxMB          int               `koanf:"unzip_max_mb" validate:"min=1"`
	UnzipMaxFiles       int               `koanf:"unzip_max_files" validate:"min=1"`
	Timeout             time.Duration     `koanf:"timeout" validate:"min=1m"`
	SlotsPerNode        int               `koanf:"slots_per_node" validate:"min=1"`
	ScratchDir          string            `koanf:"scratch_dir" validate:"required"`
	MirrorDir           string            `koanf:"mirror_dir" validate:"required"`
	SandboxRuntime      string            `koanf:"sandbox_runtime" validate:"oneof=runsc runc"`
	Images              map[string]string `koanf:"images"`
	HMACKey             Secret            `koanf:"hmac_key"`
	SourceRetention     time.Duration     `koanf:"source_retention"`
	RateLimitPerHour    int               `koanf:"rate_limit_per_hour"`
	AutocloseGuardRatio float64           `koanf:"autoclose_guard_ratio" validate:"min=0,max=1"`
}

func appDefaults() *cgconfig.AppConfig {
	app := cgconfig.DefaultAppConfig()
	app.App.Name = "warden"
	app.Server.Host = "127.0.0.1"
	app.Server.Port = 8010
	app.Server.ReadTimeout = 30 * time.Second
	app.Server.WriteTimeout = 60 * time.Second
	app.Server.ShutdownTimeout = 20 * time.Second
	app.Database = cgconfig.DatabaseSection{
		Host: "localhost", Port: 5432, User: "warden_app", Name: "warden", SSLMode: "prefer",
		MaxConns: 10, MinConns: 1, MaxConnLifetime: time.Hour, MaxConnIdleTime: 30 * time.Minute,
		ConnectTimeout: 5 * time.Second,
	}
	// Unused common-go sections: keep them inert.
	app.EventBus = cgconfig.EventBusSection{}
	app.Cache = cgconfig.CacheSection{}
	app.Auth = cgconfig.AuthSection{}
	return app
}

func settingsDefaults() *Settings {
	return &Settings{
		OIDC: OIDCSection{
			Issuer:    "http://localhost:8180/realms/warden",
			Audience:  "warden-api",
			JWKSCache: 10 * time.Minute,
		},
		Storage: StorageSection{Endpoint: "http://localhost:8333", Bucket: "warden-uploads"},
		SMTP:    SMTPSection{Host: "localhost", Port: 1025, From: "warden@localhost", PublicBaseURL: "http://localhost:5173"},
		Scan: ScanSection{
			UploadMaxMB:         200,
			UnzipMaxMB:          1024,
			UnzipMaxFiles:       100_000,
			Timeout:             30 * time.Minute,
			SlotsPerNode:        7,
			ScratchDir:          "/scratch",
			MirrorDir:           "/mirror",
			SandboxRuntime:      "runsc",
			Images:              map[string]string{},
			SourceRetention:     time.Hour,
			RateLimitPerHour:    10,
			AutocloseGuardRatio: 0.5,
		},
	}
}

// Load reads and validates the configuration. AppConfig and Settings are loaded
// separately from the same file and environment: common-go's struct defaults
// don't flatten an embedded `koanf:",squash"` struct.
func Load() (*Config, error) {
	file := os.Getenv(EnvPrefix + "CONFIG_FILE")
	if file == "" {
		file = "config.yaml"
	}
	// WithOptionalFile would also swallow YAML syntax errors; a file that exists must parse.
	fileOpt := cgconfig.WithOptionalFile(file)
	if _, err := os.Stat(file); err == nil {
		fileOpt = cgconfig.WithFile(file)
	}
	opts := func(defaults any) []cgconfig.Option {
		return []cgconfig.Option{cgconfig.WithEnvPrefix(EnvPrefix), cgconfig.WithDefaults(defaults), fileOpt}
	}
	app, err := cgconfig.Load[cgconfig.AppConfig](opts(appDefaults())...)
	if err != nil {
		return nil, err
	}
	settings, err := cgconfig.Load[Settings](opts(settingsDefaults())...)
	if err != nil {
		return nil, err
	}
	c := &Config{AppConfig: *app, Settings: *settings}
	if err := c.resolveSecrets(); err != nil {
		return nil, err
	}
	if err := validateImages(c.Scan.Images); err != nil {
		return nil, fmt.Errorf("config: %w", err)
	}
	return c, nil
}

// resolveSecrets expands "file:/path" references.
func (c *Config) resolveSecrets() error {
	for _, s := range []*Secret{&c.Migrate.DSN, &c.Storage.AccessKey, &c.Storage.SecretKey, &c.Scan.HMACKey} {
		v, err := cgconfig.ResolveSecret(string(*s))
		if err != nil {
			return err
		}
		*s = Secret(v)
	}
	for _, s := range []*string{&c.Database.DSN, &c.Database.Password} {
		v, err := cgconfig.ResolveSecret(*s)
		if err != nil {
			return err
		}
		*s = v
	}
	return nil
}

func validateImages(images map[string]string) error {
	for tool, ref := range images {
		if !slices.Contains(Scanners, tool) {
			return fmt.Errorf("unknown scanner %q", tool)
		}
		if !digestPinned.MatchString(ref) {
			return fmt.Errorf("scanner image for %s must be pinned by @sha256 digest", tool)
		}
	}
	return nil
}
