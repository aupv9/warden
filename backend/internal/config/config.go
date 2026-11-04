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
	"errors"
	"fmt"
	"log/slog"
	"os"
	"regexp"
	"slices"
	"strings"
	"time"

	cgconfig "github.com/aupv9/common-go/config"

	"github.com/aupv9/warden/backend/internal/registry"
	"github.com/aupv9/warden/backend/internal/secretbox"
	"github.com/aupv9/warden/backend/internal/webhook"
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
	OIDC     OIDCSection     `koanf:"oidc"`
	Migrate  MigrateSection  `koanf:"migrate"`
	Storage  StorageSection  `koanf:"storage"`
	SMTP     SMTPSection     `koanf:"smtp"`
	Scan     ScanSection     `koanf:"scan"`
	Secrets  SecretsSection  `koanf:"secrets"`
	Webhook  WebhookSection  `koanf:"webhook"`
	Web      WebSection      `koanf:"web"`
	Admin    AdminSection    `koanf:"admin"`
	Notify   NotifySection   `koanf:"notify"`
	Registry RegistrySection `koanf:"registry"`
}

// RegistrySection configures image pulls (POST …/scans/pull).
type RegistrySection struct {
	// AllowHosts may be pulled from over plain http and at private addresses
	// (exact host names or IP literals, no port): development and tests only,
	// like webhook.allow_hosts.
	AllowHosts List `koanf:"allow_hosts"`
}

// NotifySection: how long in-app notifications are kept (job
// prune_notifications). Audit log, scans and issues are never pruned.
type NotifySection struct {
	ReadRetention   time.Duration `koanf:"read_retention" validate:"min=24h"`
	UnreadRetention time.Duration `koanf:"unread_retention" validate:"min=24h"`
}

// WebSection is what the bundled web UI signs in with, served unauthenticated
// at GET /api/v1/web-config (the issuer is oidc.issuer, so the UI and the API
// always trust the same provider). Nothing here is secret: it is a public
// client using the authorization-code flow with PKCE.
type WebSection struct {
	OIDCClientID string `koanf:"oidc_client_id" validate:"required"`
	OIDCScope    string `koanf:"oidc_scope" validate:"required"`
	// OIDCAudience, when set, is sent as the "audience" authorization
	// parameter (Auth0 needs it to issue a JWT access token).
	OIDCAudience string `koanf:"oidc_audience"`
}

// AdminSection is the internal listener for operators and probes: /metrics
// on both binaries, plus /healthz and /readyz on the worker (which has no
// other HTTP server). Empty Addr turns it off. It must never be published:
// bind it to loopback or an internal network.
type AdminSection struct {
	Addr string `koanf:"addr" validate:"omitempty,hostname_port"`
}

// SecretsSection holds the key that encrypts what Warden must read back in
// clear (webhook URLs and signing secrets; see internal/secretbox). Without
// Key, webhooks are unavailable.
type SecretsSection struct {
	// Key is "<key id>:<base64 of 32 bytes>" (WARDEN_SECRETS__KEY).
	Key Secret `koanf:"key"`
	// OldKeys: earlier keys, comma-separated, that still decrypt (rotation).
	OldKeys Secret `koanf:"old_keys"`
}

// WebhookSection configures outgoing webhooks.
type WebhookSection struct {
	// AllowHosts may be reached over http and at private addresses (exact host
	// names or IP literals): development and tests only.
	AllowHosts List `koanf:"allow_hosts"`
	// FailureLimit: deliveries failing in a row before a webhook is turned off.
	FailureLimit int `koanf:"failure_limit" validate:"min=1,max=1000"`
}

type OIDCSection struct {
	Issuer    string        `koanf:"issuer" validate:"required,url"`
	Audience  string        `koanf:"audience" validate:"required"`
	JWKSCache time.Duration `koanf:"jwks_cache"`
	// RequireMFARoles: org roles that must sign in with a second factor to use
	// an org (403 MFA_REQUIRED otherwise). Empty disables the rule.
	RequireMFARoles List `koanf:"require_mfa_roles"`
	// JWKSURL pins the signing-key URL. Empty: discovered from the issuer's
	// /.well-known/openid-configuration, so any OIDC provider works.
	JWKSURL string `koanf:"jwks_url" validate:"omitempty,url"`
	// Algorithms the access tokens may be signed with: RS256 and/or ES256.
	Algorithms List `koanf:"algorithms"`
	// MFAAMR / MFAACR: a token proves a second factor when its "amr" claim holds
	// one of MFAAMR, or its "acr" claim equals one of MFAACR (providers differ).
	MFAAMR List `koanf:"mfa_amr"`
	MFAACR List `koanf:"mfa_acr"`
	// ConsoleURL: optional link to the identity provider's admin console, shown
	// to org admins on the Sign-in settings page. Display only; never fetched.
	ConsoleURL string `koanf:"console_url" validate:"omitempty,url"`
}

// TokenAlgorithms are the signing algorithms Warden can verify; anything else
// (HS*, none, PS*) is rejected at startup.
var TokenAlgorithms = []string{"RS256", "ES256"}

// List is a list setting given as a YAML list or, in the environment, as a
// comma-separated string (an empty string is an empty list).
type List []string

func (l *List) UnmarshalText(b []byte) error {
	out := List{}
	for _, s := range strings.Split(string(b), ",") {
		if s = strings.TrimSpace(s); s != "" {
			out = append(out, s)
		}
	}
	*l = out
	return nil
}

// KubeSection configures the kubernetes sandbox backend. The worker may only
// create, watch, exec into and delete Pods in Namespace (a Role, nothing
// cluster-wide); every scanner Pod runs with RuntimeClass, no service
// account token and no network (the namespace's NetworkPolicy denies all).
type KubeSection struct {
	Namespace string `koanf:"namespace"`
	// RuntimeClass must name a RuntimeClass whose handler is runsc (gVisor);
	// the worker checks at startup.
	RuntimeClass string `koanf:"runtime_class"`
	// MirrorPVC: the claim holding the offline scanner data (the mirror),
	// mounted read-only into Trivy's and Opengrep's Pods.
	MirrorPVC string `koanf:"mirror_pvc"`
	// IOImage carries warden-sandbox-io, which moves input into and reports out
	// of a scanner Pod over the exec API (normally the warden image itself);
	// pinned by digest like the scanner images.
	IOImage string `koanf:"io_image"`
	// Kubeconfig is for development only; empty means in-cluster credentials.
	Kubeconfig string `koanf:"kubeconfig"`
}

// MigrateSection: only warden-migrate connects as the schema owner.
type MigrateSection struct {
	DSN Secret `koanf:"dsn"`
}

type StorageSection struct {
	Endpoint string `koanf:"endpoint"`
	// PublicEndpoint, when set, is the base URL browsers and the CLI reach the
	// store at, used only to sign presigned URLs; the API and worker talk to
	// Endpoint (e.g. an internal network name). Empty: Endpoint for both.
	PublicEndpoint string `koanf:"public_endpoint" validate:"omitempty,url"`
	Bucket         string `koanf:"bucket"`
	AccessKey      Secret `koanf:"access_key"`
	SecretKey      Secret `koanf:"secret_key"`
}

// SMTPSection configures notification email. STARTTLS is required unless the
// host is a loopback name (see notify.SMTPSender).
type SMTPSection struct {
	Host          string `koanf:"host"`
	Port          int    `koanf:"port" validate:"min=1,max=65535"`
	From          string `koanf:"from"`
	PublicBaseURL string `koanf:"public_base_url"`
	Username      string `koanf:"username"`
	Password      Secret `koanf:"password"`
	// ImplicitTLS: TLS from the first byte (port 465) instead of STARTTLS.
	ImplicitTLS bool `koanf:"implicit_tls"`
	// DigestHour is the UTC hour of the daily SLA digest.
	DigestHour int `koanf:"digest_hour" validate:"min=0,max=23"`
}

type ScanSection struct {
	UploadMaxMB    int           `koanf:"upload_max_mb" validate:"min=1"`
	UnzipMaxMB     int           `koanf:"unzip_max_mb" validate:"min=1"`
	UnzipMaxFiles  int           `koanf:"unzip_max_files" validate:"min=1"`
	Timeout        time.Duration `koanf:"timeout" validate:"min=1m"`
	SlotsPerNode   int           `koanf:"slots_per_node" validate:"min=1"`
	ScratchDir     string        `koanf:"scratch_dir" validate:"required"`
	MirrorDir      string        `koanf:"mirror_dir" validate:"required"`
	SandboxRuntime string        `koanf:"sandbox_runtime" validate:"oneof=runsc runc"`
	// SandboxBackend: "docker" runs each scanner with the host's Docker
	// daemon (the worker holds its socket); "kubernetes" runs each scanner
	// as a gVisor Pod in Kube.Namespace and needs no socket (sandbox/kube).
	SandboxBackend      string            `koanf:"sandbox_backend" validate:"oneof=docker kubernetes"`
	Kube                KubeSection       `koanf:"kube"`
	Images              map[string]string `koanf:"images"`
	HMACKey             Secret            `koanf:"hmac_key"`
	SourceRetention     time.Duration     `koanf:"source_retention"`
	RateLimitPerHour    int               `koanf:"rate_limit_per_hour"`
	AutocloseGuardRatio float64           `koanf:"autoclose_guard_ratio" validate:"min=0,max=1"`
	// ImageUploadMaxMB caps image tarballs (docker save), which run larger than source zips.
	ImageUploadMaxMB int `koanf:"image_upload_max_mb" validate:"min=1"`
	// ImportMaxMB caps an imported SARIF file or GitLab SAST report
	// (POST …/scans/import).
	ImportMaxMB int `koanf:"import_max_mb" validate:"min=1"`
	// SBOMRetention: how long a scan's SBOM is kept (then deleted by the purge job).
	SBOMRetention time.Duration `koanf:"sbom_retention" validate:"min=1h"`
	// HistoryUploadMaxMB caps git bundles (history scans); HistoryMaxCommits
	// is how many commits one reads, the newest (the scan says when it cut).
	HistoryUploadMaxMB int `koanf:"history_upload_max_mb" validate:"min=1"`
	HistoryMaxCommits  int `koanf:"history_max_commits" validate:"min=1"`
	// PullMaxMB caps an image the worker pulls from a registry (manifests and
	// layers as sent); PullPlatform picks the image of a multi-platform
	// manifest list ("os/arch[/variant]").
	PullMaxMB    int    `koanf:"pull_max_mb" validate:"min=1"`
	PullPlatform string `koanf:"pull_platform" validate:"required"`
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
			// Admins and security leads change who can do what and decide
			// exceptions: a stolen password alone must not be enough.
			RequireMFARoles: List{"org_admin", "security_lead"},
			Algorithms:      List{"RS256"},
			MFAAMR:          List{"otp", "mfa", "hwk", "webauthn"},
		},
		Storage: StorageSection{Endpoint: "http://localhost:8333", Bucket: "warden-uploads"},
		SMTP:    SMTPSection{Host: "localhost", Port: 1025, From: "warden@localhost", PublicBaseURL: "http://localhost:5173", DigestHour: 8},
		Scan: ScanSection{
			UploadMaxMB:         200,
			UnzipMaxMB:          1024,
			UnzipMaxFiles:       100_000,
			Timeout:             30 * time.Minute,
			SlotsPerNode:        7,
			ScratchDir:          "/scratch",
			MirrorDir:           "/mirror",
			SandboxRuntime:      "runsc",
			SandboxBackend:      "docker",
			Kube:                KubeSection{Namespace: "warden-sandbox", RuntimeClass: "gvisor"},
			Images:              map[string]string{},
			SourceRetention:     time.Hour,
			RateLimitPerHour:    10,
			AutocloseGuardRatio: 0.5,
			SBOMRetention:       365 * 24 * time.Hour,
			ImageUploadMaxMB:    2048,
			ImportMaxMB:         50,
			HistoryUploadMaxMB:  1024,
			HistoryMaxCommits:   50_000,
			PullMaxMB:           2048,
			PullPlatform:        "linux/amd64",
		},
		Webhook: WebhookSection{FailureLimit: 10},
		Web:     WebSection{OIDCClientID: "warden-web", OIDCScope: "openid profile email"},
		Notify:  NotifySection{ReadRetention: 90 * 24 * time.Hour, UnreadRetention: 365 * 24 * time.Hour},
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
	if len(c.OIDC.Algorithms) == 0 {
		return nil, errors.New("config: oidc.algorithms must list at least one algorithm")
	}
	for _, a := range c.OIDC.Algorithms {
		if !slices.Contains(TokenAlgorithms, a) {
			return nil, fmt.Errorf("config: oidc.algorithms: unsupported algorithm %q (want RS256 or ES256)", a)
		}
	}
	if u := c.OIDC.ConsoleURL; u != "" && !strings.HasPrefix(u, "https://") && !strings.HasPrefix(u, "http://") {
		return nil, errors.New("config: oidc.console_url must be an http or https URL")
	}
	for _, r := range c.OIDC.RequireMFARoles {
		if !slices.Contains(orgRoles, r) {
			return nil, fmt.Errorf("config: oidc.require_mfa_roles: unknown org role %q", r)
		}
	}
	if _, err := c.Keyring(); err != nil {
		return nil, fmt.Errorf("config: %w", err)
	}
	for _, h := range c.Webhook.AllowHosts {
		if !webhook.ValidAllowHost(h) {
			return nil, fmt.Errorf("config: webhook.allow_hosts: %q must be a host name or IP address, without scheme or port", h)
		}
	}
	for _, h := range c.Registry.AllowHosts {
		if !webhook.ValidAllowHost(h) {
			return nil, fmt.Errorf("config: registry.allow_hosts: %q must be a host name or IP address, without scheme or port", h)
		}
	}
	if _, err := registry.ParsePlatform(c.Scan.PullPlatform); err != nil {
		return nil, fmt.Errorf("config: scan.pull_platform: %w", err)
	}
	if err := c.checkProdSecrets(); err != nil {
		return nil, err
	}
	return c, nil
}

// LoadServer is Load for warden-api and warden-worker, which also get the
// production checks of what a running server uses (see checkProd).
func LoadServer() (*Config, error) {
	c, err := Load()
	if err != nil {
		return nil, err
	}
	if err := c.checkProdServer(); err != nil {
		return nil, err
	}
	return c, nil
}

var orgRoles = []string{"org_admin", "security_lead", "member"}

// Keyring parses secrets.key and secrets.old_keys (nil when no key is set).
// Errors name the setting, never the key.
func (c *Config) Keyring() (*secretbox.Keyring, error) {
	return secretbox.Parse(c.Secrets.Key.Reveal(), c.Secrets.OldKeys.Reveal())
}

// resolveSecrets expands "file:/path" references.
func (c *Config) resolveSecrets() error {
	for _, s := range []*Secret{&c.Migrate.DSN, &c.Storage.AccessKey, &c.Storage.SecretKey, &c.Scan.HMACKey, &c.SMTP.Password,
		&c.Secrets.Key, &c.Secrets.OldKeys} {
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
