package worker

import (
	"context"
	"crypto/hmac"
	"crypto/sha256"
	"encoding/hex"
	"errors"
	"fmt"
	"log/slog"
	"path/filepath"
	"regexp"
	"time"

	"github.com/google/uuid"
	"github.com/jackc/pgx/v5"
	"github.com/jackc/pgx/v5/pgxpool"

	"github.com/aupv9/warden/backend/internal/config"
	"github.com/aupv9/warden/backend/internal/db"
	"github.com/aupv9/warden/backend/internal/notify"
	"github.com/aupv9/warden/backend/internal/scan/orchestrator"
	"github.com/aupv9/warden/backend/internal/scan/redact"
	"github.com/aupv9/warden/backend/internal/scan/results"
	"github.com/aupv9/warden/backend/internal/scan/sandbox"
	"github.com/aupv9/warden/backend/internal/scan/zipcheck"
)

// DB is what job code may do inside a transaction.
type DB = results.DB

// TxFunc runs fn in one transaction scoped to orgID for RLS (db.WithOrg). The
// worker connects as warden_app, so every org's work happens inside its own
// scope; uuid.Nil leaves app.org_id unset (only organization is readable).
type TxFunc func(ctx context.Context, orgID uuid.UUID, fn func(DB) error) error

// PoolTx is the production TxFunc.
func PoolTx(pool *pgxpool.Pool) TxFunc {
	return func(ctx context.Context, orgID uuid.UUID, fn func(DB) error) error {
		return db.WithOrg(ctx, pool, orgID, func(tx pgx.Tx) error { return fn(tx) })
	}
}

// Store is the object storage the worker needs (storage.Client).
type Store interface {
	Download(ctx context.Context, key, dest string) error
	Delete(ctx context.Context, key string) error
	// Put stores an artifact Warden produced (SBOMs).
	Put(ctx context.Context, key string, body []byte, sha256Hex, contentType string) error
}

// Sandbox runs scanner containers (sandbox.Run / sandbox.Kill in production).
type Sandbox interface {
	Run(ctx context.Context, spec sandbox.ToolSpec, c sandbox.RunConfig) sandbox.ToolRun
	Kill(scanID, tool string)
}

type DockerSandbox struct{}

func (DockerSandbox) Run(ctx context.Context, spec sandbox.ToolSpec, c sandbox.RunConfig) sandbox.ToolRun {
	return sandbox.Run(ctx, spec, c)
}
func (DockerSandbox) Kill(scanID, tool string) { sandbox.Kill(scanID, tool) }

type Settings struct {
	ScratchDir  string // absolute; per-scan directories are created under it
	MirrorDir   string // absolute; offline scanner data
	Runtime     string // runsc, or runc for local development
	Images      map[string]string
	HMACMaster  []byte
	GuardRatio  float64
	ScanTimeout time.Duration
	// SourceRetention: uploaded objects of finished scans older than this are deleted.
	SourceRetention time.Duration
	// AbandonUploadAfter: pending_upload scans older than this are cancelled.
	AbandonUploadAfter time.Duration
	// StuckAfter: queued/running scans older than this lose their source too.
	StuckAfter time.Duration
	// PublicBaseURL prefixes links in notification emails (validated).
	PublicBaseURL string
	// DigestHour is the UTC hour of the daily SLA digest.
	DigestHour int
	// Limits are the archive limits (scan.upload_max_mb, unzip_max_mb, unzip_max_files).
	Limits orchestrator.Limits
	// SBOMRetention: stored SBOMs are deleted this long after their scan.
	SBOMRetention time.Duration
}

// Env is everything the jobs need; tests substitute fakes.
type Env struct {
	Tx      TxFunc
	Store   Store
	Sandbox Sandbox
	// Mailer sends notification email; nil disables email.
	Mailer notify.Sender
	Settings
	Now func() time.Time
	Log *slog.Logger
}

const (
	abandonUploadAfter = time.Hour
	// Generous so a long queue doesn't lose sources; the retention sweep still
	// bounds how long an upload can outlive a crashed worker.
	stuckAfter = 24 * time.Hour
)

// NewEnv builds the production environment from configuration.
func NewEnv(cfg *config.Config, pool *pgxpool.Pool, store Store, log *slog.Logger) (*Env, error) {
	s := cfg.Scan
	master := []byte(s.HMACKey.Reveal())
	if len(master) < redact.MinKeyBytes {
		return nil, fmt.Errorf("WARDEN_SCAN__HMAC_KEY must be at least %d bytes", redact.MinKeyBytes)
	}
	scratch, err := filepath.Abs(s.ScratchDir)
	if err != nil {
		return nil, err
	}
	mirror, err := filepath.Abs(s.MirrorDir)
	if err != nil {
		return nil, err
	}
	for _, t := range sandbox.ToolNames {
		if s.Images[t] == "" {
			log.Warn("no scanner image configured; this tool will fail", "tool", t)
		}
	}
	if s.SandboxRuntime != "runsc" {
		log.Warn("scanner sandbox is not gVisor (runsc); acceptable for local development only", "runtime", s.SandboxRuntime)
	}
	m := cfg.SMTP
	base, err := notify.BaseURL(m.PublicBaseURL)
	if err != nil {
		return nil, fmt.Errorf("WARDEN_SMTP__PUBLIC_BASE_URL: %w", err)
	}
	mailer, err := notify.NewSMTP(notify.SMTPConfig{Host: m.Host, Port: m.Port, From: m.From,
		Username: m.Username, Password: m.Password.Reveal(), ImplicitTLS: m.ImplicitTLS})
	if err != nil {
		return nil, fmt.Errorf("smtp: %w", err)
	}
	return &Env{
		Tx: PoolTx(pool), Store: store, Sandbox: DockerSandbox{}, Mailer: mailer, Now: time.Now, Log: log,
		Settings: Settings{
			ScratchDir: scratch, MirrorDir: mirror, Runtime: s.SandboxRuntime, Images: s.Images,
			HMACMaster: master, GuardRatio: s.AutocloseGuardRatio, ScanTimeout: s.Timeout,
			SourceRetention: s.SourceRetention, AbandonUploadAfter: abandonUploadAfter, StuckAfter: stuckAfter,
			PublicBaseURL: base, DigestHour: m.DigestHour, Limits: ScanLimits(s), SBOMRetention: s.SBOMRetention,
		},
	}, nil
}

// ScanLimits maps the archive settings onto the checks: the archive itself
// may be as large as an upload, its content as large as unzip_max_mb.
func ScanLimits(s config.ScanSection) orchestrator.Limits {
	return orchestrator.Limits{Zip: zipcheck.Limits{
		MaxZipBytes: int64(s.UploadMaxMB) << 20, MaxTotalBytes: int64(s.UnzipMaxMB) << 20, MaxEntries: s.UnzipMaxFiles,
	}}
}

// OrgKey derives the organization's secret-fingerprint key from the master key:
// HMAC-SHA256(master, label || org_id), hex-encoded (64 bytes). Keys differ per
// org, so identical secrets in two orgs don't correlate, and nothing per-org has
// to be stored.
func OrgKey(master []byte, orgID string) ([]byte, error) {
	if len(master) < redact.MinKeyBytes {
		return nil, errors.New("HMAC master key too short")
	}
	if _, err := uuid.Parse(orgID); err != nil {
		return nil, fmt.Errorf("org id: %w", err)
	}
	m := hmac.New(sha256.New, master)
	m.Write([]byte("warden/org-secret-key/v1\x00" + orgID))
	return []byte(hex.EncodeToString(m.Sum(nil))), nil
}

var imageRef = regexp.MustCompile(`^(?:[^@]*/)?[^/@:]+(?::([^@/]+))?@(sha256:[0-9a-f]{64})$`)

// imageInfo returns the tag (as the tool version, may be empty) and digest of a
// digest-pinned image reference.
func imageInfo(ref string) (version, digest string) {
	m := imageRef.FindStringSubmatch(ref)
	if m == nil {
		return "", ""
	}
	return m[1], m[2]
}
