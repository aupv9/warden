// Package service holds Warden's business rules: who may do what (checked here
// with internal/domain/rbac before any data is touched; RLS is the second line of
// defence), the issue workflow (internal/domain/issuestate) and the audit trail.
// Every write runs in one transaction together with its audit_log entry.
package service

import (
	"context"
	"errors"
	"log/slog"
	"net/http"
	"slices"
	"strings"
	"time"
	"unicode/utf8"

	apperrors "github.com/aupv9/common-go/errors"
	"github.com/google/uuid"

	"github.com/aupv9/warden/backend/internal/domain/rbac"
)

type Config struct {
	// UploadMaxBytes caps file_size on scan creation (source scans).
	UploadMaxBytes int64
	// ImageUploadMaxBytes caps file_size of image scans.
	ImageUploadMaxBytes int64
	// RateLimitPerHour caps scans created per user per hour (≤ 0: unlimited).
	RateLimitPerHour int
	// UploadURLTTL is how long a presigned upload URL is valid.
	UploadURLTTL time.Duration
	// Limits is reported by GET /me.
	Limits Limits
	// RequireMFARoles are the org roles that must sign in with a second factor
	// to use an org (oidc.require_mfa_roles); API tokens are exempt. Orgs can
	// add roles (SignInPolicy.MFARoles), not remove these.
	RequireMFARoles []rbac.Role
	// SignIn is shown on the Sign-in settings page.
	SignIn SignInConfig
}

type Service struct {
	db      DB
	objects ObjectStore
	cfg     Config
	log     *slog.Logger
	now     func() time.Time
	metrics *ttlCache
}

func New(db DB, objects ObjectStore, cfg Config, log *slog.Logger) *Service {
	if cfg.UploadURLTTL == 0 {
		cfg.UploadURLTTL = 15 * time.Minute
	}
	if log == nil {
		log = slog.New(slog.DiscardHandler)
	}
	return &Service{db: db, objects: objects, cfg: cfg, log: log, now: time.Now, metrics: &ttlCache{}}
}

// SetClock replaces the clock (tests).
func (s *Service) SetClock(now func() time.Time) { s.now = now }

// Actor is the authenticated caller acting inside one org.
type Actor struct {
	UserID    uuid.UUID
	OrgID     uuid.UUID
	OrgRole   rbac.Role
	IP        string
	UserAgent string
	// Token is set when the request authenticated with an API token: the actor
	// is the token's creator, limited to the token's project.
	Token *TokenAuth
	// MFA: this sign-in had a second factor (false for API tokens).
	MFA bool
}

func (a *Actor) seesAllProjects() bool {
	return a.OrgRole == rbac.OrgAdmin || a.OrgRole == rbac.SecurityLead
}

func (a *Actor) vis() Visibility {
	return Visibility{OrgID: a.OrgID, UserID: a.UserID, All: a.seesAllProjects()}
}

// Error constructors. Each call returns a fresh value: AppError metadata is mutable.

func errNotFound() error { return apperrors.NotFound("NOT_FOUND", "not found") }

func errForbidden() error {
	return apperrors.Forbidden("FORBIDDEN", "you don't have permission to do this")
}

func forbiddenMsg(msg string) error { return apperrors.Forbidden("FORBIDDEN", msg) }

func errConflict(msg string) error { return apperrors.Conflict("CONFLICT", msg) }

func errVersionConflict() error {
	return apperrors.Conflict("VERSION_CONFLICT", "the issue was changed by someone else; reload it and try again")
}

func errInvalidTransition(msg string) error {
	return apperrors.Invalid("INVALID_TRANSITION", msg).WithHTTPStatus(http.StatusUnprocessableEntity)
}

func errUploadMismatch() error {
	return apperrors.Invalid("UPLOAD_MISMATCH", "the uploaded object is missing or its size doesn't match").
		WithHTTPStatus(http.StatusUnprocessableEntity)
}

// errRateLimited carries retry_after (seconds) in its metadata; the API also
// sends it as the Retry-After header.
func errRateLimited(retryAfter time.Duration) error {
	secs := int64((retryAfter + time.Second - 1) / time.Second)
	if secs < 1 {
		secs = 1
	}
	return apperrors.Invalid("RATE_LIMITED", "too many scans; try again later").
		WithHTTPStatus(http.StatusTooManyRequests).WithMetadata("retry_after", secs)
}

// ErrValidation builds a 422 VALIDATION_FAILED with per-field messages.
func ErrValidation(fields map[string]string) error {
	m := make(map[string]any, len(fields))
	for k, v := range fields {
		m[k] = v
	}
	return apperrors.Invalid("VALIDATION_FAILED", "validation failed").
		WithHTTPStatus(http.StatusUnprocessableEntity).WithMetadata("fields", m)
}

func errField(field, msg string) error { return ErrValidation(map[string]string{field: msg}) }

// fieldErrors collects validation failures.
type fieldErrors map[string]string

func (f fieldErrors) add(field, msg string) {
	if _, ok := f[field]; !ok {
		f[field] = msg
	}
}

func (f fieldErrors) err() error {
	if len(f) == 0 {
		return nil
	}
	return ErrValidation(f)
}

// inOrg runs fn in one org-scoped transaction after re-checking, inside that
// transaction, that the actor is still a member (the HTTP middleware checked
// too, but the service doesn't rely on it). A non-member gets 404.
func (s *Service) inOrg(ctx context.Context, a *Actor, fn func(Repo) error) error {
	return s.db.InOrg(ctx, a.OrgID, func(r Repo) error {
		role, err := r.MemberRole(ctx, a.OrgID, a.UserID)
		if errors.Is(err, ErrNotFound) {
			return errNotFound()
		}
		if err != nil {
			return err
		}
		a.OrgRole = role
		return fn(r)
	})
}

// projectAccess returns the caller's role in a project they can see; 404 when
// the project doesn't exist or the caller can't see it. An API token reaches
// only its own project, and only while its user may still run scans there.
func projectAccess(ctx context.Context, r Repo, a *Actor, projectID uuid.UUID) (rbac.Role, error) {
	if a.Token != nil && projectID != a.Token.ProjectID {
		return "", errNotFound()
	}
	role, err := r.ProjectRole(ctx, projectID, a.UserID)
	if errors.Is(err, ErrNotFound) {
		return "", errNotFound()
	}
	if err != nil {
		return "", err
	}
	if role == "" && !a.seesAllProjects() {
		return "", errNotFound()
	}
	if a.Token != nil && !rbac.Can(rbac.RunScan, a.OrgRole, role, false) {
		return "", forbiddenMsg("the API token's user can no longer run scans in this project")
	}
	return role, nil
}

// notFound maps the repository sentinel to the API's 404.
func notFound(err error) error {
	if errors.Is(err, ErrNotFound) {
		return errNotFound()
	}
	return err
}

func (s *Service) audit(ctx context.Context, r Repo, a *Actor, action, targetType, targetID string, data map[string]any) error {
	if data == nil {
		data = map[string]any{}
	}
	if a.Token != nil {
		data["via_token"] = a.Token.ID.String()
	}
	uid := a.UserID
	return r.AppendAudit(ctx, AuditRecord{
		OrgID: a.OrgID, ActorID: &uid, Action: action, TargetType: targetType, TargetID: targetID,
		IP: a.IP, UserAgent: a.UserAgent, Data: data,
	})
}

var (
	orgRoles     = []rbac.Role{rbac.OrgAdmin, rbac.SecurityLead, rbac.Member}
	projectRoles = []rbac.Role{rbac.Owner, rbac.Developer, rbac.Viewer}
	allTools     = []string{"gitleaks", "opengrep", "trivy", "checkov"}
	severities   = []string{"critical", "high", "medium", "low", "info"}
)

func validOrgRole(r string) bool     { return slices.Contains(orgRoles, rbac.Role(r)) }
func validProjectRole(r string) bool { return slices.Contains(projectRoles, rbac.Role(r)) }

// validTools checks a tool list: non-empty, known tools, no duplicates.
func validTools(tools []string) bool {
	if len(tools) == 0 || len(tools) > len(allTools) {
		return false
	}
	for i, t := range tools {
		if !slices.Contains(allTools, t) || slices.Contains(tools[:i], t) {
			return false
		}
	}
	return true
}

func ptr[T any](v T) *T { return &v }

// validText: valid UTF-8 without NUL. Postgres text rejects NUL, so a crafted
// "\u0000" in a JSON string must be a 422, not a 500.
func validText(s string) bool { return utf8.ValidString(s) && !strings.ContainsRune(s, 0) }
