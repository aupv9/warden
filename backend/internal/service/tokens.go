package service

import (
	"context"
	"crypto/rand"
	"crypto/sha256"
	"crypto/subtle"
	"encoding/base32"
	"encoding/hex"
	"errors"
	"fmt"
	"log/slog"
	"regexp"
	"slices"
	"strings"
	"time"
	"unicode/utf8"

	"github.com/google/uuid"

	"github.com/aupv9/warden/backend/internal/domain/rbac"
	"github.com/aupv9/warden/backend/internal/ids"
)

// API tokens are machine credentials for CI: bound to one project, acting as
// the user who created them, limited to a few routes by scope (the allow-list
// lives in the API's authentication middleware). The format is
// wdn_<prefix>_<secret>: the prefix (8 base32 characters, 40 random bits) finds
// the row, the secret (32 random bytes, base32) proves possession. Only
// sha256(secret) is stored, and the full token is returned once, at creation.
const (
	TokenPrefix     = "wdn_"
	ScopeScanWrite  = "scan:write"
	ScopeIssuesRead = "issues:read"

	maxTokenNameLen = 80
	maxTokenDays    = 365
)

var (
	tokenScopes = []string{ScopeScanWrite, ScopeIssuesRead}
	tokenB32    = base32.StdEncoding.WithPadding(base32.NoPadding)
	tokenFormat = regexp.MustCompile(`^wdn_([a-z2-7]{8})_([a-z2-7]{52})$`)
	// dummyHash is compared against when no token has the prefix, so an unknown
	// prefix costs the same as a wrong secret.
	dummyHash = strings.Repeat("0", 64)
)

// ApiToken is a token as listed to project managers (never with its secret).
type ApiToken struct {
	ID         uuid.UUID `json:"id"`
	Name       string    `json:"name"`
	Prefix     string    `json:"prefix"`
	Scopes     []string  `json:"scopes"`
	CreatedBy  UserRef   `json:"created_by"`
	CreatedAt  Time      `json:"created_at"`
	ExpiresAt  Time      `json:"expires_at"`
	LastUsedAt *Time     `json:"last_used_at"`
	RevokedAt  *Time     `json:"revoked_at"`
}

// TokenRef identifies the token that created a scan.
type TokenRef struct {
	ID     uuid.UUID `json:"id"`
	Name   string    `json:"name"`
	Prefix string    `json:"prefix"`
}

// CreatedToken is the only response that carries the secret.
type CreatedToken struct {
	Token  ApiToken `json:"token"`
	Secret string   `json:"secret"`
}

type NewToken struct {
	ID        uuid.UUID
	OrgID     uuid.UUID
	ProjectID uuid.UUID
	CreatedBy uuid.UUID
	Name      string
	Prefix    string
	Hash      string // hex sha256 of the secret
	Scopes    []string
	ExpiresAt time.Time
}

// TokenRecord is what warden_lookup_token returns.
type TokenRecord struct {
	ID        uuid.UUID
	OrgID     uuid.UUID
	ProjectID uuid.UUID
	UserID    uuid.UUID
	Hash      string
	Scopes    []string
	ExpiresAt time.Time
	RevokedAt *time.Time
}

// TokenAuth is an authenticated API token: the org and project it is bound to,
// its scopes and the user it acts as.
type TokenAuth struct {
	ID        uuid.UUID
	OrgID     uuid.UUID
	ProjectID uuid.UUID
	Prefix    string
	Scopes    []string
	User      User
}

// Has reports whether the token carries scope.
func (t *TokenAuth) Has(scope string) bool { return slices.Contains(t.Scopes, scope) }

// TokenRepo is the token part of Repo.
type TokenRepo interface {
	// LookupToken finds a token by prefix across orgs, through the SECURITY
	// DEFINER function warden_lookup_token; ErrNotFound if there is none.
	LookupToken(ctx context.Context, prefix string) (TokenRecord, error)
	// UserByID returns an app_user row.
	UserByID(ctx context.Context, userID uuid.UUID) (User, error)
	// TouchToken records a use, at most once a minute.
	TouchToken(ctx context.Context, tokenID uuid.UUID, now time.Time) error
	InsertToken(ctx context.Context, t NewToken) error
	// Tokens lists a project's tokens, newest first, revoked ones included.
	Tokens(ctx context.Context, projectID uuid.UUID) ([]ApiToken, error)
	// Token returns one of the project's tokens, or ErrNotFound.
	Token(ctx context.Context, projectID, tokenID uuid.UUID) (ApiToken, error)
	RevokeToken(ctx context.Context, tokenID uuid.UUID, at time.Time) error
}

// newTokenSecret returns a fresh token, its prefix and the hash to store.
func newTokenSecret() (token, prefix, hash string, err error) {
	var p [5]byte // 40 bits: 8 base32 characters
	var s [32]byte
	if _, err := rand.Read(p[:]); err != nil {
		return "", "", "", err
	}
	if _, err := rand.Read(s[:]); err != nil {
		return "", "", "", err
	}
	prefix = strings.ToLower(tokenB32.EncodeToString(p[:]))
	secret := strings.ToLower(tokenB32.EncodeToString(s[:]))
	return TokenPrefix + prefix + "_" + secret, prefix, hashSecret(secret), nil
}

func hashSecret(secret string) string {
	sum := sha256.Sum256([]byte(secret))
	return hex.EncodeToString(sum[:])
}

// IsAPIToken reports whether a bearer credential is meant as an API token (as
// opposed to an OIDC access token). It says nothing about validity.
func IsAPIToken(s string) bool { return strings.HasPrefix(s, TokenPrefix) }

// AuthenticateToken maps a bearer API token to its org, project, scopes and
// user. A malformed, unknown, wrong, expired or revoked token, and one whose
// user is deactivated or no longer in the org, all get the same generic 401 as a
// bad access token; the reason is logged (with the non-secret prefix at most).
// Whether the user may still run scans in the project is checked on every
// request by the service (projectAccess).
func (s *Service) AuthenticateToken(ctx context.Context, raw string) (*TokenAuth, error) {
	m := tokenFormat.FindStringSubmatch(raw)
	if m == nil {
		s.log.InfoContext(ctx, "api token rejected", slog.String("reason", "malformed"))
		return nil, errUnauthenticated()
	}
	prefix, secret := m[1], m[2]
	reject := func(reason string) (*TokenAuth, error) {
		s.log.InfoContext(ctx, "api token rejected", slog.String("prefix", prefix), slog.String("reason", reason))
		return nil, errUnauthenticated()
	}

	var rec TokenRecord
	err := s.db.InOrg(ctx, uuid.Nil, func(r Repo) error {
		var err error
		rec, err = r.LookupToken(ctx, prefix)
		return err
	})
	found := err == nil
	if err != nil && !errors.Is(err, ErrNotFound) {
		return nil, err
	}
	want := dummyHash
	if found {
		want = rec.Hash
	}
	match := subtle.ConstantTimeCompare([]byte(hashSecret(secret)), []byte(want)) == 1
	now := s.now()
	switch {
	case !found || !match:
		return reject("unknown token or wrong secret")
	case rec.RevokedAt != nil:
		return reject("revoked")
	case !now.Before(rec.ExpiresAt):
		return reject("expired")
	}

	// From here on, everything runs under the token's org (RLS).
	out := &TokenAuth{ID: rec.ID, OrgID: rec.OrgID, ProjectID: rec.ProjectID, Prefix: prefix, Scopes: rec.Scopes}
	var reason string
	err = s.db.InOrg(ctx, rec.OrgID, func(r Repo) error {
		u, err := r.UserByID(ctx, rec.UserID)
		if errors.Is(err, ErrNotFound) || err == nil && !u.IsActive {
			reason = "user deactivated"
			return nil
		}
		if err != nil {
			return err
		}
		if _, err := r.MemberRole(ctx, rec.OrgID, rec.UserID); errors.Is(err, ErrNotFound) {
			reason = "user is no longer a member of the org"
			return nil
		} else if err != nil {
			return err
		}
		out.User = u
		return r.TouchToken(ctx, rec.ID, now)
	})
	if err != nil {
		return nil, err
	}
	if reason != "" {
		return reject(reason)
	}
	return out, nil
}

// Tokens lists a project's tokens (manage_project_members).
func (s *Service) Tokens(ctx context.Context, a *Actor, projectID uuid.UUID) (Items[ApiToken], error) {
	out := Items[ApiToken]{Items: []ApiToken{}}
	err := s.inOrg(ctx, a, func(r Repo) error {
		role, err := projectAccess(ctx, r, a, projectID)
		if err != nil {
			return err
		}
		if !rbac.Can(rbac.ManageProjectMembers, a.OrgRole, role, false) {
			return errForbidden()
		}
		t, err := r.Tokens(ctx, projectID)
		if err != nil {
			return err
		}
		if t != nil {
			out.Items = t
		}
		return nil
	})
	return out, err
}

type CreateTokenInput struct {
	Name          string   `json:"name"`
	Scopes        []string `json:"scopes"`
	ExpiresInDays int      `json:"expires_in_days"`
}

func validScopes(scopes []string) bool {
	if len(scopes) == 0 || len(scopes) > len(tokenScopes) {
		return false
	}
	for i, sc := range scopes {
		if !slices.Contains(tokenScopes, sc) || slices.Contains(scopes[:i], sc) {
			return false
		}
	}
	return true
}

// CreateToken creates a token for the project and returns its secret, once.
// The caller needs manage_project_members, and run_scan too: the token acts as
// them, and every use re-checks run_scan, so a token they couldn't use would be
// dead on arrival.
func (s *Service) CreateToken(ctx context.Context, a *Actor, projectID uuid.UUID, in CreateTokenInput) (CreatedToken, error) {
	fe := fieldErrors{}
	name := strings.TrimSpace(in.Name)
	if name == "" || utf8.RuneCountInString(name) > maxTokenNameLen || !validText(name) || strings.ContainsFunc(name, isControl) {
		fe.add("name", "must be 1-80 characters")
	}
	if !validScopes(in.Scopes) {
		fe.add("scopes", "must be a non-empty list of distinct scopes: scan:write, issues:read")
	}
	if in.ExpiresInDays < 1 || in.ExpiresInDays > maxTokenDays {
		fe.add("expires_in_days", "must be between 1 and 365")
	}
	var out CreatedToken
	err := s.inOrg(ctx, a, func(r Repo) error {
		role, err := projectAccess(ctx, r, a, projectID)
		if err != nil {
			return err
		}
		if !rbac.Can(rbac.ManageProjectMembers, a.OrgRole, role, false) {
			return errForbidden()
		}
		if !rbac.Can(rbac.RunScan, a.OrgRole, role, false) {
			return forbiddenMsg("an API token acts as you, and you can't run scans in this project")
		}
		if err := fe.err(); err != nil {
			return err
		}
		secret, prefix, hash, err := newTokenSecret()
		if err != nil {
			return fmt.Errorf("generate token: %w", err)
		}
		id := ids.New()
		expires := s.now().Add(time.Duration(in.ExpiresInDays) * 24 * time.Hour).UTC().Truncate(time.Second)
		if err := r.InsertToken(ctx, NewToken{
			ID: id, OrgID: a.OrgID, ProjectID: projectID, CreatedBy: a.UserID, Name: name, Prefix: prefix,
			Hash: hash, Scopes: in.Scopes, ExpiresAt: expires,
		}); err != nil {
			// A prefix collision (40 random bits) is not worth a retry loop.
			return err
		}
		tok, err := r.Token(ctx, projectID, id)
		if err != nil {
			return err
		}
		out = CreatedToken{Token: tok, Secret: secret}
		return s.audit(ctx, r, a, "token.created", "api_token", id.String(), map[string]any{
			"project_id": projectID.String(), "name": name, "prefix": prefix, "scopes": in.Scopes,
			"expires_at": expires.Format(time.RFC3339),
		})
	})
	return out, err
}

// RevokeToken revokes a project's token (idempotent: revoking a revoked token
// changes nothing and isn't audited again).
func (s *Service) RevokeToken(ctx context.Context, a *Actor, projectID, tokenID uuid.UUID) error {
	return s.inOrg(ctx, a, func(r Repo) error {
		role, err := projectAccess(ctx, r, a, projectID)
		if err != nil {
			return err
		}
		if !rbac.Can(rbac.ManageProjectMembers, a.OrgRole, role, false) {
			return errForbidden()
		}
		tok, err := r.Token(ctx, projectID, tokenID)
		if err != nil {
			return notFound(err)
		}
		if tok.RevokedAt != nil {
			return nil
		}
		if err := r.RevokeToken(ctx, tokenID, s.now()); err != nil {
			return err
		}
		return s.audit(ctx, r, a, "token.revoked", "api_token", tokenID.String(), map[string]any{
			"project_id": projectID.String(), "name": tok.Name, "prefix": tok.Prefix, "scopes": tok.Scopes,
		})
	})
}
