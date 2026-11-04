package service

import (
	"context"
	"errors"
	"fmt"
	"slices"
	"strconv"
	"strings"
	"time"
	"unicode/utf8"

	apperrors "github.com/aupv9/common-go/errors"
	"github.com/google/uuid"

	"github.com/aupv9/warden/backend/internal/domain/rbac"
	"github.com/aupv9/warden/backend/internal/domain/registry"
	"github.com/aupv9/warden/backend/internal/ids"
	"github.com/aupv9/warden/backend/internal/secretbox"
)

// Registry credentials (v0.7 wave 2), managed by org admins and security leads
// (manage_registries): they open the org's private registries to Warden. The
// password is stored encrypted (registry.SealPassword) and is write-only: no
// response, audit entry or log line ever holds it. Audit entries name the
// host and username only.

// RegistryChecker authenticates against https://<host>/v2/ with a credential,
// through the same guarded client as pulls (https only, no proxy, internal
// addresses refused at dial time, redirects to them too). errKind is one of
// registry.ErrUnauthorized, ErrUnreachable or ErrBlocked when ok is false, ""
// when it is true; anything else is reported as unreachable. It must never log
// or return the password.
type RegistryChecker interface {
	Check(ctx context.Context, host, username, password string) (ok bool, errKind string)
}

// UnreachableChecker is the RegistryChecker of a server built without the
// worker's registry client: every test reports unreachable.
type UnreachableChecker struct{}

func (UnreachableChecker) Check(context.Context, string, string, string) (bool, string) {
	return false, registry.ErrUnreachable
}

// RegistryConfig is what the registry routes and pulls need from the server.
type RegistryConfig struct {
	// Keys (secrets.key): nil makes credentials unavailable.
	Keys *secretbox.Keyring
	// AllowHosts (registry.allow_hosts) may be pulled from at an IP literal or
	// a single-label host name: development only. The worker enforces the
	// rest of the policy when it dials.
	AllowHosts []string
	// Checker tests credentials; nil is UnreachableChecker.
	Checker RegistryChecker
}

const (
	maxRegistryUsername   = 256
	maxRegistryPassword   = 4096
	registryTestsPerHour  = 10
	registryCheckTimeout  = 30 * time.Second
	auditRegistryTested   = "registry.tested"
	registryCredentialRef = "registry_credential"
)

// RegistryCredential is a credential as the API shows it: never its password.
type RegistryCredential struct {
	ID         uuid.UUID `json:"id"`
	Host       string    `json:"host"`
	Username   string    `json:"username"`
	CreatedBy  *UserRef  `json:"created_by"`
	CreatedAt  Time      `json:"created_at"`
	UpdatedAt  Time      `json:"updated_at"`
	LastUsedAt *Time     `json:"last_used_at"`
	LastError  *string   `json:"last_error"`
}

// RegistryCredentialRecord is a credential row with its encrypted password.
type RegistryCredentialRecord struct {
	RegistryCredential
	OrgID       uuid.UUID `json:"-"`
	PasswordEnc []byte    `json:"-"`
	KeyID       string    `json:"-"`
}

type RegistryCredentialList struct {
	Items []RegistryCredential `json:"items"`
}

type CreateRegistryCredentialInput struct {
	Host     string `json:"host"`
	Username string `json:"username"`
	Password string `json:"password"`
}

type UpdateRegistryCredentialInput struct {
	Username *string `json:"username"`
	Password *string `json:"password"`
}

// RegistryTestResult is the outcome of POST /registries/{id}/test.
type RegistryTestResult struct {
	OK    bool    `json:"ok"`
	Error *string `json:"error"`
}

// RegistryRepo is the registry part of Repo. Every method runs under the org's
// app.org_id (registry_credential has forced RLS).
type RegistryRepo interface {
	// RegistryCredentials lists the org's credentials by host.
	RegistryCredentials(ctx context.Context) ([]RegistryCredentialRecord, error)
	// RegistryCredential returns one, locked when forUpdate; ErrNotFound if none.
	RegistryCredential(ctx context.Context, id uuid.UUID, forUpdate bool) (RegistryCredentialRecord, error)
	// LockRegistryCredentials serializes creation per org, so the cap holds.
	LockRegistryCredentials(ctx context.Context, orgID uuid.UUID) error
	CountRegistryCredentials(ctx context.Context) (int, error)
	// InsertRegistryCredential returns an error wrapping ErrConflict when the
	// org has credentials for the host.
	InsertRegistryCredential(ctx context.Context, c RegistryCredentialRecord) error
	// UpdateRegistryCredential writes username, password_enc, key_id,
	// updated_at, last_used_at and last_error.
	UpdateRegistryCredential(ctx context.Context, c RegistryCredentialRecord) error
	// RecordRegistryCheck stores a test's outcome: on success last_used_at =
	// at and last_error cleared, else last_error = errKind. A deleted row is
	// left alone.
	RecordRegistryCheck(ctx context.Context, id uuid.UUID, ok bool, errKind string, at time.Time) error
	DeleteRegistryCredential(ctx context.Context, id uuid.UUID) error
}

func errRegistriesUnavailable() error {
	return apperrors.Conflict("SECRETS_KEY_MISSING", "registry credentials are unavailable: the server has no secrets.key (ask your operator)")
}

func errRegistryKey() error {
	return errConflict("the server can't read this credential's stored password with its current keys; set a new password")
}

// registries checks manage_registries. API tokens never get here (the API's
// allow-list has no registry route); the check is repeated anyway.
func registries(a *Actor) error {
	if a.Token != nil || !rbac.Can(rbac.ManageRegistries, a.OrgRole, "", false) {
		return errForbidden()
	}
	return nil
}

func (s *Service) registryChecker() RegistryChecker {
	if s.cfg.Registries.Checker != nil {
		return s.cfg.Registries.Checker
	}
	return UnreachableChecker{}
}

// validRegistryUsername: 1-256 characters of text, kept as given (no trimming:
// it is a credential).
func validRegistryUsername(fe fieldErrors, u string) {
	if u == "" || utf8.RuneCountInString(u) > maxRegistryUsername || !validText(u) || strings.ContainsFunc(u, isControl) {
		fe.add("username", "must be 1-256 characters, without control characters")
	}
}

// validRegistryPassword: messages never echo the value.
func validRegistryPassword(fe fieldErrors, p string) {
	if p == "" || utf8.RuneCountInString(p) > maxRegistryPassword || !validText(p) || strings.ContainsFunc(p, isControl) {
		fe.add("password", "must be 1-4096 characters, without control characters or line breaks")
	}
}

// RegistryCredentials lists the org's registry credentials.
func (s *Service) RegistryCredentials(ctx context.Context, a *Actor) (RegistryCredentialList, error) {
	out := RegistryCredentialList{Items: []RegistryCredential{}}
	err := s.inOrg(ctx, a, func(r Repo) error {
		if err := registries(a); err != nil {
			return err
		}
		list, err := r.RegistryCredentials(ctx)
		for _, c := range list {
			out.Items = append(out.Items, c.RegistryCredential)
		}
		return err
	})
	return out, err
}

// CreateRegistryCredential stores credentials for a host: at most one per host
// and MaxPerOrg per org.
func (s *Service) CreateRegistryCredential(ctx context.Context, a *Actor, in CreateRegistryCredentialInput) (RegistryCredential, error) {
	var out RegistryCredential
	err := s.inOrg(ctx, a, func(r Repo) error {
		if err := registries(a); err != nil {
			return err
		}
		keys := s.cfg.Registries.Keys
		if !keys.Available() {
			return errRegistriesUnavailable()
		}
		fe := fieldErrors{}
		if !registry.ValidHost(in.Host) {
			fe.add("host", "must be a registry host name in lower case with an optional port, such as ghcr.io or registry.example.com:5000 (no scheme, path or IP address)")
		}
		validRegistryUsername(fe, in.Username)
		validRegistryPassword(fe, in.Password)
		if err := fe.err(); err != nil {
			return err
		}
		if err := r.LockRegistryCredentials(ctx, a.OrgID); err != nil {
			return err
		}
		if n, err := r.CountRegistryCredentials(ctx); err != nil {
			return err
		} else if n >= registry.MaxPerOrg {
			return errConflict(fmt.Sprintf("an organization can have at most %d registry credentials", registry.MaxPerOrg))
		}
		id := ids.New()
		enc, keyID, err := registry.SealPassword(keys, a.OrgID, id, in.Password)
		if err != nil {
			return err
		}
		now := Time(s.now().UTC())
		c := RegistryCredentialRecord{OrgID: a.OrgID, PasswordEnc: enc, KeyID: keyID, RegistryCredential: RegistryCredential{
			ID: id, Host: in.Host, Username: in.Username, CreatedBy: &UserRef{ID: a.UserID}, CreatedAt: now, UpdatedAt: now,
		}}
		if err := r.InsertRegistryCredential(ctx, c); errors.Is(err, ErrConflict) {
			return errConflict("this organization already has credentials for " + in.Host)
		} else if err != nil {
			return err
		}
		stored, err := r.RegistryCredential(ctx, id, false)
		if err != nil {
			return err
		}
		out = stored.RegistryCredential
		return s.audit(ctx, r, a, "registry.created", registryCredentialRef, id.String(), map[string]any{
			"host": in.Host, "username": in.Username,
		})
	})
	return out, err
}

// UpdateRegistryCredential changes the username and/or password (the host is
// fixed). A new password is sealed under the active key; any change clears
// last_error, which was about the old credentials.
func (s *Service) UpdateRegistryCredential(ctx context.Context, a *Actor, id uuid.UUID, in UpdateRegistryCredentialInput) (RegistryCredential, error) {
	var out RegistryCredential
	err := s.inOrg(ctx, a, func(r Repo) error {
		if err := registries(a); err != nil {
			return err
		}
		c, err := r.RegistryCredential(ctx, id, true)
		if err != nil {
			return notFound(err)
		}
		fe := fieldErrors{}
		if in.Username == nil && in.Password == nil {
			fe.add("body", "must change the username or the password")
		}
		if in.Username != nil {
			validRegistryUsername(fe, *in.Username)
		}
		if in.Password != nil {
			validRegistryPassword(fe, *in.Password)
		}
		if err := fe.err(); err != nil {
			return err
		}
		var changed []string
		if in.Username != nil && *in.Username != c.Username {
			c.Username, changed = *in.Username, append(changed, "username")
		}
		if in.Password != nil {
			keys := s.cfg.Registries.Keys
			if !keys.Available() {
				return errRegistriesUnavailable()
			}
			// Always re-sealed, even when it is the same password: whether it
			// changed is not something to find out by decrypting.
			if c.PasswordEnc, c.KeyID, err = registry.SealPassword(keys, a.OrgID, id, *in.Password); err != nil {
				return err
			}
			changed = append(changed, "password")
		}
		if len(changed) == 0 {
			out = c.RegistryCredential
			return nil
		}
		c.UpdatedAt, c.LastError = Time(s.now().UTC()), nil
		if err := r.UpdateRegistryCredential(ctx, c); err != nil {
			return err
		}
		stored, err := r.RegistryCredential(ctx, id, false)
		if err != nil {
			return err
		}
		out = stored.RegistryCredential
		return s.audit(ctx, r, a, "registry.updated", registryCredentialRef, id.String(), map[string]any{
			"host": c.Host, "username": c.Username, "changed": changed,
		})
	})
	return out, err
}

// DeleteRegistryCredential deletes a credential; later pulls from its host are
// anonymous.
func (s *Service) DeleteRegistryCredential(ctx context.Context, a *Actor, id uuid.UUID) error {
	return s.inOrg(ctx, a, func(r Repo) error {
		if err := registries(a); err != nil {
			return err
		}
		c, err := r.RegistryCredential(ctx, id, true)
		if err != nil {
			return notFound(err)
		}
		if err := r.DeleteRegistryCredential(ctx, id); err != nil {
			return err
		}
		return s.audit(ctx, r, a, "registry.deleted", registryCredentialRef, id.String(), map[string]any{
			"host": c.Host, "username": c.Username,
		})
	})
}

// TestRegistryCredential checks a credential against its registry, at most
// registryTestsPerHour per credential per hour. The attempt is audited (and
// counted) before the registry is called; the call itself runs outside any
// transaction, and its outcome is stored after.
func (s *Service) TestRegistryCredential(ctx context.Context, a *Actor, id uuid.UUID) (RegistryTestResult, error) {
	var host, username, password string
	err := s.inOrg(ctx, a, func(r Repo) error {
		if err := registries(a); err != nil {
			return err
		}
		c, err := r.RegistryCredential(ctx, id, true) // the lock serializes the rate check
		if err != nil {
			return notFound(err)
		}
		now := s.now().UTC()
		target := id.String()
		n, oldest, err := r.AuditSince(ctx, AuditCount{OrgID: a.OrgID, Action: auditRegistryTested, TargetID: &target, Since: now.Add(-time.Hour)})
		if err != nil {
			return err
		}
		if n >= registryTestsPerHour {
			return rateLimited(oldest.Add(time.Hour).Sub(now),
				"these credentials were tested "+strconv.Itoa(registryTestsPerHour)+" times in the last hour; try again later")
		}
		keys := s.cfg.Registries.Keys
		if !keys.Available() {
			return errRegistriesUnavailable()
		}
		if password, err = registry.OpenPassword(keys, a.OrgID, id, c.KeyID, c.PasswordEnc); err != nil {
			return errRegistryKey()
		}
		host, username = c.Host, c.Username
		return s.audit(ctx, r, a, auditRegistryTested, registryCredentialRef, target, map[string]any{
			"host": c.Host, "username": c.Username,
		})
	})
	if err != nil {
		return RegistryTestResult{}, err
	}
	cctx, cancel := context.WithTimeout(ctx, registryCheckTimeout)
	ok, kind := s.registryChecker().Check(cctx, host, username, password)
	cancel()
	if ok {
		kind = ""
	} else if !registry.ValidError(kind) {
		kind = registry.ErrUnreachable
	}
	// Recorded even if the caller went away meanwhile: the registry was asked.
	rctx := context.WithoutCancel(ctx)
	err = s.inOrg(rctx, a, func(r Repo) error {
		return r.RecordRegistryCheck(rctx, id, ok, kind, s.now().UTC())
	})
	if err != nil {
		return RegistryTestResult{}, err
	}
	out := RegistryTestResult{OK: ok}
	if !ok {
		out.Error = &kind
	}
	return out, nil
}

// pullHostAllowed: registry.allow_hosts, compared like webhook.allow_hosts.
func (s *Service) pullHostAllowed(name string) bool {
	return slices.ContainsFunc(s.cfg.Registries.AllowHosts, func(h string) bool { return strings.EqualFold(h, name) })
}
