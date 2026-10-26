package service

import (
	"context"
	"errors"
	"log/slog"
	"net/mail"
	"strings"

	apperrors "github.com/aupv9/common-go/errors"
	"github.com/google/uuid"

	"github.com/aupv9/warden/backend/internal/domain/rbac"
	"github.com/aupv9/warden/backend/internal/ids"
)

// Identity is what the API takes from a verified access token.
type Identity struct {
	Sub   string
	Email string
	Name  string
	MFA   bool
	// EmailVerified is the token's email_verified claim, nil when absent.
	EmailVerified *bool
}

// Generic: a token we can't map to an account is reported like any bad token.
func errUnauthenticated() error {
	return apperrors.Unauthorized("UNAUTHORIZED", "invalid or expired token")
}

func errAccountUnavailable() error {
	return apperrors.Forbidden("FORBIDDEN", "your account is not available")
}

// Authenticate maps a token to its app_user, provisioning the user on first
// sight (upsert by keycloak sub) and refreshing email, display name and MFA when
// they change. Inactive users get 403 on every endpoint.
func (s *Service) Authenticate(ctx context.Context, id Identity) (User, error) {
	email := strings.TrimSpace(id.Email)
	if id.Sub == "" || !validEmail(email) {
		s.log.InfoContext(ctx, "token rejected", slog.String("reason", "missing sub or email"))
		return User{}, errUnauthenticated()
	}
	// Members are added by email, so an address the IdP says is unverified must
	// not be able to claim someone else's invitations.
	if id.EmailVerified != nil && !*id.EmailVerified {
		s.log.InfoContext(ctx, "token rejected", slog.String("reason", "email not verified"))
		return User{}, errUnauthenticated()
	}
	name := cleanName(id.Name)
	display := name
	if display == "" {
		display = email
	}
	mfa := id.MFA
	var out User
	err := s.db.InOrg(ctx, uuid.Nil, func(r Repo) error {
		u, err := r.UserBySub(ctx, id.Sub)
		if errors.Is(err, ErrNotFound) {
			// An email that already belongs to another account is not linked
			// automatically: that would hand the account to whoever controls the
			// new identity.
			if _, err := r.UserByEmail(ctx, email); err == nil {
				s.log.WarnContext(ctx, "sign-in refused: email belongs to another account", slog.String("sub", id.Sub))
				return errAccountUnavailable()
			} else if !errors.Is(err, ErrNotFound) {
				return err
			}
			out = User{ID: ids.New(), Sub: id.Sub, Email: email, DisplayName: display, IsActive: true, MFA: &mfa}
			if err := r.InsertUser(ctx, out); err != nil {
				if errors.Is(err, ErrConflict) {
					return errAccountUnavailable()
				}
				return err
			}
			return nil
		}
		if err != nil {
			return err
		}
		if !u.IsActive {
			return errAccountUnavailable()
		}
		changed := false
		if !strings.EqualFold(u.Email, email) {
			if other, err := r.UserByEmail(ctx, email); err == nil && other.ID != u.ID {
				s.log.WarnContext(ctx, "email change ignored: address belongs to another account", slog.String("user_id", u.ID.String()))
			} else if err != nil && !errors.Is(err, ErrNotFound) {
				return err
			} else {
				u.Email, changed = email, true
			}
		}
		if u.DisplayName != display {
			u.DisplayName, changed = display, true
		}
		if u.MFA == nil || *u.MFA != mfa {
			u.MFA, changed = &mfa, true
		}
		if changed {
			if err := r.UpdateUser(ctx, u); err != nil {
				return err
			}
		}
		out = u
		return nil
	})
	return out, err
}

// cleanName makes the token's name claim storable: valid UTF-8, no control
// characters, at most 200 characters.
func cleanName(s string) string {
	s = strings.Map(func(r rune) rune {
		if r < 0x20 || r == 0x7f {
			return -1
		}
		return r
	}, strings.ToValidUTF8(s, ""))
	s = strings.TrimSpace(s)
	if r := []rune(s); len(r) > maxNameLen {
		s = strings.TrimSpace(string(r[:maxNameLen]))
	}
	return s
}

func validEmail(s string) bool {
	if s == "" || len(s) > 254 {
		return false
	}
	a, err := mail.ParseAddress(s)
	return err == nil && a.Address == s
}

// Me returns the caller's profile and org memberships.
func (s *Service) Me(ctx context.Context, u User, id Identity) (Me, error) {
	out := Me{ID: u.ID, Sub: u.Sub, Email: u.Email, MFA: id.MFA, Orgs: []OrgRef{}, Limits: s.cfg.Limits}
	if n := cleanName(id.Name); n != "" {
		out.Name = &n
	}
	err := s.db.InOrg(ctx, uuid.Nil, func(r Repo) error {
		orgs, err := r.UserOrgs(ctx, u.ID)
		if err != nil {
			return err
		}
		if orgs != nil {
			out.Orgs = orgs
		}
		return nil
	})
	return out, err
}

// OrgRole returns the user's role in org, or 404 if they aren't a member.
func (s *Service) OrgRole(ctx context.Context, userID, orgID uuid.UUID) (rbac.Role, error) {
	var role rbac.Role
	err := s.db.InOrg(ctx, uuid.Nil, func(r Repo) error {
		var err error
		role, err = r.MemberRole(ctx, orgID, userID)
		return notFound(err)
	})
	return role, err
}
