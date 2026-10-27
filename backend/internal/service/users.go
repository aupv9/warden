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
			// new identity. The operator can allow it once (warden-admin user
			// relink --next-sign-in), for a verified address within the window.
			if prev, err := r.UserByEmail(ctx, email); err == nil {
				if !s.relinkAllowed(prev, id) {
					s.log.WarnContext(ctx, "sign-in refused: email belongs to another account", slog.String("sub", id.Sub))
					return errAccountUnavailable()
				}
				if err := r.RelinkUser(ctx, prev.ID, id.Sub); err != nil {
					if errors.Is(err, ErrConflict) {
						return errAccountUnavailable()
					}
					return err
				}
				if err := AuditRelink(ctx, r, prev.ID, "next_sign_in", "sign-in"); err != nil {
					return err
				}
				s.log.InfoContext(ctx, "account relinked to a new identity", slog.String("user_id", prev.ID.String()), slog.String("sub", id.Sub))
				prev.Sub, prev.RelinkUntil = id.Sub, nil
				return s.refreshUser(ctx, r, prev, email, display, mfa, &out)
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
		return s.refreshUser(ctx, r, u, email, display, mfa, &out)
	})
	return out, err
}

// relinkAllowed: the account is open for relinking (window not expired), is
// active, and the provider says the address is verified. An absent
// email_verified claim isn't enough here.
func (s *Service) relinkAllowed(u User, id Identity) bool {
	return u.IsActive && u.RelinkUntil != nil && s.now().Before(*u.RelinkUntil) &&
		id.EmailVerified != nil && *id.EmailVerified
}

// AuditRelink records user.relinked in every org the user belongs to (audit_log
// has no RLS; the chain is per org). via is "sign-in" or "warden-admin".
func AuditRelink(ctx context.Context, r Repo, userID uuid.UUID, mode, via string) error {
	orgs, err := r.UserOrgs(ctx, userID)
	if err != nil {
		return err
	}
	for _, o := range orgs {
		if err := r.AppendAudit(ctx, AuditRecord{
			OrgID: o.ID, Action: "user.relinked", TargetType: "user", TargetID: userID.String(),
			Data: map[string]any{"mode": mode, "via": via},
		}); err != nil {
			return err
		}
	}
	return nil
}

// refreshUser updates email, display name and MFA from the token when they
// changed, and stores the result in out.
func (s *Service) refreshUser(ctx context.Context, r Repo, u User, email, display string, mfa bool, out *User) error {
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
	*out = u
	return nil
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
	out := Me{ID: u.ID, Sub: u.Sub, Email: u.Email, MFA: id.MFA, Orgs: []OrgRef{}, Limits: s.cfg.Limits, MFARequiredOrgs: []uuid.UUID{}}
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
		for _, o := range out.Orgs {
			if !id.MFA && s.MFARequired(o.Role, o.MFARoles) {
				out.MFARequiredOrgs = append(out.MFARequiredOrgs, o.ID)
			}
		}
		return nil
	})
	return out, err
}

// OrgRole returns the user's role in org, or 404 if they aren't a member.
// OrgAccess returns the user's role in the org and whether that role must
// sign in with a second factor there (server rule plus the org's policy).
func (s *Service) OrgAccess(ctx context.Context, userID, orgID uuid.UUID) (rbac.Role, bool, error) {
	var (
		role rbac.Role
		mfa  bool
	)
	err := s.db.InOrg(ctx, uuid.Nil, func(r Repo) error {
		var err error
		if role, err = r.MemberRole(ctx, orgID, userID); err != nil {
			return notFound(err)
		}
		p, err := r.OrgSignInPolicy(ctx, orgID)
		if err != nil {
			return err
		}
		mfa = s.MFARequired(role, p.MFARoles)
		return nil
	})
	return role, mfa, err
}
