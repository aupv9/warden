package service

import (
	"context"
	"fmt"
	"slices"
	"strings"
	"time"

	apperrors "github.com/aupv9/common-go/errors"
	"github.com/google/uuid"

	"github.com/aupv9/warden/backend/internal/domain/rbac"
)

// SignInConfig is how the server trusts the identity provider (config oidc.*).
// Org admins see it on the Sign-in settings page; only the operator changes it.
type SignInConfig struct {
	Issuer     string
	Audience   string
	Algorithms []string
	// KeysURL is the pinned JWKS URL ("" when discovered from the issuer).
	KeysURL    string
	ConsoleURL string
	MFAAMR     []string
	MFAACR     []string
	// KeyStatus reports the signing-key cache without fetching; nil reports "not_loaded".
	KeyStatus func() KeyStatus
}

// KeyStatus mirrors auth.KeyStatus, so the service doesn't depend on the verifier.
type KeyStatus struct {
	Count     int
	FetchedAt time.Time
	Err       string
}

// SignInPolicy is an org's addition to the server's sign-in rules. It can only
// tighten them: MFARoles adds to oidc.require_mfa_roles, and
// AllowedEmailDomains limits who can be added as a member (empty: any).
type SignInPolicy struct {
	MFARoles            []rbac.Role `json:"mfa_roles"`
	AllowedEmailDomains []string    `json:"allowed_email_domains"`
}

type SignInSettings struct {
	Provider SignInProvider `json:"provider"`
	Keys     SignInKeys     `json:"keys"`
	MFA      SignInMFA      `json:"mfa"`
	Policy   SignInPolicy   `json:"policy"`
}

type SignInProvider struct {
	Issuer     string   `json:"issuer"`
	Audience   string   `json:"audience"`
	Algorithms []string `json:"algorithms"`
	KeysURL    *string  `json:"keys_url"`
	ConsoleURL *string  `json:"console_url"`
}

type SignInKeys struct {
	Status    string     `json:"status"`
	Count     int        `json:"count"`
	FetchedAt *time.Time `json:"fetched_at"`
	Error     *string    `json:"error"`
}

type SignInMFA struct {
	AMR            []string    `json:"amr"`
	ACR            []string    `json:"acr"`
	InstanceRoles  []rbac.Role `json:"instance_roles"`
	OrgRoles       []rbac.Role `json:"org_roles"`
	EffectiveRoles []rbac.Role `json:"effective_roles"`
}

// SignInRepo: org sign-in policy and account relinking.
type SignInRepo interface {
	OrgSignInPolicy(ctx context.Context, orgID uuid.UUID) (SignInPolicy, error)
	SetOrgSignInPolicy(ctx context.Context, orgID uuid.UUID, p SignInPolicy) error
	// RelinkUser points the account at a new identity-provider subject and
	// closes its relink window. ErrConflict if another account has that subject.
	RelinkUser(ctx context.Context, userID uuid.UUID, sub string) error
}

const (
	maxEmailDomains = 20
	// RelinkWindowMax bounds `warden-admin user relink --next-sign-in --within`.
	RelinkWindowMax = 7 * 24 * time.Hour
)

func errMFANotEnabled() error {
	return apperrors.Conflict("MFA_NOT_ENABLED", "Sign in with a second factor before requiring it for your own role.")
}

// MFARequired reports whether members with this org role must have signed in
// with a second factor: the server requires it, or the org added the role.
func (s *Service) MFARequired(role rbac.Role, orgRoles []rbac.Role) bool {
	return slices.Contains(s.cfg.RequireMFARoles, role) || slices.Contains(orgRoles, role)
}

// effectiveMFARoles is the union of the server's and the org's roles, in role order.
func (s *Service) effectiveMFARoles(orgRoles []rbac.Role) []rbac.Role {
	return sortRoles(append(slices.Clone(s.cfg.RequireMFARoles), orgRoles...))
}

// sortRoles orders org roles as org_admin, security_lead, member and drops duplicates.
func sortRoles(in []rbac.Role) []rbac.Role {
	out := []rbac.Role{}
	for _, r := range orgRoles {
		if slices.Contains(in, r) {
			out = append(out, r)
		}
	}
	return out
}

// SignInSettings shows how sign-in works for the org: the server's provider
// settings, the key cache, and the org's policy. Org admins and security leads.
func (s *Service) SignInSettings(ctx context.Context, a *Actor) (SignInSettings, error) {
	var out SignInSettings
	err := s.inOrg(ctx, a, func(r Repo) error {
		if !canViewSignIn(a.OrgRole) {
			return errForbidden()
		}
		p, err := r.OrgSignInPolicy(ctx, a.OrgID)
		if err != nil {
			return notFound(err)
		}
		out = s.signInSettings(p)
		return nil
	})
	return out, err
}

func canViewSignIn(role rbac.Role) bool {
	return rbac.Can(rbac.ManageUsers, role, "", false) || rbac.Can(rbac.ConfigurePolicy, role, "", false)
}

func (s *Service) signInSettings(p SignInPolicy) SignInSettings {
	c := s.cfg.SignIn
	out := SignInSettings{
		Provider: SignInProvider{Issuer: c.Issuer, Audience: c.Audience, Algorithms: nonNil(c.Algorithms),
			KeysURL: optString(c.KeysURL), ConsoleURL: optString(c.ConsoleURL)},
		Keys: SignInKeys{Status: "not_loaded"},
		MFA: SignInMFA{AMR: nonNil(c.MFAAMR), ACR: nonNil(c.MFAACR), InstanceRoles: sortRoles(s.cfg.RequireMFARoles),
			OrgRoles: sortRoles(p.MFARoles), EffectiveRoles: s.effectiveMFARoles(p.MFARoles)},
		Policy: SignInPolicy{MFARoles: sortRoles(p.MFARoles), AllowedEmailDomains: nonNil(p.AllowedEmailDomains)},
	}
	if c.KeyStatus != nil {
		st := c.KeyStatus()
		out.Keys.Count = st.Count
		if !st.FetchedAt.IsZero() {
			t := st.FetchedAt.UTC()
			out.Keys.FetchedAt = &t
			out.Keys.Status = "ok"
		}
		if st.Err != "" {
			e := st.Err
			out.Keys.Status, out.Keys.Error = "error", &e
		}
	}
	return out
}

type SignInPolicyInput struct {
	MFARoles            []string `json:"mfa_roles"`
	AllowedEmailDomains []string `json:"allowed_email_domains"`
}

func (in SignInPolicyInput) validate() (SignInPolicy, error) {
	fe := fieldErrors{}
	out := SignInPolicy{MFARoles: []rbac.Role{}, AllowedEmailDomains: []string{}}
	if in.MFARoles == nil {
		fe.add("mfa_roles", "is required")
	}
	for _, r := range in.MFARoles {
		if !validOrgRole(r) || slices.Contains(out.MFARoles, rbac.Role(r)) {
			fe.add("mfa_roles", "must be distinct values of org_admin, security_lead, member")
			break
		}
		out.MFARoles = append(out.MFARoles, rbac.Role(r))
	}
	out.MFARoles = sortRoles(out.MFARoles)
	switch {
	case in.AllowedEmailDomains == nil:
		fe.add("allowed_email_domains", "is required")
	case len(in.AllowedEmailDomains) > maxEmailDomains:
		fe.add("allowed_email_domains", fmt.Sprintf("must contain at most %d domains", maxEmailDomains))
	}
	for i, d := range in.AllowedEmailDomains {
		if i >= maxEmailDomains {
			break
		}
		d = strings.ToLower(strings.TrimSpace(d))
		field := fmt.Sprintf("allowed_email_domains[%d]", i)
		switch {
		case !validDomain(d):
			fe.add(field, "must be a domain name such as example.com")
		case slices.Contains(out.AllowedEmailDomains, d):
			fe.add(field, "is listed twice")
		default:
			out.AllowedEmailDomains = append(out.AllowedEmailDomains, d)
		}
	}
	return out, fe.err()
}

// validDomain accepts a lowercase DNS name with at least two labels: letters,
// digits and inner hyphens, 1-63 characters per label, 253 in all. No
// wildcards, IP addresses or trailing dot.
func validDomain(d string) bool {
	if len(d) == 0 || len(d) > 253 {
		return false
	}
	labels := strings.Split(d, ".")
	if len(labels) < 2 {
		return false
	}
	for _, l := range labels {
		if len(l) == 0 || len(l) > 63 || l[0] == '-' || l[len(l)-1] == '-' {
			return false
		}
		for _, c := range l {
			if !(c >= 'a' && c <= 'z' || c >= '0' && c <= '9' || c == '-') {
				return false
			}
		}
	}
	// The top-level label of a real domain is never all digits (that's an IPv4 address).
	tld := labels[len(labels)-1]
	return strings.Trim(tld, "0123456789") != ""
}

// SetSignInPolicy replaces the org's sign-in policy (org admins). An admin
// can't require a second factor for their own role without having signed in
// with one, so an org can't lock out the person changing the rule.
func (s *Service) SetSignInPolicy(ctx context.Context, a *Actor, in SignInPolicyInput) (SignInSettings, error) {
	p, verr := in.validate()
	var out SignInSettings
	err := s.inOrg(ctx, a, func(r Repo) error {
		if !rbac.Can(rbac.ManageUsers, a.OrgRole, "", false) {
			return errForbidden()
		}
		if verr != nil {
			return verr
		}
		cur, err := r.OrgSignInPolicy(ctx, a.OrgID)
		if err != nil {
			return notFound(err)
		}
		cur.MFARoles, cur.AllowedEmailDomains = sortRoles(cur.MFARoles), nonNil(cur.AllowedEmailDomains)
		if s.MFARequired(a.OrgRole, p.MFARoles) && !a.MFA {
			return errMFANotEnabled()
		}
		out = s.signInSettings(p)
		if slices.Equal(cur.MFARoles, p.MFARoles) && slices.Equal(cur.AllowedEmailDomains, p.AllowedEmailDomains) {
			return nil
		}
		if err := r.SetOrgSignInPolicy(ctx, a.OrgID, p); err != nil {
			return err
		}
		return s.audit(ctx, r, a, "org.sign_in_policy_changed", "org", a.OrgID.String(), map[string]any{"from": cur, "to": p})
	})
	return out, err
}

// emailDomainAllowed checks an address against an org's allowed domains
// (exact match on the part after the last "@", case-insensitive).
func emailDomainAllowed(email string, domains []string) bool {
	if len(domains) == 0 {
		return true
	}
	at := strings.LastIndexByte(email, '@')
	return at >= 0 && slices.Contains(domains, strings.ToLower(email[at+1:]))
}

// CheckEmailDomain returns the field error AddMember gives for an address
// outside the org's allowed domains (shared with warden-admin).
func CheckEmailDomain(email string, p SignInPolicy) error {
	if emailDomainAllowed(email, p.AllowedEmailDomains) {
		return nil
	}
	return errField("email", "must be an address at one of: "+strings.Join(p.AllowedEmailDomains, ", "))
}

func nonNil[T any](s []T) []T {
	if s == nil {
		return []T{}
	}
	return s
}

func optString(s string) *string {
	if s == "" {
		return nil
	}
	return &s
}
