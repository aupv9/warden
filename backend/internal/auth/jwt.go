// Package auth verifies OIDC access tokens from any standard provider (Keycloak
// by default; Okta, Entra ID, Auth0, …): RS256 (optionally ES256) only,
// signature checked against the provider's JWKS, and iss/aud/exp/iat/sub required. It implements
// common-go's auth.Verifier, but not with common-go's JWKSVerifier, which leaves
// exp/iat/sub optional, accepts encryption keys and short RSA keys, and has no
// response size limit or HTTP timeout.
package auth

import (
	"context"
	"crypto"
	"errors"
	"fmt"
	"slices"
	"strings"
	"time"

	cgauth "github.com/aupv9/common-go/auth"
	apperrors "github.com/aupv9/common-go/errors"
	"github.com/golang-jwt/jwt/v5"
)

const leeway = 30 * time.Second

var mfaMethods = []string{"otp", "mfa", "hwk", "webauthn"}

// Email returns the "email" claim, or "".
func Email(p *cgauth.Principal) string { s, _ := p.Claims["email"].(string); return s }

// Name returns the "name" claim, or "".
func Name(p *cgauth.Principal) string { s, _ := p.Claims["name"].(string); return s }

// AMR returns the authentication methods the token was issued after.
func AMR(p *cgauth.Principal) []string {
	var out []string
	if amr, ok := p.Claims["amr"].([]any); ok {
		for _, a := range amr {
			if s, ok := a.(string); ok {
				out = append(out, s)
			}
		}
	}
	return out
}

// MFAPolicy decides whether a token proves a second factor. Providers say it
// differently: Keycloak, Entra ID and Okta list methods in "amr" (otp, mfa,
// hwk, webauthn); some use an "acr" level instead.
type MFAPolicy struct {
	AMR []string // any of these in the amr claim
	ACR []string // or the acr claim equal to one of these
}

// DefaultMFAPolicy accepts the common amr values.
var DefaultMFAPolicy = MFAPolicy{AMR: mfaMethods}

func (m MFAPolicy) Satisfied(p *cgauth.Principal) bool {
	if slices.ContainsFunc(AMR(p), func(a string) bool { return slices.Contains(m.AMR, a) }) {
		return true
	}
	acr, _ := p.Claims["acr"].(string)
	return acr != "" && slices.Contains(m.ACR, acr)
}

// MFA reports whether the token says a second factor was used, by the default
// policy (admins and security leads must have one).
func MFA(p *cgauth.Principal) bool { return DefaultMFAPolicy.Satisfied(p) }

// MFAOf applies v's MFA policy when v is a *Verifier, the default otherwise.
func MFAOf(v any, p *cgauth.Principal) bool {
	if vv, ok := v.(*Verifier); ok {
		return vv.MFA.Satisfied(p)
	}
	return MFA(p)
}

// KeySource resolves a token's kid to the provider's signing key (*rsa.PublicKey
// or *ecdsa.PublicKey). The JWT library checks the key type against the token's
// algorithm, so an RS256 token can't be verified with an EC key or vice versa.
type KeySource interface {
	Key(ctx context.Context, kid string) (crypto.PublicKey, error)
}

type Verifier struct {
	Issuer   string
	Audience string
	Keys     KeySource
	// Algs are the accepted signing algorithms (default RS256).
	Algs []string
	MFA  MFAPolicy
	now  func() time.Time
}

// NewVerifier accepts RS256 tokens and the default MFA policy; set Algs and MFA
// for other providers.
func NewVerifier(issuer, audience string, keys KeySource) *Verifier {
	return &Verifier{Issuer: issuer, Audience: audience, Keys: keys, Algs: []string{"RS256"}, MFA: DefaultMFAPolicy}
}

var _ cgauth.Verifier = (*Verifier)(nil)

// rejected wraps the reason as the Cause, which is logged but never rendered:
// clients only see a generic message, so verifier internals (key ids, which
// check failed) don't leak.
func rejected(reason error) error {
	return &apperrors.AppError{
		Kind: apperrors.KindUnauthorized, Code: "UNAUTHORIZED", Message: "invalid or expired token", Cause: reason,
	}
}

func (v *Verifier) Verify(ctx context.Context, token string) (*cgauth.Principal, error) {
	if token == "" {
		return nil, &apperrors.AppError{Kind: apperrors.KindUnauthorized, Code: "UNAUTHORIZED", Message: "missing bearer token"}
	}
	opts := []jwt.ParserOption{
		jwt.WithValidMethods(v.algs()),
		jwt.WithIssuer(v.Issuer),
		jwt.WithAudience(v.Audience),
		jwt.WithExpirationRequired(),
		jwt.WithIssuedAt(),
		jwt.WithLeeway(leeway),
	}
	if v.now != nil {
		opts = append(opts, jwt.WithTimeFunc(v.now))
	}
	claims := jwt.MapClaims{}
	_, err := jwt.NewParser(opts...).ParseWithClaims(token, claims, func(t *jwt.Token) (any, error) {
		kid, _ := t.Header["kid"].(string)
		if kid == "" {
			return nil, errors.New("token has no kid")
		}
		return v.Keys.Key(ctx, kid)
	})
	if err != nil {
		return nil, rejected(err)
	}
	if _, ok := claims["iat"]; !ok {
		return nil, rejected(errors.New("missing iat"))
	}
	sub, _ := claims["sub"].(string)
	if sub == "" {
		return nil, rejected(errors.New("missing sub"))
	}
	iss, _ := claims["iss"].(string)
	scope, _ := claims["scope"].(string)
	return &cgauth.Principal{Subject: sub, Issuer: iss, Scopes: strings.Fields(scope), Claims: claims}, nil
}

func (v *Verifier) algs() []string {
	if len(v.Algs) == 0 {
		return []string{"RS256"}
	}
	return v.Algs
}

// StaticKeys is a KeySource for tests and fixed deployments.
type StaticKeys map[string]crypto.PublicKey

func (s StaticKeys) Key(_ context.Context, kid string) (crypto.PublicKey, error) {
	if k, ok := s[kid]; ok {
		return k, nil
	}
	return nil, fmt.Errorf("unknown kid %q", kid)
}
