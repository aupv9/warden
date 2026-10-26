// Package auth verifies Keycloak access tokens: RS256 only, signature checked
// against the realm's JWKS, and iss/aud/exp/iat/sub required. It implements
// common-go's auth.Verifier, but not with common-go's JWKSVerifier, which leaves
// exp/iat/sub optional, accepts encryption keys and short RSA keys, and has no
// response size limit or HTTP timeout.
package auth

import (
	"context"
	"crypto/rsa"
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

// MFA reports whether the token says a second factor was used (admins and
// security leads must have one).
func MFA(p *cgauth.Principal) bool {
	return slices.ContainsFunc(AMR(p), func(m string) bool { return slices.Contains(mfaMethods, m) })
}

// KeySource resolves a token's kid to the realm's RSA signing key.
type KeySource interface {
	Key(ctx context.Context, kid string) (*rsa.PublicKey, error)
}

type Verifier struct {
	Issuer   string
	Audience string
	Keys     KeySource
	now      func() time.Time
}

func NewVerifier(issuer, audience string, keys KeySource) *Verifier {
	return &Verifier{Issuer: issuer, Audience: audience, Keys: keys}
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
		jwt.WithValidMethods([]string{"RS256"}),
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

// StaticKeys is a KeySource for tests and fixed deployments.
type StaticKeys map[string]*rsa.PublicKey

func (s StaticKeys) Key(_ context.Context, kid string) (*rsa.PublicKey, error) {
	if k, ok := s[kid]; ok {
		return k, nil
	}
	return nil, fmt.Errorf("unknown kid %q", kid)
}
