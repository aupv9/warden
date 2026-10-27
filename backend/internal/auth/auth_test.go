package auth

import (
	"context"
	"crypto/rand"
	"crypto/rsa"
	"crypto/x509"
	"encoding/base64"
	"encoding/json"
	"math/big"
	"net/http"
	"net/http/httptest"
	"strings"
	"sync/atomic"
	"testing"
	"time"

	apperrors "github.com/aupv9/common-go/errors"
	"github.com/golang-jwt/jwt/v5"
)

const (
	issuer   = "http://localhost:8180/realms/warden"
	audience = "warden-api"
)

var testKey = mustKey(2048)

func mustKey(bits int) *rsa.PrivateKey {
	k, err := rsa.GenerateKey(rand.Reader, bits)
	if err != nil {
		panic(err)
	}
	return k
}

func claims(over map[string]any) jwt.MapClaims {
	now := time.Now().Unix()
	c := jwt.MapClaims{
		"sub": "u-1", "iss": issuer, "aud": audience, "iat": now, "exp": now + 300,
		"email": "dev@example.com", "amr": []string{"pwd", "otp"},
	}
	for k, v := range over {
		if v == nil {
			delete(c, k)
		} else {
			c[k] = v
		}
	}
	return c
}

func sign(t *testing.T, c jwt.MapClaims, kid string) string {
	t.Helper()
	tok := jwt.NewWithClaims(jwt.SigningMethodRS256, c)
	if kid != "" {
		tok.Header["kid"] = kid
	}
	s, err := tok.SignedString(testKey)
	if err != nil {
		t.Fatal(err)
	}
	return s
}

func verifier() *Verifier {
	return NewVerifier(issuer, audience, StaticKeys{"k1": &testKey.PublicKey})
}

func TestValidToken(t *testing.T) {
	p, err := verifier().Verify(context.Background(), sign(t, claims(nil), "k1"))
	if err != nil {
		t.Fatal(err)
	}
	if p.Subject != "u-1" || p.Issuer != issuer || Email(p) != "dev@example.com" || Name(p) != "" || !MFA(p) {
		t.Fatalf("%+v", p)
	}
}

// Rejections are 401 AppErrors whose client-visible message is generic; the
// reason stays in Cause (logged, never rendered).
func TestRejectionIsGenericAppError(t *testing.T) {
	_, err := verifier().Verify(context.Background(), sign(t, claims(nil), "k2"))
	ae, ok := apperrors.As(err)
	if !ok || ae.HTTPStatus() != 401 || ae.Message != "invalid or expired token" || len(ae.Metadata) != 0 {
		t.Fatalf("%#v", err)
	}
	if !strings.Contains(ae.Cause.Error(), "k2") {
		t.Fatalf("cause %v", ae.Cause)
	}
}

func TestRejectsBadClaims(t *testing.T) {
	for name, over := range map[string]map[string]any{
		"aud":         {"aud": "other-api"},
		"iss":         {"iss": "https://evil/realms/x"},
		"expired":     {"exp": time.Now().Unix() - 120},
		"no exp":      {"exp": nil},
		"no iat":      {"iat": nil},
		"future iat":  {"iat": time.Now().Unix() + 3600},
		"no sub":      {"sub": nil},
		"empty sub":   {"sub": ""},
		"no aud":      {"aud": nil},
		"not before":  {"nbf": time.Now().Unix() + 3600},
		"numeric sub": {"sub": 5},
	} {
		if _, err := verifier().Verify(context.Background(), sign(t, claims(over), "k1")); err == nil {
			t.Errorf("%s accepted", name)
		}
	}
}

func TestRejectsWrongKeyAndMissingKid(t *testing.T) {
	other := mustKey(2048)
	tok := jwt.NewWithClaims(jwt.SigningMethodRS256, claims(nil))
	tok.Header["kid"] = "k1"
	forged, _ := tok.SignedString(other)
	for name, s := range map[string]string{
		"wrong key":   forged,
		"no kid":      sign(t, claims(nil), ""),
		"unknown kid": sign(t, claims(nil), "k2"),
		"garbage":     "a.b.c",
		"empty":       "",
	} {
		if _, err := verifier().Verify(context.Background(), s); err == nil {
			t.Errorf("%s accepted", name)
		}
	}
}

// HS256 signed with the RSA public key bytes is the classic alg-confusion attack.
func TestRejectsAlgConfusionAndNone(t *testing.T) {
	pub, _ := x509.MarshalPKIXPublicKey(&testKey.PublicKey)
	for _, secret := range [][]byte{[]byte("secret"), pub} {
		tok := jwt.NewWithClaims(jwt.SigningMethodHS256, claims(nil))
		tok.Header["kid"] = "k1"
		s, _ := tok.SignedString(secret)
		if _, err := verifier().Verify(context.Background(), s); err == nil {
			t.Fatal("HS256 accepted")
		}
	}
	tok := jwt.NewWithClaims(jwt.SigningMethodNone, claims(nil))
	tok.Header["kid"] = "k1"
	s, _ := tok.SignedString(jwt.UnsafeAllowNoneSignatureType)
	if _, err := verifier().Verify(context.Background(), s); err == nil {
		t.Fatal("alg=none accepted")
	}
}

func b64(b []byte) string { return base64.RawURLEncoding.EncodeToString(b) }

func jwkOf(kid string, k *rsa.PublicKey, use string) map[string]string {
	return map[string]string{
		"kid": kid, "kty": "RSA", "alg": "RS256", "use": use,
		"n": b64(k.N.Bytes()), "e": b64(big.NewInt(int64(k.E)).Bytes()),
	}
}

func TestParseJWKSFiltersUnsafeKeys(t *testing.T) {
	small := mustKey(1024)
	body, _ := json.Marshal(map[string]any{"keys": []any{
		jwkOf("sig", &testKey.PublicKey, "sig"),
		jwkOf("enc", &testKey.PublicKey, "enc"),
		jwkOf("small", &small.PublicKey, "sig"),
		map[string]string{"kid": "ec", "kty": "EC"},
		map[string]string{"kid": "bad", "kty": "RSA", "n": "!!", "e": "AQAB"},
	}})
	keys, err := ParseJWKS(body, []string{"RS256"})
	if err != nil {
		t.Fatal(err)
	}
	if len(keys) != 1 || keys["sig"] == nil {
		t.Fatalf("%v", keys)
	}
	if _, err := ParseJWKS([]byte(`{"keys":[]}`), []string{"RS256"}); err == nil {
		t.Fatal("empty JWKS accepted")
	}
}

func TestJWKSFetchCacheAndMissRateLimit(t *testing.T) {
	var hits atomic.Int32
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		hits.Add(1)
		if r.URL.Path != "/realms/warden/protocol/openid-connect/certs" {
			http.NotFound(w, r)
			return
		}
		_ = json.NewEncoder(w).Encode(map[string]any{"keys": []any{jwkOf("k1", &testKey.PublicKey, "sig")}})
	}))
	defer srv.Close()

	now := time.Now()
	j := NewJWKS(issuer, srv.URL+"/realms/warden/protocol/openid-connect/certs", 10*time.Minute, []string{"RS256"})
	j.now = func() time.Time { return now }
	v := NewVerifier(issuer, audience, j)
	ctx := context.Background()

	for range 3 {
		if _, err := v.Verify(ctx, sign(t, claims(nil), "k1")); err != nil {
			t.Fatal(err)
		}
	}
	for range 5 { // forged kids
		_, _ = v.Verify(ctx, sign(t, claims(nil), "nope"))
	}
	if n := hits.Load(); n != 1 {
		t.Fatalf("%d fetches, want 1", n)
	}
	now = now.Add(2 * time.Minute)
	_, _ = v.Verify(ctx, sign(t, claims(nil), "nope"))
	_, _ = v.Verify(ctx, sign(t, claims(nil), "nope"))
	if n := hits.Load(); n != 2 {
		t.Fatalf("%d fetches, want 2", n)
	}
	now = now.Add(11 * time.Minute)
	if _, err := v.Verify(ctx, sign(t, claims(nil), "k1")); err != nil || hits.Load() != 3 {
		t.Fatalf("expired cache not refreshed: %v hits=%d", err, hits.Load())
	}
}

func TestJWKSRejectsOversizedResponse(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		_, _ = w.Write([]byte(`{"keys":[],"pad":"` + strings.Repeat("a", maxJWKSBytes) + `"}`))
	}))
	defer srv.Close()
	if _, err := NewJWKS(issuer, srv.URL, time.Minute, []string{"RS256"}).Key(context.Background(), "k1"); err == nil {
		t.Fatal("oversized JWKS accepted")
	}
}
