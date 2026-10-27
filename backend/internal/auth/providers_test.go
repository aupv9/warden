package auth

import (
	"context"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"strings"
	"sync/atomic"
	"testing"
	"time"

	cgauth "github.com/aupv9/common-go/auth"
	"github.com/golang-jwt/jwt/v5"
)

var ecTestKey = func() *ecdsa.PrivateKey {
	k, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		panic(err)
	}
	return k
}()

func ecJWK(kid string, k *ecdsa.PublicKey) map[string]string {
	b, _ := k.Bytes() // 0x04 || X || Y
	return map[string]string{"kid": kid, "kty": "EC", "crv": "P-256", "use": "sig", "x": b64(b[1:33]), "y": b64(b[33:])}
}

func signWith(t *testing.T, m jwt.SigningMethod, key any, c jwt.MapClaims, kid string) string {
	t.Helper()
	tok := jwt.NewWithClaims(m, c)
	tok.Header["kid"] = kid
	s, err := tok.SignedString(key)
	if err != nil {
		t.Fatal(err)
	}
	return s
}

// provider serves discovery and keys like Okta/Entra/Auth0 do: the JWKS lives at
// whatever jwks_uri says, not at Keycloak's path.
func provider(t *testing.T, doc func(base string) map[string]any, keys ...any) (*httptest.Server, *atomic.Int32) {
	t.Helper()
	var hits atomic.Int32
	var srv *httptest.Server
	srv = httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		hits.Add(1)
		switch r.URL.Path {
		case "/oauth2/default/.well-known/openid-configuration":
			_ = json.NewEncoder(w).Encode(doc(srv.URL))
		case "/oauth2/default/v1/keys":
			_ = json.NewEncoder(w).Encode(map[string]any{"keys": keys})
		case "/elsewhere":
			http.Redirect(w, r, "/oauth2/default/v1/keys", http.StatusFound)
		default:
			http.NotFound(w, r)
		}
	}))
	t.Cleanup(srv.Close)
	return srv, &hits
}

func oktaDoc(base string) map[string]any {
	return map[string]any{"issuer": base + "/oauth2/default", "jwks_uri": base + "/oauth2/default/v1/keys"}
}

func TestDiscoveryFindsKeysAtTheProvidersJWKSURI(t *testing.T) {
	srv, _ := provider(t, oktaDoc, jwkOf("k1", &testKey.PublicKey, "sig"))
	iss := srv.URL + "/oauth2/default"
	v := NewVerifier(iss, audience, NewJWKS(iss, "", time.Minute, []string{"RS256"}))
	if _, err := v.Verify(context.Background(), sign(t, claims(map[string]any{"iss": iss}), "k1")); err != nil {
		t.Fatal(err)
	}
}

func TestDiscoveryRejectsTamperedDocuments(t *testing.T) {
	for name, doc := range map[string]func(string) map[string]any{
		"other issuer": func(b string) map[string]any {
			return map[string]any{"issuer": "https://evil.example", "jwks_uri": b + "/oauth2/default/v1/keys"}
		},
		"http on another host": func(string) map[string]any {
			return map[string]any{"issuer": "", "jwks_uri": "http://evil.example/keys"}
		},
		"credentials in uri": func(b string) map[string]any {
			return map[string]any{"issuer": "", "jwks_uri": "https://u:p@evil.example/keys"}
		},
		"no jwks_uri":     func(string) map[string]any { return map[string]any{"issuer": ""} },
		"redirected keys": func(b string) map[string]any { return map[string]any{"issuer": "", "jwks_uri": b + "/elsewhere"} },
	} {
		t.Run(name, func(t *testing.T) {
			var srv *httptest.Server
			srv, _ = provider(t, func(b string) map[string]any {
				d := doc(b)
				if d["issuer"] == "" {
					d["issuer"] = b + "/oauth2/default"
				}
				return d
			}, jwkOf("k1", &testKey.PublicKey, "sig"))
			iss := srv.URL + "/oauth2/default"
			if _, err := NewJWKS(iss, "", time.Minute, []string{"RS256"}).Key(context.Background(), "k1"); err == nil {
				t.Fatal("accepted")
			}
		})
	}
}

func TestCheckKeysURL(t *testing.T) {
	for raw, ok := range map[string]bool{
		"https://login.example.com/keys":           true,
		"http://keycloak:8080/realms/w/certs":      true, // same scheme and host as an internal http issuer
		"http://other:8080/realms/w/certs":         false,
		"http://KEYCLOAK:8080/realms/w/certs":      true,
		"ftp://keycloak:8080/keys":                 false,
		"/relative":                                false,
		"https://user:pass@login.example.com/keys": false,
	} {
		if err := checkKeysURL("http://keycloak:8080/realms/w", raw); (err == nil) != ok {
			t.Errorf("%s: %v", raw, err)
		}
	}
}

func TestPinnedJWKSURLSkipsDiscovery(t *testing.T) {
	srv, hits := provider(t, oktaDoc, jwkOf("k1", &testKey.PublicKey, "sig"))
	j := NewJWKS("https://unused.example", srv.URL+"/oauth2/default/v1/keys", time.Minute, []string{"RS256"})
	if _, err := j.Key(context.Background(), "k1"); err != nil || hits.Load() != 1 {
		t.Fatal(err, hits.Load())
	}
}

func TestES256OnlyWhenEnabled(t *testing.T) {
	keys := []any{ecJWK("ec1", &ecTestKey.PublicKey), jwkOf("rsa1", &testKey.PublicKey, "sig")}
	srv, _ := provider(t, oktaDoc, keys...)
	iss := srv.URL + "/oauth2/default"
	c := claims(map[string]any{"iss": iss})
	es := signWith(t, jwt.SigningMethodES256, ecTestKey, c, "ec1")

	rsOnly := NewVerifier(iss, audience, NewJWKS(iss, "", time.Minute, []string{"RS256"}))
	if _, err := rsOnly.Verify(context.Background(), es); err == nil {
		t.Fatal("ES256 accepted while only RS256 is enabled")
	}
	both := NewVerifier(iss, audience, NewJWKS(iss, "", time.Minute, []string{"RS256", "ES256"}))
	both.Algs = []string{"RS256", "ES256"}
	if _, err := both.Verify(context.Background(), es); err != nil {
		t.Fatal(err)
	}
	if _, err := both.Verify(context.Background(), sign(t, c, "rsa1")); err != nil {
		t.Fatal(err)
	}
	// Algorithm/key confusion: an ES256 header pointing at the RSA key, and an
	// RS256 header pointing at the EC key, both fail.
	if _, err := both.Verify(context.Background(), signWith(t, jwt.SigningMethodES256, ecTestKey, c, "rsa1")); err == nil {
		t.Fatal("ES256 token verified with an RSA key")
	}
	if _, err := both.Verify(context.Background(), sign(t, c, "ec1")); err == nil {
		t.Fatal("RS256 token verified with an EC key")
	}
}

func TestParseJWKSDropsBadECKeys(t *testing.T) {
	good := ecJWK("good", &ecTestKey.PublicKey)
	offCurve := ecJWK("off", &ecTestKey.PublicKey)
	offCurve["y"] = b64(append(make([]byte, 31), 7))
	p384 := ecJWK("p384", &ecTestKey.PublicKey)
	p384["crv"] = "P-384"
	short := ecJWK("short", &ecTestKey.PublicKey)
	short["x"] = b64([]byte{1, 2, 3})
	wrongAlg := ecJWK("alg", &ecTestKey.PublicKey)
	wrongAlg["alg"] = "ES384"
	body, _ := json.Marshal(map[string]any{"keys": []any{good, offCurve, p384, short, wrongAlg}})
	keys, err := ParseJWKS(body, []string{"ES256"})
	if err != nil || len(keys) != 1 || keys["good"] == nil {
		t.Fatalf("%v %v", keys, err)
	}
	// With only RS256 accepted, EC keys are not usable at all.
	if _, err := ParseJWKS(body, []string{"RS256"}); err == nil || !strings.Contains(err.Error(), "no usable") {
		t.Fatal(err)
	}
}

func TestMFAPolicy(t *testing.T) {
	p := func(c map[string]any) *cgauth.Principal { return &cgauth.Principal{Claims: c} }
	okta := MFAPolicy{AMR: []string{"mfa"}, ACR: []string{"urn:okta:loa:2fa:any"}}
	for _, c := range []struct {
		claims map[string]any
		policy MFAPolicy
		want   bool
	}{
		{map[string]any{"amr": []any{"pwd", "otp"}}, DefaultMFAPolicy, true},
		{map[string]any{"amr": []any{"pwd"}}, DefaultMFAPolicy, false},
		{map[string]any{"amr": "otp"}, DefaultMFAPolicy, false}, // not a list
		{map[string]any{"acr": "urn:okta:loa:2fa:any"}, okta, true},
		{map[string]any{"acr": "urn:okta:loa:1fa:any"}, okta, false},
		{map[string]any{"acr": "urn:okta:loa:2fa:any"}, DefaultMFAPolicy, false},
		{map[string]any{}, MFAPolicy{}, false},
	} {
		if got := c.policy.Satisfied(p(c.claims)); got != c.want {
			t.Errorf("%v %+v: got %v", c.claims, c.policy, got)
		}
	}
	v := NewVerifier(issuer, audience, StaticKeys{})
	v.MFA = okta
	if !MFAOf(v, p(map[string]any{"acr": "urn:okta:loa:2fa:any"})) || MFAOf(nil, p(map[string]any{"acr": "urn:okta:loa:2fa:any"})) {
		t.Fatal("MFAOf")
	}
}
