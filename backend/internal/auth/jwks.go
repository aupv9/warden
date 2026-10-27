package auth

import (
	"context"
	"crypto"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rsa"
	"encoding/base64"
	"encoding/json"
	"fmt"
	"io"
	"math/big"
	"net/http"
	"net/url"
	"slices"
	"strings"
	"sync"
	"time"
)

const (
	maxJWKSBytes  = 1 << 20
	minRSABits    = 2048
	missRefetchIn = time.Minute
)

// JWKS fetches and caches the provider's signing keys. An unknown kid triggers
// at most one refetch per minute, so forged tokens can't make Warden hammer the
// identity provider.
//
// The key URL is either pinned (URL) or discovered from the issuer's
// /.well-known/openid-configuration on every refresh, so it follows the
// provider (Keycloak, Okta, Entra ID, Auth0, …). Discovery must name the
// configured issuer, and the discovered jwks_uri must be https or on the
// issuer's own scheme and host: a tampered document can't point Warden at
// keys served from somewhere else over plain http.
type JWKS struct {
	Issuer   string
	URL      string
	Lifespan time.Duration
	// Algs are the accepted token algorithms; only keys usable for them are kept.
	Algs   []string
	Client *http.Client

	mu        sync.Mutex
	keys      map[string]crypto.PublicKey
	fetchedAt time.Time
	now       func() time.Time
}

// NewJWKS discovers the key URL from issuer unless jwksURL is set.
func NewJWKS(issuer, jwksURL string, lifespan time.Duration, algs []string) *JWKS {
	return &JWKS{
		Issuer:   strings.TrimRight(issuer, "/"),
		URL:      jwksURL,
		Lifespan: lifespan,
		Algs:     algs,
		Client: &http.Client{
			Timeout: 5 * time.Second,
			// Discovery and keys are read where they are, never via a redirect.
			CheckRedirect: func(*http.Request, []*http.Request) error { return http.ErrUseLastResponse },
		},
	}
}

func (j *JWKS) clock() time.Time {
	if j.now != nil {
		return j.now()
	}
	return time.Now()
}

func (j *JWKS) Key(ctx context.Context, kid string) (crypto.PublicKey, error) {
	j.mu.Lock()
	defer j.mu.Unlock()
	age := j.clock().Sub(j.fetchedAt)
	if j.keys == nil || age > j.Lifespan {
		if err := j.refresh(ctx); err != nil {
			return nil, err
		}
	} else if _, ok := j.keys[kid]; !ok && age > missRefetchIn {
		if err := j.refresh(ctx); err != nil {
			return nil, err
		}
	}
	if k, ok := j.keys[kid]; ok {
		return k, nil
	}
	return nil, fmt.Errorf("unknown kid %q", kid)
}

func (j *JWKS) refresh(ctx context.Context) error {
	keysURL := j.URL
	if keysURL == "" {
		var err error
		if keysURL, err = j.discover(ctx); err != nil {
			return err
		}
	}
	body, err := j.get(ctx, keysURL, "JWKS")
	if err != nil {
		return err
	}
	keys, err := ParseJWKS(body, j.Algs)
	if err != nil {
		return err
	}
	j.keys, j.fetchedAt = keys, j.clock()
	return nil
}

// discover reads jwks_uri from the issuer's OpenID configuration.
func (j *JWKS) discover(ctx context.Context) (string, error) {
	body, err := j.get(ctx, j.Issuer+"/.well-known/openid-configuration", "OIDC discovery")
	if err != nil {
		return "", err
	}
	var doc struct {
		Issuer  string `json:"issuer"`
		JWKSURI string `json:"jwks_uri"`
	}
	if err := json.Unmarshal(body, &doc); err != nil {
		return "", fmt.Errorf("parse OIDC discovery: %w", err)
	}
	if strings.TrimRight(doc.Issuer, "/") != j.Issuer {
		return "", fmt.Errorf("OIDC discovery names issuer %q, want %q", doc.Issuer, j.Issuer)
	}
	if err := checkKeysURL(j.Issuer, doc.JWKSURI); err != nil {
		return "", err
	}
	return doc.JWKSURI, nil
}

// checkKeysURL accepts an https jwks_uri, or one on the issuer's own scheme and
// host (an internal http issuer such as http://keycloak:8080 in a compose file).
func checkKeysURL(issuer, raw string) error {
	u, err := url.Parse(raw)
	if err != nil || u.Host == "" || u.User != nil {
		return fmt.Errorf("OIDC discovery: invalid jwks_uri %q", raw)
	}
	if u.Scheme == "https" {
		return nil
	}
	iss, err := url.Parse(issuer)
	if err == nil && u.Scheme == "http" && iss.Scheme == "http" && strings.EqualFold(u.Host, iss.Host) {
		return nil
	}
	return fmt.Errorf("OIDC discovery: jwks_uri %q must be https or on the issuer's host", raw)
}

func (j *JWKS) get(ctx context.Context, rawURL, what string) ([]byte, error) {
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, rawURL, nil)
	if err != nil {
		return nil, err
	}
	req.Header.Set("Accept", "application/json")
	resp, err := j.Client.Do(req)
	if err != nil {
		return nil, fmt.Errorf("fetch %s: %w", what, err)
	}
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusOK {
		return nil, fmt.Errorf("fetch %s: HTTP %d", what, resp.StatusCode)
	}
	body, err := io.ReadAll(io.LimitReader(resp.Body, maxJWKSBytes+1))
	if err != nil {
		return nil, fmt.Errorf("fetch %s: %w", what, err)
	}
	if len(body) > maxJWKSBytes {
		return nil, fmt.Errorf("fetch %s: response too large", what)
	}
	return body, nil
}

type jwk struct {
	Kid string `json:"kid"`
	Kty string `json:"kty"`
	Alg string `json:"alg"`
	Use string `json:"use"`
	N   string `json:"n"`
	E   string `json:"e"`
	Crv string `json:"crv"`
	X   string `json:"x"`
	Y   string `json:"y"`
}

// ParseJWKS keeps only signing keys usable for the accepted algorithms: RSA keys
// of at least 2048 bits for RS256, P-256 keys for ES256. Encryption keys
// (providers publish those too) and keys for other algorithms are dropped, and
// EC points are checked to lie on the curve.
func ParseJWKS(body []byte, algs []string) (map[string]crypto.PublicKey, error) {
	var set struct {
		Keys []jwk `json:"keys"`
	}
	if err := json.Unmarshal(body, &set); err != nil {
		return nil, fmt.Errorf("parse JWKS: %w", err)
	}
	keys := map[string]crypto.PublicKey{}
	for _, k := range set.Keys {
		if k.Kid == "" || (k.Use != "" && k.Use != "sig") || (k.Alg != "" && !slices.Contains(algs, k.Alg)) {
			continue
		}
		switch {
		case k.Kty == "RSA" && slices.Contains(algs, "RS256") && (k.Alg == "" || k.Alg == "RS256"):
			if pk := rsaKey(k); pk != nil {
				keys[k.Kid] = pk
			}
		case k.Kty == "EC" && k.Crv == "P-256" && slices.Contains(algs, "ES256") && (k.Alg == "" || k.Alg == "ES256"):
			if pk := ecKey(k); pk != nil {
				keys[k.Kid] = pk
			}
		}
	}
	if len(keys) == 0 {
		return nil, fmt.Errorf("parse JWKS: no usable signing keys for %s", strings.Join(algs, ", "))
	}
	return keys, nil
}

func rsaKey(k jwk) *rsa.PublicKey {
	nb, err1 := base64.RawURLEncoding.DecodeString(k.N)
	eb, err2 := base64.RawURLEncoding.DecodeString(k.E)
	if err1 != nil || err2 != nil || len(eb) == 0 || len(eb) > 4 {
		return nil
	}
	n := new(big.Int).SetBytes(nb)
	e := new(big.Int).SetBytes(eb)
	if n.BitLen() < minRSABits || !e.IsInt64() || e.Int64() < 3 || e.Int64()%2 == 0 {
		return nil
	}
	return &rsa.PublicKey{N: n, E: int(e.Int64())}
}

func ecKey(k jwk) *ecdsa.PublicKey {
	x, err1 := base64.RawURLEncoding.DecodeString(k.X)
	y, err2 := base64.RawURLEncoding.DecodeString(k.Y)
	if err1 != nil || err2 != nil || len(x) != 32 || len(y) != 32 {
		return nil
	}
	// ParseUncompressedPublicKey rejects points that aren't on the curve.
	pk, err := ecdsa.ParseUncompressedPublicKey(elliptic.P256(), append(append([]byte{4}, x...), y...))
	if err != nil {
		return nil
	}
	return pk
}
