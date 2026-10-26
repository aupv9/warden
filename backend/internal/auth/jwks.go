package auth

import (
	"context"
	"crypto/rsa"
	"encoding/base64"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"math/big"
	"net/http"
	"strings"
	"sync"
	"time"
)

const (
	maxJWKSBytes  = 1 << 20
	minRSABits    = 2048
	missRefetchIn = time.Minute
)

// JWKS fetches and caches the realm's signing keys. An unknown kid triggers at
// most one refetch per minute, so forged tokens can't make Warden hammer Keycloak.
type JWKS struct {
	URL      string
	Lifespan time.Duration
	Client   *http.Client

	mu        sync.Mutex
	keys      map[string]*rsa.PublicKey
	fetchedAt time.Time
	now       func() time.Time
}

func NewJWKS(issuer string, lifespan time.Duration) *JWKS {
	return &JWKS{
		URL:      strings.TrimRight(issuer, "/") + "/protocol/openid-connect/certs",
		Lifespan: lifespan,
		Client:   &http.Client{Timeout: 5 * time.Second},
	}
}

func (j *JWKS) clock() time.Time {
	if j.now != nil {
		return j.now()
	}
	return time.Now()
}

func (j *JWKS) Key(ctx context.Context, kid string) (*rsa.PublicKey, error) {
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
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, j.URL, nil)
	if err != nil {
		return err
	}
	resp, err := j.Client.Do(req)
	if err != nil {
		return fmt.Errorf("fetch JWKS: %w", err)
	}
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusOK {
		return fmt.Errorf("fetch JWKS: HTTP %d", resp.StatusCode)
	}
	body, err := io.ReadAll(io.LimitReader(resp.Body, maxJWKSBytes+1))
	if err != nil {
		return fmt.Errorf("fetch JWKS: %w", err)
	}
	if len(body) > maxJWKSBytes {
		return errors.New("fetch JWKS: response too large")
	}
	keys, err := ParseJWKS(body)
	if err != nil {
		return err
	}
	j.keys, j.fetchedAt = keys, j.clock()
	return nil
}

type jwk struct {
	Kid string `json:"kid"`
	Kty string `json:"kty"`
	Alg string `json:"alg"`
	Use string `json:"use"`
	N   string `json:"n"`
	E   string `json:"e"`
}

// ParseJWKS keeps only RSA signing keys usable for RS256 of at least 2048 bits;
// Keycloak also publishes encryption keys, which must never verify tokens.
func ParseJWKS(body []byte) (map[string]*rsa.PublicKey, error) {
	var set struct {
		Keys []jwk `json:"keys"`
	}
	if err := json.Unmarshal(body, &set); err != nil {
		return nil, fmt.Errorf("parse JWKS: %w", err)
	}
	keys := map[string]*rsa.PublicKey{}
	for _, k := range set.Keys {
		if k.Kid == "" || k.Kty != "RSA" || (k.Use != "" && k.Use != "sig") || (k.Alg != "" && k.Alg != "RS256") {
			continue
		}
		nb, err1 := base64.RawURLEncoding.DecodeString(k.N)
		eb, err2 := base64.RawURLEncoding.DecodeString(k.E)
		if err1 != nil || err2 != nil || len(eb) == 0 || len(eb) > 4 {
			continue
		}
		n := new(big.Int).SetBytes(nb)
		e := new(big.Int).SetBytes(eb)
		if n.BitLen() < minRSABits || !e.IsInt64() || e.Int64() < 3 || e.Int64()%2 == 0 {
			continue
		}
		keys[k.Kid] = &rsa.PublicKey{N: n, E: int(e.Int64())}
	}
	if len(keys) == 0 {
		return nil, errors.New("parse JWKS: no usable RS256 signing keys")
	}
	return keys, nil
}
