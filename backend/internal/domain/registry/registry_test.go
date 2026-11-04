package registry

import (
	"crypto/rand"
	"encoding/base64"
	"errors"
	"strings"
	"testing"

	"github.com/google/uuid"

	"github.com/aupv9/warden/backend/internal/secretbox"
)

func TestValidHost(t *testing.T) {
	for _, h := range []string{"ghcr.io", "registry.example.com:5000", "a.b", "xn--bcher-kva.example", "r-1.example.co:1", "x.io:65535"} {
		if !ValidHost(h) {
			t.Errorf("%q refused", h)
		}
	}
	for _, h := range []string{
		"", "localhost", "registry", "localhost:5000", // one label
		"GHCR.io", "https://ghcr.io", "ghcr.io/acme", "ghcr.io/", "ghcr.io?x=1", "ghcr.io#x", // case, scheme, path
		"user@ghcr.io", "user:pw@ghcr.io", // user info
		"127.0.0.1", "10.0.0.1:5000", "169.254.169.254", "127.1", "1.2.3.4.5", // IP literals and look-alikes
		"[::1]", "[::1]:5000", "::1", "fd00::1",
		"ghcr.io:", "ghcr.io:0", "ghcr.io:05000", "ghcr.io:65536", "ghcr.io:99999", "ghcr.io:1:2",
		"-a.io", "a-.io", "a..io", ".a.io", "a.io.", "a_b.io", "a b.io", "a.io\n", "ɡhcr.io",
		strings.Repeat("a", 64) + ".io", strings.Repeat("a.", 127) + "io",
	} {
		if ValidHost(h) {
			t.Errorf("%q accepted", h)
		}
	}
}

func TestParseRef(t *testing.T) {
	digest := "sha256:" + strings.Repeat("ab", 32)
	ref, err := ParseRef("registry.example.com:5000/acme/api-server__x@"+digest, nil)
	if err != nil || ref.Host != "registry.example.com:5000" || ref.Repository != "acme/api-server__x" || ref.Digest != digest ||
		ref.Name() != "registry.example.com:5000/acme/api-server__x" || ref.String() != "registry.example.com:5000/acme/api-server__x@"+digest {
		t.Fatal(ref, err)
	}
	allow := func(name string) bool { return name == "localhost" || name == "127.0.0.1" }
	for _, s := range []string{"localhost:5000/api@" + digest, "127.0.0.1:5000/a/b@" + digest, "localhost/api@" + digest} {
		if _, err := ParseRef(s, allow); err != nil {
			t.Errorf("%q with allow_hosts: %v", s, err)
		}
		if _, err := ParseRef(s, nil); !errors.Is(err, ErrRefHost) {
			t.Errorf("%q without allow_hosts: %v", s, err)
		}
	}
	for s, want := range map[string]error{
		"ghcr.io/acme/api:1.2":                                 ErrRefFormat, // a tag, no digest
		"ghcr.io/acme/api:1.2@" + digest:                       ErrRefFormat, // tag and digest
		"ghcr.io/acme/api@sha256:" + strings.Repeat("a", 63):   ErrRefFormat,
		"ghcr.io/acme/api@sha512:" + strings.Repeat("a", 128):  ErrRefFormat,
		"ghcr.io/acme/api@SHA256:" + strings.Repeat("a", 64):   ErrRefFormat,
		"ghcr.io/acme/api@" + strings.ToUpper(digest[7:]):      ErrRefFormat,
		"ghcr.io@" + digest:                                    ErrRefFormat, // no repository
		"acme@" + digest:                                       ErrRefFormat,
		"https://ghcr.io/acme/api@" + digest:                   ErrRefFormat,
		"user:pw@ghcr.io/acme/api@" + digest:                   ErrRefFormat,
		"GHCR.io/acme/api@" + digest:                           ErrRefFormat,
		"ghcr.io/Acme/api@" + digest:                           ErrRefFormat,
		"ghcr.io/acme/../api@" + digest:                        ErrRefFormat,
		"ghcr.io//api@" + digest:                               ErrRefFormat,
		"ghcr.io/acme/api/@" + digest:                          ErrRefFormat,
		"ghcr.io/acme/api?x=1@" + digest:                       ErrRefFormat,
		"ghcr.io/acme/api@" + digest + "\n":                    ErrRefFormat,
		" ghcr.io/acme/api@" + digest:                          ErrRefFormat,
		"ghcr.io:0/acme/api@" + digest:                         ErrRefFormat,
		"ghcr.io:65536/acme/api@" + digest:                     ErrRefFormat,
		"[::1]:5000/acme/api@" + digest:                        ErrRefFormat,
		"ghcr.io/" + strings.Repeat("a/", 130) + "b@" + digest: ErrRefFormat, // target over 255
		"ghcr.io/" + strings.Repeat("a", 600) + "@" + digest:   ErrRefFormat, // over 512
		"10.0.0.1:5000/acme/api@" + digest:                     ErrRefHost,
		"169.254.169.254/latest/meta@" + digest:                ErrRefHost,
		"127.1/acme/api@" + digest:                             ErrRefHost,
		"localhost/acme/api@" + digest:                         ErrRefHost,
		"library/nginx@" + digest:                              ErrRefHost, // no implicit docker.io
		"library/alpine/x@" + digest:                           ErrRefHost,
		"registry:5000/acme/api@" + digest:                     ErrRefHost, // one label, even with a port
		"docker/api@" + digest:                                 ErrRefHost,
	} {
		if _, err := ParseRef(s, nil); !errors.Is(err, want) {
			t.Errorf("%q: got %v, want %v", s, err, want)
		}
	}
}

func TestPasswordIsBoundToOrgRowAndKey(t *testing.T) {
	raw := make([]byte, 32)
	_, _ = rand.Read(raw)
	keys, err := secretbox.Parse("k1:"+base64.StdEncoding.EncodeToString(raw), "")
	if err != nil {
		t.Fatal(err)
	}
	org, id := uuid.New(), uuid.New()
	pw := "ghp_" + strings.Repeat("Z", 36)
	enc, keyID, err := SealPassword(keys, org, id, pw)
	if err != nil || keyID != "k1" || strings.Contains(string(enc), pw) {
		t.Fatal(keyID, err)
	}
	if got, err := OpenPassword(keys, org, id, keyID, enc); err != nil || got != pw {
		t.Fatal(got, err)
	}
	for name, open := range map[string]func() error{
		"other org": func() error { _, err := OpenPassword(keys, uuid.New(), id, keyID, enc); return err },
		"other row": func() error { _, err := OpenPassword(keys, org, uuid.New(), keyID, enc); return err },
		"tampered": func() error {
			bad := append([]byte(nil), enc...)
			bad[len(bad)-1] ^= 1
			_, err := OpenPassword(keys, org, id, keyID, bad)
			return err
		},
		"unknown key": func() error { _, err := OpenPassword(keys, org, id, "k2", enc); return err },
		"no keys":     func() error { _, err := OpenPassword(nil, org, id, keyID, enc); return err },
	} {
		if open() == nil {
			t.Errorf("%s: opened", name)
		}
	}
	if _, _, err := SealPassword(nil, org, id, pw); !errors.Is(err, secretbox.ErrKeyUnavailable) {
		t.Fatal(err)
	}
}

func TestValidError(t *testing.T) {
	for _, s := range []string{ErrUnauthorized, ErrUnreachable, ErrBlocked} {
		if !ValidError(s) {
			t.Error(s)
		}
	}
	if ValidError("") || ValidError("timeout") {
		t.Fatal("unknown outcome accepted")
	}
}
