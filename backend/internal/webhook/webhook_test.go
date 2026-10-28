package webhook

import (
	"bytes"
	"crypto/rand"
	"encoding/base64"
	"errors"
	"net/netip"
	"regexp"
	"strings"
	"testing"

	"github.com/google/uuid"

	"github.com/aupv9/warden/backend/internal/secretbox"
)

// The Standard Webhooks test vector (standard-webhooks spec README). The
// secret is the spec's public example, assembled here so no secret-shaped
// literal sits in the repository.
func TestSignMatchesStandardWebhooksVector(t *testing.T) {
	secret, err := base64.StdEncoding.DecodeString("MfKQ9r8GKYqr" + "TwjUPD8ILPZIo2LaLaSw")
	if err != nil {
		t.Fatal(err)
	}
	got := Sign(secret, "msg_p5jXN8AQM9LWM0D4loKWxJek", 1614265330, []byte(`{"test": 2432232314}`))
	if got != "v1,g0hM9SsE+OTPJTGt/tmIKtSyZlE3uFJELVlNIOLJ1OE=" {
		t.Fatal(got)
	}
	// Any change to id, timestamp or body changes it.
	for _, other := range []string{
		Sign(secret, "msg_p5jXN8AQM9LWM0D4loKWxJel", 1614265330, []byte(`{"test": 2432232314}`)),
		Sign(secret, "msg_p5jXN8AQM9LWM0D4loKWxJek", 1614265331, []byte(`{"test": 2432232314}`)),
		Sign(secret, "msg_p5jXN8AQM9LWM0D4loKWxJek", 1614265330, []byte(`{"test": 2432232315}`)),
	} {
		if other == got {
			t.Fatal("signature ignores a part")
		}
	}
}

func TestNewSecret(t *testing.T) {
	raw, shown, err := NewSecret()
	if err != nil || len(raw) != 32 || !regexp.MustCompile(`^whsec_[A-Za-z0-9+/]{43}=$`).MatchString(shown) {
		t.Fatal(len(raw), shown, err)
	}
	if dec, _ := base64.StdEncoding.DecodeString(strings.TrimPrefix(shown, SecretPrefix)); !bytes.Equal(dec, raw) {
		t.Fatal("shown secret isn't the raw one")
	}
	if _, again, _ := NewSecret(); again == shown {
		t.Fatal("secret repeated")
	}
}

func keyring(t *testing.T, id string, old ...string) (*secretbox.Keyring, string) {
	t.Helper()
	raw := make([]byte, 32)
	_, _ = rand.Read(raw)
	k := id + ":" + base64.StdEncoding.EncodeToString(raw)
	ring, err := secretbox.Parse(k, strings.Join(old, ","))
	if err != nil {
		t.Fatal(err)
	}
	return ring, k
}

// A sealed URL or secret opens only for its own org, webhook and column, and
// survives a key rotation through old_keys.
func TestSealOpenReseal(t *testing.T) {
	k1, k1s := keyring(t, "k1")
	org, id := uuid.New(), uuid.New()
	secret := bytes.Repeat([]byte{7}, 32)
	s, err := Seal(k1, org, id, "https://hooks.example.com/x", secret)
	if err != nil || s.KeyID != "k1" {
		t.Fatal(err)
	}
	if u, sec, err := Open(k1, org, id, s); err != nil || u != "https://hooks.example.com/x" || !bytes.Equal(sec, secret) {
		t.Fatal(u, err)
	}
	for name, try := range map[string]func() error{
		"other org":     func() error { _, _, err := Open(k1, uuid.New(), id, s); return err },
		"other webhook": func() error { _, _, err := Open(k1, org, uuid.New(), s); return err },
		"swapped columns": func() error {
			_, _, err := Open(k1, org, id, Sealed{URL: s.Secret, Secret: s.URL, KeyID: s.KeyID})
			return err
		},
		"no keys": func() error { _, _, err := Open(nil, org, id, s); return err },
	} {
		if err := try(); err == nil {
			t.Errorf("%s: opened", name)
		}
	}

	k2, _ := keyring(t, "k2", k1s)
	if _, _, err := Open(k2, org, id, s); err != nil {
		t.Fatal("old key doesn't open:", err)
	}
	r, changed, err := Reseal(k2, org, id, s)
	if err != nil || !changed || r.KeyID != "k2" {
		t.Fatal(r.KeyID, changed, err)
	}
	if u, sec, err := Open(k2, org, id, r); err != nil || u != "https://hooks.example.com/x" || !bytes.Equal(sec, secret) {
		t.Fatal(err)
	}
	if _, changed, _ := Reseal(k2, org, id, r); changed {
		t.Fatal("resealed twice")
	}
	// Slack: no secret.
	sl, _ := Seal(k2, org, id, "https://hooks.slack.com/services/T/B/x", nil)
	if _, sec, err := Open(k2, org, id, sl); err != nil || sec != nil || sl.Secret != nil {
		t.Fatal(err)
	}
}

func TestBlocked(t *testing.T) {
	blocked := []string{
		"127.0.0.1", "127.255.255.254", "10.1.2.3", "172.16.0.1", "172.31.255.255", "192.168.1.1", "169.254.169.254",
		"100.64.0.1", "100.100.100.200", "0.0.0.0", "0.1.2.3", "255.255.255.255", "224.0.0.1", "239.1.1.1", "240.0.0.1",
		"192.0.0.192", "192.0.2.1", "198.18.0.1", "198.19.255.255", "198.51.100.7", "203.0.113.9", "192.88.99.1",
		"::", "::1", "fe80::1", "fc00::1", "fd00:ec2::254", "ff02::1", "fec0::1", "2001:db8::1", "100::1",
		"::ffff:127.0.0.1", "::ffff:10.0.0.1", "::ffff:169.254.169.254", // IPv4-mapped
		"::127.0.0.1", "::a00:1", // IPv4-compatible
		"64:ff9b::7f00:1", "64:ff9b::a9fe:a9fe", // NAT64 of loopback and metadata
		"2002:7f00:1::1", "2002:a9fe:a9fe::", // 6to4 of loopback and metadata
		"2001::1",            // Teredo
		"64:ff9b:1::8.8.8.8", // local-use NAT64
	}
	for _, s := range blocked {
		if !Blocked(netip.MustParseAddr(s)) {
			t.Errorf("%s allowed", s)
		}
	}
	if !Blocked(netip.Addr{}) || !Blocked(netip.MustParseAddr("fe80::1%eth0")) {
		t.Error("invalid or zoned address allowed")
	}
	for _, s := range []string{"8.8.8.8", "1.1.1.1", "34.120.0.1", "2606:4700:4700::1111", "::ffff:8.8.8.8",
		"64:ff9b::808:808", "2002:808:808::1", "100.63.255.255", "100.128.0.1", "172.32.0.1", "198.20.0.1"} {
		if Blocked(netip.MustParseAddr(s)) {
			t.Errorf("%s blocked", s)
		}
	}
}

func TestParseURL(t *testing.T) {
	p := Policy{AllowHosts: []string{"127.0.0.1", "Receiver.Local"}}
	ok := map[string]string{
		"https://hooks.example.com/in/abc?x=1":       "https://hooks.example.com/…",
		"https://HOOKS.example.com":                  "https://hooks.example.com",
		"https://hooks.example.com/":                 "https://hooks.example.com",
		"https://hooks.example.com:8443/x":           "https://hooks.example.com:8443/…",
		"https://8.8.8.8/x":                          "https://8.8.8.8/…",
		"https://[2606:4700:4700::1111]/x":           "https://[2606:4700:4700::1111]/…",
		"http://127.0.0.1:9000/hook":                 "http://127.0.0.1:9000/…", // allowed host: http and loopback
		"http://receiver.local/x":                    "http://receiver.local/…",
		"https://hooks.slack.com/services/T0/B0/xyz": "https://hooks.slack.com/…",
	}
	for raw, hint := range ok {
		kind := KindGeneric
		if strings.Contains(raw, "slack") {
			kind = KindSlack
		}
		tg, err := p.Parse(kind, raw)
		if err != nil || tg.Hint() != hint {
			t.Errorf("%s: %q %v", raw, tg.Hint(), err)
		}
	}
	bad := map[string]string{
		"":                                     MsgInvalid,
		"hooks.example.com/x":                  MsgInvalid,
		"http://hooks.example.com/x":           MsgHTTPS,
		"ftp://hooks.example.com/x":            MsgHTTPS,
		"javascript:alert(1)":                  MsgHTTPS,
		"https://user:pw@hooks.example.com/x":  MsgUserInfo,
		"https://user@hooks.example.com/x":     MsgUserInfo,
		"https://hooks.example.com/x#frag":     MsgFragment,
		"https://hooks.example.com/x y":        MsgInvalid,
		"https://hooks.example.com/\r\nX: y":   MsgInvalid,
		"https://hööks.example.com/":           MsgInvalid,
		"https://127.0.0.3/x":                  MsgPrivate,
		"https://[::1]/x":                      MsgPrivate,
		"https://[::ffff:127.0.0.1]/x":         MsgPrivate,
		"https://[::ffff:7f00:1]/x":            MsgPrivate,
		"https://169.254.169.254/latest":       MsgPrivate,
		"https://[fe80::1%25eth0]/x":           MsgInvalid,
		"https://0x7f.0.0.1/x":                 MsgInvalid, // octal, hex and decimal forms of 127.0.0.1
		"https://0177.0.0.1/x":                 MsgInvalid,
		"https://2130706433/x":                 MsgInvalid,
		"https://127.1/x":                      MsgInvalid,
		"https://0x7f000001/x":                 MsgInvalid,
		"https://hooks.example.com:0/x":        MsgInvalid,
		"https://hooks.example.com:99999/x":    MsgInvalid,
		"https://hooks.example.com:/x":         MsgInvalid,
		"https://hooks.example.com:080/x":      MsgInvalid,
		"https://exa_mple..com/x":              MsgInvalid,
		"https://" + strings.Repeat("a", 2050): MsgTooLong,
		"http://127.0.0.2/x":                   MsgHTTPS, // not the allowed host
	}
	for raw, msg := range bad {
		_, err := p.Parse(KindGeneric, raw)
		var ue *URLError
		if !errors.As(err, &ue) || ue.Msg != msg {
			t.Errorf("%q: %v, want %q", raw, err, msg)
		}
	}
	for _, raw := range []string{
		"https://hooks.example.com/services/T/B/x", "http://hooks.slack.com/services/T/B/x",
		"https://hooks.slack.com/services/", "https://hooks.slack.com/other/T/B/x", "https://hooks.slack.com:8443/services/T/B/x",
		"https://hooks.slack.com.evil.example/services/T/B/x", "https://evil.example/https://hooks.slack.com/services/T",
	} {
		_, err := p.Parse(KindSlack, raw)
		var ue *URLError
		if !errors.As(err, &ue) || (ue.Msg != MsgSlack && ue.Msg != MsgHTTPS) {
			t.Errorf("slack %q: %v", raw, err)
		}
	}
}
