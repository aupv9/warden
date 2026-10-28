package secretbox

import (
	"bytes"
	"crypto/rand"
	"encoding/base64"
	"errors"
	"fmt"
	"log/slog"
	"strings"
	"testing"
)

// key builds a "<id>:<base64>" key at test time (no key material in fixtures).
func key(t *testing.T, id string) (string, string) {
	t.Helper()
	raw := make([]byte, KeyBytes)
	if _, err := rand.Read(raw); err != nil {
		t.Fatal(err)
	}
	b64 := base64.StdEncoding.EncodeToString(raw)
	return id + ":" + b64, b64
}

func TestParse(t *testing.T) {
	k1, _ := key(t, "k1")
	k0, _ := key(t, "k0")
	if k, err := Parse("", ""); k != nil || err != nil || k.Available() {
		t.Fatal(k, err)
	}
	k, err := Parse(k1, " "+k0+" ,")
	if err != nil || k.ActiveID() != "k1" || !k.Has("k0") || k.Has("k2") || strings.Join(k.IDs(), ",") != "k1,k0" {
		t.Fatal(k, err)
	}

	short := base64.StdEncoding.EncodeToString(make([]byte, 16))
	zero := base64.StdEncoding.EncodeToString(make([]byte, 32))
	_, b64 := key(t, "x")
	urlSafe := strings.NewReplacer("+", "-", "/", "_").Replace(b64)
	for name, c := range map[string][2]string{
		"no colon":           {"k1" + b64, ""},
		"upper-case id":      {"K1:" + b64, ""},
		"long id":            {strings.Repeat("a", 33) + ":" + b64, ""},
		"empty id":           {":" + b64, ""},
		"id with a dot":      {"k.1:" + b64, ""},
		"16 bytes":           {"k1:" + short, ""},
		"33 bytes":           {"k1:" + base64.StdEncoding.EncodeToString(make([]byte, 33)), ""},
		"not base64":         {"k1:" + strings.Repeat("!", 44), ""},
		"unpadded":           {"k1:" + strings.TrimRight(b64, "="), ""},
		"url-safe alphabet":  {"k1:" + urlSafe + "/", ""},
		"all zero":           {"k1:" + zero, ""},
		"old without active": {"", k0},
		"duplicate id":       {k1, k1},
		"bad old key":        {k1, "k0:" + short},
	} {
		_, err := Parse(c[0], c[1])
		if err == nil {
			t.Errorf("%s: accepted", name)
			continue
		}
		// The key never appears in an error.
		if strings.Contains(err.Error(), b64) || strings.Contains(err.Error(), short) {
			t.Errorf("%s: error leaks the key: %v", name, err)
		}
	}
}

func TestSealOpen(t *testing.T) {
	k1, b64 := key(t, "k1")
	k, err := Parse(k1, "")
	if err != nil {
		t.Fatal(err)
	}
	ad := []byte("org\x00row\x00url")
	ct, id, err := k.Seal([]byte("https://hooks.example.test/x"), ad)
	if err != nil || id != "k1" {
		t.Fatal(id, err)
	}
	if bytes.Contains(ct, []byte("hooks.example")) {
		t.Fatal("plaintext in ciphertext")
	}
	got, err := k.Open("k1", ct, ad)
	if err != nil || string(got) != "https://hooks.example.test/x" {
		t.Fatal(string(got), err)
	}
	// A fresh nonce every time.
	ct2, _, _ := k.Seal([]byte("https://hooks.example.test/x"), ad)
	if bytes.Equal(ct, ct2) {
		t.Fatal("nonce reused")
	}

	// Every flipped bit, a truncation and an extension fail.
	for i := range ct {
		bad := bytes.Clone(ct)
		bad[i] ^= 0x01
		if _, err := k.Open("k1", bad, ad); !errors.Is(err, ErrOpen) {
			t.Fatalf("byte %d flipped: %v", i, err)
		}
	}
	for _, bad := range [][]byte{ct[:len(ct)-1], append(bytes.Clone(ct), 0), nil, ct[:5]} {
		if _, err := k.Open("k1", bad, ad); !errors.Is(err, ErrOpen) {
			t.Fatalf("len %d: %v", len(bad), err)
		}
	}
	// Moved to another row or column: other additional data.
	for _, other := range [][]byte{[]byte("org\x00row\x00secret"), []byte("org\x00other\x00url"), nil} {
		if _, err := k.Open("k1", ct, other); !errors.Is(err, ErrOpen) {
			t.Fatalf("ad %q: %v", other, err)
		}
	}
	// The same id with a different key (an operator mistake) fails closed.
	k1b, _ := key(t, "k1")
	kb, _ := Parse(k1b, "")
	if _, err := kb.Open("k1", ct, ad); !errors.Is(err, ErrOpen) {
		t.Fatal(err)
	}
	// Claiming another key id fails even when that key is the same bytes.
	same, _ := Parse("k2:"+b64, "")
	if _, err := same.Open("k2", ct, ad); !errors.Is(err, ErrOpen) {
		t.Fatal(err)
	}
	if _, err := k.Open("k9", ct, ad); !errors.Is(err, ErrKeyUnavailable) {
		t.Fatal(err)
	}

	// No keyring: nothing seals or opens.
	var none *Keyring
	if _, _, err := none.Seal([]byte("x"), ad); !errors.Is(err, ErrKeyUnavailable) {
		t.Fatal(err)
	}
	if _, err := none.Open("k1", ct, ad); !errors.Is(err, ErrKeyUnavailable) {
		t.Fatal(err)
	}
}

// After a rotation the old key still opens what it sealed; new seals use the
// new key.
func TestRotation(t *testing.T) {
	k1, _ := key(t, "k1")
	k2, _ := key(t, "k2")
	old, _ := Parse(k1, "")
	ct, _, _ := old.Seal([]byte("secret"), []byte("ad"))
	rotated, err := Parse(k2, k1)
	if err != nil {
		t.Fatal(err)
	}
	if got, err := rotated.Open("k1", ct, []byte("ad")); err != nil || string(got) != "secret" {
		t.Fatal(err)
	}
	if _, id, _ := rotated.Seal([]byte("x"), nil); id != "k2" {
		t.Fatal(id)
	}
	// Dropping the old key makes its rows unreadable, not readable by another.
	dropped, _ := Parse(k2, "")
	if _, err := dropped.Open("k1", ct, []byte("ad")); !errors.Is(err, ErrKeyUnavailable) {
		t.Fatal(err)
	}
}

func TestKeyringNeverPrintsKeys(t *testing.T) {
	k1, b64 := key(t, "k1")
	k, _ := Parse(k1, "")
	var logged bytes.Buffer
	slog.New(slog.NewTextHandler(&logged, nil)).Info("x", "keys", k)
	for _, s := range []string{fmt.Sprint(k), fmt.Sprintf("%v %+v %#v %s", k, k, k, k), logged.String()} {
		if strings.Contains(s, b64) || !strings.Contains(s, "keyring(k1)") {
			t.Fatalf("%q", s)
		}
	}
}
