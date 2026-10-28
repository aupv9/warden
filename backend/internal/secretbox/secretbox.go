// Package secretbox encrypts the few credentials Warden has to read back in
// clear (webhook URLs and signing secrets): API tokens can be hashed, these
// can't, because Warden itself must send them.
//
// AES-256-GCM with a random 96-bit nonce per seal, under a server key given as
// secrets.key = "<key id>:<base64 of exactly 32 bytes>". The key id is stored
// beside each ciphertext and is part of the additional data, as is whatever the
// caller binds the ciphertext to (org, row id, column), so a ciphertext copied
// to another row, column or key id fails to open. secrets.old_keys only
// decrypt, so the key can be rotated: rows sealed under an old key keep working
// until they are re-encrypted. Key material is never logged or printed: errors
// name the setting, never its value, and a Keyring formats as its key ids.
package secretbox

import (
	"bytes"
	"crypto/aes"
	"crypto/cipher"
	"crypto/rand"
	"encoding/base64"
	"errors"
	"fmt"
	"log/slog"
	"regexp"
	"slices"
	"strings"
)

// KeyBytes is the length of every key (AES-256).
const KeyBytes = 32

// version is the first byte of every ciphertext, so the format can change.
const version byte = 1

const nonceSize = 12

var keyIDFormat = regexp.MustCompile(`^[a-z0-9_-]{1,32}$`)

var (
	// ErrKeyUnavailable: no key with the ciphertext's key id (or no keyring).
	ErrKeyUnavailable = errors.New("secretbox: key unavailable")
	// ErrOpen: the ciphertext is malformed, was modified, or was sealed for
	// other additional data.
	ErrOpen = errors.New("secretbox: can't decrypt")
)

// Keyring holds the active key and the old ones. A nil *Keyring is valid and
// has no keys: Available is false and every Seal/Open fails.
type Keyring struct {
	active string
	aeads  map[string]cipher.AEAD
}

// Parse validates secrets.key (active) and secrets.old_keys (comma-separated)
// and builds the keyring. Both empty returns nil, nil: encryption is off. Old
// keys without an active key are an error, as is any malformed key, a key id
// used twice, or an all-zero key (a placeholder, not a key).
func Parse(active, old string) (*Keyring, error) {
	active = strings.TrimSpace(active)
	var olds []string
	for _, s := range strings.Split(old, ",") {
		if s = strings.TrimSpace(s); s != "" {
			olds = append(olds, s)
		}
	}
	if active == "" {
		if len(olds) > 0 {
			return nil, errors.New("secrets.old_keys is set but secrets.key is not")
		}
		return nil, nil
	}
	k := &Keyring{aeads: map[string]cipher.AEAD{}}
	id, aead, err := parseKey(active)
	if err != nil {
		return nil, fmt.Errorf("secrets.key: %w", err)
	}
	k.active = id
	k.aeads[id] = aead
	for i, s := range olds {
		id, aead, err := parseKey(s)
		if err != nil {
			return nil, fmt.Errorf("secrets.old_keys[%d]: %w", i, err)
		}
		if _, dup := k.aeads[id]; dup {
			return nil, fmt.Errorf("secrets.old_keys[%d]: key id %q is used twice", i, id)
		}
		k.aeads[id] = aead
	}
	return k, nil
}

// parseKey reads "<id>:<base64>". Error messages may name the id (it isn't
// secret and helps the operator) but never the key.
func parseKey(s string) (string, cipher.AEAD, error) {
	id, b64, ok := strings.Cut(s, ":")
	if !ok {
		return "", nil, errors.New(`must be "<key id>:<base64 of 32 bytes>"`)
	}
	if !keyIDFormat.MatchString(id) {
		return "", nil, errors.New("the key id must be 1-32 characters of a-z, 0-9, _ and -")
	}
	raw, err := base64.StdEncoding.Strict().DecodeString(b64)
	if err != nil || len(raw) != KeyBytes {
		return "", nil, fmt.Errorf("key %q must be the standard base64 of exactly %d bytes (openssl rand -base64 32)", id, KeyBytes)
	}
	if bytes.Count(raw, []byte{0}) == len(raw) {
		return "", nil, fmt.Errorf("key %q is all zero bytes", id)
	}
	block, err := aes.NewCipher(raw)
	clear(raw)
	if err != nil {
		return "", nil, err
	}
	aead, err := cipher.NewGCM(block)
	if err != nil {
		return "", nil, err
	}
	return id, aead, nil
}

// Available reports whether there is an active key to seal with.
func (k *Keyring) Available() bool { return k != nil && k.active != "" }

// ActiveID is the id of the key Seal uses ("" without a keyring).
func (k *Keyring) ActiveID() string {
	if k == nil {
		return ""
	}
	return k.active
}

// Has reports whether the keyring can open ciphertexts of key id.
func (k *Keyring) Has(id string) bool {
	if k == nil {
		return false
	}
	_, ok := k.aeads[id]
	return ok
}

// IDs lists the key ids, active first.
func (k *Keyring) IDs() []string {
	if k == nil {
		return nil
	}
	var old []string
	for id := range k.aeads {
		if id != k.active {
			old = append(old, id)
		}
	}
	slices.Sort(old)
	return append([]string{k.active}, old...)
}

// String, GoString and LogValue show key ids only, so a keyring that ends up in
// a log line or a %v can't leak a key.
func (k *Keyring) String() string {
	if k == nil {
		return "keyring(none)"
	}
	return "keyring(" + strings.Join(k.IDs(), ",") + ")"
}
func (k *Keyring) GoString() string     { return k.String() }
func (k *Keyring) LogValue() slog.Value { return slog.StringValue(k.String()) }

func additional(keyID string, ad []byte) []byte {
	out := make([]byte, 0, 20+len(keyID)+len(ad))
	out = append(out, "warden/secretbox/v1\x00"...)
	out = append(out, keyID...)
	out = append(out, 0)
	return append(out, ad...)
}

// Seal encrypts plain under the active key, bound to ad, and returns the
// ciphertext and the key id to store with it.
func (k *Keyring) Seal(plain, ad []byte) ([]byte, string, error) {
	if !k.Available() {
		return nil, "", ErrKeyUnavailable
	}
	nonce := make([]byte, nonceSize)
	if _, err := rand.Read(nonce); err != nil {
		return nil, "", err
	}
	out := make([]byte, 0, 1+nonceSize+len(plain)+16)
	out = append(out, version)
	out = append(out, nonce...)
	out = k.aeads[k.active].Seal(out, nonce, plain, additional(k.active, ad))
	return out, k.active, nil
}

// Open decrypts a ciphertext sealed under key id for ad.
func (k *Keyring) Open(keyID string, ct, ad []byte) ([]byte, error) {
	if !k.Has(keyID) {
		return nil, ErrKeyUnavailable
	}
	if len(ct) < 1+nonceSize+16 || ct[0] != version {
		return nil, ErrOpen
	}
	plain, err := k.aeads[keyID].Open(nil, ct[1:1+nonceSize], ct[1+nonceSize:], additional(keyID, ad))
	if err != nil {
		return nil, ErrOpen
	}
	return plain, nil
}
