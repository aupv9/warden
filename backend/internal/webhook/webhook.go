// Package webhook sends outbox events to an org's webhooks and Slack channels.
//
// The flow (see 00012_webhooks.sql for the tables):
//
//   - Queue.Enqueue runs inside the notification dispatcher's transaction and
//     writes one webhook_delivery per matching enabled webhook, with the exact
//     body to send. The body is built from notify.Facts, the same allow-list of
//     columns emails use: never snippets, descriptions, file contents, comment
//     bodies, email addresses or secrets.
//   - Sender (the worker's send_webhooks job) claims due deliveries with
//     next_at as a lease, decrypts the URL and secret (secretbox), and POSTs.
//   - Client is the only HTTP client that talks to webhook URLs. URLs are chosen
//     by org admins, so it is built against SSRF: https only, no proxy, no
//     redirects, and every address it connects to is checked when it dials
//     (Blocked), so neither DNS rebinding nor a redirect can reach an internal
//     service. Responses are read up to a cap and discarded, never stored.
package webhook

import (
	"crypto/hmac"
	"crypto/rand"
	"crypto/sha256"
	"encoding/base64"
	"errors"
	"strconv"
	"strings"

	"github.com/google/uuid"

	"github.com/aupv9/warden/backend/internal/secretbox"
)

// Kinds.
const (
	KindGeneric = "generic"
	KindSlack   = "slack"
)

// MaxPerOrg caps an org's webhooks.
const MaxPerOrg = 20

// Delivery errors (webhook_delivery.error).
const (
	ErrTimeout        = "timeout"
	ErrDNS            = "dns"
	ErrConnect        = "connect"
	ErrTLS            = "tls"
	ErrBlockedAddress = "blocked_address"
	ErrRedirect       = "redirect"
	ErrHTTPStatus     = "http_status"
	ErrDisabled       = "disabled"
	ErrKeyUnavailable = "key_unavailable"
)

// SecretPrefix starts every signing secret (Standard Webhooks).
const SecretPrefix = "whsec_"

const secretBytes = 32

// NewSecret returns a fresh signing secret: the raw bytes to store (encrypted)
// and the whsec_ form shown to the user once.
func NewSecret() ([]byte, string, error) {
	raw := make([]byte, secretBytes)
	if _, err := rand.Read(raw); err != nil {
		return nil, "", err
	}
	return raw, FormatSecret(raw), nil
}

// FormatSecret is the whsec_ form of a raw secret.
func FormatSecret(raw []byte) string { return SecretPrefix + base64.StdEncoding.EncodeToString(raw) }

// Sign returns the Standard Webhooks signature header value: "v1," and the
// base64 HMAC-SHA256 of "<id>.<timestamp>.<body>" under the raw secret.
func Sign(secret []byte, id string, timestamp int64, body []byte) string {
	m := hmac.New(sha256.New, secret)
	m.Write([]byte(id + "." + strconv.FormatInt(timestamp, 10) + "."))
	m.Write(body)
	return "v1," + base64.StdEncoding.EncodeToString(m.Sum(nil))
}

// Encrypted columns. The column name is part of the additional data, so a URL
// ciphertext can't be read back as a secret or the other way round.
const (
	colURL    = "url_enc"
	colSecret = "secret_enc"
)

// additional binds a ciphertext to its org, webhook and column; uuids have a
// fixed length, so the encoding is unambiguous.
func additional(org, id uuid.UUID, column string) []byte {
	return []byte("webhook\x00" + org.String() + "\x00" + id.String() + "\x00" + column)
}

// Sealed is a webhook's encrypted URL and secret under one key.
type Sealed struct {
	URL    []byte
	Secret []byte // nil for Slack
	KeyID  string
}

// Seal encrypts a webhook's URL and secret (nil for Slack) under the active key.
func Seal(keys *secretbox.Keyring, org, id uuid.UUID, url string, secret []byte) (Sealed, error) {
	u, keyID, err := keys.Seal([]byte(url), additional(org, id, colURL))
	if err != nil {
		return Sealed{}, err
	}
	out := Sealed{URL: u, KeyID: keyID}
	if secret != nil {
		if out.Secret, _, err = keys.Seal(secret, additional(org, id, colSecret)); err != nil {
			return Sealed{}, err
		}
	}
	return out, nil
}

// Open decrypts a webhook's URL and secret (nil when it has none).
func Open(keys *secretbox.Keyring, org, id uuid.UUID, s Sealed) (string, []byte, error) {
	u, err := keys.Open(s.KeyID, s.URL, additional(org, id, colURL))
	if err != nil {
		return "", nil, err
	}
	var secret []byte
	if s.Secret != nil {
		if secret, err = keys.Open(s.KeyID, s.Secret, additional(org, id, colSecret)); err != nil {
			return "", nil, err
		}
		if len(secret) != secretBytes {
			return "", nil, errors.New("webhook: stored secret has the wrong length")
		}
	}
	return string(u), secret, nil
}

// Reseal re-encrypts a webhook's columns under the active key (key rotation).
// It is a no-op when they already are.
func Reseal(keys *secretbox.Keyring, org, id uuid.UUID, s Sealed) (Sealed, bool, error) {
	if s.KeyID == keys.ActiveID() {
		return s, false, nil
	}
	url, secret, err := Open(keys, org, id, s)
	if err != nil {
		return Sealed{}, false, err
	}
	out, err := Seal(keys, org, id, url, secret)
	return out, err == nil, err
}

// cleanLine makes a value safe for one line of text: control characters
// (newlines included) become spaces.
func cleanLine(s string) string {
	return strings.Map(func(r rune) rune {
		if r < 0x20 || r == 0x7f || (r >= 0x80 && r < 0xa0) || r == ' ' || r == ' ' {
			return ' '
		}
		return r
	}, s)
}
