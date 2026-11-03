// Package registry is what the API and the worker share about container
// registries (v0.7): the formats of a registry host and of an image reference
// Warden pulls, the outcomes of a pull or credential test, and how a stored
// credential's password is sealed.
//
// Formats are those of the OpenAPI document (RegistryCredential.host,
// PullScanRequest.image_ref). A reference is always pinned by digest, never a
// tag, so what is scanned is exactly what was asked for. Neither format lets a
// user name a scheme, user info, path or query; IP literals are refused for
// credentials, and for pulls unless registry.allow_hosts lists them (a
// development setting). The worker's client checks every address it dials
// anyway: these checks only give a clear error early.
package registry

import (
	"errors"
	"net/netip"
	"regexp"
	"strconv"
	"strings"

	"github.com/google/uuid"

	"github.com/aupv9/warden/backend/internal/secretbox"
)

// MaxPerOrg caps an org's registry credentials.
const MaxPerOrg = 20

// Outcomes of a pull or credential test that failed (registry_credential.last_error).
const (
	// ErrUnauthorized: the registry refused the credentials (401/403).
	ErrUnauthorized = "unauthorized"
	// ErrUnreachable: DNS, connect, TLS, timeout or an unexpected answer.
	ErrUnreachable = "unreachable"
	// ErrBlocked: the host resolved to (or redirected to) an address Warden
	// never connects to.
	ErrBlocked = "blocked"
)

// ValidError reports whether s is one of the outcomes above.
func ValidError(s string) bool {
	return s == ErrUnauthorized || s == ErrUnreachable || s == ErrBlocked
}

// Limits of the formats.
const (
	MaxHost   = 253
	MaxRef    = 512
	MaxTarget = 255
)

var (
	hostFormat = regexp.MustCompile(`^[a-z0-9]([a-z0-9-]{0,61}[a-z0-9])?(\.[a-z0-9]([a-z0-9-]{0,61}[a-z0-9])?)+(:[0-9]{1,5})?$`)
	refFormat  = regexp.MustCompile(`^[a-z0-9]([a-z0-9.-]*[a-z0-9])?(:[0-9]{1,5})?(/[a-z0-9]+(?:(?:[._]|__|-+)[a-z0-9]+)*)+@sha256:[0-9a-f]{64}$`)
	// numeric: a last label that is a number makes the host an IPv4 address
	// to URL parsers and resolvers (1.2.3.4, 10.0.0.010, 0x7f.1 can't match
	// hostFormat but 127.1 can), so such a host is treated as an IP literal.
	numeric = regexp.MustCompile(`^[0-9]+$`)
)

// SplitHost splits "name[:port]". ok is false for a port that is empty, has a
// leading zero or is outside 1-65535.
func SplitHost(host string) (name, port string, ok bool) {
	name, port, hasPort := strings.Cut(host, ":")
	if !hasPort {
		return name, "", true
	}
	n, err := strconv.Atoi(port)
	if err != nil || n < 1 || n > 65535 || port[0] == '0' {
		return name, port, false
	}
	return name, port, true
}

// isIPLiteral: an address, or a name resolvers would read as one.
func isIPLiteral(name string) bool {
	if _, err := netip.ParseAddr(name); err == nil {
		return true
	}
	labels := strings.Split(name, ".")
	return numeric.MatchString(labels[len(labels)-1])
}

// ValidHost reports whether host is a registry host a credential may be stored
// for: a lower-case DNS name with at least two labels and an optional port, no
// IP literal.
func ValidHost(host string) bool {
	if len(host) > MaxHost || !hostFormat.MatchString(host) {
		return false
	}
	name, _, ok := SplitHost(host)
	return ok && !isIPLiteral(name)
}

// Ref is a parsed image reference: Host/Repository@Digest.
type Ref struct {
	// Host is the registry host, with its port if one was given.
	Host string
	// Repository is the path after the host (acme/api).
	Repository string
	// Digest is sha256:<64 hex>.
	Digest string
}

// Name is the repository with its host (ghcr.io/acme/api): a pulled scan's
// target, under which its issues are tracked.
func (r Ref) Name() string { return r.Host + "/" + r.Repository }

func (r Ref) String() string { return r.Name() + "@" + r.Digest }

// Errors of ParseRef.
var (
	ErrRefFormat = errors.New("must be registry-host/repository@sha256:<64 hex digits>, without a tag")
	ErrRefHost   = errors.New("must name a registry host with a domain (ghcr.io, registry.example.com:5000), not an IP address")
)

// ParseRef parses a digest-pinned reference. allowed reports whether a host
// name (without port) is in registry.allow_hosts: only those may be a single
// label (localhost) or an IP literal. The first path component is always the
// host: there is no implicit docker.io.
func ParseRef(s string, allowed func(name string) bool) (Ref, error) {
	if len(s) > MaxRef || !refFormat.MatchString(s) {
		return Ref{}, ErrRefFormat
	}
	at := strings.LastIndexByte(s, '@')
	host, repo, _ := strings.Cut(s[:at], "/")
	ref := Ref{Host: host, Repository: repo, Digest: s[at+1:]}
	name, _, ok := SplitHost(host)
	if !ok || len(ref.Name()) > MaxTarget {
		return Ref{}, ErrRefFormat
	}
	if allowed != nil && allowed(name) {
		return ref, nil
	}
	if !ValidHost(host) {
		return Ref{}, ErrRefHost
	}
	return ref, nil
}

// passwordColumn is part of the additional data, so a ciphertext can't be
// moved to another column.
const passwordColumn = "password_enc"

// additional binds a password ciphertext to its org, credential row and
// column; uuids have a fixed length, so the encoding is unambiguous.
func additional(org, id uuid.UUID) []byte {
	return []byte("registry_credential\x00" + org.String() + "\x00" + id.String() + "\x00" + passwordColumn)
}

// SealPassword encrypts a credential's password under the active key and
// returns the ciphertext and the key id to store beside it.
func SealPassword(keys *secretbox.Keyring, org, id uuid.UUID, password string) ([]byte, string, error) {
	return keys.Seal([]byte(password), additional(org, id))
}

// OpenPassword decrypts a credential's password (secretbox.ErrKeyUnavailable
// or ErrOpen when it can't).
func OpenPassword(keys *secretbox.Keyring, org, id uuid.UUID, keyID string, enc []byte) (string, error) {
	b, err := keys.Open(keyID, enc, additional(org, id))
	if err != nil {
		return "", err
	}
	return string(b), nil
}
