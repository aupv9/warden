package registry

import (
	"log/slog"

	dregistry "github.com/aupv9/warden/backend/internal/domain/registry"
)

// Pull failures (scan.error_code).
const (
	// CodeUnauthorized: the registry refused the org's credentials, or wants
	// some and the org has none for the host.
	CodeUnauthorized = "PULL_UNAUTHORIZED"
	// CodeNotFound: the registry has no manifest with that digest.
	CodeNotFound = "PULL_NOT_FOUND"
	// CodeTooLarge: over scan.pull_max_mb, a manifest over MaxManifestBytes,
	// or more than MaxLayers layers.
	CodeTooLarge = "PULL_TOO_LARGE"
	// CodeBlocked: an internal or reserved address, plain http, a redirect
	// Warden won't follow, or a token realm on another site while the org has
	// credentials for the host.
	CodeBlocked = "PULL_BLOCKED"
	// CodePlatform: a multi-platform index without scan.pull_platform.
	CodePlatform = "PULL_PLATFORM"
	// CodeFailed: anything else (unreachable, timeouts, digest mismatches,
	// malformed or unsupported manifests, 5xx).
	CodeFailed = "PULL_FAILED"
)

// Reasons are registry_credential.last_error and the test endpoint's error.
const (
	ReasonUnauthorized = dregistry.ErrUnauthorized
	ReasonUnreachable  = dregistry.ErrUnreachable
	ReasonBlocked      = dregistry.ErrBlocked
)

// Error is a pull or check failure. Detail is for logs: it never holds a
// credential, a token or a URL's query (CDN redirects sign theirs).
type Error struct {
	Code   string
	Detail string
	// Unreachable: no answer (DNS, connect, TLS, timeout before headers).
	Unreachable bool
}

func (e *Error) Error() string { return "registry: " + e.Code + ": " + e.Detail }

// Reason maps the failure onto registry_credential.last_error: "" when it
// says nothing about the credentials or the registry's reachability.
func (e *Error) Reason() string {
	switch {
	case e.Code == CodeUnauthorized:
		return ReasonUnauthorized
	case e.Code == CodeBlocked:
		return ReasonBlocked
	case e.Unreachable:
		return ReasonUnreachable
	}
	return ""
}

func fail(code, detail string) *Error { return &Error{Code: code, Detail: detail} }

// Credentials are an org's for one registry host. They format without the
// password, so one that ends up in a log line or a %v can't leak it.
type Credentials struct {
	Username string
	Password string
}

func (c Credentials) String() string       { return "credentials(" + c.Username + ", password redacted)" }
func (c Credentials) GoString() string     { return c.String() }
func (c Credentials) LogValue() slog.Value { return slog.StringValue(c.String()) }
