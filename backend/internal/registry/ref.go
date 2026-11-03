// Package registry pulls one image, pinned by digest, from an OCI
// distribution registry and writes it as a `docker save` tarball, so a pulled
// image is checked (imagecheck) and scanned exactly like an uploaded one. It
// also checks a registry credential (GET /v2/) for the API's test endpoint.
//
// The registry, every host it redirects to and its token realm are hostile:
//   - Every connection goes through the webhook address guard
//     (webhook.Dialer): no loopback, private, link-local (cloud metadata),
//     CGNAT, ULA or NAT64/6to4-embedded private address, checked at dial time
//     (DNS rebinding), unless the host is in registry.allow_hosts. No proxy.
//   - https only; http only to registry.allow_hosts (tried after https fails
//     with a non-TLS answer, like Docker's insecure registries).
//   - Redirects are followed by hand, at most maxRedirects, each hop re-checked
//     (https, guard); blobs are commonly served from a CDN on another host.
//     Authorization goes only to the registry's own origin, never to a hop.
//   - Credentials: Basic only to the registry's origin; to a Bearer token realm
//     only when the realm is on the registry host's site (see sameSite).
//   - Every manifest and blob is verified against its digest, sizes are
//     checked against descriptors, and the whole pull is capped (Limits).
//
// Why not go-containerregistry: its bearer transport sends the Basic
// credentials to whatever realm the registry names, it follows redirects
// through net/http's policy, and pkg/authn brings docker/cli into the module
// graph. The pull path Warden needs (two manifests, blobs, the token flow) is
// small enough to own, so every request it makes is visible here.
package registry

import (
	"errors"
	"fmt"
	"regexp"
	"strconv"
	"strings"
)

// Ref is an image reference pinned by digest: host[:port]/repository@sha256:….
type Ref struct {
	// Host is the registry as written (lower case, with port): the org's
	// credentials are looked up by it.
	Host       string
	Repository string
	Digest     string
}

// MaxRefLen is scan.image_ref's limit.
const MaxRefLen = 512

// refPattern is the API's PullScanRequest.image_ref pattern, with groups.
var refPattern = regexp.MustCompile(`^([a-z0-9](?:[a-z0-9.-]*[a-z0-9])?(?::[0-9]{1,5})?)/` +
	`([a-z0-9]+(?:(?:[._]|__|-+)[a-z0-9]+)*(?:/[a-z0-9]+(?:(?:[._]|__|-+)[a-z0-9]+)*)*)` +
	`@(sha256:[0-9a-f]{64})$`)

// ParseRef parses a digest-pinned reference. Tags are refused: Warden never
// pulls by tag.
func ParseRef(s string) (Ref, error) {
	if len(s) > MaxRefLen {
		return Ref{}, errors.New("image reference too long")
	}
	m := refPattern.FindStringSubmatch(s)
	if m == nil {
		return Ref{}, errors.New("image reference must be host/repository@sha256:<digest>")
	}
	if err := checkHost(m[1]); err != nil {
		return Ref{}, err
	}
	return Ref{Host: m[1], Repository: m[2], Digest: m[3]}, nil
}

// checkHost validates host[:port] (the reference's registry, or a credential's).
func checkHost(h string) error {
	name, port, hasPort := strings.Cut(h, ":")
	if name == "" || len(h) > 253+6 {
		return errors.New("bad registry host")
	}
	if hasPort {
		n, err := strconv.Atoi(port)
		if err != nil || n < 1 || n > 65535 || port[0] == '0' {
			return errors.New("bad registry port")
		}
	}
	return nil
}

func (r Ref) String() string { return r.Host + "/" + r.Repository + "@" + r.Digest }

// Docker Hub is named docker.io in references; its API lives elsewhere.
const dockerHubAPI = "registry-1.docker.io"

func isDockerHub(host string) bool { return host == "docker.io" || host == "index.docker.io" }

// apiHost is the host[:port] the distribution API is reached at.
func apiHost(host string) string {
	if isDockerHub(host) {
		return dockerHubAPI
	}
	return host
}

// apiRepository is the repository as the API names it (Docker Hub's official
// images live under library/).
func (r Ref) apiRepository() string {
	if isDockerHub(r.Host) && !strings.Contains(r.Repository, "/") {
		return "library/" + r.Repository
	}
	return r.Repository
}

// Platform selects an image from a multi-platform index (scan.pull_platform).
type Platform struct {
	OS, Arch, Variant string
}

var platformPart = regexp.MustCompile(`^[a-z0-9][a-z0-9._-]{0,31}$`)

// ParsePlatform reads "os/arch[/variant]" (linux/amd64, linux/arm64/v8).
func ParsePlatform(s string) (Platform, error) {
	parts := strings.Split(s, "/")
	if len(parts) < 2 || len(parts) > 3 {
		return Platform{}, fmt.Errorf("platform %q must be os/arch[/variant]", s)
	}
	for _, p := range parts {
		if !platformPart.MatchString(p) {
			return Platform{}, fmt.Errorf("platform %q must be os/arch[/variant] in lower case", s)
		}
	}
	p := Platform{OS: parts[0], Arch: parts[1]}
	if len(parts) == 3 {
		p.Variant = parts[2]
	}
	return p, nil
}

func (p Platform) String() string {
	s := p.OS + "/" + p.Arch
	if p.Variant != "" {
		s += "/" + p.Variant
	}
	return s
}
