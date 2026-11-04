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
	"strings"

	dregistry "github.com/aupv9/warden/backend/internal/domain/registry"
)

// Ref is an image reference pinned by digest, as domain/registry.ParseRef
// reads it (the API and the worker both apply it, with registry.allow_hosts).
type Ref = dregistry.Ref

// checkHost validates host[:port] (a credential's, for Check).
func checkHost(h string) error {
	name, _, ok := dregistry.SplitHost(h)
	if name == "" || !ok || len(h) > dregistry.MaxHost+6 {
		return errors.New("bad registry host")
	}
	return nil
}

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
func apiRepository(r Ref) string {
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
