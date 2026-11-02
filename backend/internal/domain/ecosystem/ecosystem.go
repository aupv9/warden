// Package ecosystem names a package's ecosystem the way OSV does and
// normalizes package names and versions so that the component inventory, its
// search and OSV malicious-package advisories compare like with like.
//
// Inputs come from Trivy's report of the scanned code and from OSV feeds, both
// untrusted; callers cap them first (scan/trivyjson, internal/intel). The
// functions here are pure and never fail: an input they don't recognise maps to
// a conservative value (Unknown, or the name lower-cased).
package ecosystem

import (
	"regexp"
	"strings"
)

// OSV ecosystem names Warden matches malicious-package advisories for.
const (
	Npm       = "npm"
	PyPI      = "PyPI"
	Go        = "Go"
	Maven     = "Maven"
	CratesIO  = "crates.io"
	RubyGems  = "RubyGems"
	NuGet     = "NuGet"
	Packagist = "Packagist"
	// Unknown is a package whose type Trivy didn't give or Warden can't name.
	Unknown = "unknown"
)

// OSV is the ecosystems with OSV malicious-package feeds, in mirror order.
var OSV = []string{Npm, PyPI, Go, Maven, CratesIO, RubyGems, NuGet, Packagist}

// Valid is the shape of a stored ecosystem (the component and
// malicious_package CHECK constraints).
var Valid = regexp.MustCompile(`^[A-Za-z0-9.+_-]{1,32}$`)

// byTrivyType maps Trivy's result Type (the analyzer: "npm", "gomod",
// "poetry"...) to an OSV ecosystem.
var byTrivyType = map[string]string{
	"npm": Npm, "yarn": Npm, "pnpm": Npm, "bun": Npm, "node-pkg": Npm,
	"pip": PyPI, "pipenv": PyPI, "poetry": PyPI, "uv": PyPI, "python-pkg": PyPI,
	"gomod": Go, "gobinary": Go,
	"jar": Maven, "pom": Maven, "gradle": Maven, "sbt": Maven,
	"cargo": CratesIO, "rustbinary": CratesIO, "rust-binary": CratesIO,
	"bundler": RubyGems, "gemspec": RubyGems,
	"nuget": NuGet, "dotnet-core": NuGet, "packages-props": NuGet,
	"composer": Packagist, "composer-vendor": Packagist,
}

// byPURLType maps a package URL type to an OSV ecosystem.
var byPURLType = map[string]string{
	"npm": Npm, "pypi": PyPI, "golang": Go, "maven": Maven, "cargo": CratesIO,
	"gem": RubyGems, "nuget": NuGet, "composer": Packagist,
}

var purlType = regexp.MustCompile(`^pkg:([a-z0-9.+-]{1,32})/`)

// FromTrivy names the ecosystem of a package Trivy reported in a result of
// type trivyType, with purl as a fallback. Language packages get their OSV
// name; others (OS packages: "alpine", "debian"...) keep Trivy's type, or the
// purl type; Unknown when neither is usable.
func FromTrivy(trivyType, purl string) string {
	t := strings.ToLower(strings.TrimSpace(trivyType))
	if e, ok := byTrivyType[t]; ok {
		return e
	}
	var pt string
	if m := purlType.FindStringSubmatch(purl); m != nil {
		pt = m[1]
		if e, ok := byPURLType[pt]; ok {
			return e
		}
	}
	for _, c := range []string{t, pt} {
		if c != "" && Valid.MatchString(c) {
			return c
		}
	}
	return Unknown
}

// IsOSV reports whether eco has an OSV malicious-package feed.
func IsOSV(eco string) bool {
	for _, e := range OSV {
		if e == eco {
			return true
		}
	}
	return false
}

var (
	pypiSeparators = regexp.MustCompile(`[-_.]+`)
)

// MatchName is name normalized for matching and search: lower-cased (registries
// refuse names differing only in case, and a broader match is the safe side
// for malicious packages), PyPI per PEP 503 (runs of -_. become -), crates.io
// with _ as - (crates.io treats them as the same name).
func MatchName(eco, name string) string {
	n := strings.ToLower(strings.TrimSpace(name))
	switch eco {
	case PyPI:
		n = pypiSeparators.ReplaceAllString(n, "-")
	case CratesIO:
		n = strings.ReplaceAll(n, "_", "-")
	}
	return n
}

// MatchVersion is version normalized for comparing a scanned package with an
// advisory's version list: Go module versions lose the leading v (Trivy
// reports v1.2.3, OSV lists 1.2.3), PyPI versions are lower-cased (PEP 440 is
// case-insensitive). Other versions compare exactly.
func MatchVersion(eco, version string) string {
	v := strings.TrimSpace(version)
	switch eco {
	case Go:
		v = strings.TrimPrefix(v, "v")
	case PyPI:
		v = strings.ToLower(v)
	}
	return v
}
