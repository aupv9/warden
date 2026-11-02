// Package trivyjson reads packages and their licenses out of Trivy's JSON report. The
// report is derived from the scanned (attacker-controlled) code, so it is
// hostile input: the file size, the package and license counts and every
// string are capped, a document of the wrong shape is rejected as a whole, and
// license names reach the policy only as validated SPDX ids.
//
// License names are SPDX expressions in the best case ("MIT", "(MIT OR
// Apache-2.0)"), but lockfiles carry anything ("SEE LICENSE IN LICENSE.txt").
// Expressions are parsed into alternatives (OR: the user may pick any) of ids
// that all apply (AND). "X WITH exception" counts as X: an exception only
// relaxes a license, so deny/allow rules written for X still hold. Anything
// that doesn't parse within the caps becomes LicenseRef-unknown, keeping
// Trivy's category for it.
package trivyjson

import (
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"os"
	"regexp"
	"slices"
	"strings"
	"unicode"

	"github.com/aupv9/warden/backend/internal/domain/ecosystem"
	"github.com/aupv9/warden/backend/internal/domain/licensepolicy"
)

const (
	MaxFileBytes          = 256 << 20
	MaxPackages           = 200_000
	MaxLicensesPerPackage = 50
	MaxResults            = 100_000
	MaxTarget             = 2048
	MaxPkgName            = 256
	MaxPkgVersion         = 128
	MaxLicenseName        = 256
	MaxPURL               = 512
	// Expression caps: tokens, parenthesis depth, alternatives, ids per alternative.
	maxTokens       = 64
	maxDepth        = 8
	maxAlternatives = 16
	maxTerms        = 16
	maxExpression   = 255
)

// UnknownID stands for a license name that isn't an SPDX id or expression.
const UnknownID = "LicenseRef-unknown"

// Classes of Trivy results that list packages.
const (
	ClassOSPackages   = "os-pkgs"
	ClassLangPackages = "lang-pkgs"
)

var (
	ErrReport = errors.New("trivy JSON")
	osFamily  = regexp.MustCompile(`^[a-z][a-z0-9.-]{0,31}$`)
	// purl is the start of a package URL; the rest is percent-encoded text
	// that is only stored and shown, never parsed.
	purl = regexp.MustCompile(`^pkg:[a-z0-9.+-]{1,32}/[\x21-\x7e]+$`)
)

func reportErr(format string, args ...any) error {
	return fmt.Errorf("%w: %s", ErrReport, fmt.Sprintf(format, args...))
}

// License is one license declared by one package.
type License struct {
	// Target is Trivy's result target: a lockfile path (relative to the scan
	// root), or for OS packages the image and its OS ("/src/image.tar (alpine 3.18.0)").
	Target     string
	Class      string
	PkgName    string
	PkgVersion string
	// License is an SPDX id, a normalized SPDX expression ("MIT OR Apache-2.0")
	// or UnknownID.
	License string
	// Terms is License as alternatives of ids that all apply; never empty.
	Terms [][]string
	// Category is Trivy's classification of the declared name.
	Category licensepolicy.Category
	// Declared is the name as the package declared it, sanitized and capped
	// (shown in the issue when it isn't a valid expression).
	Declared string
	// FilePath is Target as an issue file path; Parse leaves it empty for the
	// caller, which knows how the scan's paths are normalized.
	FilePath string
}

// Package is one package Trivy found, for the component inventory and the
// malicious-package match. Trivy's root and workspace packages (the scanned
// project itself) are left out.
type Package struct {
	// Target and Class are as in License.
	Target string
	Class  string
	// Ecosystem is ecosystem.FromTrivy of the result type and PURL;
	// MatchName and MatchVersion are Name and Version normalized for it.
	Ecosystem    string
	Name         string
	MatchName    string
	Version      string
	MatchVersion string
	// PURL is Trivy's package URL, "" when missing or not shaped like one.
	PURL string
	// Licenses are the License values of the package's licenses, deduplicated.
	Licenses []string
	// FilePath is as in License: set by the caller.
	FilePath string
}

// Report is what Warden uses from Trivy's JSON.
type Report struct {
	// OSFamily is the scanned image's OS ("alpine"), "" for none or unrecognized.
	OSFamily string
	Licenses []License
	// Packages has one entry per (target, ecosystem, name, version).
	Packages []Package
}

// The subset of Trivy's schema that is read. A field of the wrong type fails
// the whole decode; unknown fields (vulnerabilities, layers...) are skipped.
type document struct {
	Metadata struct {
		OS *struct {
			Family string `json:"Family"`
		} `json:"OS"`
	} `json:"Metadata"`
	Results []struct {
		Target   string `json:"Target"`
		Class    string `json:"Class"`
		Type     string `json:"Type"`
		Packages []struct {
			Name       string `json:"Name"`
			Version    string `json:"Version"`
			Identifier struct {
				PURL string `json:"PURL"`
			} `json:"Identifier"`
			Relationship string   `json:"Relationship"`
			Licenses     []string `json:"Licenses"`
		} `json:"Packages"`
		Licenses []struct {
			Category string `json:"Category"`
			Name     string `json:"Name"`
		} `json:"Licenses"`
	} `json:"Results"`
}

// Load reads a report of at most MaxFileBytes.
func Load(path string) (*Report, error) {
	st, err := os.Stat(path)
	if err != nil {
		return nil, err
	}
	if st.Size() > MaxFileBytes {
		return nil, reportErr("report larger than %d bytes", MaxFileBytes)
	}
	f, err := os.Open(path)
	if err != nil {
		return nil, err
	}
	defer f.Close()
	return Parse(f)
}

// Parse decodes a report from r (read up to MaxFileBytes).
func Parse(r io.Reader) (*Report, error) {
	dec := json.NewDecoder(io.LimitReader(r, MaxFileBytes+1))
	var doc document
	// encoding/json bounds nesting depth itself, so a deeply nested document
	// is an error, not a stack overflow.
	if err := dec.Decode(&doc); err != nil {
		return nil, reportErr("invalid JSON: %v", err)
	}
	if _, err := dec.Token(); err != io.EOF {
		return nil, reportErr("trailing data after the JSON document")
	}
	if len(doc.Results) > MaxResults {
		return nil, reportErr("more than %d results", MaxResults)
	}

	// Trivy classifies each license name once; the packages refer to names.
	categories := map[string]licensepolicy.Category{}
	packages := 0
	for _, res := range doc.Results {
		packages += len(res.Packages)
		for _, l := range res.Licenses {
			if _, ok := categories[l.Name]; !ok && len(l.Name) <= MaxLicenseName {
				categories[l.Name] = licensepolicy.ParseCategory(l.Category)
			}
		}
	}
	if packages > MaxPackages {
		return nil, reportErr("more than %d packages", MaxPackages)
	}

	out := &Report{}
	if m := doc.Metadata.OS; m != nil && osFamily.MatchString(m.Family) {
		out.OSFamily = m.Family
	}
	type key struct{ target, pkg, version, license string }
	type pkgKey struct{ target, eco, name, version string }
	seen := map[key]bool{}
	pkgIndex := map[pkgKey]int{}
	for _, res := range doc.Results {
		if res.Class != ClassOSPackages && res.Class != ClassLangPackages {
			continue
		}
		target := clean(res.Target, MaxTarget)
		for _, p := range res.Packages {
			if len(p.Licenses) > MaxLicensesPerPackage {
				return nil, reportErr("a package declares more than %d licenses", MaxLicensesPerPackage)
			}
			name := clean(p.Name, MaxPkgName)
			if name == "" {
				continue
			}
			version := clean(p.Version, MaxPkgVersion)
			pi := -1
			if p.Relationship != "root" && p.Relationship != "workspace" {
				pu := ""
				if len(p.Identifier.PURL) <= MaxPURL && purl.MatchString(p.Identifier.PURL) {
					pu = p.Identifier.PURL
				}
				eco := ecosystem.FromTrivy(res.Type, pu)
				pk := pkgKey{target, eco, ecosystem.MatchName(eco, name), version}
				var ok bool
				if pi, ok = pkgIndex[pk]; !ok {
					pi = len(out.Packages)
					pkgIndex[pk] = pi
					out.Packages = append(out.Packages, Package{Target: target, Class: res.Class, Ecosystem: eco,
						Name: name, MatchName: pk.name, Version: version, MatchVersion: ecosystem.MatchVersion(eco, version), PURL: pu})
				}
			}
			for _, declared := range p.Licenses {
				l := License{Target: target, Class: res.Class, PkgName: name, PkgVersion: version,
					Category: licensepolicy.Unknown, Declared: clean(declared, MaxLicenseName)}
				if c, ok := categories[declared]; ok {
					l.Category = c
				}
				l.License, l.Terms = UnknownID, [][]string{{UnknownID}}
				if expr, terms, ok := ParseExpression(declared); ok {
					l.License, l.Terms = expr, terms
				}
				if pi >= 0 && !slices.Contains(out.Packages[pi].Licenses, l.License) {
					out.Packages[pi].Licenses = append(out.Packages[pi].Licenses, l.License)
				}
				k := key{target, name, version, l.License}
				if seen[k] {
					continue
				}
				seen[k] = true
				out.Licenses = append(out.Licenses, l)
			}
		}
	}
	return out, nil
}

// clean caps s at limit runes and replaces invalid UTF-8 and control
// characters (NUL can't be stored in Postgres text; escapes have no business
// in a package name) with U+FFFD.
func clean(s string, limit int) string {
	s = strings.ToValidUTF8(s, "\uFFFD")
	s = strings.Map(func(r rune) rune {
		if unicode.IsControl(r) || unicode.Is(unicode.Bidi_Control, r) {
			return '\uFFFD'
		}
		return r
	}, s)
	if r := []rune(s); len(r) > limit {
		s = string(r[:limit])
	}
	return strings.TrimSpace(s)
}

// ParseExpression parses an SPDX license expression. It returns the
// expression normalized (single spaces, upper-case operators, no outer
// parentheses) and as alternatives of ids, or ok=false when s isn't one
// within the caps.
func ParseExpression(s string) (expr string, terms [][]string, ok bool) {
	if len(s) > MaxLicenseName {
		return "", nil, false
	}
	toks := tokenize(s)
	if len(toks) == 0 || len(toks) > maxTokens {
		return "", nil, false
	}
	p := &parser{toks: toks}
	terms, ok = p.or(0)
	if !ok || p.pos != len(toks) {
		return "", nil, false
	}
	expr = strings.Join(trimOuter(toks), " ")
	expr = strings.ReplaceAll(strings.ReplaceAll(expr, "( ", "("), " )", ")")
	if len(expr) > maxExpression {
		return "", nil, false
	}
	return expr, terms, true
}

// tokenize splits on spaces and parentheses; operators are upper-cased.
func tokenize(s string) []string {
	var toks []string
	for _, f := range strings.Fields(strings.NewReplacer("(", " ( ", ")", " ) ").Replace(s)) {
		switch u := strings.ToUpper(f); u {
		case "OR", "AND", "WITH":
			f = u
		}
		toks = append(toks, f)
	}
	return toks
}

// trimOuter drops parentheses that enclose the whole expression.
func trimOuter(toks []string) []string {
	for len(toks) >= 2 && toks[0] == "(" && toks[len(toks)-1] == ")" {
		depth := 0
		for i, t := range toks {
			switch t {
			case "(":
				depth++
			case ")":
				depth--
			}
			if depth == 0 && i < len(toks)-1 {
				return toks // the first "(" closes before the end: "(A) OR (B)"
			}
		}
		toks = toks[1 : len(toks)-1]
	}
	return toks
}

type parser struct {
	toks []string
	pos  int
}

func (p *parser) peek() string {
	if p.pos < len(p.toks) {
		return p.toks[p.pos]
	}
	return ""
}

// or := and ("OR" and)*
func (p *parser) or(depth int) ([][]string, bool) {
	terms, ok := p.and(depth)
	for ok && p.peek() == "OR" {
		p.pos++
		var more [][]string
		if more, ok = p.and(depth); ok {
			terms = append(terms, more...)
			ok = len(terms) <= maxAlternatives
		}
	}
	return terms, ok
}

// and := with ("AND" with)*; the result is the cross product of alternatives.
func (p *parser) and(depth int) ([][]string, bool) {
	terms, ok := p.with(depth)
	for ok && p.peek() == "AND" {
		p.pos++
		var right [][]string
		if right, ok = p.with(depth); !ok {
			break
		}
		if len(terms)*len(right) > maxAlternatives {
			return nil, false
		}
		var product [][]string
		for _, a := range terms {
			for _, b := range right {
				ids := slices.Clone(a)
				for _, id := range b {
					if !slices.Contains(ids, id) {
						ids = append(ids, id)
					}
				}
				if len(ids) > maxTerms {
					return nil, false
				}
				product = append(product, ids)
			}
		}
		terms = product
	}
	return terms, ok
}

// with := atom ["WITH" id]; the exception is checked and dropped.
func (p *parser) with(depth int) ([][]string, bool) {
	terms, ok := p.atom(depth)
	if ok && p.peek() == "WITH" {
		p.pos++
		if !licensepolicy.ID.MatchString(p.peek()) || len(terms) != 1 || len(terms[0]) != 1 {
			return nil, false // an exception applies to one license id
		}
		p.pos++
	}
	return terms, ok
}

// atom := id | "(" or ")"
func (p *parser) atom(depth int) ([][]string, bool) {
	t := p.peek()
	switch {
	case t == "(":
		if depth >= maxDepth {
			return nil, false
		}
		p.pos++
		terms, ok := p.or(depth + 1)
		if !ok || p.peek() != ")" {
			return nil, false
		}
		p.pos++
		return terms, true
	case t == "OR" || t == "AND" || t == "WITH":
		return nil, false
	case licensepolicy.ID.MatchString(t):
		p.pos++
		return [][]string{{t}}, true
	}
	return nil, false
}
