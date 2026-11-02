package trivyjson

import (
	"bytes"
	"errors"
	"reflect"
	"slices"
	"strings"
	"testing"
	"unicode"
	"unicode/utf8"

	"github.com/aupv9/warden/backend/internal/domain/ecosystem"
	"github.com/aupv9/warden/backend/internal/domain/licensepolicy"
)

// checkTerms: alternatives of valid SPDX ids, within the caps, never empty.
func checkTerms(t *testing.T, terms [][]string) {
	t.Helper()
	if len(terms) == 0 || len(terms) > maxAlternatives {
		t.Fatalf("%d alternatives", len(terms))
	}
	for _, alt := range terms {
		if len(alt) == 0 || len(alt) > maxTerms {
			t.Fatalf("alternative of %d ids", len(alt))
		}
		for _, id := range alt {
			if !licensepolicy.ID.MatchString(id) {
				t.Fatalf("id %q", id)
			}
		}
	}
}

// checkClean: valid UTF-8, no control or bidi characters, no outer space, capped.
func checkClean(t *testing.T, what, s string, limit int) {
	t.Helper()
	if !utf8.ValidString(s) || utf8.RuneCountInString(s) > limit || strings.TrimSpace(s) != s ||
		strings.ContainsFunc(s, func(r rune) bool { return unicode.IsControl(r) || unicode.Is(unicode.Bidi_Control, r) }) {
		t.Fatalf("%s %q", what, s)
	}
}

// FuzzParseExpression: an accepted expression is normalized (parsing it
// again gives the same expression and terms) and within the caps.
func FuzzParseExpression(f *testing.F) {
	for _, s := range []string{"MIT", "  GPL-2.0+ ", "((MIT or Apache-2.0))", "(MIT) OR (Apache-2.0)", "MIT AND (Apache-2.0 OR BSD-3-Clause)",
		"MIT OR Apache-2.0 AND BSD-3-Clause", "GPL-2.0-only WITH Classpath-exception-2.0", "(A OR B OR C OR D OR E) AND (F OR G OR H OR I)",
		"SEE LICENSE IN LICENSE.txt", "MIT\u202eTIM", "((((((((MIT))))))))", "(MIT)AND(BSD)with X"} {
		f.Add(s)
	}
	f.Fuzz(func(t *testing.T, s string) {
		expr, terms, ok := ParseExpression(s)
		if !ok {
			return
		}
		checkTerms(t, terms)
		if len(expr) > maxExpression || expr == "" || strings.TrimSpace(expr) != expr || strings.Contains(expr, "  ") {
			t.Fatalf("%q -> expr %q", s, expr)
		}
		expr2, terms2, ok := ParseExpression(expr)
		if !ok || expr2 != expr || !reflect.DeepEqual(terms2, terms) {
			t.Fatalf("%q -> %q %v, which parses as %q %v %v", s, expr, terms, expr2, terms2, ok)
		}
	})
}

// FuzzParse: every string kept is clean and capped, licenses are valid
// expressions or UnknownID, and packages are unique and normalized as
// ecosystem says.
func FuzzParse(f *testing.F) {
	f.Add(report(
		M{"Target": "app/go.mod", "Class": "lang-pkgs", "Type": "gomod", "Packages": []any{
			M{"Name": "github.com/a/b", "Version": "v1.2.3", "Identifier": M{"PURL": "pkg:golang/github.com/a/b@v1.2.3"}, "Licenses": []string{"MIT"}},
			M{"Name": "root", "Relationship": "root", "Licenses": []string{"(MIT OR Apache-2.0)"}},
		}},
		M{"Target": "requirements.txt", "Class": "lang-pkgs", "Type": "pip", "Packages": []any{pkg("Foo_Bar", "1.0RC1", "GPL-2.0-only WITH Classpath-exception-2.0"), pkg("foo.bar", "1.0rc1")}},
		M{"Class": "license", "Licenses": []any{M{"Category": "restricted", "Name": "GPL-2.0-only WITH Classpath-exception-2.0"}}},
	))
	f.Add(report(M{"Target": "/src/image.tar (alpine 3.18.0)", "Class": "os-pkgs", "Type": "alpine", "Packages": []any{pkg("musl", "1.2.4-r1", "MIT", "SEE LICENSE IN x")}}))
	f.Add([]byte(`{"Metadata":{"OS":{"Family":"alpine"}},"Results":[{"Class":"lang-pkgs","Packages":[{"Name":"evil\u0000\u001b[31m\u202e","Licenses":["MIT"]}]}]}`))
	f.Add([]byte(`{"Results":[{"Class":"lang-pkgs","Packages":"lodash"}]}`))
	f.Fuzz(func(t *testing.T, data []byte) {
		if len(data) > 64<<10 {
			return
		}
		r, err := Parse(bytes.NewReader(data))
		if err != nil {
			if !errors.Is(err, ErrReport) {
				t.Fatalf("error that isn't ErrReport: %v", err)
			}
			return
		}
		if r.OSFamily != "" && !osFamily.MatchString(r.OSFamily) {
			t.Fatalf("OS family %q", r.OSFamily)
		}
		type lk struct{ target, pkg, version, license string }
		seenL := map[lk]bool{}
		for _, l := range r.Licenses {
			checkClean(t, "target", l.Target, MaxTarget)
			checkClean(t, "package", l.PkgName, MaxPkgName)
			checkClean(t, "version", l.PkgVersion, MaxPkgVersion)
			checkClean(t, "declared", l.Declared, MaxLicenseName)
			if l.PkgName == "" || (l.Class != ClassOSPackages && l.Class != ClassLangPackages) {
				t.Fatalf("license %+v", l)
			}
			checkTerms(t, l.Terms)
			if l.License != UnknownID {
				if expr, terms, ok := ParseExpression(l.License); !ok || expr != l.License || !reflect.DeepEqual(terms, l.Terms) {
					t.Fatalf("license %q is not a normalized expression", l.License)
				}
			} else if !reflect.DeepEqual(l.Terms, [][]string{{UnknownID}}) {
				t.Fatalf("unknown license with terms %v", l.Terms)
			}
			k := lk{l.Target, l.PkgName, l.PkgVersion, l.License}
			if seenL[k] {
				t.Fatalf("license listed twice: %+v", k)
			}
			seenL[k] = true
		}
		type pk struct{ target, eco, name, version string }
		seenP := map[pk]bool{}
		for _, p := range r.Packages {
			checkClean(t, "target", p.Target, MaxTarget)
			checkClean(t, "package", p.Name, MaxPkgName)
			checkClean(t, "version", p.Version, MaxPkgVersion)
			if p.Name == "" || !ecosystem.Valid.MatchString(p.Ecosystem) ||
				p.MatchName != ecosystem.MatchName(p.Ecosystem, p.Name) || p.MatchVersion != ecosystem.MatchVersion(p.Ecosystem, p.Version) {
				t.Fatalf("package %+v", p)
			}
			if p.PURL != "" && (len(p.PURL) > MaxPURL || !purl.MatchString(p.PURL)) {
				t.Fatalf("purl %q", p.PURL)
			}
			k := pk{p.Target, p.Ecosystem, p.MatchName, p.Version}
			if seenP[k] {
				t.Fatalf("package listed twice: %+v", k)
			}
			seenP[k] = true
			for i, l := range p.Licenses {
				if slices.Contains(p.Licenses[:i], l) || (l != UnknownID && !licensepolicy.ID.MatchString(strings.Fields(strings.Trim(l, "()"))[0])) {
					t.Fatalf("package licenses %v", p.Licenses)
				}
			}
		}
	})
}
