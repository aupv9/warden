package trivyjson

import (
	"bytes"
	"encoding/json"
	"errors"
	"os"
	"path/filepath"
	"reflect"
	"strings"
	"testing"

	"github.com/aupv9/warden/backend/internal/domain/licensepolicy"
)

type M = map[string]any

func pkg(name, version string, licenses ...string) M {
	return M{"ID": name + "@" + version, "Name": name, "Version": version, "Licenses": licenses}
}

// report has the shape of `trivy fs --scanners vuln,license --list-all-pkgs --format json`
// (Trivy 0.75): packages per lockfile, and a "license" result that classifies each name.
func report(results ...M) []byte {
	b, _ := json.Marshal(M{"SchemaVersion": 2, "ArtifactName": "/src", "ArtifactType": "filesystem", "Results": results})
	return b
}

func parse(t *testing.T, b []byte) *Report {
	t.Helper()
	r, err := Parse(bytes.NewReader(b))
	if err != nil {
		t.Fatal(err)
	}
	return r
}

func TestParseRealShape(t *testing.T) {
	b := report(
		M{"Target": "app/go.mod", "Class": "lang-pkgs", "Type": "gomod", "Packages": []any{
			M{"ID": "example.com/app", "Name": "example.com/app", "Version": nil, "Licenses": nil},
			pkg("golang.org/x/net", "v0.7.0"),
		}, "Vulnerabilities": []any{M{"VulnerabilityID": "CVE-2023-0001", "PkgName": "golang.org/x/net"}}},
		M{"Target": "app/package-lock.json", "Class": "lang-pkgs", "Type": "npm", "Packages": []any{
			pkg("gpl-thing", "1.0.0", "GPL-3.0-only"),
			pkg("lodash", "4.17.15", "MIT"),
			pkg("node-forge", "0.9.0", "(BSD-3-Clause OR GPL-2.0)"),
			pkg("weird", "2.0.0", "SEE LICENSE IN LICENSE.txt"),
			pkg("lodash", "4.17.15", "MIT"), // listed twice (nested node_modules)
		}},
		M{"Target": "app/package-lock.json", "Class": "license", "Licenses": []any{
			M{"Severity": "HIGH", "Category": "restricted", "PkgName": "gpl-thing", "FilePath": "app/package-lock.json", "Name": "GPL-3.0-only"},
			M{"Severity": "LOW", "Category": "notice", "PkgName": "lodash", "Name": "MIT"},
			M{"Severity": "LOW", "Category": "notice", "PkgName": "node-forge", "Name": "(BSD-3-Clause OR GPL-2.0)"},
			M{"Severity": "UNKNOWN", "Category": "unknown", "PkgName": "weird", "Name": "SEE LICENSE IN LICENSE.txt"},
		}},
	)
	r := parse(t, b)
	want := []License{
		{Target: "app/package-lock.json", Class: ClassLangPackages, PkgName: "gpl-thing", PkgVersion: "1.0.0", License: "GPL-3.0-only",
			Terms: [][]string{{"GPL-3.0-only"}}, Category: licensepolicy.Restricted, Declared: "GPL-3.0-only"},
		{Target: "app/package-lock.json", Class: ClassLangPackages, PkgName: "lodash", PkgVersion: "4.17.15", License: "MIT",
			Terms: [][]string{{"MIT"}}, Category: licensepolicy.Notice, Declared: "MIT"},
		{Target: "app/package-lock.json", Class: ClassLangPackages, PkgName: "node-forge", PkgVersion: "0.9.0", License: "BSD-3-Clause OR GPL-2.0",
			Terms: [][]string{{"BSD-3-Clause"}, {"GPL-2.0"}}, Category: licensepolicy.Notice, Declared: "(BSD-3-Clause OR GPL-2.0)"},
		{Target: "app/package-lock.json", Class: ClassLangPackages, PkgName: "weird", PkgVersion: "2.0.0", License: UnknownID,
			Terms: [][]string{{UnknownID}}, Category: licensepolicy.Unknown, Declared: "SEE LICENSE IN LICENSE.txt"},
	}
	if !reflect.DeepEqual(r.Licenses, want) {
		t.Fatalf("got  %+v\nwant %+v", r.Licenses, want)
	}
	if r.OSFamily != "" {
		t.Fatal(r.OSFamily)
	}
}

func TestParseImageShape(t *testing.T) {
	b, _ := json.Marshal(M{"ArtifactName": "/src/image.tar", "ArtifactType": "container_image",
		"Metadata": M{"OS": M{"Family": "alpine", "Name": "3.18.0"}},
		"Results": []any{
			M{"Target": "/src/image.tar (alpine 3.18.0)", "Class": "os-pkgs", "Type": "alpine", "Packages": []any{
				pkg("busybox", "1.36.0-r9", "GPL-2.0-only"),
				pkg("ssl_client", "3.1.0-r4", "Apache-2.0 AND MIT"),
			}},
			M{"Target": "OS Packages", "Class": "license", "Licenses": []any{
				M{"Category": "restricted", "PkgName": "busybox", "FilePath": "", "Name": "GPL-2.0-only"},
			}},
		}})
	r := parse(t, b)
	if r.OSFamily != "alpine" || len(r.Licenses) != 2 {
		t.Fatalf("%+v", r)
	}
	if l := r.Licenses[0]; l.Class != ClassOSPackages || l.Target != "/src/image.tar (alpine 3.18.0)" || l.Category != licensepolicy.Restricted {
		t.Fatalf("%+v", l)
	}
	// A name Trivy didn't classify is unknown.
	if l := r.Licenses[1]; !reflect.DeepEqual(l.Terms, [][]string{{"Apache-2.0", "MIT"}}) || l.Category != licensepolicy.Unknown {
		t.Fatalf("%+v", l)
	}
	for _, fam := range []string{"Alpine", "../etc", strings.Repeat("a", 40), "a\x00"} {
		b, _ := json.Marshal(M{"Metadata": M{"OS": M{"Family": fam}}})
		if r := parse(t, b); r.OSFamily != "" {
			t.Fatalf("family %q accepted", fam)
		}
	}
}

func TestParseExpression(t *testing.T) {
	cases := []struct {
		in    string
		expr  string
		terms [][]string
	}{
		{"MIT", "MIT", [][]string{{"MIT"}}},
		{"  GPL-2.0+ ", "GPL-2.0+", [][]string{{"GPL-2.0+"}}},
		{"LicenseRef-acme-EULA", "LicenseRef-acme-EULA", [][]string{{"LicenseRef-acme-EULA"}}},
		{"((MIT or Apache-2.0))", "MIT OR Apache-2.0", [][]string{{"MIT"}, {"Apache-2.0"}}},
		{"(MIT) OR (Apache-2.0)", "(MIT) OR (Apache-2.0)", [][]string{{"MIT"}, {"Apache-2.0"}}},
		{"MIT AND (Apache-2.0 OR BSD-3-Clause)", "MIT AND (Apache-2.0 OR BSD-3-Clause)", [][]string{{"MIT", "Apache-2.0"}, {"MIT", "BSD-3-Clause"}}},
		{"MIT OR Apache-2.0 AND BSD-3-Clause", "MIT OR Apache-2.0 AND BSD-3-Clause", [][]string{{"MIT"}, {"Apache-2.0", "BSD-3-Clause"}}},
		{"MIT AND MIT", "MIT AND MIT", [][]string{{"MIT"}}},
		{"GPL-2.0-only WITH Classpath-exception-2.0", "GPL-2.0-only WITH Classpath-exception-2.0", [][]string{{"GPL-2.0-only"}}},
	}
	for _, c := range cases {
		expr, terms, ok := ParseExpression(c.in)
		if !ok || expr != c.expr || !reflect.DeepEqual(terms, c.terms) {
			t.Errorf("%q: got %q %v %v", c.in, expr, terms, ok)
		}
	}
}

// Anything that isn't a well-formed expression of valid ids, within the caps,
// is refused (and becomes LicenseRef-unknown).
func TestParseExpressionRejects(t *testing.T) {
	deep := strings.Repeat("(", maxDepth+1) + "MIT" + strings.Repeat(")", maxDepth+1)
	many := strings.TrimSuffix(strings.Repeat("MIT OR ", maxTokens), " OR ")
	wide := "(A OR B OR C OR D OR E) AND (F OR G OR H OR I)" // 20 alternatives
	var longAnd []string
	for i := range maxTerms + 1 {
		longAnd = append(longAnd, "L"+string(rune('a'+i)))
	}
	for _, in := range []string{
		"", "   ", "SEE LICENSE IN LICENSE.txt", "Apache 2.0", "MIT OR", "OR MIT", "(MIT", "MIT)", "MIT AND AND BSD",
		"MIT WITH", "(MIT OR BSD) WITH Classpath-exception-2.0", "MIT WITH <x>", "<script>alert(1)</script>",
		"-MIT", "MIT\x00", "MIT;rm -rf", strings.Repeat("a", 65), strings.Repeat("A", MaxLicenseName+1),
		deep, many, wide, strings.Join(longAnd, " AND "), "MIT\u202eTIM",
	} {
		if expr, terms, ok := ParseExpression(in); ok {
			t.Errorf("%q accepted as %q %v", in, expr, terms)
		}
	}
}

func TestParseRejectsHostileDocuments(t *testing.T) {
	tooManyPkgs := make([]any, MaxPackages+1)
	for i := range tooManyPkgs {
		tooManyPkgs[i] = M{"Name": "p"}
	}
	manyLicenses := make([]string, MaxLicensesPerPackage+1)
	for i := range manyLicenses {
		manyLicenses[i] = "MIT"
	}
	for name, doc := range map[string][]byte{
		"not JSON":       []byte("{"),
		"array":          []byte("[]"),
		"trailing":       []byte(`{"Results":[]} {}`),
		"deep nesting":   []byte(`{"x":` + strings.Repeat("[", 20000) + strings.Repeat("]", 20000) + `}`),
		"results type":   []byte(`{"Results":{"Target":"x"}}`),
		"packages type":  []byte(`{"Results":[{"Class":"lang-pkgs","Packages":"lodash"}]}`),
		"licenses type":  []byte(`{"Results":[{"Class":"lang-pkgs","Packages":[{"Name":"a","Licenses":"MIT"}]}]}`),
		"name type":      []byte(`{"Results":[{"Class":"lang-pkgs","Packages":[{"Name":1}]}]}`),
		"too many pkgs":  report(M{"Class": "lang-pkgs", "Packages": tooManyPkgs}),
		"many licenses":  report(M{"Class": "lang-pkgs", "Packages": []any{M{"Name": "a", "Licenses": manyLicenses}}}),
		"too many items": []byte(`{"Results":[` + strings.TrimSuffix(strings.Repeat(`{},`, MaxResults+1), ",") + `]}`),
	} {
		if _, err := Parse(bytes.NewReader(doc)); !errors.Is(err, ErrReport) {
			t.Errorf("%s: got %v", name, err)
		}
	}
}

func TestParseCapsStrings(t *testing.T) {
	huge := strings.Repeat("x", 1<<20)
	b := report(
		M{"Target": huge, "Class": "lang-pkgs", "Packages": []any{
			pkg("evil\x00\x1b[31m\u202e"+huge, huge, "MIT"),
			pkg("", "1.0", "MIT"), // no name: skipped
			pkg("ok", "1.0", huge),
		}},
		M{"Class": "license", "Licenses": []any{M{"Category": "forbidden", "Name": huge}}},
	)
	r := parse(t, b)
	if len(r.Licenses) != 2 {
		t.Fatalf("%d licenses", len(r.Licenses))
	}
	l := r.Licenses[0]
	if len([]rune(l.Target)) > MaxTarget || len([]rune(l.PkgName)) > MaxPkgName || len([]rune(l.PkgVersion)) > MaxPkgVersion ||
		strings.ContainsAny(l.PkgName, "\x00\x1b\u202e") || !strings.HasPrefix(l.PkgName, "evil\uFFFD") {
		t.Fatalf("%q", l.PkgName[:20])
	}
	// A huge license name is unknown, and its classification isn't trusted either.
	if u := r.Licenses[1]; u.License != UnknownID || u.Category != licensepolicy.Unknown || len([]rune(u.Declared)) > MaxLicenseName {
		t.Fatalf("%+v", u.License)
	}
}

func TestLoadCapsFileSize(t *testing.T) {
	p := filepath.Join(t.TempDir(), "trivy.json")
	if err := os.WriteFile(p, report(), 0o600); err != nil {
		t.Fatal(err)
	}
	if _, err := Load(p); err != nil {
		t.Fatal(err)
	}
	f, _ := os.OpenFile(p, os.O_WRONLY, 0)
	_ = f.Truncate(MaxFileBytes + 1) // sparse
	f.Close()
	if _, err := Load(p); !errors.Is(err, ErrReport) {
		t.Fatal(err)
	}
	if _, err := Load(filepath.Join(t.TempDir(), "missing")); err == nil {
		t.Fatal("missing file loaded")
	}
	// A stream longer than the cap is cut off and fails to decode.
	big := io0(MaxFileBytes)
	if _, err := Parse(big); !errors.Is(err, ErrReport) {
		t.Fatal(err)
	}
}

// io0 is a reader of n spaces followed by a valid document: past the cap.
func io0(n int) *bytes.Reader {
	return bytes.NewReader(append(bytes.Repeat([]byte(" "), n), []byte(`{"Results":[]}`)...))
}

func TestParsePackages(t *testing.T) {
	withPURL := func(m M, purl, rel string) M { m["Identifier"] = M{"PURL": purl}; m["Relationship"] = rel; return m }
	b := report(
		M{"Target": "go.mod", "Class": "lang-pkgs", "Type": "gomod", "Packages": []any{
			withPURL(M{"ID": "example.com/app", "Name": "example.com/app"}, "pkg:golang/example.com/app", "root"),
			withPURL(pkg("golang.org/x/net", "v0.7.0"), "pkg:golang/golang.org/x/net@v0.7.0", "direct"),
		}},
		M{"Target": "package-lock.json", "Class": "lang-pkgs", "Type": "npm", "Packages": []any{
			withPURL(pkg("@Scope/Pkg", "1.0.0", "MIT", "(MIT)", "Apache-2.0"), "pkg:npm/%40scope/pkg@1.0.0", "direct"),
			withPURL(pkg("@scope/pkg", "1.0.0", "MIT"), "pkg:npm/%40scope/pkg@1.0.0", "indirect"), // same match name: one entry
			withPURL(pkg("evil", "1.0.0"), "javascript:alert(1)", "direct"),
			withPURL(pkg("spaced", "1.0.0"), "pkg:npm/a b@1", "direct"),
			withPURL(pkg("long", "1.0.0"), "pkg:npm/"+strings.Repeat("a", MaxPURL), "direct"),
			withPURL(pkg("ws", "0.0.0"), "pkg:npm/ws@0.0.0", "workspace"),
		}},
		M{"Target": "requirements.txt", "Class": "lang-pkgs", "Type": "pip", "Packages": []any{pkg("Django_Rest.Framework", "3.0RC1")}},
		M{"Target": "x", "Class": "secret", "Type": "npm", "Packages": []any{pkg("not-a-package-result", "1")}},
	)
	r := parse(t, b)
	got := map[string]Package{}
	for _, p := range r.Packages {
		got[p.Name] = p
	}
	if len(r.Packages) != 6 {
		t.Fatalf("%d packages: %+v", len(r.Packages), r.Packages)
	}
	if _, ok := got["example.com/app"]; ok {
		t.Fatal("root package listed")
	}
	if p := got["golang.org/x/net"]; p.Ecosystem != "Go" || p.MatchVersion != "0.7.0" || p.PURL != "pkg:golang/golang.org/x/net@v0.7.0" || p.Target != "go.mod" {
		t.Fatalf("%+v", p)
	}
	if p := got["@Scope/Pkg"]; p.MatchName != "@scope/pkg" || !reflect.DeepEqual(p.Licenses, []string{"MIT", "Apache-2.0"}) {
		t.Fatalf("%+v", p)
	}
	for _, n := range []string{"evil", "spaced", "long"} {
		if got[n].PURL != "" {
			t.Errorf("%s: PURL %q kept", n, got[n].PURL)
		}
	}
	if p := got["Django_Rest.Framework"]; p.Ecosystem != "PyPI" || p.MatchName != "django-rest-framework" || p.MatchVersion != "3.0rc1" {
		t.Fatalf("%+v", p)
	}
}

func TestParsePackagesSanitized(t *testing.T) {
	b := report(M{"Target": "t\u202e", "Class": "os-pkgs", "Type": "alpine\x00", "Packages": []any{
		M{"Name": "bad\u202ename\x1b", "Version": "1\x00", "Identifier": M{"PURL": "pkg:apk/alpine/x\u202e@1"}},
	}})
	r := parse(t, b)
	if len(r.Packages) != 1 {
		t.Fatal(r.Packages)
	}
	p := r.Packages[0]
	if strings.ContainsAny(p.Name+p.Version+p.Target, "\x00\x1b\u202e") || p.PURL != "" || p.Ecosystem != "unknown" {
		t.Fatalf("%+v", p)
	}
}
