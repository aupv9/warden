package ecosystem

import "testing"

func TestFromTrivy(t *testing.T) {
	for _, c := range []struct{ typ, purl, want string }{
		{"npm", "pkg:npm/%40fontsource/inter@5.3.0", Npm},
		{"yarn", "", Npm},
		{"poetry", "", PyPI},
		{"gomod", "pkg:golang/github.com/a/b@v1.0.0", Go},
		{"jar", "", Maven},
		{"cargo", "", CratesIO},
		{"bundler", "", RubyGems},
		{"dotnet-core", "", NuGet},
		{"composer", "", Packagist},
		{"", "pkg:pypi/requests@2.0", PyPI},         // purl fallback
		{"something-new", "pkg:maven/a/b@1", Maven}, // unknown type, known purl
		{"alpine", "pkg:apk/alpine/musl@1.2", "alpine"},
		{"", "pkg:deb/debian/libc6@2.36", "deb"},
		{"", "", Unknown},
		{"bad type!", "not a purl", Unknown},
		{"bad type!", "pkg:rpm/redhat/x@1", "rpm"},
		{"  NPM ", "", Npm},
	} {
		if got := FromTrivy(c.typ, c.purl); got != c.want {
			t.Errorf("FromTrivy(%q, %q) = %q, want %q", c.typ, c.purl, got, c.want)
		}
	}
}

func TestMatchName(t *testing.T) {
	for _, c := range []struct{ eco, name, want string }{
		{PyPI, "Django_REST.framework", "django-rest-framework"},
		{PyPI, "a--_.b", "a-b"},
		{CratesIO, "serde_json", "serde-json"},
		{Npm, "@Scope/Pkg", "@scope/pkg"},
		{Maven, "Org.Apache.Logging.Log4j:log4j-core", "org.apache.logging.log4j:log4j-core"},
		{Go, "github.com/Sirupsen/logrus", "github.com/sirupsen/logrus"},
		{"alpine", " musl ", "musl"},
	} {
		if got := MatchName(c.eco, c.name); got != c.want {
			t.Errorf("MatchName(%q, %q) = %q, want %q", c.eco, c.name, got, c.want)
		}
	}
}

func TestMatchVersion(t *testing.T) {
	for _, c := range []struct{ eco, v, want string }{
		{Go, "v1.2.3", "1.2.3"},
		{Go, "1.2.3", "1.2.3"},
		{PyPI, "1.0RC1", "1.0rc1"},
		{Npm, "1.0.0-Beta", "1.0.0-Beta"},
	} {
		if got := MatchVersion(c.eco, c.v); got != c.want {
			t.Errorf("MatchVersion(%q, %q) = %q, want %q", c.eco, c.v, got, c.want)
		}
	}
}

func TestOSVNamesAreValid(t *testing.T) {
	for _, e := range append(OSV, Unknown) {
		if !Valid.MatchString(e) {
			t.Errorf("%q fails Valid", e)
		}
		if e != Unknown && !IsOSV(e) {
			t.Errorf("IsOSV(%q) = false", e)
		}
	}
}
