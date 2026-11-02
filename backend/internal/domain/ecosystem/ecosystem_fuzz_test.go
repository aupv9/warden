package ecosystem

import (
	"strings"
	"testing"
	"unicode/utf8"
)

// FuzzMatch: MatchName is idempotent (a stored match name normalizes to
// itself, so searching by one finds it) and keeps the rune count within the
// input's (callers cap the input in runes); MatchVersion is idempotent except
// for Go's single leading "v"; FromTrivy always returns a storable ecosystem.
func FuzzMatch(f *testing.F) {
	for _, s := range []struct{ eco, name, version string }{
		{PyPI, "Foo__Bar.baz", "1.0RC1"}, {CratesIO, "serde_json", "1.0.0"}, {Go, "GitHub.com/A/B", "vv1.2.3"},
		{Npm, "  @Scope/Pkg  ", " 1.0.0 "}, {"alpine", "İstanbul", " 1-r0"}, {PyPI, "-_.a-_.", "V 1"}, {Unknown, "\xff\xfe", "\x00"},
	} {
		f.Add(s.eco, s.name, s.version)
	}
	f.Fuzz(func(t *testing.T, eco, name, version string) {
		if len(name)+len(version) > 4096 {
			return
		}
		n := MatchName(eco, name)
		if MatchName(eco, n) != n {
			t.Fatalf("MatchName(%q, %q) = %q, then %q", eco, name, n, MatchName(eco, n))
		}
		if utf8.RuneCountInString(n) > utf8.RuneCountInString(name) {
			t.Fatalf("MatchName(%q, %q) = %q is longer", eco, name, n)
		}
		if strings.TrimSpace(n) != n {
			t.Fatalf("MatchName(%q, %q) = %q keeps outer space", eco, name, n)
		}
		v := MatchVersion(eco, version)
		if utf8.RuneCountInString(v) > utf8.RuneCountInString(version) {
			t.Fatalf("MatchVersion(%q, %q) = %q is longer", eco, version, v)
		}
		if eco != Go && MatchVersion(eco, v) != v {
			t.Fatalf("MatchVersion(%q, %q) = %q, then %q", eco, version, v, MatchVersion(eco, v))
		}
		if e := FromTrivy(name, version); !Valid.MatchString(e) {
			t.Fatalf("FromTrivy(%q, %q) = %q", name, version, e)
		}
	})
}
