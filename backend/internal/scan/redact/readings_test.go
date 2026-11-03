package redact_test

import (
	"fmt"
	"net/url"
	"strings"
	"unicode/utf8"

	"github.com/aupv9/warden/backend/internal/domain/fingerprint"
)

// readings are s and what a reader may decode it into: url.PathUnescape,
// url.QueryUnescape and url.Parse's path (strict, as the parser and browsers
// decode), nested up to 4 times, the SARIF parser's path (NormPath, which
// decodes once or twice and folds "\", "//" and "/./"), and invalid UTF-8
// shown as U+FFFD per byte (encoding/json, the parser) or per run
// (strings.ToValidUTF8). Independent of the redactor's own decoder on purpose.
func readings(s string) []string {
	seen := map[string]bool{}
	var out []string
	add := func(r string) bool {
		if seen[r] {
			return false
		}
		seen[r] = true
		out = append(out, r)
		return true
	}
	// Only the decoders nest; NormPath and the U+FFFD views are what a
	// reader ends with.
	final := func(x string) {
		for _, d := range []string{x, fingerprint.NormPath(x, "", true), fingerprint.NormPath(x, "", false)} {
			add(d)
			add(strings.ToValidUTF8(d, "�"))
			add(perByte(d))
		}
	}
	level := []string{s}
	decoded := map[string]bool{s: true}
	for depth := 0; len(level) > 0; depth++ {
		var next []string
		for _, x := range level {
			final(x)
			if depth == 4 {
				continue
			}
			var ds []string
			if d, err := url.PathUnescape(x); err == nil {
				ds = append(ds, d)
			}
			if d, err := url.QueryUnescape(x); err == nil {
				ds = append(ds, d)
			}
			if u, err := url.Parse(x); err == nil {
				ds = append(ds, u.Path)
			}
			for _, d := range ds {
				if !decoded[d] {
					decoded[d] = true
					next = append(next, d)
				}
			}
		}
		level = next
	}
	return out
}

func perByte(s string) string {
	var sb strings.Builder
	for len(s) > 0 {
		r, size := utf8.DecodeRuneInString(s)
		sb.WriteRune(r)
		s = s[size:]
	}
	return sb.String()
}

// pct percent-encodes every byte of s: hex case 'U'pper, 'l'ower, or 'm'ixed
// per byte and per digit.
func pct(s string, hexCase byte) string {
	var sb strings.Builder
	for i := range len(s) {
		h := fmt.Sprintf("%02X", s[i])
		switch {
		case hexCase == 'l':
			h = strings.ToLower(h)
		case hexCase == 'm' && i%2 == 0:
			h = strings.ToLower(h[:1]) + h[1:]
		case hexCase == 'm':
			h = h[:1] + strings.ToLower(h[1:])
		}
		sb.WriteString("%" + h)
	}
	return sb.String()
}

// encodings are the forms of secret an attacker could name a file (or write
// any other string) with so that a reader decodes it back.
func encodings(secret string) []string {
	half := ""
	for i := range len(secret) {
		if i%2 == 0 {
			half += pct(secret[i:i+1], 'U')
		} else {
			half += secret[i : i+1]
		}
	}
	slashy := strings.NewReplacer("/", `\`).Replace(secret)
	doubled := strings.ReplaceAll(secret, "/", "//")
	dotted := strings.ReplaceAll(secret, "/", "/./")
	return []string{
		pct(secret, 'U'), pct(secret, 'l'), pct(secret, 'm'), half,
		url.PathEscape(secret), url.QueryEscape(secret),
		pct(pct(secret, 'U'), 'l'),                       // two levels
		strings.ReplaceAll(pct(secret, 'U'), "%", "%25"), // "%2541…"
		slashy, doubled, dotted, pct(doubled, 'm'),
	}
}
