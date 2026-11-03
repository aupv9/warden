package redact

import (
	"cmp"
	"net/url"
	"slices"
	"strings"
	"unicode/utf8"
)

// A secret can also come back by decoding. Gitleaks writes an artifact URI as
// the raw path (v8.30: "/src/dir/%41KIA….txt" for a file of that name), and
// the SARIF parser percent-decodes it (twice for a file: URI: url.Parse, then
// url.PathUnescape) and folds "\", "//" and "/./" (fingerprint.NormPath) after
// this redactor ran: a file named "%41KIA…" next to the key "AKIA…" would
// rebuild the key in the issue's path. So scrubString also masks every
// substring that turns into a secret under nested percent-decoding (either hex
// case, any mix of escaped and literal bytes, "+" read as a space as
// url.QueryUnescape does), invalid UTF-8 shown as U+FFFD, and that path
// folding.
const (
	// maxLevels bounds the nested percent-decodings checked; a string that
	// still decodes after that ("%252525…") is masked whole.
	maxLevels = 16
	// maxRounds bounds the re-checks after masking (a mask's visible prefix
	// can complete another secret); a string still matching after that is
	// masked whole.
	maxRounds = 16
)

func scrubString(s string, reps []replacement) string {
	for _, r := range reps {
		s = strings.ReplaceAll(s, r.secret, r.masked)
	}
	if len(reps) == 0 || plain(s) {
		return s
	}
	for range maxRounds {
		next, ok := maskDecoded(s, reps)
		if !ok {
			return "****"
		}
		if next == s {
			return s
		}
		s = next
	}
	if next, ok := maskDecoded(s, reps); ok && next == s {
		return s
	}
	return "****"
}

// plain reports that no decoding or folding changes s, so the literal
// replacement was enough.
func plain(s string) bool {
	return !strings.ContainsAny(s, "%+\\�") && !strings.Contains(s, "//") && !strings.Contains(s, "/./") && utf8.ValidString(s)
}

// view is a transformed string: byte b[i] came from s[lo[i]:hi[i]] of the
// original.
type view struct {
	b      []byte
	lo, hi []int
}

func identity(s string) view {
	v := view{b: []byte(s), lo: make([]int, len(s)), hi: make([]int, len(s))}
	for i := range len(s) {
		v.lo[i], v.hi[i] = i, i+1
	}
	return v
}

func (v *view) add(b byte, lo, hi int) {
	v.b = append(v.b, b)
	v.lo = append(v.lo, lo)
	v.hi = append(v.hi, hi)
}

func isHex(c byte) bool {
	return '0' <= c && c <= '9' || 'a' <= c && c <= 'f' || 'A' <= c && c <= 'F'
}

func unhex(c byte) byte {
	switch {
	case c <= '9':
		return c - '0'
	case c <= 'F':
		return c - 'A' + 10
	}
	return c - 'a' + 10
}

// decodeOnce decodes every valid %XX: a superset of url.PathUnescape and
// url.Parse, which refuse the whole string over one bad escape.
func decodeOnce(v view) (view, bool) {
	var out view
	changed := false
	for i := 0; i < len(v.b); i++ {
		if v.b[i] == '%' && i+2 < len(v.b) && isHex(v.b[i+1]) && isHex(v.b[i+2]) {
			out.add(unhex(v.b[i+1])<<4|unhex(v.b[i+2]), v.lo[i], v.hi[i+2])
			i += 2
			changed = true
			continue
		}
		out.add(v.b[i], v.lo[i], v.hi[i])
	}
	return out, changed
}

const replChar = "�"

func isSlash(c byte) bool { return c == '/' || c == '\\' }

// normalize folds what a reader of v may see instead: a run of invalid bytes
// or U+FFFD becomes one U+FFFD (encoding/json and the parser replace per byte,
// strings.ToValidUTF8 per run), "+" a space, "\" a "/", and a run of "/" or
// "/./" one "/" (fingerprint.NormPath). Secrets and views are folded alike, so
// whatever these readers would show a secret in is matched; folding can only
// match more.
func normalize(v view) view {
	var out view
	extend := func(hi int) { out.hi[len(out.hi)-1] = max(out.hi[len(out.hi)-1], hi) }
	last := func() byte {
		if len(out.b) == 0 {
			return 0
		}
		return out.b[len(out.b)-1]
	}
	repl := false
	for i := 0; i < len(v.b); {
		r, size := utf8.DecodeRune(v.b[i:])
		lo, hi := v.lo[i], v.hi[i+size-1]
		if r == utf8.RuneError {
			if repl {
				extend(hi)
			} else {
				for j := range len(replChar) {
					out.add(replChar[j], lo, hi)
				}
				repl = true
			}
			i += size
			continue
		}
		repl = false
		if size > 1 {
			for j := range size {
				out.add(v.b[i+j], v.lo[i+j], v.hi[i+j])
			}
			i += size
			continue
		}
		c := v.b[i]
		switch c {
		case '+':
			c = ' '
		case '\\':
			c = '/'
		}
		switch {
		case c == '/' && last() == '/':
			extend(hi)
		case c == '.' && last() == '/' && i+1 < len(v.b) && isSlash(v.b[i+1]):
			extend(hi)
		default:
			out.add(c, lo, hi)
		}
		i++
	}
	return out
}

type span struct {
	lo, hi int
	rep    *replacement
}

// maskDecoded masks, at the least-decoded level that has a match, every
// substring of s that a secret matches in that level's folded view. It returns
// s unchanged when no level matches, and false when s nests more than
// maxLevels percent-encodings.
func maskDecoded(s string, reps []replacement) (string, bool) {
	v := identity(s)
	for level := 0; ; level++ {
		nv := normalize(v)
		text := string(nv.b)
		var found []span
		for k := range reps {
			r := &reps[k]
			if r.norm == "" {
				continue
			}
			for from := 0; from < len(text); {
				i := strings.Index(text[from:], r.norm)
				if i < 0 {
					break
				}
				i += from
				j := i + len(r.norm)
				found = append(found, span{nv.lo[i], nv.hi[j-1], r})
				from = j
			}
		}
		if len(found) > 0 {
			return replaceSpans(s, found), true
		}
		d, changed := decodeOnce(v)
		if !changed {
			return s, true
		}
		if level == maxLevels {
			return "", false
		}
		v = d
	}
}

// replaceSpans replaces each span of s with its secret's mask: the plain mask
// where s holds the secret literally, else the mask with its visible part
// escaped, so that inserting it doesn't change how the URI around it parses.
// Overlapping spans are merged and masked whole.
func replaceSpans(s string, found []span) string {
	slices.SortFunc(found, func(a, b span) int { return cmp.Or(cmp.Compare(a.lo, b.lo), cmp.Compare(b.hi, a.hi)) })
	var sb strings.Builder
	pos := 0
	for i := 0; i < len(found); {
		cur := found[i]
		merged := false
		for i++; i < len(found) && found[i].lo < cur.hi; i++ {
			cur.hi = max(cur.hi, found[i].hi)
			merged = true
		}
		sb.WriteString(s[pos:cur.lo])
		switch {
		case merged:
			sb.WriteString("****")
		case s[cur.lo:cur.hi] == cur.rep.secret:
			sb.WriteString(cur.rep.masked)
		default:
			sb.WriteString(url.PathEscape(strings.TrimSuffix(cur.rep.masked, "****")) + "****")
		}
		pos = cur.hi
	}
	sb.WriteString(s[pos:])
	return sb.String()
}
