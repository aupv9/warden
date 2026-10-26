// Package fingerprint implements issue identity: a finding keeps
// its fingerprint when code moves, and repeated identical findings in one file are
// told apart by their order (k).
package fingerprint

import (
	"crypto/hmac"
	"crypto/sha256"
	"encoding/hex"
	"net/url"
	"slices"
	"strconv"
	"strings"
	"unicode"
)

// NormPath turns a SARIF artifact URI into a path relative to the upload root.
// underMount strips the sandbox mount point (/src); rootDir strips the single
// top-level directory most zips have (e.g. "payment-main/").
func NormPath(uri, rootDir string, underMount bool) string {
	if strings.HasPrefix(uri, "file:") {
		if u, err := url.Parse(uri); err == nil {
			uri = u.Path
		} else {
			uri = strings.TrimPrefix(uri, "file:")
		}
	}
	if p, err := url.PathUnescape(uri); err == nil {
		uri = p
	}
	path := strings.ReplaceAll(uri, `\`, "/")
	var parts []string
	for _, p := range strings.Split(path, "/") {
		if p != "" && p != "." {
			parts = append(parts, p)
		}
	}
	if underMount && len(parts) > 0 && parts[0] == "src" {
		parts = parts[1:]
	}
	if rootDir != "" && len(parts) > 1 && parts[0] == rootDir {
		parts = parts[1:]
	}
	return strings.Join(parts, "/")
}

// isSpace matches Python's str.isspace, which also counts the ASCII separators
// 0x1c-0x1f; keeping the definitions equal keeps code fingerprints stable.
func isSpace(r rune) bool {
	return unicode.IsSpace(r) || (r >= 0x1c && r <= 0x1f)
}

// SplitLines splits like Python's str.splitlines (no trailing empty element).
func SplitLines(s string) []string {
	var out []string
	start := 0
	rs := []rune(s)
	for i := 0; i < len(rs); i++ {
		switch rs[i] {
		case '\n', '\v', '\f', 0x1c, 0x1d, 0x1e, 0x85, 0x2028, 0x2029:
		case '\r':
			if i+1 < len(rs) && rs[i+1] == '\n' {
				out = append(out, string(rs[start:i]))
				i++
				start = i + 1
				continue
			}
		default:
			continue
		}
		out = append(out, string(rs[start:i]))
		start = i + 1
	}
	if start < len(rs) {
		out = append(out, string(rs[start:]))
	}
	return out
}

func collapseSpace(line string) string {
	var b strings.Builder
	inSpace := false
	for _, r := range line {
		if isSpace(r) {
			inSpace = true
			continue
		}
		if inSpace && b.Len() > 0 {
			b.WriteByte(' ')
		}
		inSpace = false
		b.WriteRune(r)
	}
	return b.String()
}

// CodeContentKey hashes the flagged lines with whitespace runs collapsed, so
// reindenting code doesn't create a new issue.
func CodeContentKey(lines []string) string {
	norm := make([]string, len(lines))
	for i, l := range lines {
		norm[i] = collapseSpace(l)
	}
	sum := sha256.Sum256([]byte(strings.Join(norm, "\n")))
	return hex.EncodeToString(sum[:])
}

// SecretContentKey is an HMAC with the per-org key, so the raw secret is never
// stored and identical secrets in different orgs don't correlate.
func SecretContentKey(secret string, orgKey []byte) string {
	m := hmac.New(sha256.New, orgKey)
	m.Write([]byte(secret))
	return hex.EncodeToString(m.Sum(nil))
}

func SCAContentKey(cve, pkg, version string) string {
	return cve + "|" + pkg + "|" + version
}

func Fingerprint(tool, ruleID, path, contentKey string, k int) string {
	raw := strings.Join([]string{tool, ruleID, path, contentKey, strconv.Itoa(k)}, "|")
	sum := sha256.Sum256([]byte(raw))
	return hex.EncodeToString(sum[:])
}

// Key is the identity of a finding before ordering.
type Key struct {
	Tool, RuleID, FilePath, ContentKey string
}

type Fingerprinted[T any] struct {
	Finding     T
	Fingerprint string
}

// Assign groups findings by Key, orders each group by start line (0 when unknown)
// and gives the k-th finding fingerprint(..., k). Groups come out in first-seen order.
func Assign[T any](findings []T, key func(T) Key, startLine func(T) int) []Fingerprinted[T] {
	groups := map[Key][]T{}
	var order []Key
	for _, f := range findings {
		k := key(f)
		if _, ok := groups[k]; !ok {
			order = append(order, k)
		}
		groups[k] = append(groups[k], f)
	}
	out := make([]Fingerprinted[T], 0, len(findings))
	for _, k := range order {
		items := groups[k]
		slices.SortStableFunc(items, func(a, b T) int { return startLine(a) - startLine(b) })
		for i, f := range items {
			out = append(out, Fingerprinted[T]{f, Fingerprint(k.Tool, k.RuleID, k.FilePath, k.ContentKey, i)})
		}
	}
	return out
}
