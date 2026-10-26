// Package redact runs inside the Gitleaks sandbox: it replaces every copy of each
// detected secret in the raw SARIF with a mask and records an HMAC of the secret
// as the content key, so the raw value never leaves the sandbox.
package redact

import (
	"cmp"
	"crypto/hmac"
	"crypto/sha256"
	"encoding/hex"
	"errors"
	"fmt"
	"slices"
	"strings"
)

const (
	ContentKeyProp  = "warden.contentKey"
	visiblePrefix   = 4
	minLenForPrefix = 12
	MinKeyBytes     = 32
)

// Mask keeps the first 4 characters of secrets of at least 12 characters; shorter
// ones would leak too large a fraction of the secret.
func Mask(secret string) string {
	r := []rune(secret)
	if len(r) < minLenForPrefix {
		return "****"
	}
	return string(r[:visiblePrefix]) + "****"
}

type replacement struct{ secret, masked string }

// scrub replaces every secret in every string of v, object keys included.
func scrub(v any, reps []replacement) any {
	switch t := v.(type) {
	case string:
		for _, r := range reps {
			t = strings.ReplaceAll(t, r.secret, r.masked)
		}
		return t
	case []any:
		for i := range t {
			t[i] = scrub(t[i], reps)
		}
		return t
	case map[string]any:
		out := make(map[string]any, len(t))
		for k, val := range t {
			out[scrub(k, reps).(string)] = scrub(val, reps)
		}
		return out
	}
	return v
}

func contentKey(key []byte, secret string) string {
	m := hmac.New(sha256.New, key)
	m.Write([]byte(secret))
	return hex.EncodeToString(m.Sum(nil))
}

// firstSnippet is where Gitleaks puts the matched secret.
func firstSnippet(result map[string]any) string {
	locs, _ := result["locations"].([]any)
	for _, l := range locs {
		loc, _ := l.(map[string]any)
		pl, _ := loc["physicalLocation"].(map[string]any)
		region, _ := pl["region"].(map[string]any)
		snip, _ := region["snippet"].(map[string]any)
		if s, ok := snip["text"].(string); ok && s != "" {
			return s
		}
	}
	return ""
}

// Doc redacts the whole document: every secret found in any result is masked
// everywhere (another result's message, invocations, keys), and each result gets
// the HMAC of its own secret as properties["warden.contentKey"]. A result that
// isn't an object can't be checked, so the document is refused.
func Doc(doc map[string]any, key []byte) (map[string]any, error) {
	if len(key) < MinKeyBytes {
		return nil, errors.New("HMAC key too short")
	}
	runs, _ := doc["runs"].([]any)
	var reps []replacement
	seen := map[string]bool{}
	keys := map[[2]int]string{}
	for i, r := range runs {
		run, ok := r.(map[string]any)
		if !ok {
			return nil, fmt.Errorf("runs[%d] is not an object", i)
		}
		results, _ := run["results"].([]any)
		for j, res := range results {
			m, ok := res.(map[string]any)
			if !ok {
				return nil, fmt.Errorf("runs[%d].results[%d] is not an object", i, j)
			}
			secret := firstSnippet(m)
			keys[[2]int{i, j}] = contentKey(key, secret)
			if secret != "" && !seen[secret] {
				seen[secret] = true
				reps = append(reps, replacement{secret, Mask(secret)})
			}
		}
	}
	// Longest first, so a secret that contains a shorter one is masked whole.
	slices.SortFunc(reps, func(a, b replacement) int { return cmp.Compare(len(b.secret), len(a.secret)) })

	out := scrub(doc, reps).(map[string]any)
	runs, _ = out["runs"].([]any)
	for i, r := range runs {
		results, _ := r.(map[string]any)["results"].([]any)
		for j, res := range results {
			m := res.(map[string]any)
			props, ok := m["properties"].(map[string]any)
			if !ok {
				props = map[string]any{}
				m["properties"] = props
			}
			props[ContentKeyProp] = keys[[2]int{i, j}]
		}
	}
	return out, nil
}
