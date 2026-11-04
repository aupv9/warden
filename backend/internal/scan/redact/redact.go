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

// OrgRulePrefix starts the ids of an organization's own Gitleaks rules
// (internal/rules.Prefix; not imported, this runs in the sandbox image).
const OrgRulePrefix = "org."

// Mask keeps the first 4 characters of secrets of at least 12 characters; shorter
// ones would leak too large a fraction of the secret.
func Mask(secret string) string {
	r := []rune(secret)
	if len(r) < minLenForPrefix {
		return "****"
	}
	return string(r[:visiblePrefix]) + "****"
}

// replacement is a secret, its mask, and its folded form for matching
// decoded views (see normalize).
type replacement struct{ secret, masked, norm string }

// scrub replaces every secret in every string of v, object keys included.
func scrub(v any, reps []replacement) any {
	switch t := v.(type) {
	case string:
		return scrubString(t, reps)
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

// keptFingerprints are the partialFingerprints Gitleaks writes in git mode
// that leave the sandbox. The others go: commitMessage can quote the secret
// (or another one Gitleaks didn't match), and author and email are personal
// data Warden has no use for.
var keptFingerprints = []string{"commitSha", "date"}

// dropCommitDetails keeps only keptFingerprints, and only as strings.
func dropCommitDetails(result map[string]any) {
	pf, ok := result["partialFingerprints"].(map[string]any)
	if !ok {
		delete(result, "partialFingerprints")
		return
	}
	kept := map[string]any{}
	for _, k := range keptFingerprints {
		if s, ok := pf[k].(string); ok {
			kept[k] = s
		}
	}
	result["partialFingerprints"] = kept
}

// Doc redacts the whole document: every secret found in any result is masked
// everywhere (another result's message, invocations, keys), also where a
// string only becomes the secret once decoded (scrubString), commit details
// other than the sha and date are dropped, and each result gets the HMAC of
// its own secret as properties["warden.contentKey"]. A result that isn't an
// object can't be checked, and masking that would rename the keys the parser
// finds results by can't be done safely, so such documents are refused.
func Doc(doc map[string]any, key []byte) (map[string]any, error) {
	if len(key) < MinKeyBytes {
		return nil, errors.New("HMAC key too short")
	}
	runs, _ := doc["runs"].([]any)
	var reps []replacement
	seen := map[string]bool{}
	keys := map[[2]int]string{}
	counts := make([]int, len(runs))
	hasRule := map[[2]int]bool{}
	for i, r := range runs {
		run, ok := r.(map[string]any)
		if !ok {
			return nil, fmt.Errorf("runs[%d] is not an object", i)
		}
		results, _ := run["results"].([]any)
		counts[i] = len(results)
		for j, res := range results {
			m, ok := res.(map[string]any)
			if !ok {
				return nil, fmt.Errorf("runs[%d].results[%d] is not an object", i, j)
			}
			_, hasRule[[2]int{i, j}] = m["ruleId"]
			dropCommitDetails(m)
			secret := firstSnippet(m)
			keys[[2]int{i, j}] = contentKey(key, secret)
			if secret == "" {
				continue
			}
			// An org rule chooses its own secretGroup, so rules shifted by a
			// few characters could each show a different visible prefix of
			// one key: secrets an org rule found are masked whole, and win
			// over a built-in rule's mask of the same secret.
			rid, _ := m["ruleId"].(string)
			if !seen[secret] {
				seen[secret] = true
				reps = append(reps, replacement{secret, Mask(secret), string(normalize(identity(secret)).b)})
			}
			if strings.HasPrefix(rid, OrgRulePrefix) {
				for k := range reps {
					if reps[k].secret == secret {
						reps[k].masked = "****"
					}
				}
			}
		}
	}
	// Longest first, so a secret that contains a shorter one is masked whole.
	slices.SortFunc(reps, func(a, b replacement) int { return cmp.Compare(len(b.secret), len(a.secret)) })

	out := scrub(doc, reps).(map[string]any)
	// Keys are scrubbed too, so a secret that is part of "runs", "results"
	// or "ruleId" would mask the key itself: the parser would then see no
	// results (or skip one) and the secret would go unreported. Refuse the
	// document instead, so the scan fails visibly.
	outRuns, _ := out["runs"].([]any)
	if len(outRuns) != len(runs) {
		return nil, errors.New("a secret masks the SARIF structure (runs)")
	}
	for i, r := range outRuns {
		results, _ := r.(map[string]any)["results"].([]any)
		if len(results) != counts[i] {
			return nil, errors.New("a secret masks the SARIF structure (results)")
		}
		for j, res := range results {
			m := res.(map[string]any)
			if _, ok := m["ruleId"]; hasRule[[2]int{i, j}] && !ok {
				return nil, errors.New("a secret masks the SARIF structure (ruleId)")
			}
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
