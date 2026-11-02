package redact_test

import (
	"regexp"
	"strings"
	"testing"

	"github.com/aupv9/warden/backend/internal/scan/redact"
	st "github.com/aupv9/warden/backend/internal/scan/scantest"
)

var hex64 = regexp.MustCompile(`^[0-9a-f]{64}$`)

// leaked walks every string of the redacted document, object keys included,
// and returns the first that still contains a secret. The content key Warden
// adds after scrubbing (a property name and an HMAC) is not scanner output.
func leaked(v any, secrets []string) (string, bool) {
	switch t := v.(type) {
	case string:
		for _, s := range secrets {
			if strings.Contains(t, s) {
				return t, true
			}
		}
	case []any:
		for _, e := range t {
			if s, ok := leaked(e, secrets); ok {
				return s, true
			}
		}
	case map[string]any:
		for k, e := range t {
			if k == redact.ContentKeyProp {
				if s, _ := e.(string); hex64.MatchString(s) {
					continue
				}
			}
			// Doc adds these keys after scrubbing (a result whose properties
			// key was masked gets a new one): they are Warden's, not output.
			if k != "properties" && k != redact.ContentKeyProp {
				if s, ok := leaked(k, secrets); ok {
					return s, true
				}
			}
			if s, ok := leaked(e, secrets); ok {
				return s, true
			}
		}
	}
	return "", false
}

// FuzzDoc: no secret Gitleaks reported survives anywhere in the redacted
// document (messages, other results, object keys, commit messages), commit
// details other than the sha and date are dropped, and every result gets a
// content key. Secrets containing the mask character are left out of the
// property: the mask itself ("****") would then count as a leak.
func FuzzDoc(f *testing.F) {
	f.Add(st.FakeSecret, "ghp_"+strings.Repeat("Q", 36), "aws-access-token has detected secret ", " in config", "add key")
	f.Add("abcdefghijkl", "abcdefghijklMNOPQRSTUVWX", "x", "y", "z")
	f.Add("abc123", "abc123abc123", "abc", "123", "abc123")
	f.Add("ĀĀĀĀĀĀĀĀĀĀĀĀ", "hunter2-xxxxxxxx", "Ā", "hunter2", "")
	f.Add("abcdEFGHabcd", "EFGHabcdEFGH", "abcdEFGH", "abcd", "EFGH")
	f.Fuzz(func(t *testing.T, secret1, secret2, before, after, commitMsg string) {
		if len(secret1)+len(secret2)+len(before)+len(after)+len(commitMsg) > 4096 {
			return
		}
		const author, email = "Author Q7xR2", "q7xr2@example.test"
		c := st.Commit{SHA: strings.Repeat("a1", 20), Date: "2026-10-28T21:36:59Z", Author: author, Email: email,
			Message: commitMsg + secret1 + secret2}
		r1 := st.HistoryResult("rule-a", "a/"+before+".py", 1, secret1, c)
		r1["message"] = st.M{"text": before + secret2 + after + secret1}
		r2 := st.HistoryResult("rule-b", after, 2, secret2, c)
		r2["properties"] = st.M{before + secret1 + after: secret2 + before, "tags": []any{after + secret2}}
		doc := st.Doc([]any{r1, r2})
		doc["runs"].([]any)[0].(st.M)["invocations"] = []any{st.M{"commandLine": before + secret1 + secret2 + after, secret2: secret1}}
		rt := st.RoundTrip(doc)

		// The secrets as the redactor sees them (the JSON round trip makes
		// invalid UTF-8 into U+FFFD).
		res := rt["runs"].([]any)[0].(st.M)["results"].([]any)
		var secrets []string
		for _, r := range res {
			loc := r.(st.M)["locations"].([]any)[0].(st.M)["physicalLocation"].(st.M)
			s := loc["region"].(st.M)["snippet"].(st.M)["text"].(string)
			if s != "" && !strings.Contains(s, "*") {
				secrets = append(secrets, s)
			}
		}

		out, err := redact.Doc(rt, st.HMACKey)
		if err != nil {
			// Refused only when a secret would mask the keys results are found by.
			for _, s := range []string{secret1, secret2} {
				if s != "" && (strings.Contains("runs", s) || strings.Contains("results", s) || strings.Contains("ruleId", s)) {
					return
				}
			}
			t.Fatal(err)
		}
		if s, ok := leaked(out, secrets); ok {
			t.Fatalf("secret left in %q", s)
		}
		// Author and email never leave the sandbox (unless the fuzzer put
		// them in another field).
		if in := secret1 + secret2 + before + after + commitMsg; !strings.Contains(in, "Q7xR2") && !strings.Contains(in, "q7xr2") {
			if s, ok := leaked(out, []string{"Q7xR2", "q7xr2"}); ok {
				t.Fatalf("commit author or email left in %q", s)
			}
		}
		runs, _ := out["runs"].([]any)
		if len(runs) != 1 {
			t.Fatalf("structure changed: %v", out)
		}
		results, _ := runs[0].(st.M)["results"].([]any)
		if len(results) != 2 {
			t.Fatalf("structure changed: %v", out)
		}
		for _, r := range results {
			m := r.(st.M)
			if pf, _ := m["partialFingerprints"].(st.M); len(pf) > 2 {
				t.Fatalf("partialFingerprints kept %v", pf)
			}
			if key, _ := m["properties"].(st.M)[redact.ContentKeyProp].(string); !hex64.MatchString(key) {
				t.Fatalf("content key %q", key)
			}
		}
	})
}

// FuzzMask: the mask never holds more than 4 characters of the secret, and
// none of one shorter than 12.
func FuzzMask(f *testing.F) {
	f.Add(st.FakeSecret)
	f.Add("abc123")
	f.Add("ĀĀĀĀĀĀĀĀĀĀĀĀ")
	f.Add("\xff\xfe\xfd\xfc\xfb\xfa\xf9\xf8\xf7\xf6\xf5\xf4")
	f.Fuzz(func(t *testing.T, secret string) {
		m := redact.Mask(secret)
		kept, ok := strings.CutSuffix(m, "****")
		if !ok || (kept != "" && len([]rune(secret)) < 12) || len([]rune(kept)) > 4 || !strings.HasPrefix(secret, kept) && kept != string([]rune(secret)[:4]) {
			t.Fatalf("Mask(%q) = %q", secret, m)
		}
	})
}
