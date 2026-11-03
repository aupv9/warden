package redact_test

import (
	"encoding/json"
	"strings"
	"testing"

	"github.com/aupv9/warden/backend/internal/scan/redact"
	st "github.com/aupv9/warden/backend/internal/scan/scantest"
)

func blob(t *testing.T, v any) string {
	t.Helper()
	b, err := json.Marshal(v)
	if err != nil {
		t.Fatal(err)
	}
	return string(b)
}

func TestRedactRemovesSecretEverywhere(t *testing.T) {
	out, err := redact.Doc(st.RoundTrip(st.GitleaksDoc()), st.HMACKey)
	if err != nil {
		t.Fatal(err)
	}
	s := blob(t, out)
	if strings.Contains(s, st.FakeSecret) || !strings.Contains(s, "AKIA****") {
		t.Fatal(s)
	}
	res := out["runs"].([]any)[0].(st.M)["results"].([]any)[0].(st.M)
	if key := res["properties"].(st.M)[redact.ContentKeyProp].(string); len(key) != 64 {
		t.Fatal(key)
	}
}

func TestRedactMasksShortSecretsFully(t *testing.T) {
	if redact.Mask("abc123") != "****" {
		t.Fatal(redact.Mask("abc123"))
	}
	if redact.Mask("ĀĀĀĀĀĀĀĀĀĀĀĀ") != "ĀĀĀĀ****" { // counts characters, not bytes
		t.Fatal(redact.Mask("ĀĀĀĀĀĀĀĀĀĀĀĀ"))
	}
}

// Secret B appears in result A's message and in an object key; both must go.
func TestRedactMasksSecretsAcrossResultsAndKeys(t *testing.T) {
	other := "ghp_" + strings.Repeat("Q", 36)
	doc := st.GitleaksDoc()
	run := doc["runs"].([]any)[0].(st.M)
	run["results"] = append(run["results"].([]any), st.M{
		"ruleId":    "github-pat",
		"message":   st.M{"text": "see " + st.FakeSecret},
		"locations": []any{st.Loc("b.py", 1, other)},
	})
	run["results"].([]any)[0].(st.M)["message"] = st.M{"text": "also " + other}
	run["invocations"] = []any{st.M{"commandLine": "x", other: true}}

	out, err := redact.Doc(st.RoundTrip(doc), st.HMACKey)
	if err != nil {
		t.Fatal(err)
	}
	s := blob(t, out)
	if strings.Contains(s, st.FakeSecret) || strings.Contains(s, other) {
		t.Fatal(s)
	}
}

// Git mode: the commit message (which can quote this secret or one Gitleaks
// didn't match), the author and the email never leave the sandbox; the sha
// and date do, as strings only.
func TestRedactDropsCommitDetails(t *testing.T) {
	unmatched := "hunter2-" + strings.Repeat("x", 8)
	sha := strings.Repeat("a1", 20)
	c := st.Commit{SHA: sha, Date: "2026-10-28T21:36:59Z", Author: "Alice Example", Email: "alice@example.test",
		Message: "add key " + st.FakeSecret + " and " + unmatched}
	weird := st.HistoryResult("generic-api-key", "b.env", 2, "s3cr3t-"+strings.Repeat("y", 10), c)
	weird["partialFingerprints"] = st.M{"commitSha": st.M{"nested": "Alice Example"}, "date": 7, "commitMessage": "x", "extra": "alice@example.test"}
	bare := st.HistoryResult("generic-api-key", "c.env", 3, "s3cr3t-"+strings.Repeat("z", 10), c)
	bare["partialFingerprints"] = "Alice Example <alice@example.test>"
	doc := st.Doc([]any{st.HistoryResult("aws-access-token", "config.py", 1, st.FakeSecret, c), weird, bare})

	out, err := redact.Doc(st.RoundTrip(doc), st.HMACKey)
	if err != nil {
		t.Fatal(err)
	}
	s := blob(t, out)
	for _, leak := range []string{st.FakeSecret, unmatched, "Alice", "alice@", "commitMessage", "author", "email", "add key"} {
		if strings.Contains(s, leak) {
			t.Errorf("%q left the sandbox: %s", leak, s)
		}
	}
	results := out["runs"].([]any)[0].(st.M)["results"].([]any)
	pf := results[0].(st.M)["partialFingerprints"].(st.M)
	if len(pf) != 2 || pf["commitSha"] != sha || pf["date"] != "2026-10-28T21:36:59Z" {
		t.Fatal(pf)
	}
	if pf := results[1].(st.M)["partialFingerprints"].(st.M); len(pf) != 0 {
		t.Fatal(pf)
	}
	if _, ok := results[2].(st.M)["partialFingerprints"]; ok {
		t.Fatal(results[2])
	}
}

func TestRedactPrefersLongestSecret(t *testing.T) {
	short := "abcdefghijkl"
	long := short + "MNOPQRSTUVWX"
	doc := st.Doc([]any{
		st.M{"ruleId": "a", "locations": []any{st.Loc("a", 1, short)}},
		st.M{"ruleId": "b", "message": st.M{"text": long}, "locations": []any{st.Loc("b", 1, long)}},
	})
	out, err := redact.Doc(st.RoundTrip(doc), st.HMACKey)
	if err != nil {
		t.Fatal(err)
	}
	if s := blob(t, out); strings.Contains(s, "MNOPQRSTUVWX") {
		t.Fatal(s)
	}
}

func TestRedactReplacesNonObjectProperties(t *testing.T) {
	doc := st.GitleaksDoc()
	doc["runs"].([]any)[0].(st.M)["results"].([]any)[0].(st.M)["properties"] = "junk"
	out, err := redact.Doc(st.RoundTrip(doc), st.HMACKey)
	if err != nil {
		t.Fatal(err)
	}
	props := out["runs"].([]any)[0].(st.M)["results"].([]any)[0].(st.M)["properties"].(st.M)
	if _, ok := props[redact.ContentKeyProp]; !ok {
		t.Fatal(props)
	}
}

func TestRedactRefusesUncheckableResults(t *testing.T) {
	doc := st.Doc([]any{"AKIA-in-a-bare-string"})
	if _, err := redact.Doc(st.RoundTrip(doc), st.HMACKey); err == nil {
		t.Fatal("non-object result passed through unredacted")
	}
	if _, err := redact.Doc(st.Doc(nil), []byte("short")); err == nil {
		t.Fatal("short key accepted")
	}
}

// Found by FuzzDoc: keys are masked too, so a secret inside "results" (or
// "runs", "ruleId") renamed the key, the parser saw no results and the
// secret went unreported (and without a content key). Such a document is
// refused, which fails the scan visibly.
func TestRedactRefusesSecretThatMasksStructure(t *testing.T) {
	for _, secret := range []string{"sul", "run", "eId"} {
		doc := st.Doc([]any{st.M{"ruleId": "r", "locations": []any{st.Loc("a.py", 1, secret)}}})
		if out, err := redact.Doc(st.RoundTrip(doc), st.HMACKey); err == nil {
			t.Errorf("%q: accepted %v", secret, out)
		}
	}
	// A secret elsewhere in a key is still masked, not refused.
	doc := st.Doc([]any{st.M{"ruleId": "r", "locations": []any{st.Loc("a.py", 1, "hunter2-xxxxxxxx")}, "hunter2-xxxxxxxx": 1}})
	if out, err := redact.Doc(st.RoundTrip(doc), st.HMACKey); err != nil || strings.Contains(blob(t, out), "hunter2-xxxxxxxx") {
		t.Fatal(out, err)
	}
}

func TestContentKeyDependsOnOrgKey(t *testing.T) {
	key := func(k []byte) string {
		out, err := redact.Doc(st.RoundTrip(st.GitleaksDoc()), k)
		if err != nil {
			t.Fatal(err)
		}
		return out["runs"].([]any)[0].(st.M)["results"].([]any)[0].(st.M)["properties"].(st.M)[redact.ContentKeyProp].(string)
	}
	if key(st.HMACKey) == key([]byte(strings.Repeat("z", 64))) {
		t.Fatal("content key ignores the org key")
	}
}

// An org rule picks its own secretGroup, so shifted rules could each show a
// different 4-character prefix of one key: whatever an org rule found is
// masked whole, also when a built-in rule found the same secret.
func TestRedactMasksOrgRuleSecretsWhole(t *testing.T) {
	other := "ghp_" + strings.Repeat("Z", 36)
	doc := st.GitleaksDoc() // a built-in finding of st.FakeSecret
	run := doc["runs"].([]any)[0].(st.M)
	run["results"] = append(run["results"].([]any),
		st.M{"ruleId": "org.acme", "message": st.M{"text": "m"}, "locations": []any{st.Loc("b.py", 1, other)}},
		st.M{"ruleId": "org.shifted", "message": st.M{"text": "m"}, "locations": []any{st.Loc("a.py", 1, st.FakeSecret)}},
	)
	out, err := redact.Doc(st.RoundTrip(doc), st.HMACKey)
	if err != nil {
		t.Fatal(err)
	}
	s := blob(t, out)
	if strings.Contains(s, other) || strings.Contains(s, st.FakeSecret) || strings.Contains(s, "ghp_****") || strings.Contains(s, "AKIA****") {
		t.Fatal(s)
	}
}
