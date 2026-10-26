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
