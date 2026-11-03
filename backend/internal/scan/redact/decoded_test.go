package redact_test

import (
	"encoding/json"
	"strings"
	"testing"

	"github.com/aupv9/warden/backend/internal/scan/redact"
	"github.com/aupv9/warden/backend/internal/scan/sarif"
	st "github.com/aupv9/warden/backend/internal/scan/scantest"
)

// parsedPaths runs the redacted document through the SARIF parser, as the
// worker does, and returns each issue's path.
func parsedPaths(t *testing.T, out map[string]any, history bool) []string {
	t.Helper()
	b, err := json.Marshal(out)
	if err != nil {
		t.Fatal(err)
	}
	doc, err := sarif.Decode(strings.NewReader(string(b)))
	if err != nil {
		t.Fatal(err)
	}
	fs, err := sarif.Parse(doc.(st.M), "gitleaks", sarif.Options{History: history})
	if err != nil {
		t.Fatal(err)
	}
	var paths []string
	for _, f := range fs {
		paths = append(paths, f.FilePath)
	}
	return paths
}

// assertNoReading fails if any string of v (object keys included), or any
// decoding of one, still holds secret.
func assertNoReading(t *testing.T, v any, secret, form string) {
	t.Helper()
	if s, ok := leaked(v, []string{secret}); ok {
		t.Errorf("form %q: secret readable from %q", form, s)
	}
}

// secretPathDoc is one Gitleaks result for a file whose path holds form (an
// encoding of secret), the secret also quoted in another field's key and in
// a message the way an attacker could.
func secretPathDoc(uri, secret, form string) st.M {
	r := st.M{
		"ruleId":    "generic-api-key",
		"message":   st.M{"text": "found in " + form},
		"locations": []any{st.Loc(uri, 1, secret)},
	}
	r["partialFingerprints"] = st.M{"commitSha": strings.Repeat("a1", 20), "date": "2026-10-28T21:36:59Z"}
	doc := st.Doc([]any{r})
	doc["runs"].([]any)[0].(st.M)["invocations"] = []any{st.M{"commandLine": "x " + form, form: true}}
	return doc
}

// Found by v0.5's fuzzing and confirmed against Gitleaks v8.30.1: it writes
// a file's path into artifactLocation.uri as is, so a file named
// "%41KIA…" next to the key "AKIA…" gave the uri "/src/sub dir/%41KIA….txt",
// which the redactor left alone and the parser decoded back into the key.
func TestRedactMasksPercentEncodedSecretInPath(t *testing.T) {
	secret := st.FakeSecret
	uri := "/src/sub dir/%41" + secret[1:] + ".txt"
	out, err := redact.Doc(st.RoundTrip(secretPathDoc(uri, secret, "%41"+secret[1:])), st.HMACKey)
	if err != nil {
		t.Fatal(err)
	}
	assertNoReading(t, out, secret, uri)
	paths := parsedPaths(t, out, false)
	if len(paths) != 1 || paths[0] != "sub dir/AKIA****.txt" {
		t.Fatalf("paths %q", paths)
	}
}

// Every encoding of the secret, for secrets with "/", "%", "+", spaces and
// non-ASCII, in source and history mode, under file: and plain URIs.
func TestRedactMasksEveryEncodingOfSecret(t *testing.T) {
	secrets := []string{
		st.FakeSecret,
		"ab/cd%ef gh" + "€ij+kl" + "/9Zq",
		"x+y z%2Fw/" + strings.Repeat("Q", 9),
		"short/%2",
		"kéy_" + strings.Repeat("ü", 6) + "%41",
	}
	for _, secret := range secrets {
		for _, form := range encodings(secret) {
			for _, uri := range []string{
				"/src/" + form + ".txt",
				"/src/dir/" + form,
				"file:///src/dir/" + form + "/x.py",
				"lib/" + form,
			} {
				for _, history := range []bool{false, true} {
					out, err := redact.Doc(st.RoundTrip(secretPathDoc(uri, secret, form)), st.HMACKey)
					if err != nil {
						t.Fatalf("%q in %q: %v", secret, uri, err)
					}
					assertNoReading(t, out, secret, uri)
					for _, p := range parsedPaths(t, out, history) {
						if strings.Contains(p, secret) {
							t.Errorf("%q: path %q", uri, p)
						}
					}
				}
			}
		}
	}
}

// The mask's visible prefix is escaped where the secret was matched only
// after decoding, so it doesn't change how the rest of the URI parses; the
// literal snippet keeps the plain mask.
func TestRedactEscapesMaskInDecodedMatch(t *testing.T) {
	secret := "a%b/" + "cdefghij" + "klmn"
	uri := "file:///src/dir/" + pct(secret, 'U') + ".txt?x#y"
	out, err := redact.Doc(st.RoundTrip(secretPathDoc(uri, secret, "z")), st.HMACKey)
	if err != nil {
		t.Fatal(err)
	}
	loc := out["runs"].([]any)[0].(st.M)["results"].([]any)[0].(st.M)["locations"].([]any)[0].(st.M)["physicalLocation"].(st.M)
	if got := loc["artifactLocation"].(st.M)["uri"]; got != "file:///src/dir/a%25b%2F****.txt?x#y" {
		t.Fatalf("uri %q", got)
	}
	if got := loc["region"].(st.M)["snippet"].(st.M)["text"]; got != "a%b/****" {
		t.Fatalf("snippet %q", got)
	}
}

// Strings that only decode or fold, and hold no secret, are left alone.
func TestRedactLeavesOtherEncodedStringsAlone(t *testing.T) {
	deep := "%41"
	for range 20 {
		deep = strings.ReplaceAll(deep, "%", "%25")
	}
	uris := []string{
		"/src/dir%20one/a+b.py",
		`/src/win\path//x/./y.py`,
		"/src/%E2%82%AC/%ZZ/%4",
		"/src/" + deep,
	}
	results := []any{st.M{"ruleId": "aws-access-token", "locations": []any{st.Loc("a.py", 1, st.FakeSecret)}}}
	for _, u := range uris {
		results = append(results, st.M{"ruleId": "x", "locations": []any{st.Loc(u, 1, "")}})
	}
	out, err := redact.Doc(st.RoundTrip(st.Doc(results)), st.HMACKey)
	if err != nil {
		t.Fatal(err)
	}
	res := out["runs"].([]any)[0].(st.M)["results"].([]any)
	for i, u := range uris {
		got := res[i+1].(st.M)["locations"].([]any)[0].(st.M)["physicalLocation"].(st.M)["artifactLocation"].(st.M)["uri"]
		want := u
		if i == len(uris)-1 {
			want = "****" // nested past what the redactor checks
		}
		if got != want {
			t.Errorf("uri %q became %q", u, got)
		}
	}
}

// Without any secret in the document, nothing is checked or masked, however
// deep the nesting.
func TestRedactNoSecretsKeepsDeepNesting(t *testing.T) {
	u := "/src/%41"
	for range 20 {
		u = strings.ReplaceAll(u, "%", "%25")
	}
	out, err := redact.Doc(st.RoundTrip(st.Doc([]any{st.M{"ruleId": "x", "locations": []any{st.Loc(u, 1, "")}}})), st.HMACKey)
	if err != nil {
		t.Fatal(err)
	}
	if got := out["runs"].([]any)[0].(st.M)["results"].([]any)[0].(st.M)["locations"].([]any)[0].(st.M)["physicalLocation"].(st.M)["artifactLocation"].(st.M)["uri"]; got != u {
		t.Fatal(got)
	}
}

// Nested deeper than the redactor follows, a string holding a secret's
// encoding is masked whole.
func TestRedactMasksDeepNestingWhole(t *testing.T) {
	secret := st.FakeSecret
	form := pct(secret, 'U')
	for range 20 {
		form = strings.ReplaceAll(form, "%", "%25")
	}
	out, err := redact.Doc(st.RoundTrip(secretPathDoc("/src/"+form, secret, "y")), st.HMACKey)
	if err != nil {
		t.Fatal(err)
	}
	got := out["runs"].([]any)[0].(st.M)["results"].([]any)[0].(st.M)["locations"].([]any)[0].(st.M)["physicalLocation"].(st.M)["artifactLocation"].(st.M)["uri"]
	if got != "****" {
		t.Fatal(got)
	}
}

// Invalid UTF-8 a decoder turns into U+FFFD must not complete a secret that
// holds U+FFFD (Gitleaks reports a secret with invalid bytes that way).
func TestRedactMasksSecretRebuiltByReplacementChar(t *testing.T) {
	secret := "�zq" + strings.Repeat("W", 12)
	for _, form := range []string{"%FFzq" + strings.Repeat("W", 12), "%ff%FEzq" + strings.Repeat("W", 12)} {
		out, err := redact.Doc(st.RoundTrip(secretPathDoc("/src/"+form, secret, form)), st.HMACKey)
		if err != nil {
			t.Fatal(err)
		}
		assertNoReading(t, out, secret, form)
	}
}
