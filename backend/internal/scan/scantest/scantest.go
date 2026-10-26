// Package scantest builds SARIF fixtures for tests. Secrets are assembled at run
// time so no real-looking credential is committed (CLAUDE.md).
package scantest

import (
	"bytes"
	"encoding/json"

	"github.com/aupv9/warden/backend/internal/scan/sarif"
)

// FakeSecret looks like an AWS access key id to Gitleaks.
var FakeSecret = "AKIA" + "Z7Q3EXAMPLEKEY99"

var HMACKey = bytes.Repeat([]byte("k"), 64)

type M = map[string]any

func Doc(results []any, rules ...any) M {
	if rules == nil {
		rules = []any{}
	}
	return M{
		"version": "2.1.0",
		"runs":    []any{M{"tool": M{"driver": M{"name": "x", "rules": rules}}, "results": results}},
	}
}

func Loc(uri string, start int, snippet ...string) M {
	region := M{"startLine": json.Number(itoa(start)), "endLine": json.Number(itoa(start))}
	if len(snippet) > 0 {
		region["snippet"] = M{"text": snippet[0]}
	}
	return M{"physicalLocation": M{"artifactLocation": M{"uri": uri}, "region": region}}
}

func GitleaksDoc() M {
	return Doc([]any{M{
		"ruleId":              "aws-access-token",
		"message":             M{"text": "aws-access-token has detected secret " + FakeSecret},
		"locations":           []any{Loc("app/config.py", 3, FakeSecret)},
		"partialFingerprints": M{"commitMessage": "oops " + FakeSecret},
	}})
}

// RoundTrip serializes and re-decodes a fixture the way Load would see it.
func RoundTrip(doc M) M {
	b, err := json.Marshal(doc)
	if err != nil {
		panic(err)
	}
	v, err := sarif.Decode(bytes.NewReader(b))
	if err != nil {
		panic(err)
	}
	return v.(M)
}

func itoa(i int) string {
	b, _ := json.Marshal(i)
	return string(b)
}
