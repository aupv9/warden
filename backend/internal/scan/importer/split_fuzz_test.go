package importer

import (
	"bytes"
	"encoding/json"
	"errors"
	"testing"
)

// FuzzElements: on any valid JSON, elements and members cut exactly what
// encoding/json reads (same elements, same keys and values, in order), and
// on anything else they return an error or nothing, never panic.
func FuzzElements(f *testing.F) {
	for _, s := range []string{
		`[]`, `[1, "a", {"b": [2, "]"]}, null, true, -1.5e3]`, ` [ "\"]\\" , {} ] `, `{"a": 1, "b\"": [ "}" ], "": {}}`,
		`{}`, `"x"`, `[`, `[1,]`, `{"a" 1}`, `[[[[]]]]`, `{"k":"A"}`,
	} {
		f.Add([]byte(s))
	}
	f.Fuzz(func(t *testing.T, raw []byte) {
		var got []json.RawMessage
		errArr := elements(raw, 1<<20, func(el json.RawMessage) error { got = append(got, el); return nil })
		var keys []string
		var vals []json.RawMessage
		members(raw, 1<<20, func(k string, v json.RawMessage) { keys = append(keys, k); vals = append(vals, v) })
		if !json.Valid(raw) {
			return
		}
		var arr []json.RawMessage
		if json.Unmarshal(raw, &arr) == nil && arr != nil {
			if errArr != nil || len(got) != len(arr) {
				t.Fatalf("elements: %v, %d vs %d", errArr, len(got), len(arr))
			}
			for i := range arr {
				if !bytes.Equal(bytes.TrimSpace(got[i]), bytes.TrimSpace(arr[i])) {
					t.Fatalf("element %d: %q vs %q", i, got[i], arr[i])
				}
			}
		} else if errArr != nil && !errors.Is(errArr, errNotArray) {
			t.Fatalf("elements of a non-array: %v", errArr)
		}
		// Object members in document order (duplicates included): decode the
		// object token by token to compare.
		dec := json.NewDecoder(bytes.NewReader(raw))
		if tok, err := dec.Token(); err != nil || tok != json.Delim('{') {
			if len(keys) != 0 {
				t.Fatalf("members of a non-object: %q", keys)
			}
			return
		}
		for i := 0; dec.More(); i++ {
			tok, _ := dec.Token()
			var v json.RawMessage
			if err := dec.Decode(&v); err != nil {
				t.Fatal(err)
			}
			if i >= len(keys) || keys[i] != tok.(string) || !bytes.Equal(bytes.TrimSpace(vals[i]), bytes.TrimSpace(v)) {
				t.Fatalf("member %d: %q", i, keys)
			}
		}
	})
}

func TestElementsLimit(t *testing.T) {
	n := 0
	err := elements([]byte(`[1,2,3]`), 2, func(json.RawMessage) error { n++; return nil })
	if !errors.Is(err, errTooMany) || n != 2 {
		t.Fatal(err, n)
	}
	if err := elements([]byte(`[1,2]`), 2, func(json.RawMessage) error { return nil }); err != nil {
		t.Fatal(err)
	}
	if err := elements([]byte(`{"a":1}`), 2, func(json.RawMessage) error { return nil }); !errors.Is(err, errNotArray) {
		t.Fatal(err)
	}
	var first []string
	firstElements([]byte(`["a","b","c"]`), 2, func(el json.RawMessage) { first = append(first, string(el)) })
	if len(first) != 2 {
		t.Fatal(first)
	}
}
