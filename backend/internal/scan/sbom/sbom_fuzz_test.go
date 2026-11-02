package sbom

import (
	"bytes"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"strings"
	"testing"
)

// member is one object member of a JSON document, duplicates included
// (encoding/json keeps the last of a repeated key; other readers may take
// the first).
type member struct {
	path  string // "metadata.component.properties[]"
	key   string
	value any // scalars only; nil for objects and arrays
}

// members lists every object member of doc by walking its tokens.
func members(t *testing.T, doc []byte) []member {
	t.Helper()
	dec := json.NewDecoder(bytes.NewReader(doc))
	dec.UseNumber()
	var out []member
	var walk func(path string) error
	walk = func(path string) error {
		tok, err := dec.Token()
		if err != nil {
			return err
		}
		switch tok {
		case json.Delim('{'):
			for dec.More() {
				k, err := dec.Token()
				if err != nil {
					return err
				}
				key := k.(string)
				m := member{path: path, key: key}
				// Peek at scalars: decode the value as a RawMessage, then walk it.
				var raw json.RawMessage
				if err := dec.Decode(&raw); err != nil {
					return err
				}
				if len(raw) > 0 && raw[0] != '{' && raw[0] != '[' {
					_ = json.Unmarshal(raw, &m.value)
				}
				out = append(out, m)
				sub := json.NewDecoder(bytes.NewReader(raw))
				outer := dec
				dec = sub
				err = walk(strings.TrimPrefix(path+"."+key, "."))
				dec = outer
				if err != nil {
					return err
				}
			}
			_, err = dec.Token()
			return err
		case json.Delim('['):
			for dec.More() {
				if err := walk(path + "[]"); err != nil {
					return err
				}
			}
			_, err = dec.Token()
			return err
		}
		return nil
	}
	if err := walk(""); err != nil {
		t.Fatalf("output is not JSON: %v", err)
	}
	return out
}

// marshaled is s as it reads back after json.Marshal (invalid UTF-8 replaced).
func marshaled(s string) string {
	b, _ := json.Marshal(s)
	var back string
	_ = json.Unmarshal(b, &back)
	return back
}

// checkStamped: valid JSON with nothing that could be markup, the hash of
// the data, and stamping again changes nothing.
func checkStamped(t *testing.T, s *Stamped, again func([]byte) (*Stamped, error)) {
	t.Helper()
	if !json.Valid(s.Data) || bytes.ContainsAny(s.Data, "<>&") {
		t.Fatalf("output %q", s.Data)
	}
	if sum := sha256.Sum256(s.Data); s.SHA256 != hex.EncodeToString(sum[:]) {
		t.Fatal("sha256")
	}
	s2, err := again(s.Data)
	if err != nil || !bytes.Equal(s2.Data, s.Data) || s2.Components != s.Components {
		t.Fatalf("stamping again: %v\n%s\n%s", err, s.Data, s2.Data)
	}
}

func FuzzStamp(f *testing.F) {
	f.Add([]byte(trivySBOM), "WEB", scanID)
	f.Add([]byte(`{"bomFormat":"CycloneDX"}`), "API", "id")
	f.Add([]byte(`{"bomFormat":"CycloneDX","metadata":{"component":{"name":"/src","properties":[{"name":"warden:scan_id","name":"x","value":"forged"},{"NAME":"warden:x"},7]}}}`), "<b>", "</b>")
	f.Add([]byte(`{"bomFormat":"CycloneDX","components":{}}`), "x", "y")
	f.Fuzz(func(t *testing.T, raw []byte, name, id string) {
		if len(raw) > 64<<10 {
			return
		}
		s, err := Stamp(raw, name, id)
		if err != nil {
			if !errors.Is(err, ErrSBOM) {
				t.Fatalf("error that isn't ErrSBOM: %v", err)
			}
			return
		}
		checkStamped(t, s, func(b []byte) (*Stamped, error) { return Stamp(b, name, id) })
		var names, stamps int
		for _, m := range members(t, s.Data) {
			switch {
			case m.path == "metadata.component" && m.key == "name":
				names++
				if m.value != marshaled(name) {
					t.Fatalf("root component named %v, want %q", m.value, name)
				}
			case m.path == "metadata.component.properties[]" && strings.EqualFold(m.key, "name"):
				if v, _ := m.value.(string); strings.HasPrefix(strings.ToLower(v), "warden:") {
					stamps++
				}
			}
		}
		if names != 1 || stamps != 1 {
			t.Fatalf("%d root names, %d warden: properties in %s", names, stamps, s.Data)
		}
	})
}

func FuzzStampSPDX(f *testing.F) {
	f.Add([]byte(trivySPDX), "WEB", scanID)
	f.Add([]byte(`{"spdxVersion":"SPDX-2.3"}`), "API", "id")
	f.Add([]byte(`{"spdxVersion":"SPDX-2.3","creationInfo":{"comment":"a","comment":"b"},"packages":[{"SPDXID":"A","name":"x"},{"SPDXID":"A"}],
		"relationships":[{"spdxElementId":"SPDXRef-DOCUMENT","relatedSpdxElement":"A","relationshipType":"DESCRIBES"}]}`), "<b>", "&")
	f.Fuzz(func(t *testing.T, raw []byte, name, id string) {
		if len(raw) > 64<<10 {
			return
		}
		s, err := StampSPDX(raw, name, id)
		if err != nil {
			if !errors.Is(err, ErrSBOM) {
				t.Fatalf("error that isn't ErrSBOM: %v", err)
			}
			return
		}
		checkStamped(t, s, func(b []byte) (*Stamped, error) { return StampSPDX(b, name, id) })
		var comments, names, namespaces int
		for _, m := range members(t, s.Data) {
			switch {
			case m.path == "creationInfo" && strings.EqualFold(m.key, "comment"):
				comments++
				if m.value != marshaled(SPDXScanIDPrefix+id) {
					t.Fatalf("comment %v", m.value)
				}
			case m.path == "" && strings.EqualFold(m.key, "name"):
				names++
				if m.value != marshaled(name) {
					t.Fatalf("document named %v", m.value)
				}
			case m.path == "" && strings.EqualFold(m.key, "documentNamespace"):
				namespaces++
				if m.value != marshaled("urn:uuid:"+id) {
					t.Fatalf("namespace %v", m.value)
				}
			}
		}
		if comments != 1 || names != 1 || namespaces != 1 {
			t.Fatalf("%d comments, %d names, %d namespaces in %s", comments, names, namespaces, s.Data)
		}
	})
}
