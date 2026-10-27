package sbom

import (
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"strings"
	"testing"
)

// trivySBOM has the shape `trivy convert --format cyclonedx` writes (spec 1.7).
const trivySBOM = `{
  "$schema": "http://cyclonedx.org/schema/bom-1.7.schema.json",
  "bomFormat": "CycloneDX", "specVersion": "1.7", "serialNumber": "urn:uuid:1affb067-2d5a-4500-93ac-ceda6e078819", "version": 1,
  "metadata": {"timestamp": "2026-10-27T16:51:32+00:00",
    "tools": {"components": [{"type": "application", "group": "aquasecurity", "name": "trivy", "version": "0.75.0"}]},
    "component": {"bom-ref": "06e11224", "type": "application", "name": "/src",
      "properties": [{"name": "aquasecurity:trivy:SchemaVersion", "value": "2"}, {"name": "warden:scan_id", "value": "forged"}]}},
  "components": [{"bom-ref": "pkg:npm/lodash@4.17.15", "type": "library", "name": "lodash", "version": "4.17.15",
      "licenses": [{"license": {"id": "MIT"}}]},
    {"bom-ref": "pkg:npm/%3Cscript%3E@1", "type": "library", "name": "<script>alert(1)</script>", "version": "1"}],
  "dependencies": []
}`

func TestStamp(t *testing.T) {
	s, err := Stamp([]byte(trivySBOM), "WEB", "0192f0c4-0000-7000-8000-000000000001")
	if err != nil {
		t.Fatal(err)
	}
	if s.Components != 2 {
		t.Fatal(s.Components)
	}
	sum := sha256.Sum256(s.Data)
	if s.SHA256 != hex.EncodeToString(sum[:]) {
		t.Fatal("sha256")
	}
	var doc struct {
		BOMFormat string `json:"bomFormat"`
		Metadata  struct {
			Tools     any `json:"tools"`
			Component struct {
				Name       string `json:"name"`
				Ref        string `json:"bom-ref"`
				Properties []struct {
					Name, Value string
				} `json:"properties"`
			} `json:"component"`
		} `json:"metadata"`
		Components []map[string]any `json:"components"`
	}
	if err := json.Unmarshal(s.Data, &doc); err != nil {
		t.Fatal(err)
	}
	c := doc.Metadata.Component
	if doc.BOMFormat != "CycloneDX" || c.Name != "WEB" || c.Ref != "06e11224" || doc.Metadata.Tools == nil || len(doc.Components) != 2 {
		t.Fatalf("%s", s.Data)
	}
	// The forged warden: property is gone; ours is the only one.
	if len(c.Properties) != 2 || c.Properties[0].Name != "aquasecurity:trivy:SchemaVersion" ||
		c.Properties[1].Name != ScanIDProperty || c.Properties[1].Value != "0192f0c4-0000-7000-8000-000000000001" {
		t.Fatalf("%+v", c.Properties)
	}
	if strings.Contains(string(s.Data), "<script>") {
		t.Fatal("markup kept unescaped")
	}
}

func TestStampAddsMissingMetadata(t *testing.T) {
	s, err := Stamp([]byte(`{"bomFormat":"CycloneDX"}`), "API", "id")
	if err != nil {
		t.Fatal(err)
	}
	if s.Components != 0 || !strings.Contains(string(s.Data), `"component":{"name":"API","properties":[{"name":"warden:scan_id","value":"id"}],"type":"application"}`) {
		t.Fatalf("%s", s.Data)
	}
}

func TestStampRejectsHostileInput(t *testing.T) {
	for name, raw := range map[string]string{
		"not JSON":          `{`,
		"array":             `[]`,
		"null":              `null`,
		"string":            `"CycloneDX"`,
		"trailing":          `{"bomFormat":"CycloneDX"} {}`,
		"not cyclonedx":     `{"bomFormat":"SPDX"}`,
		"format type":       `{"bomFormat":["CycloneDX"]}`,
		"no format":         `{"components":[]}`,
		"components object": `{"bomFormat":"CycloneDX","components":{"a":1}}`,
		"metadata array":    `{"bomFormat":"CycloneDX","metadata":[]}`,
		"component string":  `{"bomFormat":"CycloneDX","metadata":{"component":"x"}}`,
		"properties object": `{"bomFormat":"CycloneDX","metadata":{"component":{"properties":{}}}}`,
		"deep nesting":      `{"bomFormat":"CycloneDX","x":` + strings.Repeat("[", 20000) + strings.Repeat("]", 20000) + `}`,
		"too large":         `{"bomFormat":"CycloneDX","x":"` + strings.Repeat("a", MaxBytes) + `"}`,
	} {
		if _, err := Stamp([]byte(raw), "WEB", "id"); !errors.Is(err, ErrSBOM) {
			t.Errorf("%s: got %v", name, err)
		}
	}
}
