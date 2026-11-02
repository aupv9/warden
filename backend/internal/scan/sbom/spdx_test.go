package sbom

import (
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"strings"
	"testing"
)

// trivySPDX has the shape `trivy convert --format spdx-json` writes (0.75.0,
// SPDX 2.3), trimmed: the filesystem root the document describes, a lockfile
// and two packages, one of them with a hostile name.
const trivySPDX = `{
  "spdxVersion": "SPDX-2.3", "dataLicense": "CC0-1.0", "SPDXID": "SPDXRef-DOCUMENT", "name": "/src",
  "documentNamespace": "http://trivy.dev/filesystem//src-f5226aa8-ba7b-41d5-ae2e-1d65f14f3366",
  "creationInfo": {"creators": ["Organization: aquasecurity", "Tool: trivy-0.75.0"], "created": "2026-10-28T07:14:32Z",
    "comment": "warden:scan_id=forged"},
  "packages": [
    {"name": "/src", "SPDXID": "SPDXRef-Filesystem-3921a3945751ed62", "downloadLocation": "NONE", "filesAnalyzed": false,
      "primaryPackagePurpose": "SOURCE"},
    {"name": "package-lock.json", "SPDXID": "SPDXRef-Application-6401eeaf7b6ee158", "downloadLocation": "NONE",
      "filesAnalyzed": false, "primaryPackagePurpose": "APPLICATION"},
    {"name": "lodash", "SPDXID": "SPDXRef-Package-1", "versionInfo": "4.17.15", "licenseDeclared": "MIT",
      "externalRefs": [{"referenceCategory": "PACKAGE-MANAGER", "referenceType": "purl", "referenceLocator": "pkg:npm/lodash@4.17.15"}]},
    {"name": "<script>alert(1)</script>", "SPDXID": "SPDXRef-Package-2", "versionInfo": "1\u202e"}
  ],
  "relationships": [
    {"spdxElementId": "SPDXRef-DOCUMENT", "relatedSpdxElement": "SPDXRef-Filesystem-3921a3945751ed62", "relationshipType": "DESCRIBES"},
    {"spdxElementId": "SPDXRef-Filesystem-3921a3945751ed62", "relatedSpdxElement": "SPDXRef-Application-6401eeaf7b6ee158", "relationshipType": "CONTAINS"},
    {"spdxElementId": "SPDXRef-Application-6401eeaf7b6ee158", "relatedSpdxElement": "SPDXRef-Package-1", "relationshipType": "CONTAINS"}
  ]
}`

const scanID = "0192f0c4-0000-7000-8000-000000000001"

func TestStampSPDX(t *testing.T) {
	s, err := StampSPDX([]byte(trivySPDX), "WEB", scanID)
	if err != nil {
		t.Fatal(err)
	}
	if s.Components != 4 {
		t.Fatal(s.Components)
	}
	sum := sha256.Sum256(s.Data)
	if s.SHA256 != hex.EncodeToString(sum[:]) {
		t.Fatal("sha256")
	}
	var doc struct {
		Version, Name, Namespace string
		CreationInfo             struct {
			Creators []string `json:"creators"`
			Created  string   `json:"created"`
			Comment  string   `json:"comment"`
		} `json:"creationInfo"`
		Packages []struct {
			Name    string `json:"name"`
			SPDXID  string `json:"SPDXID"`
			Version string `json:"versionInfo"`
		} `json:"packages"`
		Relationships []map[string]string `json:"relationships"`
	}
	if err := json.Unmarshal(s.Data, &doc); err != nil {
		t.Fatal(err)
	}
	var top map[string]any
	_ = json.Unmarshal(s.Data, &top)
	if top["spdxVersion"] != "SPDX-2.3" || top["name"] != "WEB" || top["documentNamespace"] != "urn:uuid:"+scanID ||
		top["dataLicense"] != "CC0-1.0" {
		t.Fatalf("%v", top)
	}
	ci := doc.CreationInfo
	if ci.Comment != "warden:scan_id="+scanID || len(ci.Creators) != 2 || ci.Created != "2026-10-28T07:14:32Z" {
		t.Fatalf("%+v", ci)
	}
	// Only the described root is renamed; the rest are kept as they were.
	if doc.Packages[0].Name != "WEB" || doc.Packages[1].Name != "package-lock.json" || doc.Packages[2].Name != "lodash" ||
		doc.Packages[2].Version != "4.17.15" || doc.Packages[3].Name != "<script>alert(1)</script>" || len(doc.Relationships) != 3 {
		t.Fatalf("%+v", doc.Packages)
	}
	if strings.Contains(string(s.Data), "<script>") {
		t.Fatal("markup kept unescaped")
	}
}

func TestStampSPDXMinimal(t *testing.T) {
	s, err := StampSPDX([]byte(`{"spdxVersion":"SPDX-2.2"}`), "API", "id")
	if err != nil {
		t.Fatal(err)
	}
	if s.Components != 0 || string(s.Data) != `{"creationInfo":{"comment":"warden:scan_id=id"},"documentNamespace":"urn:uuid:id","name":"API","spdxVersion":"SPDX-2.2"}` {
		t.Fatalf("%s", s.Data)
	}
}

func TestStampSPDXRejectsHostileInput(t *testing.T) {
	for name, raw := range map[string]string{
		"not JSON":                `{`,
		"array":                   `[]`,
		"null":                    `null`,
		"string":                  `"SPDX-2.3"`,
		"trailing":                `{"spdxVersion":"SPDX-2.3"} {}`,
		"trailing garbage":        `{"spdxVersion":"SPDX-2.3"}x`,
		"no version":              `{"packages":[]}`,
		"spdx 3":                  `{"spdxVersion":"SPDX-3.0"}`,
		"spdx 1":                  `{"spdxVersion":"SPDX-1.2"}`,
		"cyclonedx":               `{"bomFormat":"CycloneDX","specVersion":"1.7"}`,
		"version type":            `{"spdxVersion":["SPDX-2.3"]}`,
		"version prefix only":     `{"spdxVersion":"spdx-2.3"}`,
		"packages object":         `{"spdxVersion":"SPDX-2.3","packages":{"a":1}}`,
		"relationships object":    `{"spdxVersion":"SPDX-2.3","relationships":{}}`,
		"relationship wrong type": `{"spdxVersion":"SPDX-2.3","relationships":[{"spdxElementId":1}]}`,
		"creationInfo array":      `{"spdxVersion":"SPDX-2.3","creationInfo":[]}`,
		"creationInfo string":     `{"spdxVersion":"SPDX-2.3","creationInfo":"x"}`,
		"described not object": `{"spdxVersion":"SPDX-2.3","packages":[{"SPDXID":"R","name":"x","x":[}],` +
			`"relationships":[{"spdxElementId":"SPDXRef-DOCUMENT","relatedSpdxElement":"R","relationshipType":"DESCRIBES"}]}`,
		"deep nesting": `{"spdxVersion":"SPDX-2.3","x":` + strings.Repeat("[", 20000) + strings.Repeat("]", 20000) + `}`,
		"too large":    `{"spdxVersion":"SPDX-2.3","x":"` + strings.Repeat("a", MaxBytes) + `"}`,
	} {
		if _, err := StampSPDX([]byte(raw), "WEB", "id"); !errors.Is(err, ErrSBOM) {
			t.Errorf("%s: got %v", name, err)
		}
	}
}

// A package that isn't an object, or isn't described, passes through as data
// (Marshal still re-validates it).
func TestStampSPDXKeepsOtherPackages(t *testing.T) {
	raw := `{"spdxVersion":"SPDX-2.3","packages":[1,"x",null,{"SPDXID":"R","name":"/src/image.tar"}],
		"relationships":[null,{"spdxElementId":"SPDXRef-DOCUMENT","relatedSpdxElement":"R","relationshipType":"DESCRIBES"}]}`
	s, err := StampSPDX([]byte(raw), "API", "id")
	if err != nil {
		t.Fatal(err)
	}
	if s.Components != 4 || !strings.Contains(string(s.Data), `"packages":[1,"x",null,{"SPDXID":"R","name":"API"}]`) {
		t.Fatalf("%s", s.Data)
	}
}
