package sbom

import (
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"strings"
)

const (
	// SPDXMediaType is SPDX JSON's registered media type.
	SPDXMediaType = "application/spdx+json"
	// SPDXScanIDPrefix starts the creationInfo comment that records the scan.
	SPDXScanIDPrefix = ScanIDProperty + "="
)

// StampSPDX validates the SPDX 2.x JSON document Trivy writes (`trivy convert
// --format spdx-json`) and returns it with the document and its described
// package named after the project (Trivy uses the scanned path, "/src"), the
// documentNamespace set to urn:uuid:<scanID> (unique per scan, as SPDX
// requires), and creationInfo.comment set to "warden:scan_id=<scanID>".
// Like Stamp, it decodes only what it changes beyond the top level; package
// names and versions are re-encoded, never interpreted.
func StampSPDX(raw []byte, name, scanID string) (*Stamped, error) {
	if len(raw) > MaxBytes {
		return nil, sbomErr("larger than %d bytes", MaxBytes)
	}
	doc, err := decodeObject(raw, "the SPDX document")
	if err != nil {
		return nil, err
	}
	var version string
	if err := json.Unmarshal(doc["spdxVersion"], &version); err != nil || !strings.HasPrefix(version, "SPDX-2.") {
		return nil, sbomErr("spdxVersion is not SPDX-2.x")
	}
	var packages []json.RawMessage
	if p, ok := doc["packages"]; ok {
		if err := json.Unmarshal(p, &packages); err != nil {
			return nil, sbomErr("packages is not an array")
		}
	}
	var rels []struct {
		From string `json:"spdxElementId"`
		To   string `json:"relatedSpdxElement"`
		Type string `json:"relationshipType"`
	}
	if r, ok := doc["relationships"]; ok {
		if err := json.Unmarshal(r, &rels); err != nil {
			return nil, sbomErr("relationships is not an array of relationships")
		}
	}
	described := map[string]bool{}
	for _, r := range rels {
		if r.From == "SPDXRef-DOCUMENT" && r.Type == "DESCRIBES" {
			described[r.To] = true
		}
	}
	if len(described) > 0 {
		for i, p := range packages {
			var id struct {
				SPDXID string `json:"SPDXID"`
			}
			if json.Unmarshal(p, &id) != nil || !described[id.SPDXID] {
				continue
			}
			pkg, err := decodeObject(p, "a described package")
			if err != nil {
				return nil, err
			}
			setFold(pkg, "name", name)
			if packages[i], err = json.Marshal(pkg); err != nil {
				return nil, sbomErr("package: %v", err)
			}
		}
		if doc["packages"], err = json.Marshal(packages); err != nil {
			return nil, sbomErr("packages: %v", err)
		}
	}

	info := object{}
	if c, ok := doc["creationInfo"]; ok {
		if info, err = decodeObject(c, "creationInfo"); err != nil {
			return nil, err
		}
	}
	// The comment is replaced, not appended to: only Warden writes warden:scan_id.
	setFold(info, "comment", SPDXScanIDPrefix+scanID)
	ci, err := json.Marshal(info)
	if err != nil {
		return nil, sbomErr("creationInfo: %v", err)
	}
	dropFold(doc, "creationInfo")
	doc["creationInfo"] = ci
	setFold(doc, "name", name)
	setFold(doc, "documentNamespace", "urn:uuid:"+scanID)
	// Marshal re-validates and compacts every raw value (and escapes <, >, &).
	out, err := json.Marshal(doc)
	if err != nil {
		return nil, sbomErr("%v", err)
	}
	sum := sha256.Sum256(out)
	return &Stamped{Data: out, SHA256: hex.EncodeToString(sum[:]), Components: len(packages)}, nil
}

// setFold sets key to the JSON string v after removing every key that equals
// it ignoring case. encoding/json matches field names case-insensitively, so
// a document holding both "documentNamespace" and "docUmentNamespace" would
// keep the forged one for some readers (found by FuzzStampSPDX).
func setFold(o object, key, v string) {
	dropFold(o, key)
	o[key], _ = json.Marshal(v)
}

func dropFold(o object, key string) {
	for k := range o {
		if strings.EqualFold(k, key) {
			delete(o, k)
		}
	}
}
