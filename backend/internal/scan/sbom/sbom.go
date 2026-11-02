// Package sbom checks and stamps the SBOMs Trivy writes for a scan: CycloneDX
// (Stamp) and SPDX (StampSPDX). Package names and versions in them come from
// the scanned code, so they are hostile input: size-capped, required to be a
// JSON object of the right format, and only ever served as a download (never
// rendered). Warden changes two things: the root component is named after the
// project (Trivy calls it "/src"), and a warden:scan_id entry ties the file to
// its scan.
package sbom

import (
	"bytes"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"strings"
)

const (
	MaxBytes = 64 << 20
	// MediaType is CycloneDX JSON's registered media type.
	MediaType = "application/vnd.cyclonedx+json"
	// ScanIDProperty names the property that records the scan.
	ScanIDProperty = "warden:scan_id"
)

var ErrSBOM = errors.New("SBOM")

func sbomErr(format string, args ...any) error {
	return fmt.Errorf("%w: %s", ErrSBOM, fmt.Sprintf(format, args...))
}

// Stamped is the SBOM as Warden stores it.
type Stamped struct {
	Data       []byte
	SHA256     string
	Components int // top-level components (Trivy doesn't nest them)
}

type object = map[string]json.RawMessage

// decodeObject decodes exactly one JSON object; other types are an error.
// encoding/json bounds the nesting depth.
func decodeObject(raw []byte, what string) (object, error) {
	dec := json.NewDecoder(bytes.NewReader(raw))
	var o object
	if err := dec.Decode(&o); err != nil || o == nil {
		return nil, sbomErr("%s is not a JSON object", what)
	}
	if _, err := dec.Token(); err != io.EOF {
		return nil, sbomErr("trailing data after %s", what)
	}
	return o, nil
}

// wardenProperty reports whether a property is named warden:..., matching
// the key and the prefix case-insensitively (as encoding/json matches
// struct fields), so no reader can take it for Warden's.
func wardenProperty(prop map[string]json.RawMessage) bool {
	for k, v := range prop {
		var name string
		if strings.EqualFold(k, "name") && json.Unmarshal(v, &name) == nil && strings.HasPrefix(strings.ToLower(name), "warden:") {
			return true
		}
	}
	return false
}

// Stamp validates raw and returns it with the root component renamed to name
// and the scan id recorded. Only the parts it changes are decoded beyond the
// top level, so memory stays a small multiple of the (capped) input.
func Stamp(raw []byte, name, scanID string) (*Stamped, error) {
	if len(raw) > MaxBytes {
		return nil, sbomErr("larger than %d bytes", MaxBytes)
	}
	doc, err := decodeObject(raw, "the SBOM")
	if err != nil {
		return nil, err
	}
	var format string
	if err := json.Unmarshal(doc["bomFormat"], &format); err != nil || format != "CycloneDX" {
		return nil, sbomErr("bomFormat is not CycloneDX")
	}
	components := 0
	if c, ok := doc["components"]; ok {
		var list []json.RawMessage
		if err := json.Unmarshal(c, &list); err != nil {
			return nil, sbomErr("components is not an array")
		}
		components = len(list)
	}

	meta := object{}
	if m, ok := doc["metadata"]; ok {
		if meta, err = decodeObject(m, "metadata"); err != nil {
			return nil, err
		}
	}
	root := object{"type": json.RawMessage(`"application"`)}
	if c, ok := meta["component"]; ok {
		if root, err = decodeObject(c, "metadata.component"); err != nil {
			return nil, err
		}
	}
	var props []json.RawMessage
	if p, ok := root["properties"]; ok {
		if err := json.Unmarshal(p, &props); err != nil {
			return nil, sbomErr("metadata.component.properties is not an array")
		}
	}
	// Only Warden writes warden: properties. A property object is re-encoded
	// from the map it decodes to: with a repeated key, encoding/json keeps the
	// last value and other readers may take the first, so a forged
	// {"name":"warden:scan_id","name":"x"} must not pass through as written.
	kept := props[:0]
	for _, p := range props {
		var prop map[string]json.RawMessage
		if json.Unmarshal(p, &prop) == nil && prop != nil {
			if wardenProperty(prop) {
				continue
			}
			if p, err = json.Marshal(prop); err != nil {
				return nil, sbomErr("metadata.component.properties: %v", err)
			}
		}
		kept = append(kept, p)
	}
	stamp, _ := json.Marshal(map[string]string{"name": ScanIDProperty, "value": scanID})
	root["properties"], _ = json.Marshal(append(kept, stamp))
	root["name"], _ = json.Marshal(name)
	if meta["component"], err = json.Marshal(root); err != nil {
		return nil, sbomErr("metadata.component: %v", err)
	}
	if doc["metadata"], err = json.Marshal(meta); err != nil {
		return nil, sbomErr("metadata: %v", err)
	}
	// Marshal re-validates and compacts every raw value (and escapes <, >, &).
	out, err := json.Marshal(doc)
	if err != nil {
		return nil, sbomErr("%v", err)
	}
	sum := sha256.Sum256(out)
	return &Stamped{Data: out, SHA256: hex.EncodeToString(sum[:]), Components: components}, nil
}
