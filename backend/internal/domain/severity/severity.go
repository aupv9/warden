// Package severity maps scanner-native levels onto Warden's five severities.
package severity

import (
	"bytes"
	_ "embed"
	"encoding/json"
	"fmt"
	"maps"
	"regexp"
	"strings"
)

type Severity string

const (
	Critical Severity = "critical"
	High     Severity = "high"
	Medium   Severity = "medium"
	Low      Severity = "low"
	Info     Severity = "info"
)

// All is ordered most to least severe; Rank follows this order.
var All = []Severity{Critical, High, Medium, Low, Info}

// Rank returns 0 for Critical up to 4 for Info, or len(All) for unknown values.
func Rank(s Severity) int {
	for i, v := range All {
		if v == s {
			return i
		}
	}
	return len(All)
}

func Parse(s string) (Severity, error) {
	v := Severity(strings.ToLower(s))
	if Rank(v) == len(All) {
		return "", fmt.Errorf("unknown severity %q", s)
	}
	return v, nil
}

var gitleaksCriticalPrefixes = []string{"private-key", "aws-", "gcp-", "azure-", "github-", "gitlab-"}

func Gitleaks(ruleID string) Severity {
	rid := strings.ToLower(ruleID)
	for _, p := range gitleaksCriticalPrefixes {
		if strings.HasPrefix(rid, p) {
			return Critical
		}
	}
	return High
}

// Opengrep uses security-severity (CVSS-like) when ≥ 9.0, else the SARIF level.
func Opengrep(level string, securitySeverity *float64) Severity {
	if securitySeverity != nil && *securitySeverity >= 9.0 {
		return Critical
	}
	if level == "" {
		level = "warning"
	}
	switch strings.ToLower(level) {
	case "error":
		return High
	case "warning":
		return Medium
	case "note":
		return Low
	case "none":
		return Info
	}
	return Medium
}

func Trivy(label string) Severity {
	switch strings.ToUpper(label) {
	case "CRITICAL":
		return Critical
	case "HIGH":
		return High
	case "MEDIUM":
		return Medium
	case "LOW":
		return Low
	}
	return Medium
}

// Checkov returns the table's severity for a check, or Medium for a check
// the table doesn't know (a custom check, or one newer than the table).
func Checkov(checkID string, table map[string]Severity) Severity {
	if s, ok := table[checkID]; ok {
		return s
	}
	return Medium
}

// OSS Checkov reports no severities, so Warden ships its own: a curated table
// for the checks of the pinned Checkov release (scanners/images.lock.json),
// built by the rubric written in the file. It is versioned with Warden rather
// than configurable, so that every install rates a check the same way.
//
//go:embed checkov_severity.json
var checkovJSON []byte

// checkovIDPattern is the form of every Checkov check id (CKV_AWS_20, CKV2_GCP_7).
var checkovIDPattern = regexp.MustCompile(`^CKV2?_[A-Z0-9]+_[0-9]+$`)

// checkovFile is the layout of checkov_severity.json.
type checkovFile struct {
	Version string            `json:"version"` // the Checkov release the ids come from
	Source  string            `json:"source"`
	Rubric  map[string]string `json:"rubric"`
	Checks  map[string]string `json:"checks"`
}

// parseCheckovTable parses and checks a table: known fields only, every id a
// Checkov id, every value one of the five severities.
func parseCheckovTable(b []byte) (*checkovFile, map[string]Severity, error) {
	dec := json.NewDecoder(bytes.NewReader(b))
	dec.DisallowUnknownFields()
	var f checkovFile
	if err := dec.Decode(&f); err != nil {
		return nil, nil, fmt.Errorf("checkov severity table: %w", err)
	}
	if f.Version == "" || len(f.Checks) == 0 {
		return nil, nil, fmt.Errorf("checkov severity table: no version or no checks")
	}
	table := make(map[string]Severity, len(f.Checks))
	for id, v := range f.Checks {
		if !checkovIDPattern.MatchString(id) {
			return nil, nil, fmt.Errorf("checkov severity table: bad check id %q", id)
		}
		// Exact spelling: Parse would also take "HIGH".
		if s := Severity(v); Rank(s) == len(All) {
			return nil, nil, fmt.Errorf("checkov severity table: %s: unknown severity %q", id, v)
		}
		table[id] = Severity(v)
	}
	return &f, table, nil
}

// Parsed once at start-up. The file is compiled in and its tests reject a bad
// edit, so the panic can't happen in a released binary.
var checkovTable = func() map[string]Severity {
	_, t, err := parseCheckovTable(checkovJSON)
	if err != nil {
		panic(err)
	}
	return t
}()

// CheckovTable returns a copy of the embedded table, for sarif.Options.
func CheckovTable() map[string]Severity {
	return maps.Clone(checkovTable)
}
