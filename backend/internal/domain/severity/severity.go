// Package severity maps scanner-native levels onto Warden's five severities.
package severity

import (
	"fmt"
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

func Checkov(checkID string, table map[string]Severity) Severity {
	if s, ok := table[checkID]; ok {
		return s
	}
	return Medium
}
