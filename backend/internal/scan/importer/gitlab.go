package importer

import (
	"encoding/json"
	"regexp"
	"strings"

	"github.com/aupv9/warden/backend/internal/domain/severity"
)

// A GitLab SAST report (gl-sast-report.json, schema 15.x) is converted to the
// same results as SARIF, under the same limits and path rules. Its location
// is a plain path, not a URI: it is not percent-decoded.

var gitlabVersion = regexp.MustCompile(`^15\.[0-9]{1,4}\.[0-9]{1,4}$`)

type gitlabReport struct {
	Version         json.RawMessage `json:"version"`
	Vulnerabilities json.RawMessage `json:"vulnerabilities"`
	Scan            struct {
		Scanner struct {
			Version string `json:"version"`
		} `json:"scanner"`
	} `json:"scan"`
}

type gitlabVulnerability struct {
	Name        string          `json:"name"`
	Message     string          `json:"message"` // deprecated in 15.x, read when present
	Description string          `json:"description"`
	Solution    string          `json:"solution"`
	Severity    string          `json:"severity"`
	Identifiers json.RawMessage `json:"identifiers"`
	Location    struct {
		File      string          `json:"file"`
		StartLine json.RawMessage `json:"start_line"`
		EndLine   json.RawMessage `json:"end_line"`
	} `json:"location"`
	Tracking struct {
		Items json.RawMessage `json:"items"`
	} `json:"tracking"`
}

type gitlabIdentifier struct {
	Type  string `json:"type"`
	Name  string `json:"name"`
	Value string `json:"value"`
}

var cweName = regexp.MustCompile(`(?i)^cwe-([0-9]{1,7})$`)

func parseGitLab(raw []byte) (*Report, error) {
	var doc gitlabReport
	if err := decode(raw, &doc); err != nil {
		return nil, invalid("not JSON")
	}
	var version string
	if json.Unmarshal(doc.Version, &version) != nil || !gitlabVersion.MatchString(version) {
		return nil, invalid("not a GitLab SAST report of schema 15.x (version)")
	}
	if absent(doc.Vulnerabilities) {
		return nil, invalid("GitLab SAST report without vulnerabilities")
	}
	rep := &Report{ToolVersion: cleanLine(doc.Scan.Scanner.Version, MaxVersion)}
	err := elements(doc.Vulnerabilities, MaxResults, func(el json.RawMessage) error {
		rep.Read++
		var v gitlabVulnerability
		if err := decode(el, &v); err != nil {
			return err
		}
		res, ok := gitlabResult(&v)
		if !ok {
			rep.Dropped++
			return nil
		}
		rep.Results = append(rep.Results, res)
		return nil
	})
	if err != nil {
		return nil, readError(err, "vulnerabilities", MaxResults)
	}
	return rep, nil
}

// gitlabResult converts one vulnerability; ok false drops it (no rule id,
// a path outside the source root).
func gitlabResult(v *gitlabVulnerability) (Result, bool) {
	// The first identifier is the primary one: the rule (semgrep_id
	// bandit.B506, gosec_rule_id G104, …).
	var ids []gitlabIdentifier
	firstElements(v.Identifiers, maxIdentifiers, func(el json.RawMessage) {
		var id gitlabIdentifier
		if decode(el, &id) == nil {
			ids = append(ids, id)
		}
	})
	if len(ids) == 0 {
		return Result{}, false
	}
	ruleID := cleanLine(ids[0].Value, MaxRuleID)
	var cwes []string
	for _, id := range ids {
		if !strings.EqualFold(id.Type, "cwe") {
			continue
		}
		c := cwe(id.Value)
		if m := cweName.FindStringSubmatch(id.Name); c == "" && m != nil {
			c = cwe(m[1])
		}
		if c != "" {
			cwes = append(cwes, c)
		}
	}
	path := ""
	if v.Location.File != "" {
		var ok bool
		if path, ok = cleanPath(v.Location.File); !ok {
			return Result{}, false
		}
	}
	if ruleID == "" {
		return Result{}, false
	}
	// Tracking signatures (scope_offset, scope_offset_compressed, hash) are
	// GitLab's partial fingerprints: they follow the code, not its line.
	fps := map[string]string{}
	firstElements(v.Tracking.Items, 1, func(el json.RawMessage) {
		var item struct {
			Signatures json.RawMessage `json:"signatures"`
		}
		if decode(el, &item) != nil {
			return
		}
		firstElements(item.Signatures, maxFingerprints, func(el json.RawMessage) {
			var sig struct {
				Algorithm string `json:"algorithm"`
				Value     string `json:"value"`
			}
			if decode(el, &sig) == nil && sig.Algorithm != "" && sig.Value != "" {
				fps[sig.Algorithm] = sig.Value
			}
		})
	})
	start, end := lines(v.Location.StartLine, v.Location.EndLine)
	return Result{
		RuleID: ruleID, Title: cleanLine(v.Name, MaxTitle), Message: cleanText(v.Message, MaxMessage),
		Description: cleanText(v.Description, MaxRuleText), Remediation: cleanText(v.Solution, MaxRuleText),
		Severity: gitlabSeverity(v.Severity), CWE: sortedCWEs(cwes), Path: path, StartLine: start, EndLine: end,
		Fingerprint: fingerprintKey(fps),
	}, true
}

// gitlabSeverity: GitLab's Info and Unknown (and anything else) are Low.
func gitlabSeverity(s string) severity.Severity {
	switch strings.ToLower(s) {
	case "critical":
		return severity.Critical
	case "high":
		return severity.High
	case "medium":
		return severity.Medium
	}
	return severity.Low
}
