package results

import (
	"fmt"

	"github.com/aupv9/warden/backend/internal/domain/fingerprint"
	"github.com/aupv9/warden/backend/internal/domain/licensepolicy"
	"github.com/aupv9/warden/backend/internal/scan/sarif"
	"github.com/aupv9/warden/backend/internal/scan/trivyjson"
)

// LicenseRulePrefix starts the rule id of every license issue ("license:MIT").
const LicenseRulePrefix = "license:"

// LicenseFindings turns the licenses the policy doesn't allow into Trivy
// findings. They are tracked like vulnerability findings: same tool, an
// SCA-style content key, and the lockfile (or image OS) as the location, so
// dedup, reopening and auto-fix work unchanged. A disabled policy yields none.
func LicenseFindings(licenses []trivyjson.License, p licensepolicy.Policy) []sarif.Finding {
	if !p.Enabled() {
		return nil
	}
	var out []sarif.Finding
	for _, l := range licenses {
		d := p.Evaluate(l.Terms, l.Category)
		if d.Action == licensepolicy.Allow {
			continue
		}
		id := l.License
		if d.Rule == licensepolicy.RuleDenyList {
			id = d.ID
		}
		ruleID := LicenseRulePrefix + id
		out = append(out, sarif.Finding{
			Tool:           "trivy",
			RuleID:         ruleID,
			Title:          truncate(fmt.Sprintf("%s uses %s (%s)", l.PkgName, id, l.Category), sarif.MaxTitle),
			Severity:       d.Action.Severity(),
			FilePath:       l.FilePath,
			ContentKey:     fingerprint.SCAContentKey(ruleID, l.PkgName, l.PkgVersion),
			Description:    licenseDescription(l, d),
			Remediation:    licenseRemediation,
			PackageName:    l.PkgName,
			PackageVersion: l.PkgVersion,
		})
	}
	return out
}

// Plain text: issue descriptions are never rendered as HTML or Markdown. The
// declared name is from the scanned code, already sanitized and capped.
func licenseDescription(l trivyjson.License, d licensepolicy.Decision) string {
	pkg := l.PkgName
	if l.PkgVersion != "" {
		pkg += " " + l.PkgVersion
	}
	s := fmt.Sprintf("The package %s declares the license %q, which Trivy classifies as %s.", pkg, l.Declared, l.Category)
	if l.License == trivyjson.UnknownID {
		s += " It is not a valid SPDX license expression."
	}
	switch d.Rule {
	case licensepolicy.RuleDenyList:
		s += fmt.Sprintf(" The organization's license policy denies %s.", d.ID)
	default:
		s += fmt.Sprintf(" The organization's license policy sets %s licenses to %s.", l.Category, d.Action)
	}
	return s
}

const licenseRemediation = "Use a version or an alternative package under a license the policy allows, or request an " +
	"exception for this issue. A security lead can change the license policy in the organization settings."

func truncate(s string, n int) string {
	if r := []rune(s); len(r) > n {
		return string(r[:n])
	}
	return s
}
