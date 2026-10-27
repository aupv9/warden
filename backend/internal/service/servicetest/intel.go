package servicetest

import (
	"cmp"
	"context"
	"strings"
	"time"

	"github.com/aupv9/warden/backend/internal/service"
)

// IntelRow is a vuln_intel row: KEV data, EPSS data, or both.
type IntelRow struct {
	KEVAdded   *time.Time
	Ransomware bool
	EPSS       *float64
	Percentile *float64
}

// SetIntel sets the exploit intelligence for a CVE.
func (f *Fake) SetIntel(cve string, r IntelRow) { f.st.Intel[cve] = r }

// SetVulnSource records a vuln_intel_source row.
func (f *Fake) SetVulnSource(s service.VulnDataSource) { f.st.VulnSrc = append(f.st.VulnSrc, s) }

// intel aggregates over cves like the store's lateral join: any KEV (earliest
// date), any ransomware, the highest EPSS and percentile.
func (f *Fake) intel(cves []string) IntelRow {
	var out IntelRow
	for _, c := range cves {
		r, ok := f.st.Intel[c]
		if !ok {
			continue
		}
		if r.KEVAdded != nil && (out.KEVAdded == nil || r.KEVAdded.Before(*out.KEVAdded)) {
			out.KEVAdded = r.KEVAdded
		}
		out.Ransomware = out.Ransomware || r.Ransomware
		out.EPSS = maxp(out.EPSS, r.EPSS)
		out.Percentile = maxp(out.Percentile, r.Percentile)
	}
	return out
}

func maxp(a, b *float64) *float64 {
	if a == nil || b != nil && *b > *a {
		return b
	}
	return a
}

// compareEPSS orders highest first, missing scores last.
func compareEPSS(a, b *float64) int {
	switch {
	case a == nil && b == nil:
		return 0
	case a == nil:
		return 1
	case b == nil:
		return -1
	}
	return cmp.Compare(*b, *a)
}

func isLicense(i IssueRow) bool { return i.Tool == "trivy" && strings.HasPrefix(i.RuleID, "license:") }

func (f *Fake) matchIntel(q service.IssueQuery, i IssueRow) bool {
	in := f.intel(i.CVE)
	license := isLicense(i)
	switch {
	case q.Kind == service.KindVulnerability && (i.Tool != "trivy" || license),
		q.Kind == service.KindLicense && !license,
		q.KEV && in.KEVAdded == nil,
		q.EPSSMin != nil && (in.EPSS == nil || *in.EPSS < *q.EPSSMin),
		q.Source == "code" && i.Target != "",
		q.Source == "image" && i.Target == "",
		q.Target != "" && i.Target != q.Target:
		return false
	}
	return true
}

func (f *Fake) VulnSources(context.Context) ([]service.VulnDataSource, error) {
	if err := f.fail("VulnSources"); err != nil {
		return nil, err
	}
	return f.st.VulnSrc, nil
}
