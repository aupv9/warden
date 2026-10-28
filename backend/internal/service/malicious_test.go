package service_test

import (
	"context"
	"net/http"
	"testing"

	"github.com/aupv9/warden/backend/internal/domain/rbac"
	"github.com/aupv9/warden/backend/internal/service"
	"github.com/aupv9/warden/backend/internal/service/servicetest"
)

// kind=malicious selects the malicious-package issues; they are neither
// vulnerabilities nor license issues, and the saved-view counts have their own
// number.
func TestIssueKindMalicious(t *testing.T) {
	x := newSetup(rbac.SecurityLead)
	ids := map[string]string{}
	add := func(name, tool, rule string) {
		id := x.f.AddIssue(x.p, "critical", "open", nil)
		x.f.SetIssue(id, func(r *servicetest.IssueRow) { r.Tool, r.RuleID = tool, rule })
		ids[id.String()] = name
	}
	add("mal", "trivy", "malicious:MAL-2026-1")
	add("vuln", "trivy", "CVE-2024-12345")
	add("lic", "trivy", "license:GPL-3.0-only")
	add("look-alike", "opengrep", "malicious:rule") // not Trivy
	ctx := context.Background()
	for kind, want := range map[string]string{"malicious": "mal", "vulnerability": "vuln", "license": "lic"} {
		p, err := x.s.Issues(ctx, x.actor(), service.IssueFilter{Kind: kind})
		if err != nil || len(p.Items) != 1 || ids[p.Items[0].ID.String()] != want {
			t.Fatalf("%s: %+v %v", kind, p.Items, err)
		}
	}
	if _, err := x.s.Issues(ctx, x.actor(), service.IssueFilter{Kind: "malware"}); status(err) != http.StatusUnprocessableEntity {
		t.Fatal(err)
	}
	tot, err := x.s.IssueTotals(ctx, x.actor(), "")
	if err != nil || tot.Malicious != 1 || tot.Licenses != 1 || tot.Active != 4 {
		t.Fatalf("%+v %v", tot, err)
	}
}
