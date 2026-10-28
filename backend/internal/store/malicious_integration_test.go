//go:build integration

package store_test

import (
	"encoding/json"
	"slices"
	"strings"
	"testing"

	"github.com/google/uuid"

	"github.com/aupv9/warden/backend/internal/service"
)

// The malicious-package read path: kind=malicious, the saved-view count, and
// license_category on the issue list and page.
func TestMaliciousAndLicenseCategoryReadPath(t *testing.T) {
	w := newWorld(t)
	f := w.org("MAL")
	lead := w.actor("MALlead", f.id)
	names := map[uuid.UUID]string{}
	mal := w.trivyIssue(f, 1, "critical", "malicious:MAL-2026-1", "")
	names[mal] = "mal"
	names[w.trivyIssue(f, 2, "high", "CVE-2024-11111", "", "CVE-2024-11111")] = "vuln"
	lic := w.trivyIssue(f, 3, "medium", "license:GPL-3.0-only", "")
	names[lic] = "lic"
	ownerExec(t, f.id, `UPDATE issue SET license_category = 'restricted' WHERE id = $1`, lic)

	for kind, want := range map[string]string{"malicious": "mal", "vulnerability": "vuln", "license": "lic"} {
		p, err := w.svc.Issues(ctx, lead, service.IssueFilter{Kind: kind})
		if err != nil {
			t.Fatal(err)
		}
		var got []string
		for _, it := range p.Items {
			got = append(got, names[it.ID])
		}
		if !slices.Equal(got, []string{want}) {
			t.Errorf("kind=%s: %v", kind, got)
		}
		if kind == "license" && (p.Items[0].LicenseCategory == nil || *p.Items[0].LicenseCategory != "restricted") {
			t.Errorf("list license_category: %v", p.Items[0].LicenseCategory)
		}
	}
	tot, err := w.svc.IssueTotals(ctx, lead, "")
	if err != nil || tot.Malicious != 1 || tot.Licenses != 1 {
		t.Fatalf("%+v %v", tot, err)
	}
	iss, err := w.svc.Issue(ctx, lead, lic)
	if err != nil || iss.LicenseCategory == nil || *iss.LicenseCategory != "restricted" {
		t.Fatal(iss.LicenseCategory, err)
	}
	m, err := w.svc.Issue(ctx, lead, mal)
	if err != nil {
		t.Fatal(err)
	}
	b, _ := json.Marshal(m)
	if !strings.Contains(string(b), `"license_category":null`) {
		t.Fatal(string(b))
	}
}
