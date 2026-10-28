//go:build integration

package store_test

import (
	"strings"
	"testing"
	"time"

	"github.com/aupv9/warden/backend/internal/domain/licensepolicy"
	"github.com/aupv9/warden/backend/internal/service"
)

// The SBOM is served while stored and unexpired, to whoever views the project.
func TestScanSBOMRoundTrip(t *testing.T) {
	w := newWorld(t)
	f := w.org("SBM")
	dev, lead := w.actor("SBMdev", f.id), w.actor("SBMlead", f.id)
	outsider := w.user("SBMout")
	must(w.svc.AddMember(ctx, w.actor("SBMadmin", f.id), service.AddMemberInput{Email: outsider.Email, Role: "member"}))

	sc := must(w.svc.Scan(ctx, dev, f.scan))
	if sc.SBOM != nil || sc.Kind != "source" || sc.Target != "" || sc.ImageRef != nil {
		t.Fatalf("%+v", sc)
	}
	if _, err := w.svc.ScanSBOM(ctx, dev, f.scan, ""); code(err) != "NOT_FOUND" {
		t.Fatal(err)
	}
	key := "sboms/" + f.id.String() + "/" + f.scan.String() + ".cdx.json"
	sum := strings.Repeat("e", 64)
	ownerExec(t, f.id, `UPDATE scan SET sbom_key = $2, sbom_size = 99, sbom_sha256 = $3, sbom_components = 175,
		sbom_expires_at = now() + interval '1 day' WHERE id = $1`, f.scan, key, sum)
	sc = must(w.svc.Scan(ctx, dev, f.scan))
	if sc.SBOM == nil || sc.SBOM.Components != 175 || sc.SBOM.Size != 99 {
		t.Fatalf("%+v", sc.SBOM)
	}
	d := must(w.svc.ScanSBOM(ctx, lead, f.scan, ""))
	if d.SHA256 != sum || d.Components != 175 || d.URL != "https://s3.test/"+key+"?name=SBM-"+f.scan.String()[:8]+".cdx.json" ||
		d.ExpiresAt.T().After(time.Now().Add(6*time.Minute)) {
		t.Fatalf("%+v", d)
	}
	if _, err := w.svc.ScanSBOM(ctx, w.actor("SBMout", f.id), f.scan, ""); code(err) != "NOT_FOUND" {
		t.Fatal(err)
	}
	// Expired, not yet purged: gone already.
	ownerExec(t, f.id, `UPDATE scan SET sbom_expires_at = now() - interval '1 second' WHERE id = $1`, f.scan)
	if sc := must(w.svc.Scan(ctx, dev, f.scan)); sc.SBOM != nil {
		t.Fatal("expired SBOM listed")
	}
	if _, err := w.svc.ScanSBOM(ctx, dev, f.scan, ""); code(err) != "NOT_FOUND" {
		t.Fatal(err)
	}
}

func TestLicensePolicyRoundTrip(t *testing.T) {
	w := newWorld(t)
	f := w.org("LIC")
	lead, dev := w.actor("LIClead", f.id), w.actor("LICdev", f.id)
	if p := must(w.svc.LicensePolicy(ctx, dev)); p.Enabled || p.Categories[licensepolicy.Forbidden] != licensepolicy.Allow {
		t.Fatalf("%+v", p)
	}
	in := service.LicensePolicyInput{Categories: map[string]string{"forbidden": "block", "restricted": "review", "reciprocal": "allow",
		"notice": "allow", "permissive": "allow", "unencumbered": "allow", "unknown": "review"}, Deny: []string{"OFL-1.1"}, Allow: []string{}}
	if _, err := w.svc.SetLicensePolicy(ctx, dev, in); code(err) != "FORBIDDEN" {
		t.Fatal(err)
	}
	must(w.svc.SetLicensePolicy(ctx, lead, in))
	p := must(w.svc.LicensePolicy(ctx, dev))
	if !p.Enabled || p.Categories[licensepolicy.Unknown] != licensepolicy.Review || len(p.Deny) != 1 {
		t.Fatalf("%+v", p)
	}
	// What the worker reads (results.Process) is the same JSON.
	if w.count(f.id, `SELECT count(*) FROM organization WHERE id = $1 AND license_policy->'categories'->>'forbidden' = 'block'
		AND license_policy->'deny' ? 'OFL-1.1'`, f.id) != 1 {
		t.Fatal("stored policy")
	}
	must(w.svc.SetLicensePolicy(ctx, lead, in)) // unchanged: no second audit entry
	if n := w.count(f.id, `SELECT count(*) FROM audit_log WHERE org_id = $1 AND action = 'org.license_policy_changed'`, f.id); n != 1 {
		t.Fatalf("%d audit entries", n)
	}
}
