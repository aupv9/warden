//go:build integration

package store_test

import (
	"encoding/json"
	"fmt"
	"testing"

	"github.com/aupv9/warden/backend/internal/service"
)

// POST /audit-log/verify recomputes the chain, records itself after the check
// without breaking the chain, reports tampering, and is rate limited per org.
func TestVerifyAuditLogChain(t *testing.T) {
	w := newWorld(t)
	f := w.org("AUV")
	admin, lead := w.actor("AUVadmin", f.id), w.actor("AUVlead", f.id)
	before := len(must(w.svc.AuditLog(ctx, admin, service.AuditFilter{PageParams: service.PageParams{Limit: "200"}})).Items)

	v := must(w.svc.VerifyAuditLog(ctx, admin))
	if !v.OK || v.Entries != before || v.FirstBadID != nil {
		t.Fatalf("%+v", v)
	}
	// The audit.verified entry is chained like any other.
	v = must(w.svc.VerifyAuditLog(ctx, lead))
	if !v.OK || v.Entries != before+1 {
		t.Fatalf("%+v", v)
	}
	if _, err := w.svc.VerifyAuditLog(ctx, w.actor("AUVdev", f.id)); code(err) != "FORBIDDEN" {
		t.Fatal(err)
	}

	// Tampering (owner rights only) is reported with the entry's id, and the
	// check is still recorded.
	var bad int64
	ownerExec(t, f.id, `UPDATE audit_log SET data = '{"x":1}' WHERE id = (SELECT min(id) FROM audit_log WHERE org_id = $1 AND action = 'member.added')`, f.id)
	must(0, w.pool.QueryRow(ctx, `SELECT min(id) FROM audit_log WHERE org_id = $1 AND action = 'member.added'`, f.id).Scan(&bad))
	v = must(w.svc.VerifyAuditLog(ctx, admin))
	if v.OK || v.FirstBadID == nil || *v.FirstBadID != fmt.Sprint(bad) || v.Entries != before+2 {
		t.Fatalf("%+v", v)
	}
	log := must(w.svc.AuditLog(ctx, admin, service.AuditFilter{Action: "audit.verified"}))
	var data map[string]any
	if len(log.Items) != 3 || json.Unmarshal(log.Items[0].Data, &data) != nil || data["ok"] != false || data["first_bad_id"] != fmt.Sprint(bad) {
		t.Fatalf("%+v", log.Items)
	}

	// 10 per org per hour.
	for range 7 {
		must(w.svc.VerifyAuditLog(ctx, lead))
	}
	if _, err := w.svc.VerifyAuditLog(ctx, admin); code(err) != "RATE_LIMITED" {
		t.Fatal(err)
	}
}
