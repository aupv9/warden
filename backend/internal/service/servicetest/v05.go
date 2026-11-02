package servicetest

import (
	"context"
	"time"

	"github.com/google/uuid"

	"github.com/aupv9/warden/backend/internal/service"
)

// v0.5: the audit-log check and audit-based rate limits.

func (f *Fake) LockAuditVerify(context.Context, uuid.UUID) error { return f.fail("LockAuditVerify") }

func (f *Fake) AuditSince(_ context.Context, q service.AuditCount) (int, time.Time, error) {
	n, oldest := 0, time.Time{}
	for k, r := range f.st.Audit {
		at := f.st.AuditAt[k]
		if r.OrgID != q.OrgID || r.OrgID != f.org || r.Action != q.Action || !at.After(q.Since) ||
			(q.ActorID != nil && (r.ActorID == nil || *r.ActorID != *q.ActorID)) {
			continue
		}
		n++
		if oldest.IsZero() || at.Before(oldest) {
			oldest = at
		}
	}
	return n, oldest, f.fail("AuditSince")
}

// VerifyAudit reports the org's entries; AuditBadID marks a broken chain.
func (f *Fake) VerifyAudit(_ context.Context, orgID uuid.UUID) (service.AuditChain, error) {
	var out service.AuditChain
	for _, r := range f.st.Audit {
		if r.OrgID == orgID && orgID == f.org {
			out.Entries++
		}
	}
	if f.AuditBadID != 0 {
		id := f.AuditBadID
		out.FirstBadID = &id
	}
	return out, f.fail("VerifyAudit")
}
