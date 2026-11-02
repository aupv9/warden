package servicetest

import (
	"context"
	"time"

	"github.com/google/uuid"

	"github.com/aupv9/warden/backend/internal/service"
)

// v0.5: the audit-log check, audit-based rate limits and the issue export.

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

func (f *Fake) CountIssues(ctx context.Context, q service.IssueQuery, limit int) (int, error) {
	if err := f.fail("CountIssues"); err != nil {
		return 0, err
	}
	q.Limit, q.After = limit, nil
	rows, err := f.Issues(ctx, q)
	return len(rows), err
}

// ExportIssues streams the list's rows. With Fail["ExportIssues"] set it sends
// at most 1000 rows, then fails (a stream that breaks halfway).
func (f *Fake) ExportIssues(ctx context.Context, q service.IssueQuery, fn func(service.IssueExportRow) error) error {
	q.After = nil
	rows, err := f.Issues(ctx, q)
	if err != nil {
		return err
	}
	for k, s := range rows {
		if k == 1000 {
			if err := f.fail("ExportIssues"); err != nil {
				return err
			}
		}
		i := f.st.Issues[s.ID]
		e := service.IssueExportRow{Key: s.Key, ProjectName: f.st.Projects[s.ProjectID].Name, Title: s.Title, Severity: s.Severity,
			Status: s.Status, Tool: s.Tool, RuleID: s.RuleID, FilePath: s.FilePath, Line: s.StartLine, Target: s.Target, CVE: i.CVE,
			KEV: s.KEV, EPSS: s.EPSS, DueAt: s.DueAt, CreatedAt: s.UpdatedAt, UpdatedAt: s.UpdatedAt}
		if s.Assignee != nil {
			e.Assignee = &s.Assignee.Email
		}
		if err := fn(e); err != nil {
			return err
		}
	}
	return f.fail("ExportIssues")
}
