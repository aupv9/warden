package service

import (
	"context"
	"net/http"
	"strconv"
	"time"

	apperrors "github.com/aupv9/common-go/errors"
	"github.com/google/uuid"

	"github.com/aupv9/warden/backend/internal/domain/rbac"
)

// auditVerifiesPerHour caps POST /audit-log/verify per org: each check reads
// the org's whole log.
const auditVerifiesPerHour = 10

// AuditRepo is what the audit-log check and the audit-based rate limits need.
type AuditRepo interface {
	// LockAuditVerify serializes audit-log checks per org, so the rate limit holds.
	LockAuditVerify(ctx context.Context, orgID uuid.UUID) error
	// AuditSince counts the org's entries of q.Action (by q.ActorID, if set)
	// created after q.Since, and returns the oldest one's time (zero if none).
	AuditSince(ctx context.Context, q AuditCount) (int, time.Time, error)
	// VerifyAudit recomputes the org's hash chain, like warden-admin audit verify.
	VerifyAudit(ctx context.Context, orgID uuid.UUID) (AuditChain, error)
}

type AuditCount struct {
	OrgID   uuid.UUID
	Action  string
	ActorID *uuid.UUID
	Since   time.Time
}

// AuditChain: Entries is the size of the org's log; FirstBadID the first entry
// whose hash doesn't match its content or its predecessor (nil: intact).
type AuditChain struct {
	Entries    int
	FirstBadID *int64
}

type AuditVerification struct {
	OK         bool    `json:"ok"`
	Entries    int     `json:"entries"`
	FirstBadID *string `json:"first_bad_id"`
	VerifiedAt Time    `json:"verified_at"`
}

// rateLimited is a 429 whose retry_after (seconds) the API also sends as Retry-After.
func rateLimited(retryAfter time.Duration, msg string) error {
	secs := max(int64((retryAfter+time.Second-1)/time.Second), 1)
	return apperrors.Invalid("RATE_LIMITED", msg).WithHTTPStatus(http.StatusTooManyRequests).WithMetadata("retry_after", secs)
}

// VerifyAuditLog checks the org's audit-log hash chain (view_audit_log) and
// records the check as audit.verified.
//
// The entry is appended after the check, in the same transaction: the check
// read one snapshot of the log and the new entry is chained by Append to
// whatever the last entry is when it takes the org's chain lock, so it can't
// break the chain it reports on, and it isn't counted in it. The check runs
// under a lock of its own (not the chain's), so audited writes in the org go on
// while it reads.
func (s *Service) VerifyAuditLog(ctx context.Context, a *Actor) (AuditVerification, error) {
	var out AuditVerification
	err := s.inOrg(ctx, a, func(r Repo) error {
		// API tokens never get here (the API's allow-list has no such route).
		if a.Token != nil || !rbac.Can(rbac.ViewAuditLog, a.OrgRole, "", false) {
			return errForbidden()
		}
		if err := r.LockAuditVerify(ctx, a.OrgID); err != nil {
			return err
		}
		now := s.now().UTC()
		n, oldest, err := r.AuditSince(ctx, AuditCount{OrgID: a.OrgID, Action: "audit.verified", Since: now.Add(-time.Hour)})
		if err != nil {
			return err
		}
		if n >= auditVerifiesPerHour {
			return rateLimited(oldest.Add(time.Hour).Sub(now),
				"the audit log was checked "+strconv.Itoa(auditVerifiesPerHour)+" times in the last hour; try again later")
		}
		chain, err := r.VerifyAudit(ctx, a.OrgID)
		if err != nil {
			return err
		}
		out = AuditVerification{OK: chain.FirstBadID == nil, Entries: chain.Entries, VerifiedAt: Time(now)}
		data := map[string]any{"ok": out.OK, "entries": out.Entries}
		if chain.FirstBadID != nil {
			id := strconv.FormatInt(*chain.FirstBadID, 10)
			out.FirstBadID, data["first_bad_id"] = &id, id
		}
		return s.audit(ctx, r, a, "audit.verified", "org", a.OrgID.String(), data)
	})
	return out, err
}
