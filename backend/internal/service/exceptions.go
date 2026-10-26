package service

import (
	"context"
	"errors"
	"slices"
	"strings"
	"time"
	"unicode/utf8"

	"github.com/google/uuid"

	"github.com/aupv9/warden/backend/internal/domain/issuestate"
	"github.com/aupv9/warden/backend/internal/domain/rbac"
	"github.com/aupv9/warden/backend/internal/ids"
	"github.com/aupv9/warden/backend/internal/notify"
)

const (
	riskAcceptedMax = issuestate.RiskAcceptedMaxDays * 24 * time.Hour
	expiringWindow  = 14 * 24 * time.Hour
)

type CreateExceptionInput struct {
	Type      string     `json:"type"`
	Reason    string     `json:"reason"`
	ExpiresAt *time.Time `json:"expires_at"`
}

func (s *Service) CreateException(ctx context.Context, a *Actor, issueID uuid.UUID, in CreateExceptionInput) (ExceptionRequest, error) {
	now := s.now().UTC().Truncate(time.Microsecond)
	fe := fieldErrors{}
	switch in.Type {
	case string(issuestate.RiskAccepted):
		switch {
		case in.ExpiresAt == nil:
			fe.add("expires_at", "is required for risk_accepted")
		case !in.ExpiresAt.After(now) || in.ExpiresAt.After(now.Add(riskAcceptedMax)):
			fe.add("expires_at", "must be in the future and at most 180 days away")
		}
	case string(issuestate.FalsePositive):
		if in.ExpiresAt != nil {
			fe.add("expires_at", "is only allowed for risk_accepted")
		}
	default:
		fe.add("type", "must be false_positive or risk_accepted")
	}
	reason := strings.TrimSpace(in.Reason)
	if n := utf8.RuneCountInString(reason); n < minReasonLen || n > maxReasonLen || !validText(reason) {
		fe.add("reason", "must be 20-5000 characters")
	}
	var out ExceptionRequest
	err := s.inOrg(ctx, a, func(r Repo) error {
		iss, role, err := issueAccess(ctx, r, a, issueID, true, s)
		if err != nil {
			return err
		}
		if !rbac.Can(rbac.ProposeException, a.OrgRole, role, isAssignee(a, iss)) {
			return errForbidden()
		}
		if err := fe.err(); err != nil {
			return err
		}
		if !slices.Contains(issuestate.Active, issuestate.Status(iss.Status)) {
			return errInvalidTransition("exceptions can only be requested for open issues")
		}
		pending, err := r.PendingExceptionID(ctx, iss.ID)
		if err != nil {
			return err
		}
		if pending != nil {
			return errConflict("the issue already has a pending exception request")
		}
		id := ids.New()
		var exp *time.Time
		if in.ExpiresAt != nil {
			e := in.ExpiresAt.UTC()
			exp = &e
		}
		err = r.InsertException(ctx, NewException{ID: id, OrgID: a.OrgID, IssueID: iss.ID, Type: in.Type, Reason: reason,
			RequestedBy: a.UserID, ExpiresAt: exp, CreatedAt: now})
		if errors.Is(err, ErrConflict) {
			return errConflict("the issue already has a pending exception request")
		}
		if err != nil {
			return err
		}
		uid := a.UserID
		if err := r.InsertIssueEvent(ctx, NewEvent{OrgID: a.OrgID, IssueID: iss.ID, ActorID: &uid, Type: "exception_requested",
			To: ptr(in.Type), Note: &reason}); err != nil {
			return err
		}
		ex, err := r.Exception(ctx, id, false)
		if err != nil {
			return err
		}
		out = ex.ExceptionRequest
		if err := outbox(ctx, r, a, notify.ExceptionRequested, notify.Payload{IssueID: notify.ID(iss.ID), ExceptionID: notify.ID(id)}); err != nil {
			return err
		}
		return s.audit(ctx, r, a, "exception.requested", "exception", id.String(),
			map[string]any{"issue_id": iss.ID.String(), "type": in.Type})
	})
	return out, err
}

type ExceptionFilter struct {
	Status string
	PageParams
}

// Exceptions lists exception requests: everything for those who decide them,
// otherwise only the caller's own requests.
func (s *Service) Exceptions(ctx context.Context, a *Actor, f ExceptionFilter) (Page[ExceptionRequest], error) {
	q := ExceptionQuery{Status: f.Status, Now: s.now()}
	fe := fieldErrors{}
	switch f.Status {
	case "", "pending", "approved", "rejected", "expiring":
	default:
		fe.add("status", "must be pending, approved, rejected or expiring")
	}
	limit, err := f.limit()
	if err != nil {
		fe.add("limit", "must be an integer between 1 and 200")
	}
	q.Limit = limit + 1
	if f.Cursor != "" {
		q.After = &ExceptionCursor{}
		if decodeCursor(f.Cursor, q.After) != nil {
			fe.add("cursor", "invalid cursor")
		}
	}
	if err := fe.err(); err != nil {
		return Page[ExceptionRequest]{}, err
	}
	var out Page[ExceptionRequest]
	err = s.inOrg(ctx, a, func(r Repo) error {
		if !rbac.Can(rbac.DecideException, a.OrgRole, "", false) {
			q.RequestedBy = &a.UserID
		}
		rows, err := r.Exceptions(ctx, q)
		if err != nil {
			return err
		}
		out.Items, out.NextCursor = page(rows, limit, func(e ExceptionRequest) any {
			return ExceptionCursor{CreatedAt: e.CreatedAt.T(), ID: e.ID}
		})
		return nil
	})
	return out, err
}

type DecisionInput struct {
	Decision  string     `json:"decision"`
	Note      *string    `json:"note"`
	ExpiresAt *time.Time `json:"expires_at"`
}

// Decide approves or rejects a pending exception request. Approval moves the
// issue to false_positive / risk_accepted through the state machine; the
// requester can never decide their own request (the database enforces it too).
func (s *Service) Decide(ctx context.Context, a *Actor, id uuid.UUID, in DecisionInput) (ExceptionRequest, error) {
	now := s.now()
	fe := fieldErrors{}
	var note *string
	if in.Note != nil {
		n := strings.TrimSpace(*in.Note)
		if utf8.RuneCountInString(n) > maxReasonLen || !validText(n) {
			fe.add("note", "must be at most 5000 characters")
		}
		if n != "" {
			note = &n
		}
	}
	switch in.Decision {
	case "approve":
	case "reject":
		if note == nil {
			fe.add("note", "is required to reject a request")
		}
		if in.ExpiresAt != nil {
			fe.add("expires_at", "is only allowed when approving")
		}
	default:
		fe.add("decision", "must be approve or reject")
	}
	var out ExceptionRequest
	err := s.inOrg(ctx, a, func(r Repo) error {
		if !rbac.Can(rbac.DecideException, a.OrgRole, "", false) {
			return errForbidden()
		}
		ex, err := r.Exception(ctx, id, true)
		if err != nil {
			return notFound(err)
		}
		if ex.RequestedByID == a.UserID {
			return forbiddenMsg("you can't decide your own exception request")
		}
		if err := fe.err(); err != nil {
			return err
		}
		if ex.Status != "pending" {
			return errConflict("the request has already been decided")
		}
		uid := a.UserID
		d := Decision{ID: ex.ID, DecidedBy: uid, Note: note}
		var issueFrom string
		if in.Decision == "approve" {
			iss, err := r.Issue(ctx, ex.IssueID, true, now)
			if err != nil {
				return err
			}
			target := issuestate.Status(ex.Type)
			rule, err := issuestate.Check(issuestate.Status(iss.Status), target, issuestate.SecurityLead)
			if errors.Is(err, issuestate.ErrInvalidTransition) {
				return errInvalidTransition("the issue is no longer open (" + iss.Status + ")")
			}
			if err != nil || !rule.RequiresApprovedException {
				return errForbidden()
			}
			if d.ExpiresAt, err = decisionExpiry(ex, in.ExpiresAt, now); err != nil {
				return err
			}
			d.Status = "approved"
			if err := r.DecideException(ctx, d); err != nil {
				return err
			}
			if err := r.UpdateIssueState(ctx, iss.ID, string(target), iss.AssigneeID); err != nil {
				return err
			}
			issueFrom = iss.Status
		} else {
			d.Status = "rejected"
			if err := r.DecideException(ctx, d); err != nil {
				return err
			}
		}
		if err := r.InsertIssueEvent(ctx, NewEvent{OrgID: a.OrgID, IssueID: ex.IssueID, ActorID: &uid, Type: "exception_decided",
			From: ptr(ex.Type), To: ptr(d.Status), Note: note}); err != nil {
			return err
		}
		if issueFrom != "" {
			if err := r.InsertIssueEvent(ctx, NewEvent{OrgID: a.OrgID, IssueID: ex.IssueID, ActorID: &uid, Type: "status_changed",
				From: ptr(issueFrom), To: ptr(ex.Type)}); err != nil {
				return err
			}
		}
		res, err := r.Exception(ctx, id, false)
		if err != nil {
			return err
		}
		out = res.ExceptionRequest
		if err := outbox(ctx, r, a, notify.ExceptionDecided, notify.Payload{IssueID: notify.ID(ex.IssueID), ExceptionID: notify.ID(id),
			UserID: notify.ID(ex.RequestedByID), Decision: in.Decision}); err != nil {
			return err
		}
		data := map[string]any{"decision": in.Decision, "issue_id": ex.IssueID.String(), "type": ex.Type}
		if d.ExpiresAt != nil {
			data["expires_at"] = d.ExpiresAt.UTC().Format(time.RFC3339)
		}
		return s.audit(ctx, r, a, "exception.decided", "exception", id.String(), data)
	})
	return out, err
}

// decisionExpiry: a risk acceptance keeps its requested expiry or a shorter one;
// a false positive has none.
func decisionExpiry(ex ExceptionMeta, override *time.Time, now time.Time) (*time.Time, error) {
	if ex.Type != string(issuestate.RiskAccepted) {
		if override != nil {
			return nil, errField("expires_at", "is only allowed for risk_accepted")
		}
		return nil, nil
	}
	var requested time.Time
	if ex.ExpiresAt != nil {
		requested = ex.ExpiresAt.T()
	}
	exp := requested
	if override != nil {
		if override.After(requested) {
			return nil, errField("expires_at", "may only shorten the requested expiry")
		}
		exp = override.UTC()
	}
	if !exp.After(now) {
		return nil, errField("expires_at", "must be in the future")
	}
	return &exp, nil
}

type AuditFilter struct {
	Action  string
	ActorID string
	// From and To bound created_at (RFC 3339, inclusive).
	From, To string
	PageParams
}

type auditCursor struct {
	ID int64 `json:"id"`
}

func (s *Service) AuditLog(ctx context.Context, a *Actor, f AuditFilter) (Page[AuditEntry], error) {
	q := AuditQuery{OrgID: a.OrgID}
	fe := fieldErrors{}
	if len(f.Action) > 100 || !validText(f.Action) {
		fe.add("action", "must be at most 100 characters")
	}
	q.Action = f.Action
	switch f.ActorID {
	case "":
	case "system":
		q.ActorSystem = true
	default:
		id, err := uuid.Parse(f.ActorID)
		if err != nil {
			fe.add("actor_id", "must be a user id or system")
		}
		q.ActorID = &id
	}
	for _, p := range []struct {
		name, raw string
		dst       **time.Time
	}{{"from", f.From, &q.From}, {"to", f.To, &q.To}} {
		if p.raw == "" {
			continue
		}
		t, err := time.Parse(time.RFC3339Nano, p.raw)
		if err != nil {
			fe.add(p.name, "must be an RFC 3339 timestamp")
			continue
		}
		*p.dst = &t
	}
	if q.From != nil && q.To != nil && q.To.Before(*q.From) {
		fe.add("to", "must not be before from")
	}
	limit, err := f.limit()
	if err != nil {
		fe.add("limit", "must be an integer between 1 and 200")
	}
	q.Limit = limit + 1
	if f.Cursor != "" {
		var c auditCursor
		if decodeCursor(f.Cursor, &c) != nil || c.ID < 1 {
			fe.add("cursor", "invalid cursor")
		}
		q.AfterID = c.ID
	}
	var out Page[AuditEntry]
	err = s.inOrg(ctx, a, func(r Repo) error {
		if !rbac.Can(rbac.ViewAuditLog, a.OrgRole, "", false) {
			return errForbidden()
		}
		if err := fe.err(); err != nil {
			return err
		}
		rows, err := r.AuditEntries(ctx, q)
		if err != nil {
			return err
		}
		out.Items, out.NextCursor = page(rows, limit, func(e AuditEntry) any { return auditCursor{ID: e.ID} })
		return nil
	})
	return out, err
}
