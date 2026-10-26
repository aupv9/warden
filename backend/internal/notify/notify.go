// Package notify turns outbox events into in-app notifications and emails.
//
// Writers (the service layer, the result processor, the worker's sweeps) call
// Insert in the same transaction as the change an event describes, so an event
// exists if and only if the change committed. The worker's
// dispatch_notifications job (Dispatcher) later resolves each event's
// recipients against the CURRENT memberships, writes one notification per
// (event, user) and sends email to those whose preference allows it.
//
// Outbox payloads carry ids only. Everything a notification shows is loaded at
// dispatch time from a fixed list of columns: org name, project key, issue key,
// title, severity, status and the actor's display name. Snippets,
// descriptions, file contents, comment bodies and secrets are never selected,
// so they can't reach an email.
package notify

import (
	"context"
	"encoding/json"
	"fmt"
	"slices"

	"github.com/google/uuid"
	"github.com/jackc/pgx/v5"
	"github.com/jackc/pgx/v5/pgconn"
)

// Event types.
const (
	IssueAssigned      = "issue.assigned"
	IssueReopened      = "issue.reopened"
	ExceptionRequested = "exception.requested"
	ExceptionDecided   = "exception.decided"
	ScanFinished       = "scan.finished"
	SLADueSoon         = "sla.due_soon"
	SLAOverdue         = "sla.overdue"
)

// Types lists every event type, in the order preferences are shown.
var Types = []string{IssueAssigned, IssueReopened, ExceptionRequested, ExceptionDecided, ScanFinished, SLADueSoon, SLAOverdue}

// DefaultEmail is the email preference of a user who never chose: on, except
// for scan.finished (people who upload usually watch the scan anyway).
func DefaultEmail(typ string) bool { return typ != ScanFinished }

// ValidType reports whether typ is a known event type.
func ValidType(typ string) bool { return slices.Contains(Types, typ) }

// Payload is an outbox event's data: ids only (see the package comment).
type Payload struct {
	IssueID     *uuid.UUID `json:"issue_id,omitempty"`
	ScanID      *uuid.UUID `json:"scan_id,omitempty"`
	ExceptionID *uuid.UUID `json:"exception_id,omitempty"`
	// ActorID is who caused the event; nil for the system.
	ActorID *uuid.UUID `json:"actor_id,omitempty"`
	// UserID is the recipient for single-recipient events (assignee,
	// exception requester, digest owner).
	UserID *uuid.UUID `json:"user_id,omitempty"`
	// Decision of exception.decided: approve or reject.
	Decision string `json:"decision,omitempty"`
	// Date of an SLA digest (YYYY-MM-DD, UTC).
	Date string `json:"date,omitempty"`
}

// Event is one outbox row to write.
type Event struct {
	OrgID   uuid.UUID
	Type    string
	Payload Payload
	// DedupeKey makes the insert idempotent per org (digests); "" for none.
	DedupeKey string
}

// Execer is the part of a transaction Insert needs (pgx.Tx, results.DB).
type Execer interface {
	Exec(ctx context.Context, sql string, args ...any) (pgconn.CommandTag, error)
}

// DB is what the dispatcher needs inside a transaction (pgx.Tx).
type DB interface {
	Execer
	Query(ctx context.Context, sql string, args ...any) (pgx.Rows, error)
	QueryRow(ctx context.Context, sql string, args ...any) pgx.Row
}

// Insert writes the event in the caller's transaction (app.org_id must be the
// event's org: outbox_event is under RLS). A repeated dedupe key is a no-op.
func Insert(ctx context.Context, db Execer, e Event) error {
	if !ValidType(e.Type) || e.OrgID == uuid.Nil {
		return fmt.Errorf("notify: invalid event %q", e.Type)
	}
	raw, err := json.Marshal(e.Payload)
	if err != nil {
		return err
	}
	var key *string
	if e.DedupeKey != "" {
		key = &e.DedupeKey
	}
	_, err = db.Exec(ctx, `INSERT INTO outbox_event (org_id, type, payload, dedupe_key) VALUES ($1, $2, $3, $4)
		ON CONFLICT (org_id, dedupe_key) DO NOTHING`, e.OrgID, e.Type, raw, key)
	if err != nil {
		return fmt.Errorf("outbox %s: %w", e.Type, err)
	}
	return nil
}

// ID returns a pointer to id (payload fields).
func ID(id uuid.UUID) *uuid.UUID { return &id }
