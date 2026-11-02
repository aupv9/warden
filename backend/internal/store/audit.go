package store

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"time"

	"github.com/google/uuid"
	"github.com/jackc/pgx/v5"

	"github.com/aupv9/warden/backend/internal/auditlog"
	"github.com/aupv9/warden/backend/internal/service"
)

// The audit log's hash chain lives in internal/auditlog, shared with the worker.

// AuditRow is the hashed content of one entry.
type AuditRow = auditlog.Row

// ChainHash returns the entry hash for row given the previous entry's hash ("" for the first).
func ChainHash(prev string, row AuditRow) (string, error) { return auditlog.ChainHash(prev, row) }

func normIP(s string) *string         { return auditlog.NormIP(s) }
func nonEmpty(s string) *string       { return auditlog.NonEmpty(s) }
func truncate(s string, n int) string { return auditlog.Truncate(s, n) }

func (r *Repo) AppendAudit(ctx context.Context, rec service.AuditRecord) error {
	return auditlog.Append(ctx, r.tx, auditlog.Record{
		OrgID: rec.OrgID, ActorID: rec.ActorID, Action: rec.Action, TargetType: rec.TargetType, TargetID: rec.TargetID,
		IP: rec.IP, UserAgent: rec.UserAgent, Data: rec.Data,
	})
}

func (r *Repo) AuditEntries(ctx context.Context, q service.AuditQuery) ([]service.AuditEntry, error) {
	sql, a := buildAuditList(q)
	rows, _ := r.tx.Query(ctx, sql, a...)
	return collect(rows, func(row pgx.CollectableRow) (service.AuditEntry, error) {
		var (
			e             service.AuditEntry
			aID           *uuid.UUID
			aEmail, aName *string
			data          []byte
		)
		err := row.Scan(&e.ID, &aID, &aEmail, &aName, &e.Action, &e.TargetType, &e.TargetID, &e.IP, &data, &e.CreatedAt)
		e.Actor = userRef(aID, aEmail, aName)
		e.Data = json.RawMessage(data)
		return e, err
	})
}

// buildAuditList filters by org explicitly: audit_log has no RLS.
func buildAuditList(q service.AuditQuery) (string, args) {
	var a args
	sql := `SELECT l.id, au.id, au.email::text, au.display_name, l.action, l.target_type, l.target_id, host(l.ip), l.data, l.created_at
		FROM audit_log l LEFT JOIN app_user au ON au.id = l.actor_id WHERE l.org_id = ` + a.add(q.OrgID)
	if q.Action != "" {
		sql += ` AND l.action = ` + a.add(q.Action)
	}
	if q.ActorSystem {
		sql += ` AND l.actor_id IS NULL`
	} else if q.ActorID != nil {
		sql += ` AND l.actor_id = ` + a.add(*q.ActorID)
	}
	if q.From != nil {
		sql += ` AND l.created_at >= ` + a.add(*q.From)
	}
	if q.To != nil {
		sql += ` AND l.created_at <= ` + a.add(*q.To)
	}
	if q.AfterID > 0 {
		sql += ` AND l.id < ` + a.add(q.AfterID)
	}
	return sql + ` ORDER BY l.id DESC LIMIT ` + a.add(q.Limit), a
}

// ErrChainBroken reports an audit log that doesn't verify.
var ErrChainBroken = errors.New("audit chain broken")

// Querier is satisfied by pgx.Tx, *pgx.Conn and *pgxpool.Pool.
type Querier interface {
	Query(ctx context.Context, sql string, args ...any) (pgx.Rows, error)
}

// ChainError names the first entry that doesn't verify; it is ErrChainBroken.
type ChainError struct {
	ID     int64
	Reason string
}

func (e *ChainError) Error() string {
	return fmt.Sprintf("%v: entry %d %s", ErrChainBroken, e.ID, e.Reason)
}
func (e *ChainError) Unwrap() error { return ErrChainBroken }

// AuditCheck is the result of CheckAuditChain.
type AuditCheck struct {
	// Entries is the size of the org's log; Good the entries before the first
	// bad one (all of them when Bad is nil).
	Entries, Good int
	Bad           *ChainError
}

// CheckAuditChain recomputes every hash of org's audit log in id order (the
// chain's order: Append takes the org's lock before the id is drawn). After
// the first bad entry the rest are only counted.
func CheckAuditChain(ctx context.Context, q Querier, orgID uuid.UUID) (AuditCheck, error) {
	var out AuditCheck
	rows, err := q.Query(ctx, `SELECT id, actor_id, action, target_type, target_id, host(ip), user_agent, data::text,
		coalesce(prev_hash, ''), hash, created_at FROM audit_log WHERE org_id = $1 ORDER BY id`, orgID)
	if err != nil {
		return out, err
	}
	defer rows.Close()
	prev := ""
	for rows.Next() {
		var (
			id       int64
			row      = AuditRow{OrgID: orgID}
			data     string
			prevHash string
			hash     string
		)
		if err := rows.Scan(&id, &row.ActorID, &row.Action, &row.TargetType, &row.TargetID, &row.IP, &row.UserAgent,
			&data, &prevHash, &hash, &row.CreatedAt); err != nil {
			return out, err
		}
		out.Entries++
		if out.Bad != nil {
			continue
		}
		if row.IP != nil {
			row.IP = normIP(*row.IP)
		}
		row.Data = []byte(data)
		if prevHash != prev {
			out.Bad = &ChainError{ID: id, Reason: "doesn't link to its predecessor"}
			continue
		}
		want, err := ChainHash(prev, row)
		if err != nil {
			return out, err
		}
		if want != hash {
			out.Bad = &ChainError{ID: id, Reason: "was modified"}
			continue
		}
		prev = hash
		out.Good++
	}
	return out, rows.Err()
}

// VerifyAuditChain recomputes every hash of org's audit log in order and returns
// the number of good entries, and a *ChainError naming the first bad entry.
func VerifyAuditChain(ctx context.Context, q Querier, orgID uuid.UUID) (int, error) {
	c, err := CheckAuditChain(ctx, q, orgID)
	if err != nil {
		return c.Good, err
	}
	if c.Bad != nil {
		return c.Good, c.Bad
	}
	return c.Good, nil
}

// LockAuditVerify serializes POST /audit-log/verify per org, so its rate
// limit holds across API instances. A lock of its own: the chain's lock
// (auditlog.Append) would block every audited write in the org during the check.
func (r *Repo) LockAuditVerify(ctx context.Context, orgID uuid.UUID) error {
	_, err := r.tx.Exec(ctx, `SELECT pg_advisory_xact_lock(hashtextextended('warden.audit_verify:' || $1::text, 0))`, orgID)
	return err
}

// AuditSince counts the org's entries of one action (by one actor, if set)
// created after since, and returns the oldest one's time (zero if none).
func (r *Repo) AuditSince(ctx context.Context, q service.AuditCount) (int, time.Time, error) {
	var (
		a      args
		n      int
		oldest *time.Time
	)
	sql := `SELECT count(*), min(created_at) FROM audit_log WHERE org_id = ` + a.add(q.OrgID) + ` AND action = ` + a.add(q.Action) +
		` AND created_at > ` + a.add(q.Since)
	if q.ActorID != nil {
		sql += ` AND actor_id = ` + a.add(*q.ActorID)
	}
	err := r.tx.QueryRow(ctx, sql, a...).Scan(&n, &oldest)
	if oldest == nil {
		return n, time.Time{}, mapErr(err)
	}
	return n, *oldest, mapErr(err)
}

// VerifyAudit checks the org's chain in the caller's transaction.
func (r *Repo) VerifyAudit(ctx context.Context, orgID uuid.UUID) (service.AuditChain, error) {
	c, err := CheckAuditChain(ctx, r.tx, orgID)
	out := service.AuditChain{Entries: c.Entries}
	if c.Bad != nil {
		out.FirstBadID = &c.Bad.ID
	}
	return out, err
}
