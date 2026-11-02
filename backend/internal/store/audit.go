package store

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"

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

// VerifyAuditChain recomputes every hash of org's audit log in order and returns
// the number of entries checked, or ErrChainBroken naming the first bad entry.
func VerifyAuditChain(ctx context.Context, q Querier, orgID uuid.UUID) (int, error) {
	rows, err := q.Query(ctx, `SELECT id, actor_id, action, target_type, target_id, host(ip), user_agent, data::text,
		coalesce(prev_hash, ''), hash, created_at FROM audit_log WHERE org_id = $1 ORDER BY id`, orgID)
	if err != nil {
		return 0, err
	}
	defer rows.Close()
	prev, n := "", 0
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
			return n, err
		}
		if row.IP != nil {
			row.IP = normIP(*row.IP)
		}
		row.Data = []byte(data)
		if prevHash != prev {
			return n, fmt.Errorf("%w: entry %d doesn't link to its predecessor", ErrChainBroken, id)
		}
		want, err := ChainHash(prev, row)
		if err != nil {
			return n, err
		}
		if want != hash {
			return n, fmt.Errorf("%w: entry %d was modified", ErrChainBroken, id)
		}
		prev = hash
		n++
	}
	return n, rows.Err()
}
