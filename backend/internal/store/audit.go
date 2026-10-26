package store

import (
	"bytes"
	"context"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"net/netip"
	"strings"
	"time"
	"unicode/utf8"

	"github.com/google/uuid"
	"github.com/jackc/pgx/v5"

	"github.com/aupv9/warden/backend/internal/service"
)

// The audit log is hash-chained per org: hash = sha256(prev_hash "\n" canonical
// row), where the canonical row is a JSON array of every stored column except id
// and the hashes. Appends to one org are serialized by a transaction-scoped
// advisory lock, taken as the last step of each write so it's held briefly.
// warden_app can only INSERT and SELECT audit_log (grants.sql), so a broken chain
// means tampering by someone with more privileges.

const maxUserAgent = 512

// AuditRow is the hashed content of one entry.
type AuditRow struct {
	OrgID      uuid.UUID
	ActorID    *uuid.UUID
	Action     string
	TargetType *string
	TargetID   *string
	IP         *string
	UserAgent  *string
	Data       []byte
	CreatedAt  time.Time
}

// canonicalJSON re-encodes JSON deterministically (sorted keys, compact), so the
// bytes we hash on insert equal what we rebuild from the jsonb column.
func canonicalJSON(raw []byte) ([]byte, error) {
	d := json.NewDecoder(bytes.NewReader(raw))
	d.UseNumber()
	var v any
	if err := d.Decode(&v); err != nil {
		return nil, err
	}
	return json.Marshal(v)
}

// ChainHash returns the entry hash for row given the previous entry's hash ("" for the first).
func ChainHash(prev string, row AuditRow) (string, error) {
	data, err := canonicalJSON(row.Data)
	if err != nil {
		return "", fmt.Errorf("audit data: %w", err)
	}
	var actor *string
	if row.ActorID != nil {
		s := row.ActorID.String()
		actor = &s
	}
	canon, err := json.Marshal([]any{
		row.OrgID.String(), actor, row.Action, row.TargetType, row.TargetID, row.IP, row.UserAgent,
		json.RawMessage(data), row.CreatedAt.UTC().Format(time.RFC3339Nano),
	})
	if err != nil {
		return "", err
	}
	h := sha256.New()
	h.Write([]byte(prev))
	h.Write([]byte{'\n'})
	h.Write(canon)
	return hex.EncodeToString(h.Sum(nil)), nil
}

func normIP(s string) *string {
	a, err := netip.ParseAddr(strings.TrimSpace(s))
	if err != nil {
		return nil
	}
	v := a.Unmap().WithZone("").String()
	return &v
}

func nonEmpty(s string) *string {
	if s == "" {
		return nil
	}
	return &s
}

// truncate cuts s to at most n bytes of valid UTF-8 without NULs (Postgres text
// rejects both; a hostile User-Agent mustn't make a write fail).
func truncate(s string, n int) string {
	s = strings.ReplaceAll(strings.ToValidUTF8(s, ""), "\x00", "")
	if len(s) <= n {
		return s
	}
	s = s[:n]
	for !utf8.ValidString(s) {
		s = s[:len(s)-1]
	}
	return s
}

func (r *Repo) AppendAudit(ctx context.Context, rec service.AuditRecord) error {
	if rec.OrgID == uuid.Nil {
		return errors.New("audit: org id required")
	}
	data, err := json.Marshal(rec.Data)
	if err != nil {
		return err
	}
	row := AuditRow{
		OrgID: rec.OrgID, ActorID: rec.ActorID, Action: rec.Action, TargetType: nonEmpty(rec.TargetType),
		TargetID: nonEmpty(rec.TargetID), IP: normIP(rec.IP), UserAgent: nonEmpty(truncate(rec.UserAgent, maxUserAgent)),
		Data: data, CreatedAt: time.Now().UTC().Truncate(time.Microsecond),
	}
	if _, err := r.tx.Exec(ctx, `SELECT pg_advisory_xact_lock(hashtextextended('warden.audit:' || $1::text, 0))`, rec.OrgID); err != nil {
		return err
	}
	var prev string
	err = r.tx.QueryRow(ctx, `SELECT hash FROM audit_log WHERE org_id = $1 ORDER BY id DESC LIMIT 1`, rec.OrgID).Scan(&prev)
	if err != nil && !errors.Is(err, pgx.ErrNoRows) {
		return err
	}
	hash, err := ChainHash(prev, row)
	if err != nil {
		return err
	}
	_, err = r.tx.Exec(ctx, `INSERT INTO audit_log (org_id, actor_id, action, target_type, target_id, ip, user_agent, data, prev_hash, hash, created_at)
		VALUES ($1, $2, $3, $4, $5, $6::inet, $7, $8, $9, $10, $11)`,
		row.OrgID, row.ActorID, row.Action, row.TargetType, row.TargetID, row.IP, row.UserAgent, string(data),
		nonEmpty(prev), hash, row.CreatedAt)
	return err
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
