// Package auditlog appends to the hash-chained audit log. It is a leaf package
// so that both the API's store and the worker (which can't import the store:
// store → service → worker) write entries the same way.
//
// The audit log is hash-chained per org: hash = sha256(prev_hash "\n" canonical
// row), where the canonical row is a JSON array of every stored column except id
// and the hashes. Appends to one org are serialized by a transaction-scoped
// advisory lock, taken as the last step of each write so it's held briefly.
// warden_app can only INSERT and SELECT audit_log (grants.sql), so a broken chain
// means tampering by someone with more privileges.
package auditlog

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
	"github.com/jackc/pgx/v5/pgconn"
)

const maxUserAgent = 512

// Row is the hashed content of one entry.
type Row struct {
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

// Record is one entry to append. ActorID nil is the system (or an operator).
type Record struct {
	OrgID      uuid.UUID
	ActorID    *uuid.UUID
	Action     string
	TargetType string
	TargetID   string
	IP         string
	UserAgent  string
	Data       map[string]any
}

// DB is the part of a transaction Append needs (pgx.Tx).
type DB interface {
	Exec(ctx context.Context, sql string, args ...any) (pgconn.CommandTag, error)
	QueryRow(ctx context.Context, sql string, args ...any) pgx.Row
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
func ChainHash(prev string, row Row) (string, error) {
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

// NormIP returns the canonical form of an IP address, or nil.
func NormIP(s string) *string {
	a, err := netip.ParseAddr(strings.TrimSpace(s))
	if err != nil {
		return nil
	}
	v := a.Unmap().WithZone("").String()
	return &v
}

// NonEmpty returns nil for "".
func NonEmpty(s string) *string {
	if s == "" {
		return nil
	}
	return &s
}

// Truncate cuts s to at most n bytes of valid UTF-8 without NULs (Postgres text
// rejects both; a hostile User-Agent mustn't make a write fail).
func Truncate(s string, n int) string {
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

// Append writes rec in the caller's transaction, chained to the org's last entry.
func Append(ctx context.Context, db DB, rec Record) error {
	if rec.OrgID == uuid.Nil {
		return errors.New("audit: org id required")
	}
	data, err := json.Marshal(rec.Data)
	if err != nil {
		return err
	}
	row := Row{
		OrgID: rec.OrgID, ActorID: rec.ActorID, Action: rec.Action, TargetType: NonEmpty(rec.TargetType),
		TargetID: NonEmpty(rec.TargetID), IP: NormIP(rec.IP), UserAgent: NonEmpty(Truncate(rec.UserAgent, maxUserAgent)),
		Data: data, CreatedAt: time.Now().UTC().Truncate(time.Microsecond),
	}
	if _, err := db.Exec(ctx, `SELECT pg_advisory_xact_lock(hashtextextended('warden.audit:' || $1::text, 0))`, rec.OrgID); err != nil {
		return err
	}
	var prev string
	err = db.QueryRow(ctx, `SELECT hash FROM audit_log WHERE org_id = $1 ORDER BY id DESC LIMIT 1`, rec.OrgID).Scan(&prev)
	if err != nil && !errors.Is(err, pgx.ErrNoRows) {
		return err
	}
	hash, err := ChainHash(prev, row)
	if err != nil {
		return err
	}
	_, err = db.Exec(ctx, `INSERT INTO audit_log (org_id, actor_id, action, target_type, target_id, ip, user_agent, data, prev_hash, hash, created_at)
		VALUES ($1, $2, $3, $4, $5, $6::inet, $7, $8, $9, $10, $11)`,
		row.OrgID, row.ActorID, row.Action, row.TargetType, row.TargetID, row.IP, row.UserAgent, string(data),
		NonEmpty(prev), hash, row.CreatedAt)
	return err
}
