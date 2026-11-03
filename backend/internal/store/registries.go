package store

import (
	"context"
	"errors"
	"fmt"
	"time"

	"github.com/google/uuid"
	"github.com/jackc/pgx/v5"

	"github.com/aupv9/warden/backend/internal/domain/registry"
	"github.com/aupv9/warden/backend/internal/secretbox"
	"github.com/aupv9/warden/backend/internal/service"
)

// Registry credentials (v0.7 wave 2). registry_credential has forced RLS;
// every query runs under the caller's app.org_id. The app may update only the
// credential and its last outcome (grants.sql).

const registrySelect = `SELECT c.id, c.org_id, c.host, c.username, c.password_enc, c.key_id,
		u.id, u.email::text, u.display_name, c.created_at, c.updated_at, c.last_used_at, c.last_error
	FROM registry_credential c LEFT JOIN app_user u ON u.id = c.created_by`

func scanRegistryCredential(row pgx.CollectableRow) (service.RegistryCredentialRecord, error) {
	var (
		c             service.RegistryCredentialRecord
		uID           *uuid.UUID
		uEmail, uName *string
	)
	err := row.Scan(&c.ID, &c.OrgID, &c.Host, &c.Username, &c.PasswordEnc, &c.KeyID,
		&uID, &uEmail, &uName, &c.CreatedAt, &c.UpdatedAt, &c.LastUsedAt, &c.LastError)
	c.CreatedBy = userRef(uID, uEmail, uName)
	return c, err
}

func (r *Repo) RegistryCredentials(ctx context.Context) ([]service.RegistryCredentialRecord, error) {
	rows, _ := r.tx.Query(ctx, registrySelect+` ORDER BY c.host`)
	return collect(rows, scanRegistryCredential)
}

func (r *Repo) RegistryCredential(ctx context.Context, id uuid.UUID, forUpdate bool) (service.RegistryCredentialRecord, error) {
	q := registrySelect + ` WHERE c.id = $1`
	if forUpdate {
		q += ` FOR UPDATE OF c`
	}
	rows, _ := r.tx.Query(ctx, q, id)
	c, err := pgx.CollectExactlyOneRow(rows, scanRegistryCredential)
	return c, mapErr(err)
}

func (r *Repo) LockRegistryCredentials(ctx context.Context, orgID uuid.UUID) error {
	_, err := r.tx.Exec(ctx, `SELECT pg_advisory_xact_lock(hashtextextended('warden.registries:' || $1::text, 0))`, orgID)
	return err
}

func (r *Repo) CountRegistryCredentials(ctx context.Context) (int, error) {
	var n int
	err := r.tx.QueryRow(ctx, `SELECT count(*) FROM registry_credential`).Scan(&n)
	return n, err
}

func (r *Repo) InsertRegistryCredential(ctx context.Context, c service.RegistryCredentialRecord) error {
	var createdBy *uuid.UUID
	if c.CreatedBy != nil {
		createdBy = &c.CreatedBy.ID
	}
	_, err := r.tx.Exec(ctx, `INSERT INTO registry_credential (id, org_id, host, username, password_enc, key_id, created_by,
			created_at, updated_at)
		VALUES ($1, $2, $3, $4, $5, $6, $7, $8, $9)`,
		c.ID, c.OrgID, c.Host, c.Username, c.PasswordEnc, c.KeyID, createdBy, c.CreatedAt.T(), c.UpdatedAt.T())
	return mapErr(err)
}

func (r *Repo) UpdateRegistryCredential(ctx context.Context, c service.RegistryCredentialRecord) error {
	var lastUsed *time.Time
	if c.LastUsedAt != nil {
		t := c.LastUsedAt.T()
		lastUsed = &t
	}
	_, err := r.tx.Exec(ctx, `UPDATE registry_credential SET username = $2, password_enc = $3, key_id = $4, updated_at = $5,
			last_used_at = $6, last_error = $7
		WHERE id = $1`,
		c.ID, c.Username, c.PasswordEnc, c.KeyID, c.UpdatedAt.T(), lastUsed, c.LastError)
	return mapErr(err)
}

func (r *Repo) RecordRegistryCheck(ctx context.Context, id uuid.UUID, ok bool, errKind string, at time.Time) error {
	var err error
	if ok {
		_, err = r.tx.Exec(ctx, `UPDATE registry_credential SET last_used_at = $2, last_error = NULL WHERE id = $1`, id, at)
	} else {
		_, err = r.tx.Exec(ctx, `UPDATE registry_credential SET last_error = $2 WHERE id = $1`, id, errKind)
	}
	return mapErr(err)
}

func (r *Repo) DeleteRegistryCredential(ctx context.Context, id uuid.UUID) error {
	_, err := r.tx.Exec(ctx, `DELETE FROM registry_credential WHERE id = $1`, id)
	return mapErr(err)
}

// ReencryptRegistryCredentials moves every registry password to the active key
// (warden-admin secrets rotate), like ReencryptWebhooks: org by org under each
// org's RLS scope; rows no key can open are left as they are and returned
// (pulls with them fail until someone sets a new password); each org with
// re-encrypted rows gets one audit entry with no actor.
func ReencryptRegistryCredentials(ctx context.Context, d *DB, keys *secretbox.Keyring) (int, []uuid.UUID, error) {
	if !keys.Available() {
		return 0, nil, errors.New("secrets.key is not set")
	}
	var orgs []uuid.UUID
	err := d.InOrg(ctx, uuid.Nil, func(sr service.Repo) error {
		rows, _ := sr.(*Repo).tx.Query(ctx, `SELECT id FROM organization ORDER BY id`)
		var err error
		orgs, err = collect(rows, pgx.RowTo[uuid.UUID])
		return err
	})
	if err != nil {
		return 0, nil, err
	}
	done, unreadable := 0, []uuid.UUID{}
	for _, org := range orgs {
		err := d.InOrg(ctx, org, func(sr service.Repo) error {
			r := sr.(*Repo)
			type row struct {
				id    uuid.UUID
				enc   []byte
				keyID string
			}
			rows, _ := r.tx.Query(ctx, `SELECT id, password_enc, key_id FROM registry_credential WHERE key_id <> $1
				ORDER BY id FOR UPDATE`, keys.ActiveID())
			list, err := collect(rows, func(cr pgx.CollectableRow) (row, error) {
				var x row
				return x, cr.Scan(&x.id, &x.enc, &x.keyID)
			})
			if err != nil {
				return err
			}
			n := 0
			for _, x := range list {
				pw, err := registry.OpenPassword(keys, org, x.id, x.keyID, x.enc)
				if err != nil {
					unreadable = append(unreadable, x.id)
					continue
				}
				enc, keyID, err := registry.SealPassword(keys, org, x.id, pw)
				if err != nil {
					return err
				}
				if _, err := r.tx.Exec(ctx, `UPDATE registry_credential SET password_enc = $2, key_id = $3 WHERE id = $1`,
					x.id, enc, keyID); err != nil {
					return err
				}
				n++
			}
			done += n
			if n == 0 {
				return nil
			}
			return r.AppendAudit(ctx, service.AuditRecord{OrgID: org, Action: "registry.reencrypted", TargetType: "org",
				TargetID: org.String(), Data: map[string]any{"count": n, "key_id": keys.ActiveID(), "via": "warden-admin"}})
		})
		if err != nil {
			return done, unreadable, fmt.Errorf("org %s: %w", org, err)
		}
	}
	return done, unreadable, nil
}
