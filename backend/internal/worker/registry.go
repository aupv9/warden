package worker

import (
	"context"
	"errors"
	"fmt"
	"log/slog"
	"time"

	"github.com/google/uuid"
	"github.com/jackc/pgx/v5"

	"github.com/aupv9/warden/backend/internal/registry"
	"github.com/aupv9/warden/backend/internal/scan/orchestrator"
	"github.com/aupv9/warden/backend/internal/secretbox"
)

// RegistrySettings configure image pulls (POST …/scans/pull).
type RegistrySettings struct {
	// Keys decrypt registry_credential.password_enc (secrets.key); without
	// them a pull that has credentials fails (PULL_FAILED) rather than going
	// anonymous.
	Keys *secretbox.Keyring
	// Client pulls (registry.NewClient with registry.allow_hosts); nil is a
	// client without allowed hosts.
	Client *registry.Client
	// Platform is scan.pull_platform.
	Platform registry.Platform
}

// pullSpec is what a pulled scan's Pull needs: the reference and the org's
// credentials for its host (nil: anonymous).
type pullSpec struct {
	ref    registry.Ref
	creds  *registry.Credentials
	credID uuid.UUID // uuid.Nil without credentials
}

// sealedCredential is a registry_credential row as stored.
type sealedCredential struct {
	ID       uuid.UUID
	Username string
	Sealed   []byte
	KeyID    string
}

// loadPull reads a pulled image scan's reference and the org's credentials
// for its host (inside the scan's org: RLS). It returns nil for a scan that
// isn't pulled. A reference that doesn't parse is the API's bug; the scan
// fails with PULL_FAILED.
func loadPull(ctx context.Context, db DB, org, scanID uuid.UUID) (*pullRow, error) {
	var pulled bool
	var imageRef *string
	if err := db.QueryRow(ctx, `SELECT pulled, image_ref FROM scan WHERE id = $1`, scanID).Scan(&pulled, &imageRef); err != nil {
		return nil, err
	}
	if !pulled {
		return nil, nil
	}
	p := &pullRow{}
	if imageRef == nil {
		p.bad = errors.New("pulled scan without image_ref")
		return p, nil
	}
	ref, err := registry.ParseRef(*imageRef)
	if err != nil {
		p.bad = err
		return p, nil
	}
	p.ref = ref
	var c sealedCredential
	err = db.QueryRow(ctx, `SELECT id, username, password_enc, key_id FROM registry_credential
		WHERE org_id = $1 AND host = $2`, org, ref.Host).Scan(&c.ID, &c.Username, &c.Sealed, &c.KeyID)
	switch {
	case errors.Is(err, pgx.ErrNoRows):
	case err != nil:
		return nil, err
	default:
		p.cred = &c
	}
	return p, nil
}

type pullRow struct {
	ref  registry.Ref
	cred *sealedCredential
	bad  error // the row can't be pulled
}

// open decrypts the credentials; the password exists in clear only in the
// pull's memory, never in a log line (registry.Credentials formats without it).
func (p *pullRow) open(keys *secretbox.Keyring, org uuid.UUID) (*pullSpec, error) {
	if p.bad != nil {
		return nil, p.bad
	}
	s := &pullSpec{ref: p.ref}
	if p.cred == nil {
		return s, nil
	}
	pw, err := registry.OpenPassword(keys, org, p.cred.ID, p.cred.KeyID, p.cred.Sealed)
	if err != nil {
		return nil, fmt.Errorf("registry credential %s (key %q) can't be decrypted: %w", p.cred.ID, p.cred.KeyID, err)
	}
	s.creds, s.credID = &registry.Credentials{Username: p.cred.Username, Password: pw}, p.cred.ID
	return s, nil
}

var _ orchestrator.Puller = (*liveDeps)(nil)

// Pull fetches the scan's image into dest (orchestrator.Puller) and records
// on the credential what happened.
func (d *liveDeps) Pull(ctx context.Context, dest string) error {
	if d.pull == nil {
		return errors.New("not a pulled scan")
	}
	r := d.env.Registry
	client := r.Client
	if client == nil {
		client = registry.NewClient(registry.Options{})
	}
	plat := r.Platform
	if plat.OS == "" {
		plat = registry.Platform{OS: "linux", Arch: "amd64"}
	}
	started := time.Now()
	res, err := client.Pull(ctx, d.pull.ref, d.pull.creds, plat, registry.Limits{MaxBytes: d.env.Limits.PullMaxBytes}, dest)
	d.recordCredential(ctx, err)
	if err != nil {
		return err
	}
	d.env.Log.Info("image pulled", "scan_id", d.scan, "ref", d.pull.ref.String(), "manifest", res.Manifest,
		"platform", res.Platform, "layers", res.Layers, "bytes", res.Bytes, "with_credentials", d.pull.creds != nil,
		"duration_ms", time.Since(started).Milliseconds())
	return nil
}

// recordCredential stamps the credential a pull used: last_used_at, and
// last_error from the outcome (cleared when the failure says nothing about
// the credentials or the registry's reachability). Best effort: a failed
// update costs only the stamp.
func (d *liveDeps) recordCredential(ctx context.Context, pullErr error) {
	if d.pull.credID == uuid.Nil {
		return
	}
	var reason *string
	var e *registry.Error
	if errors.As(pullErr, &e) {
		if r := e.Reason(); r != "" {
			reason = &r
		}
	}
	ctx, cancel := context.WithTimeout(context.WithoutCancel(ctx), 10*time.Second)
	defer cancel()
	err := d.env.Tx(ctx, d.org, func(db DB) error {
		_, err := db.Exec(ctx, `UPDATE registry_credential SET last_used_at = now(), last_error = $2 WHERE id = $1`,
			d.pull.credID, reason)
		return err
	})
	if err != nil {
		d.env.Log.Warn("registry credential not stamped", "scan_id", d.scan, "credential_id", d.pull.credID, "err", err)
	}
}

// logPullSetup reports a pulled scan that fails before pulling.
func logPullSetup(log *slog.Logger, err error) {
	log.Error("pulled scan can't start", "code", registry.CodeFailed, "err", err)
}
