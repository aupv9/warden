//go:build integration

package store_test

import (
	"context"
	"crypto/rand"
	"encoding/base64"
	"fmt"
	"slices"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/jackc/pgx/v5"

	"github.com/aupv9/warden/backend/internal/db"
	"github.com/aupv9/warden/backend/internal/domain/registry"
	"github.com/aupv9/warden/backend/internal/secretbox"
	"github.com/aupv9/warden/backend/internal/service"
	"github.com/aupv9/warden/backend/internal/store"
)

type registryStub struct {
	mu       sync.Mutex
	ok       bool
	kind     string
	password string
}

func (s *registryStub) Check(_ context.Context, _, _, password string) (bool, string) {
	s.mu.Lock()
	defer s.mu.Unlock()
	s.password = password
	return s.ok, s.kind
}

func newKey(t *testing.T) string {
	t.Helper()
	raw := make([]byte, 32)
	_, _ = rand.Read(raw)
	return base64.StdEncoding.EncodeToString(raw)
}

// The registry routes against the real schema: encryption at rest, one host
// per org, RLS between orgs, the test's outcome and rate limit (counted from
// the audit log), key rotation, and an audit trail without the password.
func TestRegistriesAgainstSchema(t *testing.T) {
	w := newWorld(t)
	k1 := newKey(t)
	keys, err := secretbox.Parse("k1:"+k1, "")
	if err != nil {
		t.Fatal(err)
	}
	stub := &registryStub{ok: true}
	clock := time.Now().UTC()
	svc := service.New(w.db, w.objs, service.Config{Registries: service.RegistryConfig{Keys: keys, Checker: stub}}, nil)
	svc.SetClock(func() time.Time { return clock })
	a, b := w.org("RGA"), w.org("RGB")
	admin, otherAdmin := w.actor("RGAadmin", a.id), w.actor("RGBadmin", b.id)

	password := "glpat-" + strings.Repeat("W", 20)
	created, err := svc.CreateRegistryCredential(ctx, admin, service.CreateRegistryCredentialInput{Host: "ghcr.io", Username: "bot", Password: password})
	if err != nil || created.CreatedBy == nil || created.CreatedBy.Email == "" || created.Host != "ghcr.io" {
		t.Fatal(created, err)
	}
	id := created.ID
	_, err = svc.CreateRegistryCredential(ctx, admin, service.CreateRegistryCredentialInput{Host: "ghcr.io", Username: "x", Password: "y"})
	if code(err) != "CONFLICT" {
		t.Fatal(err)
	}
	// Another org may use the same host; it sees only its own.
	if _, err := svc.CreateRegistryCredential(ctx, otherAdmin, service.CreateRegistryCredentialInput{Host: "ghcr.io", Username: "x", Password: "y"}); err != nil {
		t.Fatal(err)
	}
	if l, err := svc.RegistryCredentials(ctx, otherAdmin); err != nil || len(l.Items) != 1 || l.Items[0].ID == id {
		t.Fatal(l, err)
	}
	if _, err := svc.UpdateRegistryCredential(ctx, otherAdmin, id, service.UpdateRegistryCredentialInput{Username: ptr("evil")}); code(err) != "NOT_FOUND" {
		t.Fatal(err)
	}
	if err := svc.DeleteRegistryCredential(ctx, otherAdmin, id); code(err) != "NOT_FOUND" {
		t.Fatal(err)
	}

	// At rest: ciphertext only, opening for this org and row alone.
	var enc []byte
	var keyID string
	ownerOne(t, a.id, `SELECT password_enc, key_id FROM registry_credential WHERE id = $1`, []any{id}, &enc, &keyID)
	if strings.Contains(string(enc), password) || keyID != "k1" {
		t.Fatal("stored in clear")
	}
	if got, err := registry.OpenPassword(keys, a.id, id, keyID, enc); err != nil || got != password {
		t.Fatal(got, err)
	}
	if _, err := registry.OpenPassword(keys, b.id, id, keyID, enc); err == nil {
		t.Fatal("opens for another org")
	}

	// Test: the checker gets the password; the outcome is stored.
	res, err := svc.TestRegistryCredential(ctx, admin, id)
	if err != nil || !res.OK || res.Error != nil || stub.password != password {
		t.Fatal(res, err)
	}
	stub.ok, stub.kind = false, registry.ErrUnauthorized
	clock = clock.Add(time.Second)
	if res, err = svc.TestRegistryCredential(ctx, admin, id); err != nil || res.OK || *res.Error != "unauthorized" {
		t.Fatal(res, err)
	}
	l := must(svc.RegistryCredentials(ctx, admin))
	if len(l.Items) != 1 || l.Items[0].LastUsedAt == nil || l.Items[0].LastError == nil || *l.Items[0].LastError != "unauthorized" {
		t.Fatal(l)
	}
	// 10 per credential per hour.
	for i := range 8 {
		clock = clock.Add(time.Second)
		if _, err := svc.TestRegistryCredential(ctx, admin, id); err != nil {
			t.Fatal(i, err)
		}
	}
	if _, err := svc.TestRegistryCredential(ctx, admin, id); code(err) != "RATE_LIMITED" {
		t.Fatal(err)
	}

	// A new password clears the error and is sealed again.
	up, err := svc.UpdateRegistryCredential(ctx, admin, id, service.UpdateRegistryCredentialInput{Password: ptr(password + "2")})
	if err != nil || up.LastError != nil || up.LastUsedAt == nil {
		t.Fatal(up, err)
	}

	// Key rotation: with k2 active and k1 old, the row moves to k2.
	k2 := "k2:" + newKey(t)
	rotated, err := secretbox.Parse(k2, "k1:"+k1)
	if err != nil {
		t.Fatal(err)
	}
	n, unreadable, err := store.ReencryptRegistryCredentials(ctx, w.db, rotated)
	if err != nil || n < 1 || slices.Contains(unreadable, id) {
		t.Fatal(n, unreadable, err)
	}
	ownerOne(t, a.id, `SELECT password_enc, key_id FROM registry_credential WHERE id = $1`, []any{id}, &enc, &keyID)
	onlyK2, _ := secretbox.Parse(k2, "")
	if got, err := registry.OpenPassword(onlyK2, a.id, id, keyID, enc); err != nil || got != password+"2" {
		t.Fatal(keyID, err)
	}

	if err := svc.DeleteRegistryCredential(ctx, admin, id); err != nil {
		t.Fatal(err)
	}
	var left int
	ownerOne(t, a.id, `SELECT count(*) FROM registry_credential WHERE id = $1`, []any{id}, &left)
	if left != 0 {
		t.Fatal("not deleted")
	}

	// The audit trail: host and username, never the password.
	var actions, data string
	ownerOne(t, a.id, `SELECT string_agg(action, ',' ORDER BY id), string_agg(data::text, ' ') FROM audit_log
		WHERE org_id = $1 AND action IN ('registry.created', 'registry.updated', 'registry.deleted', 'registry.reencrypted')`,
		[]any{a.id}, &actions, &data)
	if actions != "registry.created,registry.updated,registry.reencrypted,registry.deleted" || strings.Contains(data, password) ||
		!strings.Contains(data, "ghcr.io") {
		t.Fatal(actions, data)
	}
	var tested int
	ownerOne(t, a.id, `SELECT count(*) FROM audit_log WHERE org_id = $1 AND action = 'registry.tested' AND target_id = $2`,
		[]any{a.id, id.String()}, &tested)
	if tested != 10 {
		t.Fatal(tested)
	}
}

// A pulled scan is queued with its job in one transaction, without an upload
// (no size or checksum); its issues carry the image layer of a secret.
func TestPullScanAgainstSchema(t *testing.T) {
	w := newWorld(t)
	f := w.org("PLA")
	dev := w.actor("PLAdev", f.id)
	ref := "ghcr.io/acme/api@sha256:" + strings.Repeat("ab", 32)
	sc, err := w.svc.CreatePullScan(ctx, dev, f.project, service.PullScanInput{ImageRef: ref})
	if err != nil || !sc.Pulled || sc.Status != "queued" || sc.Kind != "image" || sc.Target != "ghcr.io/acme/api" ||
		sc.ImageRef == nil || *sc.ImageRef != ref || sc.FileSize != 0 || fmt.Sprint(sc.Tools) != "[trivy gitleaks]" {
		t.Fatal(sc, err)
	}
	var nullSize, nullSum bool
	ownerOne(t, f.id, `SELECT file_size IS NULL, sha256 IS NULL FROM scan WHERE id = $1`, []any{sc.ID}, &nullSize, &nullSum)
	if !nullSize || !nullSum {
		t.Fatal("upload columns set")
	}
	var jobs int
	if err := w.pool.QueryRow(ctx, `SELECT count(*) FROM river_job WHERE kind = 'run_scan' AND args->>'scan_id' = $1`, sc.ID.String()).Scan(&jobs); err != nil || jobs != 1 {
		t.Fatal(jobs, err)
	}
	if got := must(w.svc.Scan(ctx, dev, sc.ID)); !got.Pulled {
		t.Fatal(got)
	}
	if got := must(w.svc.Scan(ctx, dev, f.scan)); got.Pulled {
		t.Fatal("an upload reads as pulled")
	}

	id := w.issue(f, 1, "high", "open", nil, nil)
	digest := "sha256:" + strings.Repeat("0f", 32)
	ownerExec(t, f.id, `UPDATE issue SET target = 'ghcr.io/acme/api', image_layer_digest = $2, image_layer_index = 4,
		image_layer_count = 2 WHERE id = $1`, id, digest)
	iss := must(w.svc.Issue(ctx, dev, id))
	if iss.ImageLayer == nil || iss.ImageLayer.Digest != digest || iss.ImageLayer.Index != 4 || iss.ImageLayer.Count != 2 {
		t.Fatal(iss.ImageLayer)
	}
	other := w.issue(f, 2, "low", "open", nil, nil)
	if iss := must(w.svc.Issue(ctx, dev, other)); iss.ImageLayer != nil {
		t.Fatal(iss.ImageLayer)
	}

	// RLS: another org doesn't see the scan.
	g := w.org("PLB")
	var seen int
	if err := db.WithOrg(ctx, w.pool, g.id, func(tx pgx.Tx) error {
		return tx.QueryRow(ctx, `SELECT count(*) FROM scan WHERE id = $1`, sc.ID).Scan(&seen)
	}); err != nil || seen != 0 {
		t.Fatal(seen, err)
	}
}
