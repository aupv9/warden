package servicetest

import (
	"context"
	"fmt"
	"maps"
	"slices"
	"strings"
	"time"

	"github.com/google/uuid"

	"github.com/aupv9/warden/backend/internal/service"
)

// Registry credentials (v0.7 wave 2): registry_credential, unique per (org, host).

type registryState map[uuid.UUID]service.RegistryCredentialRecord

func (r registryState) clone() registryState { return maps.Clone(r) }

func (f *Fake) registryCred(id uuid.UUID) (service.RegistryCredentialRecord, bool) {
	c, ok := f.st.registries[id]
	return c, ok && c.OrgID == f.org
}

// StoredRegistryCredential returns a credential row as stored (any org).
func (f *Fake) StoredRegistryCredential(id uuid.UUID) (service.RegistryCredentialRecord, bool) {
	c, ok := f.st.registries[id]
	return c, ok
}

func (f *Fake) withCreator(c service.RegistryCredentialRecord) service.RegistryCredentialRecord {
	if c.CreatedBy != nil {
		u := f.st.Users[c.CreatedBy.ID]
		c.CreatedBy = &service.UserRef{ID: u.ID, Email: u.Email, DisplayName: u.DisplayName}
	}
	return c
}

func (f *Fake) RegistryCredentials(_ context.Context) ([]service.RegistryCredentialRecord, error) {
	if err := f.fail("RegistryCredentials"); err != nil {
		return nil, err
	}
	var out []service.RegistryCredentialRecord
	for _, c := range f.st.registries {
		if c.OrgID == f.org {
			out = append(out, f.withCreator(c))
		}
	}
	slices.SortFunc(out, func(a, b service.RegistryCredentialRecord) int { return strings.Compare(a.Host, b.Host) })
	return out, nil
}

func (f *Fake) RegistryCredential(_ context.Context, id uuid.UUID, _ bool) (service.RegistryCredentialRecord, error) {
	if err := f.fail("RegistryCredential"); err != nil {
		return service.RegistryCredentialRecord{}, err
	}
	c, ok := f.registryCred(id)
	if !ok {
		return service.RegistryCredentialRecord{}, service.ErrNotFound
	}
	return f.withCreator(c), nil
}

// AddRegistryCredential stores a credential row as given (seeding).
func (f *Fake) AddRegistryCredential(c service.RegistryCredentialRecord) {
	if f.st.registries == nil {
		f.st.registries = registryState{}
	}
	f.st.registries[c.ID] = c
}

// SetRegistryCredential changes a stored credential (e.g. as a pull would
// record its outcome).
func (f *Fake) SetRegistryCredential(id uuid.UUID, fn func(*service.RegistryCredentialRecord)) {
	c := f.st.registries[id]
	fn(&c)
	f.st.registries[id] = c
}

func (f *Fake) LockRegistryCredentials(_ context.Context, _ uuid.UUID) error {
	return f.fail("LockRegistryCredentials")
}

func (f *Fake) CountRegistryCredentials(_ context.Context) (int, error) {
	n := 0
	for _, c := range f.st.registries {
		if c.OrgID == f.org {
			n++
		}
	}
	return n, f.fail("CountRegistryCredentials")
}

func (f *Fake) InsertRegistryCredential(_ context.Context, c service.RegistryCredentialRecord) error {
	if err := f.fail("InsertRegistryCredential"); err != nil {
		return err
	}
	for _, o := range f.st.registries {
		if o.OrgID == c.OrgID && o.Host == c.Host {
			return fmt.Errorf("%w: registry_credential_host", service.ErrConflict)
		}
	}
	if f.st.registries == nil {
		f.st.registries = registryState{}
	}
	c.PasswordEnc = slices.Clone(c.PasswordEnc)
	f.st.registries[c.ID] = c
	return nil
}

func (f *Fake) UpdateRegistryCredential(_ context.Context, c service.RegistryCredentialRecord) error {
	if err := f.fail("UpdateRegistryCredential"); err != nil {
		return err
	}
	old, ok := f.registryCred(c.ID)
	if !ok {
		return nil
	}
	// Only the columns the app may update (grants.sql).
	old.Username, old.PasswordEnc, old.KeyID = c.Username, slices.Clone(c.PasswordEnc), c.KeyID
	old.UpdatedAt, old.LastUsedAt, old.LastError = c.UpdatedAt, c.LastUsedAt, c.LastError
	f.st.registries[c.ID] = old
	return nil
}

func (f *Fake) RecordRegistryCheck(_ context.Context, id uuid.UUID, ok bool, errKind string, at time.Time) error {
	if err := f.fail("RecordRegistryCheck"); err != nil {
		return err
	}
	c, found := f.registryCred(id)
	if !found {
		return nil
	}
	if ok {
		t := service.Time(at)
		c.LastUsedAt, c.LastError = &t, nil
	} else {
		c.LastError = &errKind
	}
	f.st.registries[id] = c
	return nil
}

func (f *Fake) DeleteRegistryCredential(_ context.Context, id uuid.UUID) error {
	if err := f.fail("DeleteRegistryCredential"); err != nil {
		return err
	}
	if _, ok := f.registryCred(id); ok {
		delete(f.st.registries, id)
	}
	return nil
}
