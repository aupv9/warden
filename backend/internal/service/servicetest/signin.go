package servicetest

import (
	"context"
	"slices"

	"github.com/google/uuid"

	"github.com/aupv9/warden/backend/internal/service"
)

func (f *Fake) OrgSignInPolicy(_ context.Context, orgID uuid.UUID) (service.SignInPolicy, error) {
	if err := f.fail("OrgSignInPolicy"); err != nil {
		return service.SignInPolicy{}, err
	}
	o, ok := f.st.Orgs[orgID]
	if !ok {
		return service.SignInPolicy{}, service.ErrNotFound
	}
	p := o.SignIn
	return service.SignInPolicy{MFARoles: slices.Clone(p.MFARoles), AllowedEmailDomains: slices.Clone(p.AllowedEmailDomains)}, nil
}

func (f *Fake) SetOrgSignInPolicy(_ context.Context, orgID uuid.UUID, p service.SignInPolicy) error {
	if err := f.fail("SetOrgSignInPolicy"); err != nil {
		return err
	}
	o, ok := f.st.Orgs[orgID]
	if !ok {
		return service.ErrNotFound
	}
	o.SignIn = service.SignInPolicy{MFARoles: slices.Clone(p.MFARoles), AllowedEmailDomains: slices.Clone(p.AllowedEmailDomains)}
	f.st.Orgs[orgID] = o
	return nil
}

// RelinkUser enforces the unique subject like app_user's constraint.
func (f *Fake) RelinkUser(_ context.Context, userID uuid.UUID, sub string) error {
	if err := f.fail("RelinkUser"); err != nil {
		return err
	}
	u, ok := f.st.Users[userID]
	if !ok {
		return service.ErrNotFound
	}
	for id, other := range f.st.Users {
		if id != userID && other.Sub == sub {
			return service.ErrConflict
		}
	}
	u.Sub, u.RelinkUntil = sub, nil
	f.st.Users[userID] = u
	return nil
}

// SetSignInPolicy seeds an org's sign-in policy (outside transactions).
func (f *Fake) SetSignInPolicy(orgID uuid.UUID, p service.SignInPolicy) {
	o := f.st.Orgs[orgID]
	o.SignIn = p
	f.st.Orgs[orgID] = o
}
