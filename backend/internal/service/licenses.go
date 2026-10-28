package service

import (
	"context"

	"github.com/google/uuid"

	"github.com/aupv9/warden/backend/internal/domain/licensepolicy"
	"github.com/aupv9/warden/backend/internal/domain/rbac"
)

// LicensePolicyRepo: the org's license policy (organization.license_policy).
type LicensePolicyRepo interface {
	OrgLicensePolicy(ctx context.Context, orgID uuid.UUID) (licensepolicy.Policy, error)
	SetOrgLicensePolicy(ctx context.Context, orgID uuid.UUID, p licensepolicy.Policy) error
}

// LicensePolicy is the API's view of the policy: every category listed, and
// whether it can produce issues at all.
type LicensePolicy struct {
	Enabled    bool                                            `json:"enabled"`
	Categories map[licensepolicy.Category]licensepolicy.Action `json:"categories"`
	Deny       []string                                        `json:"deny"`
	Allow      []string                                        `json:"allow"`
}

func licensePolicyView(p licensepolicy.Policy) LicensePolicy {
	n := licensepolicy.Normalize(p)
	return LicensePolicy{Enabled: n.Enabled(), Categories: n.Categories, Deny: n.Deny, Allow: n.Allow}
}

type LicensePolicyInput struct {
	Categories map[string]string `json:"categories"`
	Deny       []string          `json:"deny"`
	Allow      []string          `json:"allow"`
}

func (in LicensePolicyInput) validate() (licensepolicy.Policy, error) {
	fe := fieldErrors{}
	p := licensepolicy.Policy{Categories: map[licensepolicy.Category]licensepolicy.Action{}, Deny: in.Deny, Allow: in.Allow}
	if in.Categories == nil {
		fe.add("categories", "is required")
	}
	for k, v := range in.Categories {
		p.Categories[licensepolicy.Category(k)] = licensepolicy.Action(v)
	}
	for _, c := range licensepolicy.Categories {
		if _, ok := in.Categories[string(c)]; in.Categories != nil && !ok {
			fe.add("categories."+string(c), "is required")
		}
	}
	if in.Deny == nil {
		fe.add("deny", "is required")
	}
	if in.Allow == nil {
		fe.add("allow", "is required")
	}
	for _, e := range p.Validate() {
		fe.add(e.Field, e.Message)
	}
	return licensepolicy.Normalize(p), fe.err()
}

// LicensePolicy returns the org's license policy (any member: it explains
// the license issues they see).
func (s *Service) LicensePolicy(ctx context.Context, a *Actor) (LicensePolicy, error) {
	var out LicensePolicy
	err := s.inOrg(ctx, a, func(r Repo) error {
		p, err := r.OrgLicensePolicy(ctx, a.OrgID)
		if err != nil {
			return notFound(err)
		}
		out = licensePolicyView(p)
		return nil
	})
	return out, err
}

// SetLicensePolicy replaces the org's license policy (security leads). It
// applies from the next scan; the change is audited with both versions.
func (s *Service) SetLicensePolicy(ctx context.Context, a *Actor, in LicensePolicyInput) (LicensePolicy, error) {
	p, verr := in.validate()
	var out LicensePolicy
	err := s.inOrg(ctx, a, func(r Repo) error {
		if !rbac.Can(rbac.ConfigurePolicy, a.OrgRole, "", false) {
			return errForbidden()
		}
		if verr != nil {
			return verr
		}
		cur, err := r.OrgLicensePolicy(ctx, a.OrgID)
		if err != nil {
			return notFound(err)
		}
		out = licensePolicyView(p)
		if licensepolicy.Equal(cur, p) {
			return nil
		}
		if err := r.SetOrgLicensePolicy(ctx, a.OrgID, p); err != nil {
			return err
		}
		return s.audit(ctx, r, a, "org.license_policy_changed", "org", a.OrgID.String(), map[string]any{
			"from": licensePolicyView(cur), "to": out,
		})
	})
	return out, err
}
