package servicetest

import (
	"context"
	"encoding/json"

	"github.com/google/uuid"

	"github.com/aupv9/warden/backend/internal/domain/licensepolicy"
	"github.com/aupv9/warden/backend/internal/service"
)

// The license policy is kept as stored JSON, like organization.license_policy.

func (f *Fake) OrgLicensePolicy(_ context.Context, orgID uuid.UUID) (licensepolicy.Policy, error) {
	if err := f.fail("OrgLicensePolicy"); err != nil {
		return licensepolicy.Policy{}, err
	}
	o, ok := f.st.Orgs[orgID]
	if !ok {
		return licensepolicy.Policy{}, service.ErrNotFound
	}
	var p licensepolicy.Policy
	if o.LicensePolicy != nil {
		if err := json.Unmarshal(o.LicensePolicy, &p); err != nil {
			return licensepolicy.Policy{}, err
		}
	}
	return p, nil
}

func (f *Fake) SetOrgLicensePolicy(_ context.Context, orgID uuid.UUID, p licensepolicy.Policy) error {
	if err := f.fail("SetOrgLicensePolicy"); err != nil {
		return err
	}
	o, ok := f.st.Orgs[orgID]
	if !ok {
		return service.ErrNotFound
	}
	raw, err := json.Marshal(p)
	if err != nil {
		return err
	}
	o.LicensePolicy = raw
	f.st.Orgs[orgID] = o
	return nil
}

// StoredLicensePolicy returns an org's license policy JSON as stored.
func (f *Fake) StoredLicensePolicy(orgID uuid.UUID) string {
	return string(f.st.Orgs[orgID].LicensePolicy)
}

// SetScanSBOM records a stored SBOM on a scan (nil: none); Formats is
// derived as the store does (SPDX when SPDXKey is set).
func (f *Fake) SetScanSBOM(id uuid.UUID, s *service.ScanSBOM) {
	if s != nil {
		s.Formats = []string{service.SBOMCycloneDXJSON}
		if s.SPDXKey != "" {
			s.Formats = append(s.Formats, service.SBOMSPDXJSON)
		}
	}
	f.setScan(id, func(r *scanRow) { r.SBOM = s })
}
