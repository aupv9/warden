package store

import (
	"context"
	"encoding/json"
	"fmt"

	"github.com/google/uuid"

	"github.com/aupv9/warden/backend/internal/domain/licensepolicy"
	"github.com/aupv9/warden/backend/internal/service"
)

func (r *Repo) OrgLicensePolicy(ctx context.Context, orgID uuid.UUID) (licensepolicy.Policy, error) {
	var raw []byte
	if err := r.tx.QueryRow(ctx, `SELECT license_policy FROM organization WHERE id = $1`, orgID).Scan(&raw); err != nil {
		return licensepolicy.Policy{}, mapErr(err)
	}
	var p licensepolicy.Policy
	if err := json.Unmarshal(raw, &p); err != nil {
		return licensepolicy.Policy{}, fmt.Errorf("organization.license_policy: %w", err)
	}
	return p, nil
}

func (r *Repo) SetOrgLicensePolicy(ctx context.Context, orgID uuid.UUID, p licensepolicy.Policy) error {
	raw, err := json.Marshal(p)
	if err != nil {
		return err
	}
	tag, err := r.tx.Exec(ctx, `UPDATE organization SET license_policy = $2 WHERE id = $1`, orgID, raw)
	if err == nil && tag.RowsAffected() == 0 {
		return service.ErrNotFound
	}
	return mapErr(err)
}
