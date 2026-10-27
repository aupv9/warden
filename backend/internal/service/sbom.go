package service

import (
	"context"
	"fmt"
	"time"

	"github.com/google/uuid"

	"github.com/aupv9/warden/backend/internal/domain/rbac"
	"github.com/aupv9/warden/backend/internal/scan/sbom"
)

// SBOMURLTTL is how long an SBOM download link is valid.
const SBOMURLTTL = 5 * time.Minute

type SBOMDownload struct {
	URL        string `json:"url"`
	ExpiresAt  Time   `json:"expires_at"`
	Format     string `json:"format"`
	Size       int64  `json:"size"`
	SHA256     string `json:"sha256"`
	Components int    `json:"components"`
}

// ScanSBOM returns a short-lived download link for the scan's SBOM: for
// whoever can view the project's results (an API token only in its own
// project). The SBOM lists what Trivy found in the scanned code, so it is
// served as an attachment of a fixed type and never rendered.
func (s *Service) ScanSBOM(ctx context.Context, a *Actor, scanID uuid.UUID) (SBOMDownload, error) {
	var out SBOMDownload
	err := s.inOrg(ctx, a, func(r Repo) error {
		sc, role, err := scanAccess(ctx, r, a, scanID, false)
		if err != nil {
			return err
		}
		if !rbac.Can(rbac.ViewResults, a.OrgRole, role, false) {
			return errForbidden()
		}
		if sc.SBOM == nil {
			return errNotFound() // Trivy didn't run or failed, or the SBOM expired
		}
		project, err := r.Project(ctx, a.vis(), sc.ProjectID, s.now())
		if err != nil {
			return notFound(err)
		}
		// Project keys are [A-Z][A-Z0-9]{1,9}: safe in a file name.
		name := fmt.Sprintf("%s-%s.cdx.json", project.Key, scanID.String()[:8])
		expires := s.now().Add(SBOMURLTTL)
		url, err := s.objects.PresignGet(ctx, sc.SBOM.Key, SBOMURLTTL, name, sbom.MediaType)
		if err != nil {
			return fmt.Errorf("presign sbom: %w", err)
		}
		out = SBOMDownload{URL: url, ExpiresAt: Time(expires), Format: "cyclonedx-json", Size: sc.SBOM.Size,
			SHA256: sc.SBOM.SHA256, Components: sc.SBOM.Components}
		return nil
	})
	return out, err
}
