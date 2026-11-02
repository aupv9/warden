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

// ScanSBOM returns a short-lived download link for the scan's SBOM in format
// ("" or cyclonedx, or spdx): for whoever can view the project's results (an
// API token only in its own project). The SBOM lists what Trivy found in the
// scanned code, so it is served as an attachment of a fixed type and never
// rendered. components is the CycloneDX count for either format: both files
// come from the same Trivy report.
func (s *Service) ScanSBOM(ctx context.Context, a *Actor, scanID uuid.UUID, format string) (SBOMDownload, error) {
	if format == "" {
		format = SBOMCycloneDX
	}
	if format != SBOMCycloneDX && format != SBOMSPDX {
		return SBOMDownload{}, errField("format", "must be cyclonedx or spdx")
	}
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
		key, size, sum, served, ext, mediaType := sc.SBOM.Key, sc.SBOM.Size, sc.SBOM.SHA256, SBOMCycloneDXJSON, "cdx.json", sbom.MediaType
		if format == SBOMSPDX {
			if sc.SBOM.SPDXKey == "" {
				return errNotFound() // Trivy's SPDX conversion failed, or the scan predates SPDX
			}
			key, size, sum, served, ext, mediaType = sc.SBOM.SPDXKey, sc.SBOM.SPDXSize, sc.SBOM.SPDXSHA256, SBOMSPDXJSON, "spdx.json", sbom.SPDXMediaType
		}
		project, err := r.Project(ctx, a.vis(), sc.ProjectID, s.now())
		if err != nil {
			return notFound(err)
		}
		// Project keys are [A-Z][A-Z0-9]{1,9}: safe in a file name.
		name := fmt.Sprintf("%s-%s.%s", project.Key, scanID.String()[:8], ext)
		expires := s.now().Add(SBOMURLTTL)
		url, err := s.objects.PresignGet(ctx, key, SBOMURLTTL, name, mediaType)
		if err != nil {
			return fmt.Errorf("presign sbom: %w", err)
		}
		out = SBOMDownload{URL: url, ExpiresAt: Time(expires), Format: served, Size: size, SHA256: sum, Components: sc.SBOM.Components}
		return nil
	})
	return out, err
}
