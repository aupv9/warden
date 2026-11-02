package service

import (
	"context"
	"time"

	"github.com/aupv9/warden/backend/internal/domain/ecosystem"
)

// VulnStaleAfter: a source whose publisher date is older than this is shown as
// stale (the mirror isn't being synced).
const VulnStaleAfter = 7 * 24 * time.Hour

// vulnSources are always reported, in this order, loaded or not: the Trivy
// DB, KEV, EPSS, then one OSV malicious-package feed per ecosystem (the
// worker's osv_mal:<ecosystem> sources).
var vulnSources = func() []string {
	out := []string{"trivy_db", "kev", "epss"}
	for _, eco := range ecosystem.OSV {
		out = append(out, "osv_mal:"+eco)
	}
	return out
}()

// VulnRepo reads vuln_intel_source (public data, no RLS).
type VulnRepo interface {
	VulnSources(ctx context.Context) ([]VulnDataSource, error)
}

type VulnDataSource struct {
	Name      string `json:"name"`
	UpdatedAt *Time  `json:"updated_at"`
	LoadedAt  *Time  `json:"loaded_at"`
	Records   *int   `json:"records"`
	Stale     bool   `json:"stale"`
	// Unsupported: OSV feeds only, advisories skipped because their version
	// ranges aren't supported (null for the others and before a load).
	Unsupported *int `json:"unsupported"`
}
type VulnData struct {
	Sources []VulnDataSource `json:"sources"`
}

// VulnData reports how fresh the vulnerability data is. Any member may read it.
func (s *Service) VulnData(ctx context.Context, a *Actor) (VulnData, error) {
	var rows []VulnDataSource
	err := s.inOrg(ctx, a, func(r Repo) error {
		var err error
		rows, err = r.VulnSources(ctx)
		return err
	})
	if err != nil {
		return VulnData{}, err
	}
	out := VulnData{Sources: make([]VulnDataSource, 0, len(vulnSources))}
	cutoff := s.now().Add(-VulnStaleAfter)
	for _, name := range vulnSources {
		src := VulnDataSource{Name: name}
		for _, row := range rows {
			if row.Name == name {
				src = row
			}
		}
		src.Stale = src.UpdatedAt == nil || src.UpdatedAt.T().Before(cutoff)
		out.Sources = append(out.Sources, src)
	}
	return out, nil
}
