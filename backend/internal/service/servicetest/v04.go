package servicetest

import (
	"context"
	"slices"
	"strings"

	"github.com/google/uuid"

	"github.com/aupv9/warden/backend/internal/service"
)

// The component inventory is written by the worker (results.Process), not by
// the API, so the fake has none; the integration tests cover the queries.

func (f *Fake) Components(_ context.Context, _ service.ComponentQuery) ([]service.ComponentSummary, error) {
	return nil, f.fail("Components")
}

func (f *Fake) ComponentUsage(_ context.Context, _ service.ComponentUsageQuery) ([]service.ComponentUsage, error) {
	return nil, f.fail("ComponentUsage")
}

func (f *Fake) ProjectComponents(_ context.Context, _ service.ProjectComponentQuery) ([]service.ProjectComponent, error) {
	return nil, f.fail("ProjectComponents")
}

// ProjectTargets lists the targets of the project's scans.
func (f *Fake) ProjectTargets(_ context.Context, projectID uuid.UUID) ([]service.ProjectTarget, error) {
	if err := f.fail("ProjectTargets"); err != nil {
		return nil, err
	}
	var out []service.ProjectTarget
	seen := map[string]bool{}
	for _, s := range f.st.Scans {
		if s.OrgID != f.org || s.ProjectID != projectID || seen[s.Target] {
			continue
		}
		seen[s.Target] = true
		kind := service.KindSource
		if s.Target != "" {
			kind = service.KindImage
		}
		out = append(out, service.ProjectTarget{Target: s.Target, Kind: kind})
	}
	slices.SortFunc(out, func(a, b service.ProjectTarget) int { return strings.Compare(a.Target, b.Target) })
	return out, nil
}
