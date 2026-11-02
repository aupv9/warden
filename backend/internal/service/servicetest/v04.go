package servicetest

import (
	"cmp"
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

func (f *Fake) ComponentEcosystems(_ context.Context, _ service.Visibility, _ *uuid.UUID) ([]service.EcosystemCount, error) {
	return nil, f.fail("ComponentEcosystems")
}

func targetKind(target string) string {
	switch target {
	case "":
		return service.KindSource
	case service.HistoryTarget:
		return service.KindHistory
	default:
		return service.KindImage
	}
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
		out = append(out, service.ProjectTarget{Target: s.Target, Kind: targetKind(s.Target)})
	}
	slices.SortFunc(out, func(a, b service.ProjectTarget) int { return strings.Compare(a.Target, b.Target) })
	return out, nil
}

// OrgTargets lists the targets of the visible, unarchived projects' scans.
func (f *Fake) OrgTargets(_ context.Context, q service.OrgTargetQuery) ([]service.OrgTarget, error) {
	if err := f.fail("OrgTargets"); err != nil {
		return nil, err
	}
	var out []service.OrgTarget
	seen := map[[2]string]bool{}
	for _, s := range f.st.Scans {
		p := f.st.Projects[s.ProjectID]
		k := [2]string{s.ProjectID.String(), s.Target}
		if s.OrgID != f.org || p.OrgID != q.Vis.OrgID || !f.visibleArchived(q.Vis, s.ProjectID, false) || seen[k] ||
			(q.ProjectID != nil && *q.ProjectID != s.ProjectID) || (q.Kind != "" && q.Kind != targetKind(s.Target)) {
			continue
		}
		seen[k] = true
		out = append(out, service.OrgTarget{ProjectID: s.ProjectID, ProjectKey: p.Key, ProjectName: p.Name,
			ProjectTarget: service.ProjectTarget{Target: s.Target, Kind: targetKind(s.Target)}})
	}
	slices.SortFunc(out, func(a, b service.OrgTarget) int {
		return cmp.Or(strings.Compare(a.ProjectKey, b.ProjectKey), strings.Compare(a.Target, b.Target))
	})
	return out, nil
}
