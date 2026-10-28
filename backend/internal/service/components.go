package service

import (
	"context"
	"strings"
	"unicode/utf8"

	"github.com/google/uuid"

	"github.com/aupv9/warden/backend/internal/domain/ecosystem"
	"github.com/aupv9/warden/backend/internal/domain/rbac"
)

// Component inventory query limits (see the OpenAPI document).
const (
	maxComponentQuery   = 128
	maxComponentName    = 256
	maxComponentVersion = 128
)

// ComponentRepo: the component inventory (results.Process keeps the component
// table to each (project, target)'s latest scan where Trivy succeeded).
type ComponentRepo interface {
	Components(ctx context.Context, q ComponentQuery) ([]ComponentSummary, error)
	ComponentUsage(ctx context.Context, q ComponentUsageQuery) ([]ComponentUsage, error)
	ProjectComponents(ctx context.Context, q ProjectComponentQuery) ([]ProjectComponent, error)
	ProjectTargets(ctx context.Context, projectID uuid.UUID) ([]ProjectTarget, error)
}

// NamePrefix matches component.match_name by prefix, in one ecosystem or ("")
// in any. Prefix is already normalized for that ecosystem.
type NamePrefix struct {
	Ecosystem string
	Prefix    string
}

// ComponentCursor positions the org-wide list (sorted by match name,
// ecosystem, version).
type ComponentCursor struct {
	MatchName string `json:"n"`
	Ecosystem string `json:"e"`
	Version   string `json:"v"`
}

// ComponentQuery is a validated GET /components. Visible, unarchived projects only.
type ComponentQuery struct {
	Vis       Visibility
	ProjectID *uuid.UUID
	Ecosystem string
	Names     []NamePrefix // any of them
	Version   string
	Malicious bool
	After     *ComponentCursor
	Limit     int
}

// UsageCursor positions a component's usage list (project key, target, path).
type UsageCursor struct {
	ProjectKey string `json:"k"`
	Target     string `json:"t"`
	Path       string `json:"p"`
}

// ComponentUsageQuery is a validated GET /components/usage.
type ComponentUsageQuery struct {
	Vis       Visibility
	ProjectID *uuid.UUID // API tokens: their own project only
	Ecosystem string
	MatchName string
	Version   string
	After     *UsageCursor
	Limit     int
}

// ProjectComponentCursor positions a project's component list.
type ProjectComponentCursor struct {
	Target    string `json:"t"`
	MatchName string `json:"n"`
	Ecosystem string `json:"e"`
	Version   string `json:"v"`
	Path      string `json:"p"`
}

// ProjectComponentQuery is a validated GET /projects/{p}/components.
type ProjectComponentQuery struct {
	ProjectID uuid.UUID
	Target    *string // nil: every target; "": source code
	Ecosystem string
	Names     []NamePrefix
	Malicious bool
	After     *ProjectComponentCursor
	Limit     int
}

// ComponentSummary is one (ecosystem, name, version) across visible projects.
type ComponentSummary struct {
	Ecosystem  string   `json:"ecosystem"`
	Name       string   `json:"name"`
	Version    string   `json:"version"`
	PURL       *string  `json:"purl"`
	Licenses   []string `json:"licenses"`
	Projects   int      `json:"projects"`
	Targets    int      `json:"targets"`
	OpenIssues int      `json:"open_issues"`
	Malicious  bool     `json:"malicious"`
	MatchName  string   `json:"-"`
}

type ComponentUsage struct {
	ProjectID   uuid.UUID `json:"project_id"`
	ProjectKey  string    `json:"project_key"`
	ProjectName string    `json:"project_name"`
	Target      string    `json:"target"`
	Path        string    `json:"path"`
	ScanID      uuid.UUID `json:"scan_id"`
	ScannedAt   Time      `json:"scanned_at"`
	FirstSeen   Time      `json:"first_seen"`
}

type ProjectComponent struct {
	Ecosystem  string   `json:"ecosystem"`
	Name       string   `json:"name"`
	Version    string   `json:"version"`
	PURL       *string  `json:"purl"`
	Licenses   []string `json:"licenses"`
	Target     string   `json:"target"`
	Path       string   `json:"path"`
	FirstSeen  Time     `json:"first_seen"`
	OpenIssues int      `json:"open_issues"`
	Malicious  bool     `json:"malicious"`
	MatchName  string   `json:"-"`
}

type ProjectTarget struct {
	Target     string `json:"target"`
	Kind       string `json:"kind"`
	LastScanAt *Time  `json:"last_scan_at"`
	OpenIssues int    `json:"open_issues"`
}

// ComponentFilter is the raw query of the component lists.
type ComponentFilter struct {
	Q, Ecosystem, Version, ProjectID, Malicious string
	// Target, for a project's list: HasTarget false means every target.
	Target    string
	HasTarget bool
	PageParams
}

// UsageFilter is the raw query of GET /components/usage.
type UsageFilter struct {
	Ecosystem, Name, Version string
	PageParams
}

// componentText: printable, valid UTF-8 without NUL, at most max runes.
func componentText(s string, max int) bool {
	return validText(s) && utf8.RuneCountInString(s) <= max
}

// namePrefixes normalizes a search prefix the way match names are: for one
// ecosystem when given, else for each normalization in use (a PyPI or crates.io
// name may be typed with _ or .).
func namePrefixes(q, eco string) []NamePrefix {
	if eco != "" {
		return []NamePrefix{{Ecosystem: eco, Prefix: ecosystem.MatchName(eco, q)}}
	}
	plain := ecosystem.MatchName("", q)
	out := []NamePrefix{{Prefix: plain}}
	for _, e := range []string{ecosystem.PyPI, ecosystem.CratesIO} {
		if n := ecosystem.MatchName(e, q); n != plain {
			out = append(out, NamePrefix{Ecosystem: e, Prefix: n})
		}
	}
	return out
}

// common validates the filters every component list shares.
func (f ComponentFilter) common(fe fieldErrors) (eco string, names []NamePrefix, malicious bool, limit int) {
	if f.Ecosystem != "" {
		if !ecosystem.Valid.MatchString(f.Ecosystem) {
			fe.add("ecosystem", "must be an ecosystem name such as npm, PyPI or Go")
		}
		eco = f.Ecosystem
	}
	if q := strings.TrimSpace(f.Q); q != "" {
		if !componentText(q, maxComponentQuery) {
			fe.add("q", "must be at most 128 characters")
		} else {
			names = namePrefixes(q, eco)
		}
	}
	switch f.Malicious {
	case "", "false":
	case "true":
		malicious = true
	default:
		fe.add("malicious", "must be true or false")
	}
	limit, err := f.limit()
	if err != nil {
		fe.add("limit", "must be an integer between 1 and 200")
	}
	return eco, names, malicious, limit
}

func (s *Service) componentQuery(a *Actor, f ComponentFilter) (ComponentQuery, error) {
	fe := fieldErrors{}
	q := ComponentQuery{Vis: a.vis()}
	q.Ecosystem, q.Names, q.Malicious, q.Limit = f.common(fe)
	if f.Version != "" {
		if !componentText(f.Version, maxComponentVersion) {
			fe.add("version", "must be at most 128 characters")
		}
		q.Version = f.Version
	}
	if f.ProjectID != "" {
		id, err := uuid.Parse(f.ProjectID)
		if err != nil {
			fe.add("project_id", "must be a UUID")
		} else {
			q.ProjectID = &id
		}
	}
	if f.Cursor != "" {
		c := &ComponentCursor{}
		if decodeCursor(f.Cursor, c) != nil {
			fe.add("cursor", "invalid cursor")
		} else {
			q.After = c
		}
	}
	return q, fe.err()
}

// Components searches the inventory of the projects the caller can see.
func (s *Service) Components(ctx context.Context, a *Actor, f ComponentFilter) (Page[ComponentSummary], error) {
	var out Page[ComponentSummary]
	err := s.inOrg(ctx, a, func(r Repo) error {
		q, err := s.componentQuery(a, f)
		if err != nil {
			return err
		}
		// The API doesn't route tokens here; if one gets here, it sees only its project.
		if a.Token != nil {
			if q.ProjectID == nil {
				q.ProjectID = &a.Token.ProjectID
			}
			if _, err := projectAccess(ctx, r, a, *q.ProjectID); err != nil {
				return err
			}
		}
		rq := q
		rq.Limit = q.Limit + 1
		rows, err := r.Components(ctx, rq)
		if err != nil {
			return err
		}
		out.Items, out.NextCursor = page(rows, q.Limit, func(c ComponentSummary) any {
			return ComponentCursor{MatchName: c.MatchName, Ecosystem: c.Ecosystem, Version: c.Version}
		})
		return nil
	})
	return out, err
}

// ComponentUsage lists where one component is used, in visible projects.
func (s *Service) ComponentUsage(ctx context.Context, a *Actor, f UsageFilter) (Page[ComponentUsage], error) {
	fe := fieldErrors{}
	q := ComponentUsageQuery{Vis: a.vis()}
	if !ecosystem.Valid.MatchString(f.Ecosystem) {
		fe.add("ecosystem", "must be an ecosystem name such as npm, PyPI or Go")
	}
	if f.Name == "" || !componentText(f.Name, maxComponentName) {
		fe.add("name", "must be 1 to 256 characters")
	}
	if f.Version == "" || !componentText(f.Version, maxComponentVersion) {
		fe.add("version", "must be 1 to 128 characters")
	}
	q.Ecosystem, q.MatchName, q.Version = f.Ecosystem, ecosystem.MatchName(f.Ecosystem, f.Name), f.Version
	limit, err := f.limit()
	if err != nil {
		fe.add("limit", "must be an integer between 1 and 200")
	}
	q.Limit = limit
	if f.Cursor != "" {
		c := &UsageCursor{}
		if decodeCursor(f.Cursor, c) != nil {
			fe.add("cursor", "invalid cursor")
		} else {
			q.After = c
		}
	}
	if err := fe.err(); err != nil {
		return Page[ComponentUsage]{}, err
	}
	var out Page[ComponentUsage]
	err = s.inOrg(ctx, a, func(r Repo) error {
		if a.Token != nil {
			q.ProjectID = &a.Token.ProjectID
			if _, err := projectAccess(ctx, r, a, *q.ProjectID); err != nil {
				return err
			}
		}
		rq := q
		rq.Limit = q.Limit + 1
		rows, err := r.ComponentUsage(ctx, rq)
		if err != nil {
			return err
		}
		out.Items, out.NextCursor = page(rows, q.Limit, func(u ComponentUsage) any {
			return UsageCursor{ProjectKey: u.ProjectKey, Target: u.Target, Path: u.Path}
		})
		return nil
	})
	return out, err
}

// ProjectComponents lists a project's current components, for whoever can
// view its results (an API token with issues:read, in its own project).
func (s *Service) ProjectComponents(ctx context.Context, a *Actor, projectID uuid.UUID, f ComponentFilter) (Page[ProjectComponent], error) {
	fe := fieldErrors{}
	q := ProjectComponentQuery{ProjectID: projectID}
	q.Ecosystem, q.Names, q.Malicious, q.Limit = f.common(fe)
	if f.HasTarget {
		if f.Target != "" && (len(f.Target) > maxTarget || !ImageTarget.MatchString(f.Target)) {
			fe.add("target", "must be empty (source code) or an image repository without tag")
		}
		t := f.Target
		q.Target = &t
	}
	if f.Cursor != "" {
		c := &ProjectComponentCursor{}
		if decodeCursor(f.Cursor, c) != nil {
			fe.add("cursor", "invalid cursor")
		} else {
			q.After = c
		}
	}
	if err := fe.err(); err != nil {
		return Page[ProjectComponent]{}, err
	}
	var out Page[ProjectComponent]
	err := s.inOrg(ctx, a, func(r Repo) error {
		role, err := projectAccess(ctx, r, a, projectID)
		if err != nil {
			return err
		}
		if !rbac.Can(rbac.ViewResults, a.OrgRole, role, false) {
			return errForbidden()
		}
		rq := q
		rq.Limit = q.Limit + 1
		rows, err := r.ProjectComponents(ctx, rq)
		if err != nil {
			return err
		}
		out.Items, out.NextCursor = page(rows, q.Limit, func(c ProjectComponent) any {
			return ProjectComponentCursor{Target: c.Target, MatchName: c.MatchName, Ecosystem: c.Ecosystem, Version: c.Version, Path: c.Path}
		})
		return nil
	})
	return out, err
}

// ProjectTargets lists the project's scan targets (source code is "").
func (s *Service) ProjectTargets(ctx context.Context, a *Actor, projectID uuid.UUID) (Items[ProjectTarget], error) {
	out := Items[ProjectTarget]{Items: []ProjectTarget{}}
	err := s.inOrg(ctx, a, func(r Repo) error {
		role, err := projectAccess(ctx, r, a, projectID)
		if err != nil {
			return err
		}
		if !rbac.Can(rbac.ViewResults, a.OrgRole, role, false) {
			return errForbidden()
		}
		rows, err := r.ProjectTargets(ctx, projectID)
		if err != nil {
			return err
		}
		if rows != nil {
			out.Items = rows
		}
		return nil
	})
	return out, err
}
