package service

import (
	"context"
	"strconv"
	"sync"
	"time"

	"github.com/google/uuid"

	"github.com/aupv9/warden/backend/internal/domain/rbac"
)

// MetricsRepo: aggregates over issue and issue_event, restricted to visible projects.
type MetricsRepo interface {
	Metrics(ctx context.Context, q MetricsQuery) (MetricsData, error)
	IssueTotals(ctx context.Context, q TotalsQuery) (IssueTotals, error)
}

// MetricsQuery covers the UTC days [Start, Now].
type MetricsQuery struct {
	Vis       Visibility
	ProjectID *uuid.UUID
	Start     time.Time // 00:00 UTC of the first day
	Now       time.Time
}

// MetricsData is what the repository computes; the service lays it out by day.
type MetricsData struct {
	// OpenDeltas: net change in active issues per UTC day ("2006-01-02") and
	// severity, from status history. Changes before Start are summed under the
	// day before Start.
	OpenDeltas map[string]SeverityCounts
	New        map[string]int // issues created per day in the window
	Fixed      map[string]int // moves to fixed per day in the window
	MTTRHours  MTTR
	SLA        SLAStats
}

type DaySeverity struct {
	Date     string `json:"date"`
	Critical int    `json:"critical"`
	High     int    `json:"high"`
	Medium   int    `json:"medium"`
	Low      int    `json:"low"`
}

type DayCount struct {
	Date  string `json:"date"`
	Count int    `json:"count"`
}

// MTTR: mean hours from creation to the first fixed/verified, for issues
// first fixed in the window; null without any.
type MTTR struct {
	Critical *float64 `json:"critical"`
	High     *float64 `json:"high"`
	Medium   *float64 `json:"medium"`
	Low      *float64 `json:"low"`
}

type SLAStats struct {
	FixedInTime int `json:"fixed_in_time"`
	FixedLate   int `json:"fixed_late"`
	OpenOverdue int `json:"open_overdue"`
}

type Metrics struct {
	Days       int           `json:"days"`
	OpenByDay  []DaySeverity `json:"open_by_day"`
	MTTRHours  MTTR          `json:"mttr_hours"`
	SLA        SLAStats      `json:"sla"`
	NewByDay   []DayCount    `json:"new_by_day"`
	FixedByDay []DayCount    `json:"fixed_by_day"`
}

type TotalsQuery struct {
	Vis       Visibility
	ProjectID *uuid.UUID
	Now       time.Time
}

type IssueTotals struct {
	Active  int `json:"active"`
	Mine    int `json:"mine"`
	PastSLA int `json:"past_sla"`
	Secrets int `json:"secrets"` // active gitleaks issues
	// KEV: active issues with a CVE in KEV; Licenses: active license-policy
	// issues (trivy, rule license:<SPDX>).
	KEV      int `json:"kev"`
	Licenses int `json:"licenses"`
}

const (
	metricsTTL        = 5 * time.Minute
	metricsCacheLimit = 1024
)

// ttlCache holds computed metrics for metricsTTL. Keys include the caller's
// visibility, so a cached answer is only ever served to someone who could see
// exactly the same projects.
type ttlCache struct {
	mu sync.Mutex
	m  map[string]cacheEntry
}

type cacheEntry struct {
	exp time.Time
	v   Metrics
}

func (c *ttlCache) get(key string, now time.Time) (Metrics, bool) {
	c.mu.Lock()
	defer c.mu.Unlock()
	e, ok := c.m[key]
	if !ok || !now.Before(e.exp) {
		return Metrics{}, false
	}
	return e.v, true
}

func (c *ttlCache) put(key string, v Metrics, now time.Time) {
	c.mu.Lock()
	defer c.mu.Unlock()
	if c.m == nil {
		c.m = map[string]cacheEntry{}
	}
	if len(c.m) >= metricsCacheLimit {
		for k, e := range c.m {
			if !now.Before(e.exp) {
				delete(c.m, k)
			}
		}
		if len(c.m) >= metricsCacheLimit {
			c.m = map[string]cacheEntry{}
		}
	}
	c.m[key] = cacheEntry{exp: now.Add(metricsTTL), v: v}
}

type MetricsFilter struct {
	Days      string
	ProjectID string
}

func optionalProject(raw string) (*uuid.UUID, error) {
	if raw == "" {
		return nil, nil
	}
	id, err := uuid.Parse(raw)
	if err != nil {
		return nil, errField("project_id", "must be a UUID")
	}
	return &id, nil
}

// scope checks view permission for an optional project filter. Without one,
// the caller sees their visible projects (a member without projects gets
// zeros: every project role holds view_dashboard / view_results).
func scope(ctx context.Context, r Repo, a *Actor, projectID *uuid.UUID, perm rbac.Perm) error {
	if projectID == nil {
		return nil
	}
	role, err := projectAccess(ctx, r, a, *projectID)
	if err != nil {
		return err
	}
	if !rbac.Can(perm, a.OrgRole, role, false) {
		return errForbidden()
	}
	return nil
}

// Metrics returns the dashboard series over the last days (UTC), cached for
// five minutes per (org, visibility, parameters).
func (s *Service) Metrics(ctx context.Context, a *Actor, f MetricsFilter) (Metrics, error) {
	days := 30
	fe := fieldErrors{}
	switch f.Days {
	case "", "30":
	case "90":
		days = 90
	case "180":
		days = 180
	default:
		fe.add("days", "must be 30, 90 or 180")
	}
	project, err := optionalProject(f.ProjectID)
	if err != nil {
		fe.add("project_id", "must be a UUID")
	}
	if err := fe.err(); err != nil {
		return Metrics{}, err
	}
	var out Metrics
	err = s.inOrg(ctx, a, func(r Repo) error {
		if err := scope(ctx, r, a, project, rbac.ViewDashboard); err != nil {
			return err
		}
		now := s.now().UTC()
		vis := a.vis()
		visKey := "all"
		if !vis.All {
			visKey = vis.UserID.String()
		}
		key := a.OrgID.String() + "|" + visKey + "|" + strconv.Itoa(days) + "|"
		if project != nil {
			key += project.String()
		}
		if m, ok := s.metrics.get(key, now); ok {
			out = m
			return nil
		}
		today := now.Truncate(24 * time.Hour)
		start := today.AddDate(0, 0, -(days - 1))
		data, err := r.Metrics(ctx, MetricsQuery{Vis: vis, ProjectID: project, Start: start, Now: now})
		if err != nil {
			return err
		}
		out = layout(data, days, start)
		s.metrics.put(key, out, now)
		return nil
	})
	return out, err
}

// layout turns per-day deltas into end-of-day series for each day in the window.
func layout(d MetricsData, days int, start time.Time) Metrics {
	m := Metrics{Days: days, MTTRHours: d.MTTRHours, SLA: d.SLA,
		OpenByDay: make([]DaySeverity, 0, days), NewByDay: make([]DayCount, 0, days), FixedByDay: make([]DayCount, 0, days)}
	var open SeverityCounts
	startKey := start.Format(time.DateOnly)
	for k, c := range d.OpenDeltas {
		if k < startKey {
			open = addCounts(open, c)
		}
	}
	for i := range days {
		date := start.AddDate(0, 0, i).Format(time.DateOnly)
		open = addCounts(open, d.OpenDeltas[date])
		m.OpenByDay = append(m.OpenByDay, DaySeverity{Date: date, Critical: max(open.Critical, 0), High: max(open.High, 0),
			Medium: max(open.Medium, 0), Low: max(open.Low, 0)})
		m.NewByDay = append(m.NewByDay, DayCount{Date: date, Count: d.New[date]})
		m.FixedByDay = append(m.FixedByDay, DayCount{Date: date, Count: d.Fixed[date]})
	}
	return m
}

func addCounts(a, b SeverityCounts) SeverityCounts {
	return SeverityCounts{Critical: a.Critical + b.Critical, High: a.High + b.High, Medium: a.Medium + b.Medium,
		Low: a.Low + b.Low, Info: a.Info + b.Info}
}

// IssueTotals counts for the saved views: active, assigned to the caller,
// past SLA, and active secrets (Gitleaks).
func (s *Service) IssueTotals(ctx context.Context, a *Actor, projectID string) (IssueTotals, error) {
	project, err := optionalProject(projectID)
	if err != nil {
		return IssueTotals{}, err
	}
	var out IssueTotals
	err = s.inOrg(ctx, a, func(r Repo) error {
		if err := scope(ctx, r, a, project, rbac.ViewResults); err != nil {
			return err
		}
		out, err = r.IssueTotals(ctx, TotalsQuery{Vis: a.vis(), ProjectID: project, Now: s.now()})
		return err
	})
	return out, err
}
