package store

import (
	"context"
	"time"

	"github.com/google/uuid"
	"github.com/jackc/pgx/v5"

	"github.com/aupv9/warden/backend/internal/service"
)

// metricsScope restricts alias i (issue) / p (project) to the caller's
// visible projects: one project, or every non-archived one.
func metricsScope(a *args, v service.Visibility, projectID *uuid.UUID) string {
	w := `p.org_id = ` + a.add(v.OrgID) + ` AND i.org_id = p.org_id AND ` + visible(a, v)
	if projectID != nil {
		return w + ` AND i.project_id = ` + a.add(*projectID)
	}
	return w + ` AND p.archived_at IS NULL`
}

// utcDay renders a timestamptz as its UTC calendar day, whatever the session
// time zone and DateStyle.
func utcDay(col string) string {
	return `to_char((` + col + ` AT TIME ZONE 'UTC')::date, 'YYYY-MM-DD')`
}

func (r *Repo) dayCounts(ctx context.Context, sql string, a args) (map[string]int, error) {
	rows, _ := r.tx.Query(ctx, sql, a...)
	out := map[string]int{}
	var (
		day string
		n   int
	)
	_, err := pgx.ForEachRow(rows, []any{&day, &n}, func() error {
		out[day] = n
		return nil
	})
	return out, err
}

// Metrics computes the dashboard aggregates. Open counts are rebuilt from
// status history: every created/status_changed event moves an issue into or
// out of the active set, so the active count at the end of a day is the sum of
// those moves up to it. Severity is the issue's current one.
func (r *Repo) Metrics(ctx context.Context, q service.MetricsQuery) (service.MetricsData, error) {
	d := service.MetricsData{OpenDeltas: map[string]service.SeverityCounts{}}
	startDay := q.Start.UTC().Format(time.DateOnly)

	var a args
	sql := `SELECT to_char(GREATEST((e.created_at AT TIME ZONE 'UTC')::date, ` + a.add(startDay) + `::date - 1), 'YYYY-MM-DD'),
			i.severity::text,
			sum((CASE WHEN e.to_value IN ` + activeStatuses + ` THEN 1 ELSE 0 END)
			  - (CASE WHEN e.from_value IN ` + activeStatuses + ` THEN 1 ELSE 0 END))::int
		FROM issue_event e JOIN issue i ON i.id = e.issue_id JOIN project p ON p.id = i.project_id
		WHERE ` + metricsScope(&a, q.Vis, q.ProjectID) + ` AND e.org_id = p.org_id
		AND e.type IN ('created', 'status_changed') AND e.created_at <= ` + a.add(q.Now) + `
		GROUP BY 1, 2`
	rows, _ := r.tx.Query(ctx, sql, a...)
	var (
		day, sev string
		n        int
	)
	if _, err := pgx.ForEachRow(rows, []any{&day, &sev, &n}, func() error {
		c := d.OpenDeltas[day]
		c.Add(sev, n)
		d.OpenDeltas[day] = c
		return nil
	}); err != nil {
		return d, err
	}

	var err error
	a = nil
	sql = `SELECT ` + utcDay("i.created_at") + `, count(*)::int FROM issue i JOIN project p ON p.id = i.project_id
		WHERE ` + metricsScope(&a, q.Vis, q.ProjectID) + ` AND i.created_at >= ` + a.add(q.Start) + ` AND i.created_at <= ` + a.add(q.Now) + `
		GROUP BY 1`
	if d.New, err = r.dayCounts(ctx, sql, a); err != nil {
		return d, err
	}

	a = nil
	sql = `SELECT ` + utcDay("e.created_at") + `, count(*)::int
		FROM issue_event e JOIN issue i ON i.id = e.issue_id JOIN project p ON p.id = i.project_id
		WHERE ` + metricsScope(&a, q.Vis, q.ProjectID) + ` AND e.org_id = p.org_id
		AND e.type = 'status_changed' AND e.to_value = 'fixed'
		AND e.created_at >= ` + a.add(q.Start) + ` AND e.created_at <= ` + a.add(q.Now) + `
		GROUP BY 1`
	if d.Fixed, err = r.dayCounts(ctx, sql, a); err != nil {
		return d, err
	}

	// MTTR and SLA compliance over issues whose FIRST fix falls in the window.
	a = nil
	sql = `WITH first_fix AS (
			SELECT i.id, i.severity, i.created_at, i.due_at, min(e.created_at) AS fixed_at
			FROM issue i JOIN project p ON p.id = i.project_id JOIN issue_event e ON e.issue_id = i.id
			WHERE ` + metricsScope(&a, q.Vis, q.ProjectID) + ` AND e.org_id = p.org_id
			AND e.type = 'status_changed' AND e.to_value IN ('fixed', 'verified')
			GROUP BY i.id)
		SELECT severity::text, avg(extract(epoch FROM fixed_at - created_at))::float8 / 3600,
			count(*) FILTER (WHERE due_at IS NOT NULL AND fixed_at <= due_at)::int,
			count(*) FILTER (WHERE due_at IS NOT NULL AND fixed_at > due_at)::int
		FROM first_fix WHERE fixed_at >= ` + a.add(q.Start) + ` AND fixed_at <= ` + a.add(q.Now) + `
		GROUP BY 1`
	rows, _ = r.tx.Query(ctx, sql, a...)
	var (
		hours        float64
		inTime, late int
	)
	if _, err := pgx.ForEachRow(rows, []any{&sev, &hours, &inTime, &late}, func() error {
		h := hours
		switch sev {
		case "critical":
			d.MTTRHours.Critical = &h
		case "high":
			d.MTTRHours.High = &h
		case "medium":
			d.MTTRHours.Medium = &h
		case "low":
			d.MTTRHours.Low = &h
		}
		d.SLA.FixedInTime += inTime
		d.SLA.FixedLate += late
		return nil
	}); err != nil {
		return d, err
	}

	a = nil
	sql = `SELECT count(*)::int FROM issue i JOIN project p ON p.id = i.project_id
		WHERE ` + metricsScope(&a, q.Vis, q.ProjectID) + ` AND i.status IN ` + activeStatuses + ` AND i.due_at < ` + a.add(q.Now)
	err = r.tx.QueryRow(ctx, sql, a...).Scan(&d.SLA.OpenOverdue)
	return d, mapErr(err)
}

func (r *Repo) IssueTotals(ctx context.Context, q service.TotalsQuery) (service.IssueTotals, error) {
	var a args
	sql := `SELECT count(*)::int,
			count(*) FILTER (WHERE i.assignee_id = ` + a.add(q.Vis.UserID) + `)::int,
			count(*) FILTER (WHERE i.due_at < ` + a.add(q.Now) + `)::int,
			count(*) FILTER (WHERE i.tool = 'gitleaks')::int,
			count(*) FILTER (WHERE ` + kevExists + `)::int,
			count(*) FILTER (WHERE i.tool = 'trivy' AND ` + licenseRule + `)::int
		FROM issue i JOIN project p ON p.id = i.project_id
		WHERE ` + metricsScope(&a, q.Vis, q.ProjectID) + ` AND i.status IN ` + activeStatuses
	var t service.IssueTotals
	err := r.tx.QueryRow(ctx, sql, a...).Scan(&t.Active, &t.Mine, &t.PastSLA, &t.Secrets, &t.KEV, &t.Licenses)
	return t, mapErr(err)
}
