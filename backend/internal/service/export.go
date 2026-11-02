package service

import (
	"context"
	"strconv"
	"strings"
	"time"

	"github.com/google/uuid"
)

const (
	// MaxExportRows caps GET /issues/export.csv.
	MaxExportRows = 50000
	// exportsPerHour caps exports per user per org: each one may read 50,000
	// rows and writes an audit entry.
	exportsPerHour = 30
)

// ExportRepo streams the issue list for the CSV export.
type ExportRepo interface {
	// CountIssues counts q's matches, stopping at limit.
	CountIssues(ctx context.Context, q IssueQuery, limit int) (int, error)
	// ExportIssues calls fn for each of q's first q.Limit matches, in the
	// list's order, without loading them all; an error from fn stops it.
	ExportIssues(ctx context.Context, q IssueQuery, fn func(IssueExportRow) error) error
}

// IssueExportRow is one CSV row: the list's columns, without descriptions,
// snippets or comments.
type IssueExportRow struct {
	Key         string
	ProjectName string
	Title       string
	Severity    string
	Status      string
	Tool        string
	RuleID      string
	FilePath    *string
	Line        *int
	Target      string
	CVE         []string
	KEV         bool
	EPSS        *float64
	Assignee    *string // email
	DueAt       *Time
	CreatedAt   Time
	UpdatedAt   Time
}

// IssueExport describes an export that was checked and recorded and is about
// to be streamed.
type IssueExport struct {
	OrgID uuid.UUID
	// Rows is what the export will contain (at most MaxExportRows);
	// Truncated says there were more.
	Rows      int
	Truncated bool
	At        time.Time
}

// ExportIssues exports the issue list (the same filters, validation, visibility
// and order) as rows. API tokens can't export.
//
// It runs in two transactions. The first validates, applies the rate limit,
// counts and appends issues.exported, and commits before any row is read, so
// every export that leaves Warden is on record even if the stream fails. The
// second streams the rows: it doesn't hold the audit log's per-org lock while
// a client reads. start is called between the two (headers); it isn't called
// when the first fails. Rows and Truncated are as of the first transaction.
func (s *Service) ExportIssues(ctx context.Context, a *Actor, f IssueFilter, start func(IssueExport) error, row func(IssueExportRow) error) error {
	f.PageParams = PageParams{} // the whole list, not a page
	var (
		q  IssueQuery
		ex IssueExport
	)
	err := s.inOrg(ctx, a, func(r Repo) error {
		// The API's allow-list keeps tokens out; checked again here.
		if a.Token != nil {
			return errForbidden()
		}
		var err error
		if q, err = s.issueQuery(a, f); err != nil {
			return err
		}
		now := s.now().UTC()
		n, oldest, err := r.AuditSince(ctx, AuditCount{OrgID: a.OrgID, Action: "issues.exported", ActorID: &a.UserID, Since: now.Add(-time.Hour)})
		if err != nil {
			return err
		}
		if n >= exportsPerHour {
			return rateLimited(oldest.Add(time.Hour).Sub(now),
				"you've exported the issue list "+strconv.Itoa(exportsPerHour)+" times in the last hour; try again later")
		}
		total, err := r.CountIssues(ctx, q, MaxExportRows+1)
		if err != nil {
			return err
		}
		ex = IssueExport{OrgID: a.OrgID, Rows: min(total, MaxExportRows), Truncated: total > MaxExportRows, At: now}
		return s.audit(ctx, r, a, "issues.exported", "org", a.OrgID.String(), exportSummary(q, ex))
	})
	if err != nil {
		return err
	}
	if err := start(ex); err != nil {
		return err
	}
	return s.inOrg(ctx, a, func(r Repo) error {
		// Membership was re-checked by inOrg; the visibility follows the role
		// as it is now.
		q.Vis = a.vis()
		q.Limit = MaxExportRows
		return r.ExportIssues(ctx, q, row)
	})
}

// exportSummary is the audit entry's data: the validated filters and the row
// count, never the rows.
func exportSummary(q IssueQuery, ex IssueExport) map[string]any {
	d := map[string]any{"rows": ex.Rows, "truncated": ex.Truncated, "sort": q.Sort, "status": q.Statuses}
	if q.ProjectID != nil {
		d["project_id"] = q.ProjectID.String()
	}
	if len(q.Severities) > 0 {
		d["severity"] = q.Severities
	}
	switch {
	case q.AssigneeNone:
		d["assignee"] = "none"
	case q.AssigneeID != nil:
		d["assignee"] = q.AssigneeID.String()
	}
	for k, v := range map[string]string{"tool": q.Tool, "kind": q.Kind, "source": q.Source, "target": q.Target} {
		if v != "" {
			d[k] = v
		}
	}
	if q.PastSLA {
		d["past_sla"] = true
	}
	if q.KEV {
		d["kev"] = true
	}
	if q.EPSSMin != nil {
		d["epss_min"] = *q.EPSSMin
	}
	if q.KeyProject != "" {
		d["q"] = q.KeyProject + "-" + strconv.Itoa(q.KeyNumber)
	} else if q.Text != "" {
		d["q"] = strings.TrimSpace(q.Text)
	}
	return d
}
