package results

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"time"

	"github.com/google/uuid"
	"github.com/jackc/pgx/v5"
	"github.com/jackc/pgx/v5/pgconn"

	"github.com/aupv9/warden/backend/internal/domain/issuestate"
	"github.com/aupv9/warden/backend/internal/domain/severity"
	"github.com/aupv9/warden/backend/internal/ids"
	"github.com/aupv9/warden/backend/internal/scan/sandbox"
	"github.com/aupv9/warden/backend/internal/scan/sarif"
)

// DB is the subset of pgx.Tx the processor uses. Process must run inside one
// transaction with app.org_id set (db.WithOrg).
type DB interface {
	Exec(ctx context.Context, sql string, args ...any) (pgconn.CommandTag, error)
	Query(ctx context.Context, sql string, args ...any) (pgx.Rows, error)
	QueryRow(ctx context.Context, sql string, args ...any) pgx.Row
}

// ErrScanNotRunning: the scan was cancelled (or already finished) meanwhile, so
// it must not touch any issue.
var ErrScanNotRunning = errors.New("scan is not running")

// Event types written by the system (actor_id NULL).
const (
	EventCreated         = "created"
	EventStatusChanged   = "status_changed"
	EventSeenAgain       = "seen_again"
	EventSeverityChanged = "severity_changed"
)

type Input struct {
	OrgID, ProjectID, ScanID uuid.UUID
	Status                   string // final scan status: completed or partial
	Runs                     []sandbox.ToolRun
	Findings                 map[string][]sarif.Finding
	GuardRatio               float64
	Now                      time.Time
}

// SLA is organization.sla_days: days to fix, by severity (info has none).
type SLA map[string]int

func (s SLA) DueAt(sev severity.Severity, now time.Time) *time.Time {
	days, ok := s[string(sev)]
	if !ok || days <= 0 {
		return nil
	}
	t := now.Add(time.Duration(days) * 24 * time.Hour)
	return &t
}

func nullable(s string) *string {
	if s == "" {
		return nil
	}
	return &s
}

// Process applies a finished scan's findings to the project's issues and marks
// the scan finished, all in the caller's transaction, so a retried attempt
// either sees the scan finished or redoes everything.
func Process(ctx context.Context, db DB, in Input) (Plan, error) {
	var status string
	err := db.QueryRow(ctx, `SELECT status FROM scan WHERE id = $1 AND project_id = $2 FOR UPDATE`, in.ScanID, in.ProjectID).Scan(&status)
	if errors.Is(err, pgx.ErrNoRows) {
		return Plan{}, fmt.Errorf("scan %s: %w", in.ScanID, ErrScanNotRunning)
	}
	if err != nil {
		return Plan{}, fmt.Errorf("lock scan: %w", err)
	}
	if status != "running" {
		return Plan{}, fmt.Errorf("scan %s is %s: %w", in.ScanID, status, ErrScanNotRunning)
	}
	// Serializes processors of the same project (issue numbers, dedupe).
	var seq int
	if err := db.QueryRow(ctx, `SELECT issue_seq FROM project WHERE id = $1 FOR UPDATE`, in.ProjectID).Scan(&seq); err != nil {
		return Plan{}, fmt.Errorf("lock project: %w", err)
	}
	var rawSLA []byte
	var sla SLA
	if err := db.QueryRow(ctx, `SELECT sla_days FROM organization WHERE id = $1`, in.OrgID).Scan(&rawSLA); err != nil {
		return Plan{}, fmt.Errorf("load sla: %w", err)
	}
	if err := json.Unmarshal(rawSLA, &sla); err != nil {
		return Plan{}, fmt.Errorf("organization.sla_days: %w", err)
	}
	existing, err := loadIssues(ctx, db, in.ProjectID)
	if err != nil {
		return Plan{}, err
	}
	plan, err := BuildPlan(PlanInput{ScanID: in.ScanID, Runs: in.Runs, Findings: in.Findings, Existing: existing, GuardRatio: in.GuardRatio})
	if err != nil {
		return Plan{}, err
	}
	a := applier{db: db, in: in, sla: sla}
	if err := a.apply(ctx, plan); err != nil {
		return Plan{}, err
	}
	return plan, nil
}

func loadIssues(ctx context.Context, db DB, projectID uuid.UUID) ([]ExistingIssue, error) {
	rows, err := db.Query(ctx, `SELECT id, fingerprint, tool, status, severity, severity_overridden, last_seen_scan_id
		FROM issue WHERE project_id = $1`, projectID)
	if err != nil {
		return nil, fmt.Errorf("load issues: %w", err)
	}
	out, err := pgx.CollectRows(rows, func(r pgx.CollectableRow) (ExistingIssue, error) {
		var e ExistingIssue
		var st, sev string
		err := r.Scan(&e.ID, &e.Fingerprint, &e.Tool, &st, &sev, &e.SeverityOverridden, &e.LastSeenScanID)
		e.Status, e.Severity = issuestate.Status(st), severity.Severity(sev)
		return e, err
	})
	if err != nil {
		return nil, fmt.Errorf("load issues: %w", err)
	}
	return out, nil
}

type applier struct {
	db  DB
	in  Input
	sla SLA
}

func (a applier) event(ctx context.Context, issueID uuid.UUID, typ string, from, to *string, note string) error {
	_, err := a.db.Exec(ctx, `INSERT INTO issue_event (org_id, issue_id, actor_id, type, from_value, to_value, note)
		VALUES ($1, $2, NULL, $3, $4, $5, $6)`, a.in.OrgID, issueID, typ, from, to, nullable(note))
	if err != nil {
		return fmt.Errorf("issue event %s: %w", typ, err)
	}
	return nil
}

// occurrence stores the normalized finding (bounded by the SARIF parser's caps,
// snippets already masked for Gitleaks), never the raw scanner output.
func (a applier) occurrence(ctx context.Context, issueID uuid.UUID, f sarif.Finding) error {
	raw, err := json.Marshal(f)
	if err != nil {
		return err
	}
	_, err = a.db.Exec(ctx, `INSERT INTO occurrence (org_id, issue_id, scan_id, file_path, start_line, raw)
		VALUES ($1, $2, $3, $4, $5, $6) ON CONFLICT (issue_id, scan_id) DO NOTHING`,
		a.in.OrgID, issueID, a.in.ScanID, nullable(f.FilePath), f.StartLine, raw)
	if err != nil {
		return fmt.Errorf("occurrence: %w", err)
	}
	return nil
}

func ptr(s string) *string { return &s }

func (a applier) apply(ctx context.Context, p Plan) error {
	now := a.in.Now
	if len(p.New) > 0 {
		var last int
		// One UPDATE … RETURNING for the batch; the project row is locked above.
		if err := a.db.QueryRow(ctx, `UPDATE project SET issue_seq = issue_seq + $2 WHERE id = $1 RETURNING issue_seq`,
			a.in.ProjectID, len(p.New)).Scan(&last); err != nil {
			return fmt.Errorf("allocate issue numbers: %w", err)
		}
		first := last - len(p.New) + 1
		for i, n := range p.New {
			if err := a.create(ctx, first+i, n, now); err != nil {
				return err
			}
		}
	}
	for _, s := range p.Seen {
		if err := a.sighting(ctx, s, now); err != nil {
			return err
		}
	}
	for _, e := range p.Fix {
		if err := a.transition(ctx, e, issuestate.Fixed, nil, "not found by "+e.Tool+" in scan "+a.in.ScanID.String()); err != nil {
			return err
		}
	}
	for tool, n := range p.ToolCounts {
		if _, err := a.db.Exec(ctx, `UPDATE scan_tool_run SET findings_count = $3 WHERE scan_id = $1 AND tool = $2`,
			a.in.ScanID, tool, n); err != nil {
			return fmt.Errorf("findings count: %w", err)
		}
	}
	stats, _ := json.Marshal(p.Stats)
	if _, err := a.db.Exec(ctx, `UPDATE scan SET status = $2, error_code = NULL, stats = $3, needs_confirmation = $4, finished_at = $5
		WHERE id = $1`, a.in.ScanID, a.in.Status, stats, p.NeedsConfirmation, now); err != nil {
		return fmt.Errorf("finish scan: %w", err)
	}
	return nil
}

func (a applier) create(ctx context.Context, number int, n NewIssue, now time.Time) error {
	f := n.Finding
	id := ids.New()
	_, err := a.db.Exec(ctx, `INSERT INTO issue (id, org_id, project_id, number, fingerprint, tool, rule_id, title,
		description, remediation, severity, status, file_path, start_line, end_line, snippet, cwe, cve,
		package_name, package_version, fixed_version, first_seen_scan_id, last_seen_scan_id, due_at, created_at, updated_at)
		VALUES ($1, $2, $3, $4, $5, $6, $7, $8, $9, $10, $11, 'open', $12, $13, $14, $15, $16, $17, $18, $19, $20, $21, $21, $22, $23, $23)`,
		id, a.in.OrgID, a.in.ProjectID, number, n.Fingerprint, f.Tool, f.RuleID, f.Title,
		nullable(f.Description), nullable(f.Remediation), string(f.Severity), nullable(f.FilePath), f.StartLine, f.EndLine,
		nullable(f.Snippet), f.CWE, f.CVE, nullable(f.PackageName), nullable(f.PackageVersion), nullable(f.FixedVersion),
		a.in.ScanID, a.sla.DueAt(f.Severity, now), now)
	if err != nil {
		return fmt.Errorf("create issue: %w", err)
	}
	if err := a.event(ctx, id, EventCreated, nil, ptr(string(issuestate.Open)), ""); err != nil {
		return err
	}
	return a.occurrence(ctx, id, f)
}

func (a applier) sighting(ctx context.Context, s Sighting, now time.Time) error {
	f, id := s.Finding, s.Issue.ID
	// Location and snippet follow the code; this isn't a user-visible edit, so
	// version and updated_at stay put.
	if _, err := a.db.Exec(ctx, `UPDATE issue SET last_seen_scan_id = $2, file_path = $3, start_line = $4, end_line = $5,
		snippet = $6 WHERE id = $1`, id, a.in.ScanID, nullable(f.FilePath), f.StartLine, f.EndLine, nullable(f.Snippet)); err != nil {
		return fmt.Errorf("update issue: %w", err)
	}
	sev := s.Issue.Severity
	if s.NewSeverity != "" {
		if _, err := a.db.Exec(ctx, `UPDATE issue SET severity = $2, version = version + 1, updated_at = $3 WHERE id = $1`,
			id, string(s.NewSeverity), now); err != nil {
			return fmt.Errorf("update severity: %w", err)
		}
		if err := a.event(ctx, id, EventSeverityChanged, ptr(string(sev)), ptr(string(s.NewSeverity)), ""); err != nil {
			return err
		}
		sev = s.NewSeverity
	}
	if s.Reopen {
		due := a.sla.DueAt(sev, now)
		if err := a.transition(ctx, s.Issue, issuestate.Reopened, due, "found again in scan "+a.in.ScanID.String()); err != nil {
			return err
		}
	}
	if s.SeenAgain {
		if err := a.event(ctx, id, EventSeenAgain, nil, ptr(a.in.ScanID.String()), ""); err != nil {
			return err
		}
	}
	return a.occurrence(ctx, id, f)
}

// transition moves an issue as the System actor. The status guard in WHERE
// makes a concurrent user change win: then nothing is written.
func (a applier) transition(ctx context.Context, e ExistingIssue, to issuestate.Status, due *time.Time, note string) error {
	if _, err := issuestate.Check(e.Status, to, issuestate.System); err != nil {
		return err
	}
	q := `UPDATE issue SET status = $3, version = version + 1, updated_at = $4 WHERE id = $1 AND status = $2`
	args := []any{e.ID, string(e.Status), string(to), a.in.Now}
	if to == issuestate.Reopened {
		q = `UPDATE issue SET status = $3, version = version + 1, updated_at = $4, due_at = $5 WHERE id = $1 AND status = $2`
		args = append(args, due)
	}
	tag, err := a.db.Exec(ctx, q, args...)
	if err != nil {
		return fmt.Errorf("transition issue: %w", err)
	}
	if tag.RowsAffected() == 0 {
		return nil
	}
	return a.event(ctx, e.ID, EventStatusChanged, ptr(string(e.Status)), ptr(string(to)), note)
}
