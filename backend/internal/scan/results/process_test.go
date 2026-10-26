package results

import (
	"context"
	"errors"
	"fmt"
	"strings"
	"testing"
	"time"

	"github.com/google/uuid"

	"github.com/aupv9/warden/backend/internal/domain/issuestate"
	"github.com/aupv9/warden/backend/internal/domain/severity"
	"github.com/aupv9/warden/backend/internal/scan/sandbox"
	"github.com/aupv9/warden/backend/internal/scan/sarif"
	"github.com/aupv9/warden/backend/internal/worker/dbtest"
)

var errDB = errors.New("db down")

func row(vals ...any) [][]any { return [][]any{vals} }

type world struct {
	in    Input
	steps []dbtest.Step
}

// newWorld: issue A (open, low → high) seen again, B (fixed) back, C (in
// progress) gone, N new. Every statement Process issues, in order.
func newWorld() world {
	org, project, scan := uuid.New(), uuid.New(), uuid.New()
	prev := uuid.New()
	a, b, c, n := fA, fB, finding("opengrep", "gone", "c.py", 1), finding("opengrep", "new", "n.py", 2)
	n.Snippet = "AKIA****" // what a redacted Gitleaks snippet looks like
	return world{
		in: Input{OrgID: org, ProjectID: project, ScanID: scan, Status: "partial", GuardRatio: 1, Now: time.Now(),
			Runs:     []sandbox.ToolRun{{Tool: "opengrep", Status: sandbox.Succeeded}, {Tool: "trivy", Status: sandbox.Failed}},
			Findings: map[string][]sarif.Finding{"opengrep": {a, b, n}}},
		steps: []dbtest.Step{
			{Prefix: "SELECT status FROM scan WHERE id = $1 AND project_id = $2 FOR UPDATE", Rows: row("running")},
			{Prefix: "SELECT issue_seq FROM project WHERE id = $1 FOR UPDATE", Rows: row(7)},
			{Prefix: "SELECT sla_days FROM organization", Rows: row([]byte(`{"critical":7,"high":30,"medium":90,"low":180}`))},
			{Prefix: "SELECT id, fingerprint", Rows: [][]any{
				{uuid.New(), fpOf(a), "opengrep", "open", "low", false, prev},
				{uuid.New(), fpOf(b), "opengrep", "fixed", "high", false, prev},
				{uuid.New(), fpOf(c), "opengrep", "in_progress", "high", false, prev},
			}},
			{Prefix: "UPDATE project SET issue_seq = issue_seq + $2", Rows: row(8), Args: func(args []any) error {
				if args[1] != 1 {
					return fmt.Errorf("allocated %v numbers", args[1])
				}
				return nil
			}},
			{Prefix: "INSERT INTO issue (", Affected: 1, Args: func(args []any) error {
				if args[3] != 8 || *args[14].(*string) != "AKIA****" {
					return fmt.Errorf("number %v snippet %v", args[3], args[14])
				}
				return nil
			}},
			{Prefix: "INSERT INTO issue_event", Affected: 1, Args: eventType(EventCreated)},
			{Prefix: "INSERT INTO occurrence", Affected: 1, Args: func(args []any) error {
				if raw := string(args[5].([]byte)); !strings.Contains(raw, `"rule_id":"new"`) {
					return fmt.Errorf("raw %s", raw)
				}
				return nil
			}},
			// A
			{Prefix: "UPDATE issue SET last_seen_scan_id", Affected: 1},
			{Prefix: "UPDATE issue SET severity", Affected: 1},
			{Prefix: "INSERT INTO issue_event", Affected: 1, Args: eventType(EventSeverityChanged)},
			{Prefix: "INSERT INTO issue_event", Affected: 1, Args: eventType(EventSeenAgain)},
			{Prefix: "INSERT INTO occurrence", Affected: 1},
			// B
			{Prefix: "UPDATE issue SET last_seen_scan_id", Affected: 1},
			{Prefix: "UPDATE issue SET status = $3, version = version + 1, updated_at = $4, due_at = $5", Affected: 1},
			{Prefix: "INSERT INTO issue_event", Affected: 1, Args: eventType(EventStatusChanged)},
			{Prefix: "INSERT INTO occurrence", Affected: 1},
			// C
			{Prefix: "UPDATE issue SET status = $3, version = version + 1, updated_at = $4 WHERE", Affected: 1},
			{Prefix: "INSERT INTO issue_event", Affected: 1, Args: eventType(EventStatusChanged)},
			{Prefix: "UPDATE scan_tool_run SET findings_count", Affected: 1},
			{Prefix: "UPDATE scan SET status = $2, error_code = NULL", Affected: 1, Args: func(args []any) error {
				if args[1] != "partial" || string(args[2].([]byte)) != `{"new":1,"fixed":1,"reopened":1,"total":3}` {
					return fmt.Errorf("%v %s", args[1], args[2])
				}
				return nil
			}},
		},
	}
}

// eventType checks the event type and that the actor is the system (NULL in SQL).
func eventType(want string) func([]any) error {
	return func(args []any) error {
		if args[2] != want {
			return fmt.Errorf("event %v, want %s", args[2], want)
		}
		return nil
	}
}

func TestProcessAppliesPlan(t *testing.T) {
	w := newWorld()
	db := dbtest.New(t, w.steps...)
	p, err := Process(context.Background(), db, w.in)
	if err != nil {
		t.Fatal(err)
	}
	if p.Stats != (Stats{New: 1, Fixed: 1, Reopened: 1, Total: 3}) {
		t.Fatalf("%+v", p.Stats)
	}
	db.Done()
}

// Every statement's failure aborts processing with an error (the caller's
// transaction then rolls back, so a retry starts clean).
func TestProcessPropagatesEveryDBError(t *testing.T) {
	for i := range newWorld().steps {
		w := newWorld()
		steps := w.steps[:i+1]
		steps[i].Err, steps[i].Args = errDB, nil
		db := dbtest.New(t, steps...)
		if _, err := Process(context.Background(), db, w.in); !errors.Is(err, errDB) {
			t.Fatalf("step %d (%s): %v", i, steps[i].Prefix, err)
		}
		db.Done()
	}
}

func TestProcessRefusesScanThatIsNotRunning(t *testing.T) {
	in := newWorld().in
	for _, s := range []dbtest.Step{
		{Prefix: "SELECT status FROM scan", Rows: row("cancelled")},
		{Prefix: "SELECT status FROM scan", Rows: row("completed")},
		{Prefix: "SELECT status FROM scan"}, // no row: other org (RLS) or deleted
	} {
		db := dbtest.New(t, s)
		if _, err := Process(context.Background(), db, in); !errors.Is(err, ErrScanNotRunning) {
			t.Fatal(err)
		}
		db.Done()
	}
}

func TestProcessRejectsCorruptSLA(t *testing.T) {
	w := newWorld()
	steps := append(w.steps[:2:2], dbtest.Step{Prefix: "SELECT sla_days", Rows: row([]byte(`[]`))})
	if _, err := Process(context.Background(), dbtest.New(t, steps...), w.in); err == nil {
		t.Fatal("corrupt sla_days accepted")
	}
}

func TestProcessRejectsBadIssueRows(t *testing.T) {
	w := newWorld()
	steps := append(w.steps[:3:3], dbtest.Step{Prefix: "SELECT id, fingerprint", Rows: [][]any{{"short"}}})
	if _, err := Process(context.Background(), dbtest.New(t, steps...), w.in); err == nil {
		t.Fatal("bad rows accepted")
	}
}

// A user changed the issue concurrently: the guarded UPDATE matches no row and
// no event is written.
func TestTransitionLosesToConcurrentChange(t *testing.T) {
	db := dbtest.New(t, dbtest.Step{Prefix: "UPDATE issue SET status", Affected: 0})
	a := applier{db: db, in: Input{Now: time.Now()}}
	if err := a.transition(context.Background(), ExistingIssue{ID: uuid.New(), Status: issuestate.Open}, issuestate.Fixed, nil, ""); err != nil {
		t.Fatal(err)
	}
	db.Done()
	// The state machine is enforced before touching the database.
	if err := a.transition(context.Background(), ExistingIssue{Status: issuestate.FalsePositive}, issuestate.Fixed, nil, ""); !errors.Is(err, issuestate.ErrInvalidTransition) {
		t.Fatal(err)
	}
}

func TestDueAt(t *testing.T) {
	now := time.Date(2026, 10, 26, 0, 0, 0, 0, time.UTC)
	sla := SLA{"critical": 7, "low": 0}
	if d := sla.DueAt(severity.Critical, now); d == nil || !d.Equal(now.AddDate(0, 0, 7)) {
		t.Fatal(d)
	}
	if sla.DueAt(severity.Info, now) != nil || sla.DueAt(severity.Low, now) != nil {
		t.Fatal("no SLA → no due date")
	}
}
