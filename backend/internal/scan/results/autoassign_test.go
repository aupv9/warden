package results

import (
	"context"
	"errors"
	"fmt"
	"testing"
	"time"

	"github.com/google/uuid"

	"github.com/aupv9/warden/backend/internal/scan/sandbox"
	"github.com/aupv9/warden/backend/internal/scan/sarif"
	"github.com/aupv9/warden/backend/internal/worker/dbtest"
)

// One new finding under src/, rules: [gone (left the project), dev].
func assignWorld(rules string, members [][]any) (Input, []dbtest.Step, uuid.UUID) {
	dev := uuid.New()
	f := finding("opengrep", "sqli", "src/app/db.py", 4)
	in := Input{OrgID: uuid.New(), ProjectID: uuid.New(), ScanID: uuid.New(), Status: "completed", GuardRatio: 1, Now: time.Now(),
		Runs: []sandbox.ToolRun{{Tool: "opengrep", Status: sandbox.Succeeded}}, Findings: map[string][]sarif.Finding{"opengrep": {f}}}
	if rules == "" {
		rules = fmt.Sprintf(`[{"match":{"path_glob":"src/**"},"assignee_id":"%s"},{"match":{"path_glob":"src/**/*.py"},"assignee_id":"%s"}]`,
			uuid.New(), dev)
	}
	if members == nil {
		members = [][]any{{dev}}
	}
	steps := []dbtest.Step{
		{Prefix: "SELECT status FROM scan", Rows: row("running")},
		{Prefix: "SELECT issue_seq FROM project", Rows: row(0)},
		{Prefix: "SELECT sla_days, license_policy FROM organization", Rows: row([]byte(`{}`), []byte(`{}`))},
		{Prefix: "SELECT id, fingerprint"},
		{Prefix: "SELECT assign_rules FROM project", Rows: row([]byte(rules))},
		{Prefix: "SELECT pm.user_id FROM project_member", Rows: members},
		{Prefix: "UPDATE project SET issue_seq", Rows: row(1)},
		{Prefix: "INSERT INTO issue (", Affected: 1, Args: func(args []any) error {
			if args[23] != "assigned" || *args[24].(*uuid.UUID) != dev {
				return fmt.Errorf("status %v assignee %v", args[23], args[24])
			}
			return nil
		}},
		{Prefix: "INSERT INTO issue_event", Affected: 1, Args: eventType(EventCreated)},
		{Prefix: "INSERT INTO issue_event", Affected: 1, Args: func(args []any) error {
			if args[2] != EventStatusChanged || *args[5].(*string) != "auto-assign rule 2" {
				return fmt.Errorf("%v %v", args[2], args[5])
			}
			return nil
		}},
		{Prefix: "INSERT INTO issue_event", Affected: 1, Args: func(args []any) error {
			if args[2] != EventAssigned || *args[4].(*string) != dev.String() || *args[5].(*string) != "auto-assign rule 2" {
				return fmt.Errorf("%v %v %v", args[2], args[4], args[5])
			}
			return nil
		}},
		{Prefix: "INSERT INTO outbox_event", Affected: 1, Args: outboxType("issue.assigned")},
		{Prefix: "INSERT INTO occurrence", Affected: 1},
		{Prefix: "UPDATE scan_tool_run SET findings_count", Affected: 1},
		{Prefix: "UPDATE scan SET status = $2, error_code = NULL", Affected: 1},
		{Prefix: "INSERT INTO outbox_event", Affected: 1, Args: outboxType("scan.finished")},
	}
	return in, steps, dev
}

func TestProcessAutoAssignsNewIssues(t *testing.T) {
	in, steps, _ := assignWorld("", nil)
	db := dbtest.New(t, steps...)
	if _, err := Process(context.Background(), db, in); err != nil {
		t.Fatal(err)
	}
	db.Done()

	// Every statement's failure aborts processing.
	for i := range steps {
		in, steps, _ := assignWorld("", nil)
		steps = steps[:i+1]
		steps[i].Err, steps[i].Args = errDB, nil
		db := dbtest.New(t, steps...)
		if _, err := Process(context.Background(), db, in); !errors.Is(err, errDB) {
			t.Fatalf("step %d (%s): %v", i, steps[i].Prefix, err)
		}
	}
}

// openSteps: the rule lookup ends without an assignment; the issue stays open.
func openSteps(steps []dbtest.Step, withMembers bool) []dbtest.Step {
	out := append([]dbtest.Step{}, steps[:5]...)
	if withMembers {
		out = append(out, steps[5])
	}
	out = append(out, steps[6], dbtest.Step{Prefix: "INSERT INTO issue (", Affected: 1, Args: func(args []any) error {
		if args[23] != "open" || args[24].(*uuid.UUID) != nil {
			return fmt.Errorf("%v %v", args[23], args[24])
		}
		return nil
	}})
	return append(out, steps[8], steps[12], steps[13], steps[14], steps[15])
}

func TestProcessWithoutEligibleRules(t *testing.T) {
	// No rules: no member lookup.
	in, steps, _ := assignWorld("[]", nil)
	db := dbtest.New(t, openSteps(steps, false)...)
	if _, err := Process(context.Background(), db, in); err != nil {
		t.Fatal(err)
	}
	db.Done()

	// Every assignee left the project.
	in, steps, _ = assignWorld("", [][]any{})
	db = dbtest.New(t, openSteps(steps, true)...)
	if _, err := Process(context.Background(), db, in); err != nil {
		t.Fatal(err)
	}
	db.Done()

	// Corrupt rules fail the processing rather than assigning wrongly.
	in, steps, _ = assignWorld("{", nil)
	db = dbtest.New(t, steps[:5]...)
	if _, err := Process(context.Background(), db, in); err == nil {
		t.Fatal("corrupt rules accepted")
	}
}
