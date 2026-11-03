package worker

import (
	"github.com/google/uuid"
	"github.com/riverqueue/river"
)

// TestRulesArgs runs one scan_rule_test row (a draft org rule against a
// snippet) in the scanner sandbox. The API enqueues it in the transaction that
// inserts the row (store.InsertRuleTest). The args name the row only: the rule
// body and the snippet stay in the database (River keeps job args for days and
// shows them to operators), and the worker reads them under the org's RLS.
// Field names and JSON are a contract with the API: keep them stable.
type TestRulesArgs struct {
	OrgID  uuid.UUID `json:"org_id"`
	TestID uuid.UUID `json:"test_id"`
}

func (TestRulesArgs) Kind() string { return "test_rules" }

// InsertOpts: tests share the scan queue, so they take a sandbox slot like a
// scan and can't run more sandboxes than scan.slots allows. One attempt: a
// test is cheap to submit again, and a retry would count against nothing.
func (TestRulesArgs) InsertOpts() river.InsertOpts {
	return river.InsertOpts{Queue: QueueScan, MaxAttempts: 1}
}
