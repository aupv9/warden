package worker

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"regexp"
	"time"
	"unicode/utf8"

	"github.com/google/uuid"
	"github.com/jackc/pgx/v5"
	"github.com/riverqueue/river"

	"github.com/aupv9/warden/backend/internal/domain/severity"
	"github.com/aupv9/warden/backend/internal/rules"
	"github.com/aupv9/warden/backend/internal/scan/orchestrator"
	"github.com/aupv9/warden/backend/internal/scan/sandbox"
	"github.com/aupv9/warden/backend/internal/scan/sarif"
	"github.com/aupv9/warden/backend/internal/scan/zipcheck"
)

// Rule tests (scan_rule_test): an org admin runs a draft rule against a
// snippet before saving it. The job runs only that tool, with only the draft
// rule (none of Warden's), in the same sandbox as scans, on a scratch
// directory named after the test (so the worker's startup cleanup knows it).
// Gitleaks still goes through warden-redact, under a throw-away HMAC key: the
// snippet may hold a real secret. What is kept is a line range and the rule's
// own text per finding, never matched text; the snippet is set to NULL and the
// directory deleted however the run ends.

// TestRulesArgs is enqueued by the API (POST /orgs/{org}/scan-rules/tests)
// in the transaction that inserts the test. Field names and JSON are a
// contract with the API: keep them stable.
type TestRulesArgs struct {
	OrgID  uuid.UUID `json:"org_id"`
	TestID uuid.UUID `json:"test_id"`
}

func (TestRulesArgs) Kind() string { return "test_rules" }

// A worker that dies mid-run gets one more attempt; the test is still running
// with its snippet, and the next attempt runs it again.
func (TestRulesArgs) InsertOpts() river.InsertOpts { return river.InsertOpts{MaxAttempts: 2} }

type TestRulesWorker struct {
	river.WorkerDefaults[TestRulesArgs]
	Env *Env
}

// Timeout: the sandbox's own limit plus the writes around it.
func (TestRulesWorker) Timeout(*river.Job[TestRulesArgs]) time.Duration {
	return sandbox.RuleTestTimeout + 2*time.Minute
}

func (w TestRulesWorker) Work(ctx context.Context, job *river.Job[TestRulesArgs]) error {
	if w.Env == nil {
		return errNoEnv
	}
	return w.Env.RunRuleTest(ctx, job.Args, job.Attempt)
}

// Rule test errors (scan_rule_test.error, API RuleTest.error).
const (
	RuleTestTimeout       = "timeout"
	RuleTestScannerFailed = "scanner_failed"
	RuleTestRuleInvalid   = "rule_invalid"
)

// RuleTestFinding is one finding of a rule test (scan_rule_test.findings).
// Message is the rule's own text, never what it matched.
type RuleTestFinding struct {
	Line    int    `json:"line"`
	EndLine *int   `json:"end_line"`
	Message string `json:"message"`
}

const (
	// maxRuleTestFindings caps what one test keeps; a snippet is small.
	maxRuleTestFindings = 200
	maxRuleTestMessage  = 1000
	// ruleTestRetention: tests (their results) are deleted a day after they
	// were made (prune_rule_tests); ruleTestStale: a test still queued or
	// running this long after it was made lost its job, and gives up its
	// snippet.
	ruleTestRetention = 24 * time.Hour
	ruleTestStale     = time.Hour
)

// snippetName is the API's check of the snippet's file name, repeated: the
// name becomes a path under src/.
var snippetName = regexp.MustCompile(`^[A-Za-z0-9._-]{1,255}$`)

type ruleTestRow struct {
	tool, filename string
	body, snippet  []byte
}

// RunRuleTest runs one rule test. It returns an error only when River should
// retry (the database is unavailable); every outcome of the run is written to
// the test.
func (e *Env) RunRuleTest(ctx context.Context, args TestRulesArgs, attempt int) error {
	var t ruleTestRow
	runnable := false
	err := e.Tx(ctx, args.OrgID, func(db DB) error {
		var state string
		if err := db.QueryRow(ctx, `SELECT tool::text, body_canonical, filename, snippet, state::text FROM scan_rule_test
			WHERE id = $1 FOR UPDATE`, args.TestID).Scan(&t.tool, &t.body, &t.filename, &t.snippet, &state); err != nil {
			return err
		}
		// Done already (a retry after the result was written), or its
		// snippet is gone: nothing to run.
		if (state != "queued" && state != "running") || t.snippet == nil {
			return nil
		}
		runnable = true
		_, err := db.Exec(ctx, `UPDATE scan_rule_test SET state = 'running' WHERE id = $1`, args.TestID)
		return err
	})
	if errors.Is(err, pgx.ErrNoRows) {
		return river.JobCancel(fmt.Errorf("rule test %s not found", args.TestID))
	}
	if err != nil || !runnable {
		return err
	}
	log := e.Log.With("rule_test_id", args.TestID, "org_id", args.OrgID, "tool", t.tool, "attempt", attempt)
	findings, code := e.ruleTest(ctx, args.TestID, t, attempt)
	t.snippet = nil
	if code != "" {
		log.Info("rule test failed", "error", code)
	}

	fin, cancel := context.WithTimeout(context.WithoutCancel(ctx), time.Minute)
	defer cancel()
	state, errCode := "done", (*string)(nil)
	if code != "" {
		state, errCode, findings = "failed", &code, nil
	}
	if findings == nil {
		findings = []RuleTestFinding{}
	}
	raw, err := json.Marshal(findings)
	if err != nil {
		return err
	}
	return e.Tx(fin, args.OrgID, func(db DB) error {
		_, err := db.Exec(fin, `UPDATE scan_rule_test SET state = $2, findings = $3, error = $4, snippet = NULL, finished_at = $5
			WHERE id = $1`, args.TestID, state, raw, errCode, e.Now().UTC())
		return err
	})
}

// ruleTest runs the test in the sandbox and returns its findings, or the
// error code of a run that produced none.
func (e *Env) ruleTest(ctx context.Context, id uuid.UUID, t ruleTestRow, attempt int) ([]RuleTestFinding, string) {
	log := e.Log.With("rule_test_id", id, "tool", t.tool)
	r, problems := parseRule(rules.Tool(t.tool), t.body)
	if len(problems) > 0 {
		return nil, RuleTestRuleInvalid
	}
	config, err := renderRules(r.Tool, []rules.Rule{r})
	if err != nil || len(config) == 0 {
		log.Warn("rule test: draft not rendered", "err", err)
		return nil, RuleTestRuleInvalid
	}
	spec, err := sandbox.RuleTestTool(string(r.Tool))
	if err != nil {
		return nil, RuleTestRuleInvalid
	}
	image := e.Images[spec.Name]
	if image == "" {
		log.Warn("rule test: " + errNoImage)
		return nil, RuleTestScannerFailed
	}

	dir := filepath.Join(e.ScratchDir, id.String())
	if err := zipcheck.RemoveAll(dir); err != nil {
		log.Error("rule test: scratch directory not cleared", "err", err)
		return nil, RuleTestScannerFailed
	}
	defer func() {
		if err := zipcheck.RemoveAll(dir); err != nil {
			log.Error("rule test: scratch directory not removed; the worker's startup cleanup will retry", "err", err)
		}
	}()
	if err := prepareRuleTest(dir, spec, t, config); err != nil {
		log.Error("rule test: scratch directory not prepared", "err", err)
		return nil, RuleTestScannerFailed
	}
	if attempt > 1 {
		// A crashed attempt may have left its container (named after the test).
		e.Sandbox.Kill(id.String(), spec.Name)
	}
	run := e.Sandbox.Run(ctx, spec, sandbox.RunConfig{
		ScanID: id.String(), ScanDir: dir, Image: image, Runtime: e.Runtime, MirrorDir: e.MirrorDir,
	})
	switch run.Status {
	case sandbox.Succeeded:
	case sandbox.Timeout:
		return nil, RuleTestTimeout
	default:
		attrs := []any{"status", run.Status}
		// Gitleaks' stderr may echo what it detected.
		if spec.Name != "gitleaks" {
			attrs = append(attrs, "stderr_tail", run.Error)
		}
		log.Warn("rule test: scanner did not succeed", attrs...)
		return nil, RuleTestScannerFailed
	}
	sev, err := severity.Parse(r.Severity)
	if err != nil {
		sev = severity.Medium // only the namespace check needs one; it isn't kept
	}
	doc, err := sarif.Load(run.Sarif)
	var fs []sarif.Finding
	if err == nil {
		fs, err = sarif.Parse(doc, spec.Name, sarif.Options{OrgRules: map[string]severity.Severity{r.ID(): sev}})
	}
	if err != nil {
		log.Warn("rule test: scanner output rejected", "err", err)
		return nil, RuleTestScannerFailed
	}
	return ruleTestFindings(fs, r), ""
}

// ruleTestFindings keeps each finding of rule r as a line range and the
// rule's own text.
func ruleTestFindings(fs []sarif.Finding, r rules.Rule) []RuleTestFinding {
	out := []RuleTestFinding{}
	for _, f := range fs {
		if len(out) == maxRuleTestFindings {
			break
		}
		if f.RuleID != r.ID() || f.StartLine == nil {
			continue
		}
		msg := f.RuleDescription
		if msg == "" {
			msg = r.ID()
		}
		var end *int
		if f.EndLine != nil {
			e := *f.EndLine
			end = &e
		}
		out = append(out, RuleTestFinding{Line: *f.StartLine, EndLine: end, Message: truncate(msg, maxRuleTestMessage)})
	}
	return out
}

func truncate(s string, n int) string {
	if utf8.RuneCountInString(s) <= n {
		return s
	}
	return string([]rune(s)[:n])
}

// prepareRuleTest lays out dir like a scan's: src/<filename> (the snippet),
// rules/<file> (the rendered draft), secrets/hmac for Gitleaks, all
// read-only for the sandbox user.
func prepareRuleTest(dir string, spec sandbox.ToolSpec, t ruleTestRow, config []byte) error {
	if !snippetName.MatchString(t.filename) || t.filename == "." || t.filename == ".." {
		return fmt.Errorf("invalid snippet file name")
	}
	if err := os.Mkdir(dir, 0o700); err != nil {
		return err
	}
	src := filepath.Join(dir, "src")
	if err := os.Mkdir(src, 0o755); err != nil {
		return err
	}
	// os.Root: the name can't leave src/, whatever it is.
	root, err := os.OpenRoot(src)
	if err != nil {
		return err
	}
	err = root.WriteFile(t.filename, t.snippet, 0o444)
	if cerr := root.Close(); err == nil {
		err = cerr
	}
	if err != nil {
		return err
	}
	if err := os.Chmod(src, 0o555); err != nil {
		return err
	}
	rulesDir := filepath.Join(dir, sandbox.RulesDir)
	if err := os.Mkdir(rulesDir, 0o755); err != nil {
		return err
	}
	if err := orchestrator.WriteReadOnly(filepath.Join(rulesDir, spec.OrgRules), config); err != nil {
		return err
	}
	if err := os.Chmod(rulesDir, 0o555); err != nil {
		return err
	}
	if !spec.NeedsHMACKey {
		return nil
	}
	// A key of its own: nothing a test reports can be matched against the
	// org's secret fingerprints.
	key, err := orchestrator.NewHMACKey()
	if err != nil {
		return err
	}
	if err := os.Mkdir(filepath.Join(dir, "secrets"), 0o700); err != nil {
		return err
	}
	return orchestrator.WriteReadOnly(filepath.Join(dir, "secrets", "hmac"), key)
}

// PruneRuleTestsArgs deletes rule tests a day old (hourly).
type PruneRuleTestsArgs struct{}

func (PruneRuleTestsArgs) Kind() string { return "prune_rule_tests" }

type PruneRuleTestsWorker struct {
	river.WorkerDefaults[PruneRuleTestsArgs]
	Env *Env
}

func (w PruneRuleTestsWorker) Work(ctx context.Context, _ *river.Job[PruneRuleTestsArgs]) error {
	if w.Env == nil {
		return errNoEnv
	}
	return w.Env.PruneRuleTests(ctx)
}

// PruneRuleTests deletes every org's rule tests older than a day, after
// failing the ones whose job was lost (they still hold their snippet).
func (e *Env) PruneRuleTests(ctx context.Context) error {
	now := e.Now().UTC()
	return e.forEachOrg(ctx, "prune_rule_tests", func(org uuid.UUID) error {
		return e.Tx(ctx, org, func(db DB) error {
			stale, err := db.Exec(ctx, `UPDATE scan_rule_test SET state = 'failed', error = 'scanner_failed', findings = '[]',
				snippet = NULL, finished_at = $2 WHERE state IN ('queued', 'running') AND created_at < $1`,
				now.Add(-ruleTestStale), now)
			if err != nil {
				return fmt.Errorf("fail stale rule tests: %w", err)
			}
			old, err := db.Exec(ctx, `DELETE FROM scan_rule_test WHERE created_at < $1`, now.Add(-ruleTestRetention))
			if err != nil {
				return fmt.Errorf("delete old rule tests: %w", err)
			}
			if stale.RowsAffected() > 0 || old.RowsAffected() > 0 {
				e.Log.Info("pruned rule tests", "org_id", org, "failed_stale", stale.RowsAffected(), "deleted", old.RowsAffected())
			}
			return nil
		})
	})
}
