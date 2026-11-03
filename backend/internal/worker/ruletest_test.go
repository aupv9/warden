package worker

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"os"
	"path/filepath"
	"slices"
	"strings"
	"testing"
	"time"

	"github.com/google/uuid"
	"github.com/riverqueue/river"

	"github.com/aupv9/warden/backend/internal/scan/redact"
	"github.com/aupv9/warden/backend/internal/scan/sandbox"
	st "github.com/aupv9/warden/backend/internal/scan/scantest"
	"github.com/aupv9/warden/backend/internal/worker/dbtest"
)

const ruleTestSelect = "SELECT tool::text, body_canonical, filename, snippet, state::text FROM scan_rule_test"

type ruleTestHarness struct {
	t    *testing.T
	env  *Env
	db   *dbtest.DB
	sb   *fakeSandbox
	org  uuid.UUID
	test uuid.UUID
	orgs []uuid.UUID
}

func newRuleTest(t *testing.T, tool, filename, state string, snippet []byte) *ruleTestHarness {
	t.Helper()
	fakeRules(t)
	h := &ruleTestHarness{t: t, org: uuid.New(), test: uuid.New(), sb: &fakeSandbox{status: map[string]sandbox.ToolStatus{}}}
	h.db = dbtest.Loose(t,
		dbtest.Step{Prefix: ruleTestSelect, Rows: row(tool, []byte("no-eval:high"), filename, snippet, state)},
		dbtest.Step{Prefix: "UPDATE scan_rule_test SET state = 'running'", Affected: 1},
		dbtest.Step{Prefix: "UPDATE scan_rule_test SET state = $2", Affected: 1},
	)
	scratch := filepath.Join(t.TempDir(), "scratch")
	if err := os.Mkdir(scratch, 0o700); err != nil {
		t.Fatal(err)
	}
	h.env = &Env{
		Tx: func(_ context.Context, org uuid.UUID, fn func(DB) error) error {
			h.orgs = append(h.orgs, org)
			return fn(h.db)
		},
		Sandbox: h.sb, Now: time.Now, Log: quietLog(),
		Settings: Settings{ScratchDir: scratch, MirrorDir: "/mirror", Runtime: "runsc", Images: testImages},
	}
	return h
}

func (h *ruleTestHarness) run(attempt int) error {
	return h.env.RunRuleTest(context.Background(), TestRulesArgs{OrgID: h.org, TestID: h.test}, attempt)
}

// result returns what the test's final write recorded: state, findings, error.
func (h *ruleTestHarness) result() (string, []RuleTestFinding, *string) {
	h.t.Helper()
	c := h.db.Calls("UPDATE scan_rule_test SET state = $2")
	if len(c) != 1 {
		h.t.Fatalf("final writes: %v", c)
	}
	if !strings.Contains(c[0].SQL, "snippet = NULL") || c[0].Args[4] == nil {
		h.t.Fatal("snippet kept or finished_at unset")
	}
	var fs []RuleTestFinding
	if err := json.Unmarshal(c[0].Args[2].([]byte), &fs); err != nil {
		h.t.Fatal(err)
	}
	if _, err := os.Stat(filepath.Join(h.env.ScratchDir, h.test.String())); !os.IsNotExist(err) {
		h.t.Fatal("scratch directory left behind")
	}
	for _, o := range h.orgs {
		if o != h.org {
			h.t.Fatal("transaction outside the test's org")
		}
	}
	return c[0].Args[1].(string), fs, c[0].Args[3].(*string)
}

// Opengrep: only the draft rule runs, on the snippet (read-only, under
// src/<filename>); findings keep a line range and the rule's own text, not
// the interpolated message.
func TestRuleTestOpengrep(t *testing.T) {
	h := newRuleTest(t, "opengrep", "app.py", "queued", []byte("eval(input())\n"))
	h.sb.docs = map[string]st.M{"opengrep": st.Doc(
		[]any{st.M{"ruleId": "rules.org.no-eval", "message": st.M{"text": "Do not call eval(input()) here"},
			"locations": []any{st.Loc("/src/app.py", 1)}}},
		st.M{"id": "rules.org.no-eval", "fullDescription": st.M{"text": "Do not call $F here"}},
	)}
	if err := h.run(1); err != nil {
		t.Fatal(err)
	}
	state, fs, errCode := h.result()
	if state != "done" || errCode != nil || len(fs) != 1 || fs[0].Line != 1 || *fs[0].EndLine != 1 || fs[0].Message != "Do not call $F here" {
		t.Fatalf("%s %+v %v", state, fs, errCode)
	}
	spec := h.sb.specs[0]
	if spec.Name != "opengrep" || slices.Contains(spec.Command, "/data/rules") || spec.Timeout != 2*time.Minute {
		t.Fatalf("%+v", spec)
	}
	if h.sb.configs[0].ScanID != h.test.String() || h.sb.configs[0].ScanDir != filepath.Join(h.env.ScratchDir, h.test.String()) {
		t.Fatalf("%+v", h.sb.configs[0])
	}
	if m := h.sb.mounted["src/app.py"]; string(m.data) != "eval(input())\n" || m.mode != 0o444 {
		t.Fatalf("%+v", m)
	}
	if m := h.sb.mounted["rules/opengrep.yml"]; string(m.data) != "opengrep org.no-eval\n" || m.mode != 0o444 {
		t.Fatalf("%+v", m)
	}
	if _, ok := h.sb.mounted["secrets/hmac"]; ok {
		t.Fatal("opengrep got a key")
	}
	if len(h.sb.killed) != 0 {
		t.Fatal("first attempt killed a container")
	}
}

// Gitleaks: redacted SARIF only (the parser refuses the raw one), a fresh key
// that isn't the org's, findings by line with the rule's description.
func TestRuleTestGitleaks(t *testing.T) {
	h := newRuleTest(t, "gitleaks", "config.env", "running", []byte("TOKEN="+st.FakeSecret+"\n"))
	doc := st.GitleaksDoc()
	run := doc["runs"].([]any)[0].(st.M)
	run["results"].([]any)[0].(st.M)["ruleId"] = "org.no-eval"
	run["tool"].(st.M)["driver"].(st.M)["rules"] = []any{st.M{"id": "org.no-eval", "shortDescription": st.M{"text": "Acme token"}}}
	red, err := redact.Doc(st.RoundTrip(doc), st.HMACKey)
	if err != nil {
		t.Fatal(err)
	}
	h.sb.docs = map[string]st.M{"gitleaks": red}
	if err := h.run(2); err != nil {
		t.Fatal(err)
	}
	state, fs, errCode := h.result()
	if state != "done" || errCode != nil || len(fs) != 1 || fs[0].Line != 3 || fs[0].Message != "Acme token" {
		t.Fatalf("%s %+v %v", state, fs, errCode)
	}
	c := h.db.Calls("UPDATE scan_rule_test SET state = $2")
	if bytes.Contains(c[0].Args[2].([]byte), []byte(st.FakeSecret)) || bytes.Contains(c[0].Args[2].([]byte), []byte("AKIA")) {
		t.Fatal("matched text stored")
	}
	if !slices.Equal(h.sb.specs[0].Command, []string{"warden-gitleaks", "rules-only"}) {
		t.Fatal(h.sb.specs[0].Command)
	}
	key := h.sb.mounted["secrets/hmac"]
	orgKey, _ := OrgKey(bytes.Repeat([]byte("m"), 32), h.org.String())
	if len(key.data) != 64 || key.mode != 0o444 || bytes.Equal(key.data, orgKey) {
		t.Fatalf("%+v", key)
	}
	if !slices.Equal(h.sb.killed, []string{"gitleaks"}) {
		t.Fatal("a retry must remove the previous attempt's container")
	}

	// Unredacted output is refused: the scanner failed, nothing kept.
	h = newRuleTest(t, "gitleaks", "config.env", "queued", []byte("x"))
	h.sb.docs = map[string]st.M{"gitleaks": doc}
	if err := h.run(1); err != nil {
		t.Fatal(err)
	}
	if state, fs, code := h.result(); state != "failed" || len(fs) != 0 || *code != RuleTestScannerFailed {
		t.Fatal(state, fs, *code)
	}
}

func TestRuleTestFailures(t *testing.T) {
	for _, c := range []struct {
		name, tool, file, want string
		status                 sandbox.ToolStatus
		noImage                bool
	}{
		{name: "invalid rule", tool: "opengrep", file: "a.py", want: RuleTestRuleInvalid},
		{name: "tool without org rules", tool: "trivy", file: "a.py", want: RuleTestRuleInvalid},
		{name: "timeout", tool: "opengrep", file: "a.py", status: sandbox.Timeout, want: RuleTestTimeout},
		{name: "scanner failed", tool: "opengrep", file: "a.py", status: sandbox.Failed, want: RuleTestScannerFailed},
		{name: "no image", tool: "opengrep", file: "a.py", noImage: true, want: RuleTestScannerFailed},
		// Names the API refuses; checked again before they become paths.
		{name: "dot dot", tool: "opengrep", file: "..", want: RuleTestScannerFailed},
		{name: "dot", tool: "opengrep", file: ".", want: RuleTestScannerFailed},
		{name: "slash", tool: "opengrep", file: "../../etc/x", want: RuleTestScannerFailed},
		{name: "absolute", tool: "opengrep", file: "/etc/passwd", want: RuleTestScannerFailed},
		{name: "empty", tool: "opengrep", file: "", want: RuleTestScannerFailed},
	} {
		t.Run(c.name, func(t *testing.T) {
			h := newRuleTest(t, c.tool, c.file, "queued", []byte("x"))
			if c.want == RuleTestRuleInvalid && c.tool == "opengrep" {
				h.db = dbtest.Loose(t,
					dbtest.Step{Prefix: ruleTestSelect, Rows: row("opengrep", []byte("bad:high"), c.file, []byte("x"), "queued")},
					dbtest.Step{Prefix: "UPDATE scan_rule_test SET state = 'running'", Affected: 1},
					dbtest.Step{Prefix: "UPDATE scan_rule_test SET state = $2", Affected: 1})
			}
			if c.status != "" {
				h.sb.status[c.tool] = c.status
			}
			if c.noImage {
				h.env.Images = nil
			}
			if err := h.run(1); err != nil {
				t.Fatal(err)
			}
			state, fs, code := h.result()
			if state != "failed" || len(fs) != 0 || code == nil || *code != c.want {
				t.Fatalf("%s %v %v", state, fs, code)
			}
			if (c.status != "") != (len(h.sb.specs) == 1) {
				t.Fatalf("sandbox runs: %d", len(h.sb.specs))
			}
			if entries, _ := os.ReadDir(filepath.Dir(h.env.ScratchDir)); len(entries) != 1 {
				t.Fatal("something written outside the scratch directory")
			}
		})
	}
}

// A test already finished (a retry after the write), or without its
// snippet, is left alone; a missing one cancels the job.
func TestRuleTestNotRunnable(t *testing.T) {
	for _, c := range []struct {
		state   string
		snippet []byte
	}{{"done", nil}, {"failed", nil}, {"running", nil}, {"done", []byte("x")}} {
		h := newRuleTest(t, "opengrep", "a.py", c.state, c.snippet)
		if err := h.run(2); err != nil {
			t.Fatal(err)
		}
		if n := len(h.db.Calls("UPDATE")); n != 0 || len(h.sb.specs) != 0 {
			t.Fatalf("%s: %d writes, %d runs", c.state, n, len(h.sb.specs))
		}
	}
	h := newRuleTest(t, "opengrep", "a.py", "queued", []byte("x"))
	h.db = dbtest.Loose(t, dbtest.Step{Prefix: ruleTestSelect})
	var cancel *river.JobCancelError
	if err := h.run(1); !errors.As(err, &cancel) {
		t.Fatal(err)
	}
}

func TestPruneRuleTests(t *testing.T) {
	org := uuid.New()
	now := time.Date(2026, 11, 3, 12, 0, 0, 0, time.UTC)
	db := dbtest.Loose(t,
		dbtest.Step{Prefix: "SELECT id FROM organization", Rows: row(org)},
		dbtest.Step{Prefix: "UPDATE scan_rule_test SET state = 'failed'", Affected: 1},
		dbtest.Step{Prefix: "DELETE FROM scan_rule_test", Affected: 2},
	)
	var orgs []uuid.UUID
	e := &Env{Tx: func(_ context.Context, o uuid.UUID, fn func(DB) error) error {
		orgs = append(orgs, o)
		return fn(db)
	}, Now: func() time.Time { return now }, Log: quietLog()}
	if err := e.PruneRuleTests(context.Background()); err != nil {
		t.Fatal(err)
	}
	stale := db.Calls("UPDATE scan_rule_test SET state = 'failed'")
	del := db.Calls("DELETE FROM scan_rule_test")
	if len(stale) != 1 || stale[0].Args[0] != now.Add(-time.Hour) || !strings.Contains(stale[0].SQL, "snippet = NULL") ||
		len(del) != 1 || del[0].Args[0] != now.Add(-24*time.Hour) {
		t.Fatal(stale, del)
	}
	if !slices.Equal(orgs, []uuid.UUID{uuid.Nil, org}) {
		t.Fatal(orgs)
	}
}
