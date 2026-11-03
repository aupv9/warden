package service_test

import (
	"context"
	"errors"
	"net/http"
	"testing"

	"github.com/google/uuid"

	"github.com/aupv9/warden/backend/internal/domain/rbac"
	"github.com/aupv9/warden/backend/internal/rules"
	"github.com/aupv9/warden/backend/internal/service"
	"github.com/aupv9/warden/backend/internal/service/servicetest"
)

func rulesSetup(role rbac.Role) setup {
	x := newSetup(role)
	x.s = service.New(x.f, nil, service.Config{ParseRule: servicetest.ParseRule}, nil)
	return x
}

// The API's allow-list keeps tokens away from these routes; the service
// refuses them on its own too, even for an org admin's token.
func TestScanRulesRefuseAPITokens(t *testing.T) {
	ctx := context.Background()
	x := rulesSetup(rbac.OrgAdmin)
	rule, err := x.s.CreateScanRule(ctx, x.actor(), service.CreateScanRuleInput{Tool: "opengrep", Name: "n", Body: "id: k"})
	if err != nil {
		t.Fatal(err)
	}
	tok := x.actor()
	tok.Token = &service.TokenAuth{ID: uuid.New(), OrgID: x.org, ProjectID: x.p, Scopes: []string{service.ScopeScanWrite, service.ScopeIssuesRead}}
	snippet := ""
	for name, call := range map[string]func() error{
		"list": func() error { _, err := x.s.ScanRules(ctx, tok, service.ScanRuleFilter{}); return err },
		"get":  func() error { _, err := x.s.ScanRule(ctx, tok, rule.ID); return err },
		"versions": func() error {
			_, err := x.s.ScanRuleVersions(ctx, tok, rule.ID, service.PageParams{})
			return err
		},
		"create": func() error {
			_, err := x.s.CreateScanRule(ctx, tok, service.CreateScanRuleInput{Tool: "opengrep", Name: "n", Body: "id: j"})
			return err
		},
		"update": func() error {
			_, err := x.s.UpdateScanRule(ctx, tok, rule.ID, service.UpdateScanRuleInput{Version: new(1), Enabled: new(false)})
			return err
		},
		"delete": func() error { return x.s.DeleteScanRule(ctx, tok, rule.ID, "1") },
		"validate": func() error {
			_, err := x.s.ValidateScanRule(ctx, tok, service.ValidateScanRuleInput{Tool: "opengrep", Body: "id: j"})
			return err
		},
		"test": func() error {
			_, err := x.s.CreateRuleTest(ctx, tok, service.RuleTestInput{Tool: "opengrep", Body: "id: j", Filename: "a.py", Snippet: &snippet})
			return err
		},
		"get test": func() error { _, err := x.s.RuleTest(ctx, tok, uuid.New()); return err },
	} {
		if err := call(); status(err) != http.StatusForbidden {
			t.Errorf("%s: %v", name, err)
		}
	}
	if len(x.f.AuditLog()) != 1 || len(x.f.TestJobs()) != 0 {
		t.Fatal(x.f.AuditLog(), x.f.TestJobs())
	}
}

// A failed write leaves nothing behind: the rule, its version and the audit
// entry are one transaction, and so are a test row and its job.
func TestScanRuleWritesAreAtomic(t *testing.T) {
	ctx := context.Background()
	x := rulesSetup(rbac.SecurityLead)
	x.f.Fail["AppendAudit"] = errors.New("audit down")
	if _, err := x.s.CreateScanRule(ctx, x.actor(), service.CreateScanRuleInput{Tool: "gitleaks", Name: "n", Body: "id: k"}); err == nil {
		t.Fatal("created without audit")
	}
	delete(x.f.Fail, "AppendAudit")
	if l, err := x.s.ScanRules(ctx, x.actor(), service.ScanRuleFilter{}); err != nil || len(l.Items) != 0 {
		t.Fatal(l, err)
	}
	x.f.Fail["InsertRuleTest"] = errors.New("db down")
	snippet := "x"
	if _, err := x.s.CreateRuleTest(ctx, x.actor(), service.RuleTestInput{Tool: "gitleaks", Body: "id: k", Filename: "a", Snippet: &snippet}); err == nil {
		t.Fatal("no error")
	}
	if len(x.f.TestJobs()) != 0 {
		t.Fatal(x.f.TestJobs())
	}
}

// Whatever the parser returns, the service stores only what the schema
// allows: a rule for this tool, a key, a severity and a canonical body of at
// most 64 KiB.
func TestScanRuleParserOutputIsChecked(t *testing.T) {
	ctx := context.Background()
	for name, r := range map[string]rules.Rule{
		"other tool":   {Tool: rules.Gitleaks, Key: "k", Severity: "high", Canonical: []byte("x")},
		"empty key":    {Tool: rules.Opengrep, Key: "", Severity: "high", Canonical: []byte("x")},
		"upper key":    {Tool: rules.Opengrep, Key: "Key", Severity: "high", Canonical: []byte("x")},
		"long key":     {Tool: rules.Opengrep, Key: string(make([]byte, 65)), Severity: "high", Canonical: []byte("x")},
		"newline key":  {Tool: rules.Opengrep, Key: "k\n", Severity: "high", Canonical: []byte("x")},
		"severity":     {Tool: rules.Opengrep, Key: "k", Severity: "error", Canonical: []byte("x")},
		"no body":      {Tool: rules.Opengrep, Key: "k", Severity: "high"},
		"huge body":    {Tool: rules.Opengrep, Key: "k", Severity: "high", Canonical: make([]byte, rules.MaxBodyBytes+1)},
		"nul in body":  {Tool: rules.Opengrep, Key: "k", Severity: "high", Canonical: []byte("a\x00b")},
		"invalid utf8": {Tool: rules.Opengrep, Key: "k", Severity: "high", Canonical: []byte{0xff}},
	} {
		x := newSetup(rbac.OrgAdmin)
		x.s = service.New(x.f, nil, service.Config{ParseRule: func(rules.Tool, []byte) (rules.Rule, []rules.Problem) { return r, nil }}, nil)
		_, err := x.s.CreateScanRule(ctx, x.actor(), service.CreateScanRuleInput{Tool: "opengrep", Name: "n", Body: "anything"})
		if code(err) != "RULE_INVALID" {
			t.Errorf("%s: %v", name, err)
		}
		v, err := x.s.ValidateScanRule(ctx, x.actor(), service.ValidateScanRuleInput{Tool: "opengrep", Body: "anything"})
		if err != nil || v.OK || len(v.Problems) != 1 {
			t.Errorf("%s: %+v %v", name, v, err)
		}
	}
	// Problems are capped.
	x := newSetup(rbac.OrgAdmin)
	many := make([]rules.Problem, 500)
	x.s = service.New(x.f, nil, service.Config{ParseRule: func(rules.Tool, []byte) (rules.Rule, []rules.Problem) { return rules.Rule{}, many }}, nil)
	if v, err := x.s.ValidateScanRule(ctx, x.actor(), service.ValidateScanRuleInput{Tool: "gitleaks", Body: "x"}); err != nil || len(v.Problems) != 50 ||
		v.Problems[0].Line != nil {
		t.Fatal(len(v.Problems), err)
	}
	// Without a parser seam, the real one is used.
	x = newSetup(rbac.OrgAdmin)
	if _, err := x.s.ValidateScanRule(ctx, x.actor(), service.ValidateScanRuleInput{Tool: "gitleaks", Body: "x"}); err != nil {
		t.Fatal(err)
	}
}
