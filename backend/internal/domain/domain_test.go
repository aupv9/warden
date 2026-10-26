package domain_test

import (
	"errors"
	"slices"
	"strings"
	"testing"

	"github.com/aupv9/warden/backend/internal/domain/fingerprint"
	"github.com/aupv9/warden/backend/internal/domain/issuestate"
	"github.com/aupv9/warden/backend/internal/domain/rbac"
	"github.com/aupv9/warden/backend/internal/domain/severity"
)

func TestNormPath(t *testing.T) {
	cases := []struct {
		uri, root  string
		underMount bool
		want       string
	}{
		{"file:///src/payment-main/app/x.py", "payment-main", true, "app/x.py"},
		{"/src/app/x.py", "", true, "app/x.py"},
		{`app\win\x.py`, "", true, "app/win/x.py"},
		{"/src/payment-main/a%20b.py", "payment-main", true, "a b.py"},
		{"src/payment-main/infra/main.tf", "payment-main", true, "infra/main.tf"},
		{"payment-main/src/package-lock.json", "payment-main", false, "src/package-lock.json"},
	}
	for _, c := range cases {
		if got := fingerprint.NormPath(c.uri, c.root, c.underMount); got != c.want {
			t.Errorf("NormPath(%q) = %q, want %q", c.uri, got, c.want)
		}
	}
}

func TestCodeContentKeyIgnoresWhitespaceChanges(t *testing.T) {
	if fingerprint.CodeContentKey([]string{"  x =   1 "}) != fingerprint.CodeContentKey([]string{"x = 1"}) {
		t.Fatal("whitespace changed the key")
	}
	if fingerprint.CodeContentKey([]string{"x = 1"}) == fingerprint.CodeContentKey([]string{"x = 2"}) {
		t.Fatal("different code, same key")
	}
}

// Same digest as the Python implementation, so fingerprints stay stable across the rewrite.
// Reference values were produced by the Python implementation (warden/domain/fingerprint.py).
func TestDigestsMatchPythonImplementation(t *testing.T) {
	for _, c := range []struct {
		lines []string
		want  string
	}{
		{[]string{"\tx  =\t1  ", " y"}, "95c5cf5e69f0a2b216258337de4ce8ee97f5c53f5ba1472eea325017cea7a7df"},
		{[]string{"a\x1cb", " z w"}, "0e8dc8d3b9075cddf1ffb6f53797ca0ed3a1db8c37ea0eaadfd30c5e5c043025"},
	} {
		if got := fingerprint.CodeContentKey(c.lines); got != c.want {
			t.Errorf("CodeContentKey(%q) = %s", c.lines, got)
		}
	}
	got := fingerprint.Fingerprint("opengrep", "r", "a.py", fingerprint.CodeContentKey([]string{"x = 1"}), 0)
	if got != "60aeea48cb2e54ce7b55968e31dbe98579330c9d2264b039880f2ba607405369" {
		t.Errorf("Fingerprint = %s", got)
	}
}

func TestSplitLinesLikePython(t *testing.T) {
	got := fingerprint.SplitLines("a\r\nb\rc\nd e\n")
	if want := []string{"a", "b", "c", "d", "e"}; !slices.Equal(got, want) {
		t.Fatalf("got %q", got)
	}
	if got := fingerprint.SplitLines(""); len(got) != 0 {
		t.Fatalf("got %q", got)
	}
}

type f struct {
	line int
	key  string
}

func assign(fs ...f) []fingerprint.Fingerprinted[f] {
	return fingerprint.Assign(fs,
		func(x f) fingerprint.Key {
			return fingerprint.Key{Tool: "opengrep", RuleID: "r", FilePath: "a.py", ContentKey: x.key}
		},
		func(x f) int { return x.line })
}

func fps(items []fingerprint.Fingerprinted[f]) []string {
	var out []string
	for _, i := range items {
		out = append(out, i.Fingerprint)
	}
	slices.Sort(out)
	return out
}

func TestFingerprintStableWhenCodeShifts(t *testing.T) {
	before := fps(assign(f{10, "k"}, f{20, "k"}))
	after := fps(assign(f{13, "k"}, f{23, "k"}))
	if !slices.Equal(before, after) || len(slices.Compact(before)) != 2 {
		t.Fatalf("before=%v after=%v", before, after)
	}
}

func TestFingerprintKOrderedByLine(t *testing.T) {
	byLine := map[int]string{}
	for _, x := range assign(f{30, "k"}, f{5, "k"}) {
		byLine[x.Finding.line] = x.Fingerprint
	}
	if byLine[5] != fingerprint.Fingerprint("opengrep", "r", "a.py", "k", 0) ||
		byLine[30] != fingerprint.Fingerprint("opengrep", "r", "a.py", "k", 1) {
		t.Fatal(byLine)
	}
}

func TestSecretKeyIsHMAC(t *testing.T) {
	a := fingerprint.SecretContentKey("AKIA123", []byte("org-key-1"))
	if a == fingerprint.SecretContentKey("AKIA123", []byte("org-key-2")) || strings.Contains(a, "AKIA") {
		t.Fatal(a)
	}
}

func TestGitleaksSeverity(t *testing.T) {
	for rule, want := range map[string]severity.Severity{
		"private-key": severity.Critical, "aws-access-token": severity.Critical, "github-pat": severity.Critical,
		"gitlab-pat": severity.Critical, "gcp-api-key": severity.Critical,
		"slack-bot-token": severity.High, "generic-api-key": severity.High,
	} {
		if got := severity.Gitleaks(rule); got != want {
			t.Errorf("%s: %s", rule, got)
		}
	}
}

func ptr(v float64) *float64 { return &v }

func TestOpengrepSeverity(t *testing.T) {
	for _, c := range []struct {
		level string
		ss    *float64
		want  severity.Severity
	}{
		{"warning", ptr(9.1), severity.Critical},
		{"error", nil, severity.High},
		{"warning", ptr(5.0), severity.Medium},
		{"note", nil, severity.Low},
		{"", nil, severity.Medium},
	} {
		if got := severity.Opengrep(c.level, c.ss); got != c.want {
			t.Errorf("%q: %s", c.level, got)
		}
	}
}

func TestTrivyAndCheckovSeverity(t *testing.T) {
	if severity.Trivy("CRITICAL") != severity.Critical || severity.Trivy("UNKNOWN") != severity.Medium {
		t.Fatal("trivy")
	}
	if severity.Checkov("CKV_AWS_20", map[string]severity.Severity{"CKV_AWS_20": severity.High}) != severity.High ||
		severity.Checkov("CKV_X", nil) != severity.Medium {
		t.Fatal("checkov")
	}
}

type triple struct {
	src, dst issuestate.Status
	actor    issuestate.Actor
}

func allowed() map[triple]bool {
	m := map[triple]bool{}
	for _, t := range []triple{
		{issuestate.Open, issuestate.Assigned, issuestate.ProjectOwner},
		{issuestate.Open, issuestate.Assigned, issuestate.SecurityLead},
		{issuestate.Open, issuestate.Assigned, issuestate.System},
		{issuestate.Assigned, issuestate.Open, issuestate.ProjectOwner},
		{issuestate.Assigned, issuestate.Open, issuestate.SecurityLead},
		{issuestate.Assigned, issuestate.InProgress, issuestate.Assignee},
		{issuestate.InProgress, issuestate.Fixed, issuestate.Assignee},
		{issuestate.Fixed, issuestate.Verified, issuestate.System},
		{issuestate.Fixed, issuestate.Verified, issuestate.SecurityLead},
		{issuestate.Fixed, issuestate.Reopened, issuestate.System},
		{issuestate.Verified, issuestate.Reopened, issuestate.System},
		{issuestate.Reopened, issuestate.InProgress, issuestate.Assignee},
		{issuestate.Reopened, issuestate.Assigned, issuestate.ProjectOwner},
		{issuestate.Reopened, issuestate.Assigned, issuestate.SecurityLead},
		{issuestate.RiskAccepted, issuestate.Reopened, issuestate.System},
		{issuestate.FalsePositive, issuestate.Open, issuestate.SecurityLead},
	} {
		m[t] = true
	}
	for _, src := range issuestate.Active {
		m[triple{src, issuestate.Fixed, issuestate.System}] = true
		m[triple{src, issuestate.FalsePositive, issuestate.SecurityLead}] = true
		m[triple{src, issuestate.RiskAccepted, issuestate.SecurityLead}] = true
	}
	return m
}

func TestStateMachineExhaustive(t *testing.T) {
	ok := allowed()
	for _, src := range issuestate.AllStatuses {
		for _, dst := range issuestate.AllStatuses {
			for _, actor := range issuestate.AllActors {
				_, err := issuestate.Check(src, dst, actor)
				if ok[triple{src, dst, actor}] {
					if err != nil {
						t.Errorf("%s→%s by %s should be allowed: %v", src, dst, actor, err)
					}
				} else if !errors.Is(err, issuestate.ErrInvalidTransition) && !errors.Is(err, issuestate.ErrForbidden) {
					t.Errorf("%s→%s by %s should be refused, got %v", src, dst, actor, err)
				}
			}
		}
	}
}

func TestExceptionTransitionsRequireApproval(t *testing.T) {
	r, _ := issuestate.Check(issuestate.Open, issuestate.RiskAccepted, issuestate.SecurityLead)
	if !r.RequiresApprovedException {
		t.Fatal("risk accepted without approval")
	}
	r, _ = issuestate.Check(issuestate.FalsePositive, issuestate.Open, issuestate.SecurityLead)
	if !r.RequiresReason {
		t.Fatal("reopen FP without reason")
	}
}

func TestOrgAdminSeparatedFromRiskAcceptance(t *testing.T) {
	if rbac.Can(rbac.DecideException, rbac.OrgAdmin, "", false) || rbac.Can(rbac.RunScan, rbac.OrgAdmin, "", false) {
		t.Fatal("org admin too powerful")
	}
	if !rbac.Can(rbac.ManageUsers, rbac.OrgAdmin, "", false) {
		t.Fatal("org admin can't manage users")
	}
}

func TestOnlySecurityLeadDecidesExceptions(t *testing.T) {
	if !slices.Equal(rbac.Matrix[rbac.DecideException], []rbac.Role{rbac.SecurityLead}) {
		t.Fatal(rbac.Matrix[rbac.DecideException])
	}
	if rbac.Can(rbac.DecideException, rbac.Member, rbac.Owner, false) {
		t.Fatal("project owner decides exceptions")
	}
}

func TestDeveloperUpdatesOnlyOwnIssues(t *testing.T) {
	if !rbac.Can(rbac.UpdateIssue, rbac.Member, rbac.Developer, true) ||
		rbac.Can(rbac.UpdateIssue, rbac.Member, rbac.Developer, false) ||
		!rbac.Can(rbac.UpdateIssue, rbac.Member, rbac.Owner, false) {
		t.Fatal("developer issue scope")
	}
}

func TestViewerIsReadOnly(t *testing.T) {
	for _, p := range rbac.AllPerms {
		if p == rbac.ViewResults || p == rbac.ViewDashboard {
			continue
		}
		if rbac.Can(p, rbac.Member, rbac.Viewer, true) {
			t.Errorf("viewer has %s", p)
		}
	}
}

func TestNonMemberSeesNothing(t *testing.T) {
	for _, p := range rbac.AllPerms {
		if rbac.Can(p, rbac.Member, "", true) {
			t.Errorf("non-member has %s", p)
		}
	}
}

func TestMatrixCoversEveryPerm(t *testing.T) {
	for _, p := range rbac.AllPerms {
		if _, ok := rbac.Matrix[p]; !ok {
			t.Errorf("%s missing from matrix", p)
		}
	}
	if len(rbac.Matrix) != len(rbac.AllPerms) {
		t.Fatal("matrix has perms not in AllPerms")
	}
}
