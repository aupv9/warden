package service_test

import (
	"context"
	"errors"
	"net/http"
	"slices"
	"strings"
	"testing"
	"time"

	apperrors "github.com/aupv9/common-go/errors"
	"github.com/google/uuid"

	"github.com/aupv9/warden/backend/internal/domain/rbac"
	"github.com/aupv9/warden/backend/internal/service"
)

func signInSetup(role rbac.Role, cfg service.Config) setup {
	x := newSetup(role)
	x.s = service.New(x.f, nil, cfg, nil)
	x.s.SetClock(func() time.Time { return x.f.Now })
	return x
}

func code(err error) string {
	if ae, ok := apperrors.As(err); ok {
		return ae.Code
	}
	return ""
}

func fields(err error) map[string]string {
	ae, ok := apperrors.As(err)
	if !ok {
		return nil
	}
	m, _ := ae.Metadata["fields"].(map[string]any)
	out := map[string]string{}
	for k, v := range m {
		out[k], _ = v.(string)
	}
	return out
}

func TestSignInSettingsShowsProviderKeysAndPolicy(t *testing.T) {
	fetched := time.Date(2026, 10, 27, 7, 0, 0, 0, time.FixedZone("ICT", 7*3600))
	st := service.KeyStatus{}
	cfg := service.Config{
		RequireMFARoles: []rbac.Role{rbac.SecurityLead, rbac.OrgAdmin},
		SignIn: service.SignInConfig{
			Issuer: "https://idp.example.com/realms/acme", Audience: "warden-api", Algorithms: []string{"RS256"},
			ConsoleURL: "https://idp.example.com/admin/", MFAAMR: []string{"otp"},
			KeyStatus: func() service.KeyStatus { return st },
		},
	}
	x := signInSetup(rbac.SecurityLead, cfg)
	x.f.SetSignInPolicy(x.org, service.SignInPolicy{MFARoles: []rbac.Role{rbac.Member}, AllowedEmailDomains: []string{"acme.test"}})

	out, err := x.s.SignInSettings(context.Background(), x.actor())
	if err != nil {
		t.Fatal(err)
	}
	if out.Provider.Issuer != cfg.SignIn.Issuer || out.Provider.KeysURL != nil || out.Provider.ConsoleURL == nil ||
		*out.Provider.ConsoleURL != "https://idp.example.com/admin/" || out.Keys.Status != "not_loaded" || out.MFA.ACR == nil {
		t.Fatalf("%+v", out)
	}
	if !slices.Equal(out.MFA.InstanceRoles, []rbac.Role{rbac.OrgAdmin, rbac.SecurityLead}) ||
		!slices.Equal(out.MFA.EffectiveRoles, []rbac.Role{rbac.OrgAdmin, rbac.SecurityLead, rbac.Member}) ||
		!slices.Equal(out.Policy.AllowedEmailDomains, []string{"acme.test"}) {
		t.Fatalf("%+v", out.MFA)
	}

	st = service.KeyStatus{Count: 2, FetchedAt: fetched}
	if out, _ = x.s.SignInSettings(context.Background(), x.actor()); out.Keys.Status != "ok" || out.Keys.Count != 2 ||
		out.Keys.FetchedAt.Location() != time.UTC || out.Keys.Error != nil {
		t.Fatalf("%+v", out.Keys)
	}
	st.Err = "unreachable"
	if out, _ = x.s.SignInSettings(context.Background(), x.actor()); out.Keys.Status != "error" || *out.Keys.Error != "unreachable" {
		t.Fatalf("%+v", out.Keys)
	}

	// Members don't see it.
	dev := x.f.AddUser("dev@acme.test")
	x.f.AddMember(x.org, dev, rbac.Member)
	if _, err := x.s.SignInSettings(context.Background(), &service.Actor{UserID: dev, OrgID: x.org}); status(err) != http.StatusForbidden {
		t.Fatal(err)
	}
}

func TestSetSignInPolicy(t *testing.T) {
	cfg := service.Config{RequireMFARoles: []rbac.Role{rbac.SecurityLead}}
	x := signInSetup(rbac.OrgAdmin, cfg)
	a := x.actor()
	in := service.SignInPolicyInput{MFARoles: []string{"member"}, AllowedEmailDomains: []string{" ACME.test ", "corp.acme.test"}}
	out, err := x.s.SetSignInPolicy(context.Background(), a, in)
	if err != nil {
		t.Fatal(err)
	}
	if !slices.Equal(out.Policy.AllowedEmailDomains, []string{"acme.test", "corp.acme.test"}) ||
		!slices.Equal(out.MFA.EffectiveRoles, []rbac.Role{rbac.SecurityLead, rbac.Member}) {
		t.Fatalf("%+v", out)
	}
	log := x.f.AuditLog()
	last := log[len(log)-1]
	if last.Action != "org.sign_in_policy_changed" || last.ActorID == nil || *last.ActorID != x.u {
		t.Fatalf("%+v", last)
	}
	// Same policy again: no change, no audit entry.
	if _, err := x.s.SetSignInPolicy(context.Background(), a, in); err != nil || len(x.f.AuditLog()) != len(log) {
		t.Fatal(err, len(x.f.AuditLog()))
	}

	// Only org admins change it; security leads see it.
	lead := x.f.AddUser("sec@acme.test")
	x.f.AddMember(x.org, lead, rbac.SecurityLead)
	la := &service.Actor{UserID: lead, OrgID: x.org, MFA: true}
	if _, err := x.s.SetSignInPolicy(context.Background(), la, in); status(err) != http.StatusForbidden {
		t.Fatal(err)
	}
	if _, err := x.s.SignInSettings(context.Background(), la); err != nil {
		t.Fatal(err)
	}
}

// An admin who signed in without a second factor can't make it mandatory for
// their own role (they would lock themselves out); with one, they can.
func TestSetSignInPolicyRefusesSelfLockout(t *testing.T) {
	x := signInSetup(rbac.OrgAdmin, service.Config{})
	a := x.actor()
	in := service.SignInPolicyInput{MFARoles: []string{"org_admin"}, AllowedEmailDomains: []string{}}
	if _, err := x.s.SetSignInPolicy(context.Background(), a, in); code(err) != "MFA_NOT_ENABLED" || status(err) != http.StatusConflict {
		t.Fatal(err)
	}
	if p, _ := x.f.OrgSignInPolicy(context.Background(), x.org); len(p.MFARoles) != 0 {
		t.Fatal("policy changed", p)
	}
	// Other roles are fine without a second factor.
	if _, err := x.s.SetSignInPolicy(context.Background(), a, service.SignInPolicyInput{MFARoles: []string{"member"}, AllowedEmailDomains: []string{}}); err != nil {
		t.Fatal(err)
	}
	a.MFA = true
	if _, err := x.s.SetSignInPolicy(context.Background(), a, in); err != nil {
		t.Fatal(err)
	}
}

func TestSetSignInPolicyValidation(t *testing.T) {
	x := signInSetup(rbac.OrgAdmin, service.Config{})
	a := x.actor()
	a.MFA = true
	many := make([]string, 21)
	for i := range many {
		many[i] = "d" + strings.Repeat("x", i) + ".test"
	}
	long := strings.Repeat("a", 64) + ".test"
	for _, tc := range []struct {
		name  string
		in    service.SignInPolicyInput
		field string
	}{
		{"missing roles", service.SignInPolicyInput{AllowedEmailDomains: []string{}}, "mfa_roles"},
		{"missing domains", service.SignInPolicyInput{MFARoles: []string{}}, "allowed_email_domains"},
		{"unknown role", service.SignInPolicyInput{MFARoles: []string{"owner"}, AllowedEmailDomains: []string{}}, "mfa_roles"},
		{"duplicate role", service.SignInPolicyInput{MFARoles: []string{"member", "member"}, AllowedEmailDomains: []string{}}, "mfa_roles"},
		{"too many domains", service.SignInPolicyInput{MFARoles: []string{}, AllowedEmailDomains: many}, "allowed_email_domains"},
		{"wildcard", service.SignInPolicyInput{MFARoles: []string{}, AllowedEmailDomains: []string{"*.acme.test"}}, "allowed_email_domains[0]"},
		{"single label", service.SignInPolicyInput{MFARoles: []string{}, AllowedEmailDomains: []string{"acme"}}, "allowed_email_domains[0]"},
		{"ip address", service.SignInPolicyInput{MFARoles: []string{}, AllowedEmailDomains: []string{"10.0.0.1"}}, "allowed_email_domains[0]"},
		{"address not domain", service.SignInPolicyInput{MFARoles: []string{}, AllowedEmailDomains: []string{"a@acme.test"}}, "allowed_email_domains[0]"},
		{"leading hyphen", service.SignInPolicyInput{MFARoles: []string{}, AllowedEmailDomains: []string{"-acme.test"}}, "allowed_email_domains[0]"},
		{"empty label", service.SignInPolicyInput{MFARoles: []string{}, AllowedEmailDomains: []string{"acme..test"}}, "allowed_email_domains[0]"},
		{"trailing dot", service.SignInPolicyInput{MFARoles: []string{}, AllowedEmailDomains: []string{"acme.test."}}, "allowed_email_domains[0]"},
		{"label too long", service.SignInPolicyInput{MFARoles: []string{}, AllowedEmailDomains: []string{long}}, "allowed_email_domains[0]"},
		{"unicode", service.SignInPolicyInput{MFARoles: []string{}, AllowedEmailDomains: []string{"acmé.test"}}, "allowed_email_domains[0]"},
		{"duplicate after lowercasing", service.SignInPolicyInput{MFARoles: []string{}, AllowedEmailDomains: []string{"acme.test", "ACME.test"}}, "allowed_email_domains[1]"},
	} {
		t.Run(tc.name, func(t *testing.T) {
			_, err := x.s.SetSignInPolicy(context.Background(), a, tc.in)
			if status(err) != http.StatusUnprocessableEntity || fields(err)[tc.field] == "" {
				t.Fatalf("%v %v", err, fields(err))
			}
		})
	}
	if len(x.f.AuditLog()) != 0 {
		t.Fatal("audited a rejected change")
	}
}

func TestOrgPolicyAddsMFARoles(t *testing.T) {
	x := signInSetup(rbac.Member, service.Config{RequireMFARoles: []rbac.Role{rbac.OrgAdmin}})
	if _, required, err := x.s.OrgAccess(context.Background(), x.u, x.org); err != nil || required {
		t.Fatal(required, err)
	}
	x.f.SetSignInPolicy(x.org, service.SignInPolicy{MFARoles: []rbac.Role{rbac.Member}})
	if role, required, err := x.s.OrgAccess(context.Background(), x.u, x.org); err != nil || !required || role != rbac.Member {
		t.Fatal(role, required, err)
	}
	other := x.f.AddOrg("Other")
	x.f.AddMember(other, x.u, rbac.Member)
	me, err := x.s.Me(context.Background(), x.f.User(x.u), service.Identity{Sub: "s"})
	if err != nil || !slices.Equal(me.MFARequiredOrgs, []uuid.UUID{x.org}) {
		t.Fatal(me.MFARequiredOrgs, err)
	}
	if me, _ = x.s.Me(context.Background(), x.f.User(x.u), service.Identity{Sub: "s", MFA: true}); len(me.MFARequiredOrgs) != 0 {
		t.Fatal(me.MFARequiredOrgs)
	}
}

func TestAddMemberHonoursAllowedDomains(t *testing.T) {
	x := signInSetup(rbac.OrgAdmin, service.Config{})
	x.f.SetSignInPolicy(x.org, service.SignInPolicy{AllowedEmailDomains: []string{"acme.test"}})
	x.f.AddUser("Dev@ACME.test")
	x.f.AddUser("eve@evil.test")
	x.f.AddUser("sub@corp.acme.test")
	x.f.AddUser("x@acme.test.evil.test")
	if _, err := x.s.AddMember(context.Background(), x.actor(), service.AddMemberInput{Email: "Dev@ACME.test", Role: "member"}); err != nil {
		t.Fatal(err)
	}
	for _, email := range []string{"eve@evil.test", "sub@corp.acme.test", "x@acme.test.evil.test"} {
		_, err := x.s.AddMember(context.Background(), x.actor(), service.AddMemberInput{Email: email, Role: "member"})
		if status(err) != http.StatusUnprocessableEntity || !strings.Contains(fields(err)["email"], "acme.test") {
			t.Fatalf("%s: %v", email, err)
		}
	}
}

// Moving to another identity provider: the person's subject changes. Without a
// relink window the new identity is refused; with one, a verified email takes
// over the account once.
func TestRelinkOnNextSignIn(t *testing.T) {
	x := signInSetup(rbac.OrgAdmin, service.Config{})
	other := x.f.AddOrg("Other")
	x.f.AddMember(other, x.u, rbac.Member)
	verified, unverified := true, false
	newID := service.Identity{Sub: "new-sub", Email: "lead@acme.test", EmailVerified: &verified}

	if _, err := x.s.Authenticate(context.Background(), newID); status(err) != http.StatusForbidden {
		t.Fatal("no window:", err)
	}
	u := x.f.User(x.u)
	until := x.f.Now.Add(time.Hour)
	u.RelinkUntil = &until
	x.f.SetUser(u)

	for name, id := range map[string]service.Identity{
		"email_verified absent": {Sub: "new-sub", Email: "lead@acme.test"},
		"email_verified false":  {Sub: "new-sub", Email: "lead@acme.test", EmailVerified: &unverified},
	} {
		if _, err := x.s.Authenticate(context.Background(), id); err == nil {
			t.Fatal(name, "accepted")
		}
	}
	got, err := x.s.Authenticate(context.Background(), newID)
	if err != nil || got.ID != x.u || got.Sub != "new-sub" || x.f.User(x.u).RelinkUntil != nil {
		t.Fatal(got, err)
	}
	relinked := 0
	for _, r := range x.f.AuditLog() {
		if r.Action == "user.relinked" && r.TargetID == x.u.String() && r.Data["via"] == "sign-in" {
			relinked++
		}
	}
	if relinked != 2 { // one entry per org
		t.Fatal(relinked)
	}
	// The window is closed: a second new identity is refused.
	if _, err := x.s.Authenticate(context.Background(), service.Identity{Sub: "third", Email: "lead@acme.test", EmailVerified: &verified}); status(err) != http.StatusForbidden {
		t.Fatal(err)
	}
	// The old subject no longer signs in to this account.
	if got, err := x.s.Authenticate(context.Background(), service.Identity{Sub: "sub-lead@acme.test", Email: "lead@acme.test"}); err == nil && got.ID == x.u {
		t.Fatal("old subject still works")
	}
}

func TestRelinkWindowExpiresAndSkipsInactive(t *testing.T) {
	x := signInSetup(rbac.OrgAdmin, service.Config{})
	verified := true
	id := service.Identity{Sub: "new-sub", Email: "lead@acme.test", EmailVerified: &verified}
	u := x.f.User(x.u)
	past := x.f.Now.Add(-time.Second)
	u.RelinkUntil = &past
	x.f.SetUser(u)
	if _, err := x.s.Authenticate(context.Background(), id); status(err) != http.StatusForbidden {
		t.Fatal("expired window:", err)
	}
	future := x.f.Now.Add(time.Hour)
	u.RelinkUntil, u.IsActive = &future, false
	x.f.SetUser(u)
	if _, err := x.s.Authenticate(context.Background(), id); status(err) != http.StatusForbidden {
		t.Fatal("inactive:", err)
	}
	if x.f.User(x.u).Sub != "sub-lead@acme.test" {
		t.Fatal("subject changed")
	}
	// A storage failure while relinking isn't swallowed.
	u.IsActive = true
	x.f.SetUser(u)
	x.f.Fail["RelinkUser"] = errors.New("db")
	if _, err := x.s.Authenticate(context.Background(), id); err == nil || status(err) != 0 {
		t.Fatal(err)
	}
}
