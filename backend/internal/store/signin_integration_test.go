//go:build integration

package store_test

import (
	"errors"
	"fmt"
	"slices"
	"strings"
	"testing"
	"time"

	"github.com/google/uuid"

	"github.com/aupv9/warden/backend/internal/domain/rbac"
	"github.com/aupv9/warden/backend/internal/service"
	"github.com/aupv9/warden/backend/internal/store"
)

func TestSignInPolicyRoundTrip(t *testing.T) {
	w := newWorld(t)
	f := w.org("SIP")
	admin := w.actor("SIPadmin", f.id)
	admin.MFA = true
	out, err := w.svc.SetSignInPolicy(ctx, admin, service.SignInPolicyInput{
		MFARoles: []string{"member", "security_lead"}, AllowedEmailDomains: []string{"test.example", "Corp.Test.Example"},
	})
	if err != nil {
		t.Fatal(err)
	}
	got := must(w.svc.SignInSettings(ctx, w.actor("SIPlead", f.id)))
	if !slices.Equal(got.Policy.MFARoles, []rbac.Role{rbac.SecurityLead, rbac.Member}) ||
		!slices.Equal(got.Policy.AllowedEmailDomains, []string{"test.example", "corp.test.example"}) ||
		!slices.Equal(out.Policy.AllowedEmailDomains, got.Policy.AllowedEmailDomains) {
		t.Fatalf("%+v", got.Policy)
	}

	// /me and the org access check read the org's roles (enum array as text).
	dev := w.users["SIPdev"]
	if _, required, err := w.svc.OrgAccess(ctx, dev.ID, f.id); err != nil || !required {
		t.Fatal(required, err)
	}
	me := must(w.svc.Me(ctx, dev, service.Identity{Sub: dev.Sub}))
	if !slices.Contains(me.MFARequiredOrgs, f.id) {
		t.Fatal(me.MFARequiredOrgs)
	}

	// Members from other domains are refused, by the API and by warden-admin.
	eve := w.user("eve") // eve-…@test.example is allowed; make an outsider
	outsider := fmt.Sprintf("out-%s@elsewhere.example", uuid.NewString()[:8])
	must(w.svc.Authenticate(ctx, service.Identity{Sub: "sub-" + outsider, Email: outsider}))
	if _, err := w.svc.AddMember(ctx, w.actor("SIPadmin", f.id), service.AddMemberInput{Email: outsider, Role: "member"}); code(err) != "VALIDATION_FAILED" {
		t.Fatal(err)
	}
	if err := store.AddOrgMember(ctx, w.db, f.id, outsider, rbac.Member); err == nil || !strings.Contains(err.Error(), "only allows") {
		t.Fatal(err)
	}
	if err := store.AddOrgMember(ctx, w.db, f.id, eve.Email, rbac.Member); err != nil {
		t.Fatal(err)
	}
	if err := store.AddOrgMember(ctx, w.db, f.id, eve.Email, rbac.Member); err == nil {
		t.Fatal("added twice")
	}
	if err := store.AddOrgMember(ctx, w.db, f.id, "nobody@test.example", rbac.Member); !errors.Is(err, store.ErrAdminNotFound) {
		t.Fatal(err)
	}
	if err := store.AddOrgMember(ctx, w.db, uuid.New(), eve.Email, rbac.Member); err == nil {
		t.Fatal("unknown org")
	}

	// The 20-domain cap holds in the database too.
	err = w.db.InOrg(ctx, f.id, func(r service.Repo) error {
		many := make([]string, 21)
		for i := range many {
			many[i] = fmt.Sprintf("d%d.example", i)
		}
		return r.SetOrgSignInPolicy(ctx, f.id, service.SignInPolicy{AllowedEmailDomains: many})
	})
	if err == nil {
		t.Fatal("21 domains stored")
	}

	assertAudit(t, w, f.id, "org.sign_in_policy_changed", "member.added")
	if n := must(store.VerifyOrgAudit(ctx, w.db, f.id)); n == 0 {
		t.Fatal("empty chain")
	}
}

// Moving to another identity provider, both ways warden-admin offers.
func TestRelink(t *testing.T) {
	w := newWorld(t)
	f := w.org("RLK")
	other := must(store.CreateOrg(ctx, w.db, "Other RLK", w.users["RLKadmin"].Email))
	dev := w.users["RLKdev"]
	must(w.svc.AddMember(ctx, w.actor("RLKadmin", other), service.AddMemberInput{Email: dev.Email, Role: "member"}))
	verified := true

	// 1. A known subject, set now.
	if err := store.RelinkUser(ctx, w.db, dev.Email, "okta|dev"); err != nil {
		t.Fatal(err)
	}
	if u, err := w.svc.Authenticate(ctx, service.Identity{Sub: "okta|dev", Email: dev.Email}); err != nil || u.ID != dev.ID {
		t.Fatal(u, err)
	}
	if _, err := w.svc.Authenticate(ctx, service.Identity{Sub: dev.Sub, Email: dev.Email}); code(err) != "FORBIDDEN" {
		t.Fatal("old subject:", err)
	}
	lead := w.users["RLKlead"]
	for _, tc := range []struct{ email, sub string }{
		{lead.Email, "okta|dev"}, // another account's subject
		{dev.Email, "okta|dev"},  // already this account's
		{dev.Email, " "},         // empty
		{dev.Email, "a\x00b"},    // control character
		{"nobody@test.example", "x"},
	} {
		if err := store.RelinkUser(ctx, w.db, tc.email, tc.sub); err == nil {
			t.Fatalf("%+v accepted", tc)
		}
	}

	// 2. The next verified sign-in, within the window.
	if _, err := store.AllowRelink(ctx, w.db, lead.Email, 8*24*time.Hour); err == nil {
		t.Fatal("window over 7 days")
	}
	until, err := store.AllowRelink(ctx, w.db, lead.Email, time.Hour)
	if err != nil || time.Until(until) > time.Hour || time.Until(until) < 59*time.Minute {
		t.Fatal(until, err)
	}
	if _, err := w.svc.Authenticate(ctx, service.Identity{Sub: "entra|lead", Email: lead.Email}); code(err) != "FORBIDDEN" {
		t.Fatal("unverified email took over:", err)
	}
	u, err := w.svc.Authenticate(ctx, service.Identity{Sub: "entra|lead", Email: lead.Email, EmailVerified: &verified})
	if err != nil || u.ID != lead.ID {
		t.Fatal(u, err)
	}
	if _, err := w.svc.Authenticate(ctx, service.Identity{Sub: "entra|someone-else", Email: lead.Email, EmailVerified: &verified}); code(err) != "FORBIDDEN" {
		t.Fatal("window stayed open:", err)
	}
	var open bool
	if err := w.pool.QueryRow(ctx, `SELECT relink_until IS NOT NULL FROM app_user WHERE id = $1`, lead.ID).Scan(&open); err != nil || open {
		t.Fatal(open, err)
	}

	// An expired window doesn't open the account.
	dev2 := w.users["RLKdev2"]
	must(store.AllowRelink(ctx, w.db, dev2.Email, time.Hour))
	if _, err := w.pool.Exec(ctx, `UPDATE app_user SET relink_until = now() - interval '1 second' WHERE id = $1`, dev2.ID); err != nil {
		t.Fatal(err)
	}
	if _, err := w.svc.Authenticate(ctx, service.Identity{Sub: "late", Email: dev2.Email, EmailVerified: &verified}); code(err) != "FORBIDDEN" {
		t.Fatal(err)
	}

	assertAudit(t, w, f.id, "user.relinked", "user.relink_allowed")
	assertAudit(t, w, other, "user.relinked")
	for _, org := range []uuid.UUID{f.id, other} {
		if _, err := store.VerifyOrgAudit(ctx, w.db, org); err != nil {
			t.Fatal(err)
		}
	}
}

func assertAudit(t *testing.T, w *world, org uuid.UUID, actions ...string) {
	t.Helper()
	for _, a := range actions {
		var n int
		err := w.pool.QueryRow(ctx, `SELECT count(*) FROM audit_log WHERE org_id = $1 AND action = $2`, org, a).Scan(&n)
		if err != nil || n == 0 {
			t.Fatalf("no %s in %s: %v", a, org, err)
		}
	}
}
