package api

import (
	"testing"

	"github.com/golang-jwt/jwt/v5"

	"github.com/aupv9/warden/backend/internal/domain/rbac"
	"github.com/aupv9/warden/backend/internal/service"
)

func TestSignInSettingsAPI(t *testing.T) {
	e := newEnv(t, func(c *service.Config) {
		c.RequireMFARoles = []rbac.Role{rbac.SecurityLead}
		c.SignIn = service.SignInConfig{Issuer: "https://idp.example.com", Audience: "warden-api", Algorithms: []string{"RS256"}}
	})
	r := e.do("GET", "/sign-in", lead, nil)
	e.expect(r, 200, "")
	if p := r.obj()["provider"].(map[string]any); p["issuer"] != "https://idp.example.com" || p["keys_url"] != nil {
		t.Fatal(r.body)
	}
	if k := r.obj()["keys"].(map[string]any); k["status"] != "not_loaded" || k["fetched_at"] != nil {
		t.Fatal(r.body)
	}
	e.expect(e.do("GET", "/sign-in", dev, nil), 403, "FORBIDDEN")
	e.expect(e.do("PUT", "/sign-in-policy", lead, map[string]any{"mfa_roles": []string{}, "allowed_email_domains": []string{}}), 403, "FORBIDDEN")

	body := map[string]any{"mfa_roles": []string{"member"}, "allowed_email_domains": []string{"acme.test"}}
	r = e.do("PUT", "/sign-in-policy", admin, body)
	e.expect(r, 200, "")
	if eff := r.obj()["mfa"].(map[string]any)["effective_roles"].([]any); len(eff) != 2 || eff[0] != "security_lead" || eff[1] != "member" {
		t.Fatal(r.body)
	}
	e.expect(e.do("PUT", "/sign-in-policy", admin, map[string]any{"mfa_roles": []string{}, "allowed_email_domains": []string{}, "extra": 1}), 422, "VALIDATION_FAILED")
	r = e.do("PUT", "/sign-in-policy", admin, map[string]any{"mfa_roles": []string{}, "allowed_email_domains": []string{"*.acme.test"}})
	e.expect(r, 422, "VALIDATION_FAILED")
	if r.Error.Metadata["fields"].(map[string]any)["allowed_email_domains[0]"] == nil {
		t.Fatal(r.body)
	}

	// The org now requires a second factor for members too.
	noMFA := jwt.MapClaims{"amr": []string{"pwd"}}
	e.expect(e.call("GET", "/api/v1/orgs/"+e.org.String()+"/issues", dev, nil, noMFA), 403, "MFA_REQUIRED")
	e.expect(e.call("GET", "/api/v1/orgs/"+e.org.String()+"/issues", dev, nil, nil), 200, "")
	if orgs := e.call("GET", "/api/v1/me", dev, nil, noMFA).obj()["mfa_required_orgs"].([]any); len(orgs) != 1 {
		t.Fatal(orgs)
	}
	// An admin can't make it mandatory for their own role without a second factor.
	r = e.call("PUT", "/api/v1/orgs/"+e.org.String()+"/sign-in-policy", admin,
		map[string]any{"mfa_roles": []string{"org_admin"}, "allowed_email_domains": []string{}}, noMFA)
	e.expect(r, 409, "MFA_NOT_ENABLED")

	// Adding a member from another domain is refused.
	e.f.AddUser("eve@evil.test")
	r = e.do("POST", "/members", admin, map[string]any{"email": "eve@evil.test", "role": "member"})
	e.expect(r, 422, "VALIDATION_FAILED")
	if r.Error.Metadata["fields"].(map[string]any)["email"] != "must be an address at one of: acme.test" {
		t.Fatal(r.body)
	}
}

// API tokens can't read or change the sign-in settings: their scopes don't
// cover these routes.
func TestSignInSettingsNotForTokens(t *testing.T) {
	e := newEnv(t)
	_, tok := e.newToken(lead, e.web, "scan:write", "issues:read")
	e.expect(e.doTok("GET", "/sign-in", tok, nil), 403, "TOKEN_SCOPE")
	e.expect(e.doTok("PUT", "/sign-in-policy", tok, map[string]any{"mfa_roles": []string{}, "allowed_email_domains": []string{}}), 403, "TOKEN_SCOPE")
}
