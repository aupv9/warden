package api

import (
	"bytes"
	"encoding/json"
	"errors"
	"log/slog"
	"net/http"
	"net/http/httptest"
	"regexp"
	"strings"
	"sync"
	"testing"
	"time"

	cgconfig "github.com/aupv9/common-go/config"
	"github.com/aupv9/common-go/health"
	"github.com/aupv9/common-go/logger"
	"github.com/aupv9/common-go/transport/httpserver"
	"github.com/gin-gonic/gin"
	"github.com/golang-jwt/jwt/v5"
	"github.com/google/uuid"
	"go.uber.org/fx"

	"github.com/aupv9/warden/backend/internal/domain/rbac"
	"github.com/aupv9/warden/backend/internal/service"
)

// callTok calls the API with a raw API token.
func (e *env) callTok(method, path, tok string, body any) resp {
	e.t.Helper()
	var raw []byte
	switch b := body.(type) {
	case nil:
	case string:
		raw = []byte(b)
	default:
		raw, _ = json.Marshal(b)
	}
	r := httptest.NewRequest(method, path, bytes.NewReader(raw))
	r.Header.Set("Authorization", "Bearer "+tok)
	r.Header.Set("Content-Type", "application/json")
	w := httptest.NewRecorder()
	e.h.ServeHTTP(w, r)
	out := resp{code: w.Code, header: w.Header(), body: w.Body.String()}
	if w.Body.Len() > 0 {
		if err := json.Unmarshal(w.Body.Bytes(), &out); err != nil {
			e.t.Fatalf("%s %s: %v: %s", method, path, err, w.Body)
		}
	}
	return out
}

func (e *env) doTok(method, path, tok string, body any) resp {
	e.t.Helper()
	return e.callTok(method, "/api/v1/orgs/"+e.org.String()+path, tok, body)
}

// newToken creates a token in project p as email and returns (id, secret).
func (e *env) newToken(email string, p uuid.UUID, scopes ...string) (string, string) {
	e.t.Helper()
	r := e.do("POST", "/projects/"+p.String()+"/tokens", email, map[string]any{"name": "CI", "scopes": scopes, "expires_in_days": 30})
	e.expect(r, 201, "")
	return r.obj()["token"].(map[string]any)["id"].(string), r.obj()["secret"].(string)
}

func scanBodyTok() map[string]any {
	return map[string]any{"file_name": "src.zip", "file_size": 1234, "sha256": strings.Repeat("ab", 32)}
}

func TestTokenManagement(t *testing.T) {
	e := newEnv(t)
	base := "/projects/" + e.web.String() + "/tokens"
	good := map[string]any{"name": " GitHub Actions ", "scopes": []string{"scan:write", "issues:read"}, "expires_in_days": 90}
	e.expect(e.do("POST", base, dev, good), 403, "FORBIDDEN")      // no manage_project_members
	e.expect(e.do("POST", base, admin, good), 403, "FORBIDDEN")    // can't run scans, so the token would be dead
	e.expect(e.do("POST", base, outsider, good), 404, "NOT_FOUND") // can't see the project
	e.expect(e.do("GET", base, dev, nil), 403, "FORBIDDEN")
	for _, bad := range []any{
		map[string]any{"name": "", "scopes": []string{"scan:write"}, "expires_in_days": 1},
		map[string]any{"name": strings.Repeat("n", 81), "scopes": []string{"scan:write"}, "expires_in_days": 1},
		map[string]any{"name": "bad\x1bname", "scopes": []string{"scan:write"}, "expires_in_days": 1},
		map[string]any{"name": "x", "scopes": []string{}, "expires_in_days": 1},
		map[string]any{"name": "x", "scopes": []string{"admin"}, "expires_in_days": 1},
		map[string]any{"name": "x", "scopes": []string{"scan:write", "scan:write"}, "expires_in_days": 1},
		map[string]any{"name": "x", "scopes": []string{"scan:write"}, "expires_in_days": 0},
		map[string]any{"name": "x", "scopes": []string{"scan:write"}, "expires_in_days": 366},
		map[string]any{"name": "x", "scopes": []string{"scan:write"}},
		`{"name":"x","scopes":["scan:write"],"expires_in_days":1,"secret":"mine"}`,
	} {
		e.expect(e.do("POST", base, owner, bad), 422, "VALIDATION_FAILED")
	}

	r := e.do("POST", base, owner, good)
	e.expect(r, 201, "")
	secret := r.obj()["secret"].(string)
	tok := r.obj()["token"].(map[string]any)
	if !regexpToken.MatchString(secret) || tok["name"] != "GitHub Actions" || tok["prefix"] != secret[4:12] ||
		tok["last_used_at"] != nil || tok["revoked_at"] != nil || tok["created_by"].(map[string]any)["email"] != owner ||
		!strings.HasPrefix(tok["expires_at"].(string), "2027-01-24") {
		t.Fatal(r.body)
	}
	// Only a hash is stored.
	row, _, _ := e.f.TokenRow(uuid.MustParse(tok["id"].(string)))
	if strings.Contains(row.Hash, secret[13:]) || len(row.Hash) != 64 || row.ProjectID != e.web || row.CreatedBy != e.u[owner] {
		t.Fatalf("%+v", row)
	}
	// Two tokens never share a secret or prefix.
	_, secret2 := e.newToken(lead, e.web, "issues:read")
	if secret2 == secret || secret2[4:12] == secret[4:12] {
		t.Fatal("token reuse")
	}

	r = e.do("GET", base, lead, nil)
	e.expect(r, 200, "")
	if len(r.items()) != 2 || strings.Contains(r.body, secret) || strings.Contains(r.body, secret2) ||
		r.items()[0].(map[string]any)["created_by"].(map[string]any)["email"] != lead {
		t.Fatal(r.body)
	}

	id := tok["id"].(string)
	e.expect(e.do("DELETE", base+"/"+id, dev, nil), 403, "FORBIDDEN")
	e.expect(e.do("DELETE", "/projects/"+e.api.String()+"/tokens/"+id, lead, nil), 404, "NOT_FOUND") // wrong project
	e.expect(e.do("DELETE", base+"/"+uuid.NewString(), owner, nil), 404, "NOT_FOUND")
	e.expect(e.do("DELETE", base+"/"+id, owner, nil), 204, "")
	e.expect(e.do("DELETE", base+"/"+id, owner, nil), 204, "") // idempotent
	r = e.do("GET", base, owner, nil)
	if r.items()[1].(map[string]any)["revoked_at"] == nil {
		t.Fatal(r.body)
	}

	var created, revoked int
	for _, a := range e.f.AuditLog() {
		raw, _ := json.Marshal(a.Data)
		if strings.Contains(string(raw), secret[13:]) || strings.Contains(string(raw), secret2[13:]) {
			t.Fatalf("secret in audit log: %s", raw)
		}
		switch a.Action {
		case "token.created":
			created++
			if a.Data["prefix"] == nil || a.Data["name"] == nil || a.Data["scopes"] == nil {
				t.Fatalf("%+v", a)
			}
		case "token.revoked":
			revoked++
		}
	}
	if created != 2 || revoked != 1 {
		t.Fatal(created, revoked)
	}

	e.f.Fail["Tokens"] = errors.New("db")
	e.expect(e.do("GET", base, owner, nil), 500, "INTERNAL")
	delete(e.f.Fail, "Tokens")
	e.f.Fail["InsertToken"] = errors.New("db")
	e.expect(e.do("POST", base, owner, good), 500, "INTERNAL")
	delete(e.f.Fail, "InsertToken")
	e.f.Fail["RevokeToken"] = errors.New("db")
	tid, _ := e.newToken(owner, e.web, "scan:write")
	e.expect(e.do("DELETE", base+"/"+tid, owner, nil), 500, "INTERNAL")
}

func TestTokenRunsAScan(t *testing.T) {
	e := newEnv(t)
	tid, tok := e.newToken(owner, e.web, "scan:write")
	r := e.doTok("POST", "/projects/"+e.web.String()+"/scans", tok, scanBodyTok())
	e.expect(r, 201, "")
	sc := r.obj()["scan"].(map[string]any)
	vt, _ := sc["via_token"].(map[string]any)
	if vt == nil || vt["id"] != tid || vt["name"] != "CI" || sc["created_by"].(map[string]any)["email"] != owner {
		t.Fatal(r.body)
	}
	scanID := sc["id"].(string)
	e.objects.sizes["scans/"+e.org.String()+"/"+scanID+".zip"] = 1234
	e.expect(e.doTok("POST", "/scans/"+scanID+"/start", tok, nil), 200, "")
	r = e.doTok("GET", "/scans/"+scanID, tok, nil)
	if r.code != 200 || r.obj()["status"] != "queued" || r.obj()["via_token"] == nil {
		t.Fatal(r.body)
	}
	r = e.doTok("GET", "/scans/"+scanID+"/gate", tok, nil)
	if r.code != 200 || r.obj()["pass"] != false || r.obj()["finished"] != false {
		t.Fatal(r.body)
	}
	e.expect(e.doTok("POST", "/scans/"+scanID+"/cancel", tok, nil), 200, "")
	// Scans created in the UI have no via_token.
	if r := e.do("POST", "/projects/"+e.web.String()+"/scans", dev, scanBodyTok()); r.obj()["scan"].(map[string]any)["via_token"] != nil {
		t.Fatal(r.body)
	}
	// Every write done with the token says so in the audit log, as its creator.
	n := 0
	for _, a := range e.f.AuditLog() {
		if strings.HasPrefix(a.Action, "scan.") && a.Data["via_token"] == tid {
			n++
			if *a.ActorID != e.u[owner] {
				t.Fatalf("%+v", a)
			}
		}
	}
	if n != 3 {
		t.Fatal(n)
	}
	_, last, _ := e.f.TokenRow(uuid.MustParse(tid))
	if last == nil {
		t.Fatal("last_used_at not set")
	}
}

func TestTokenScopesAndBinding(t *testing.T) {
	e := newEnv(t)
	_, scanTok := e.newToken(owner, e.web, "scan:write")
	_, issueTok := e.newToken(lead, e.web, "issues:read")
	webIssue := e.f.AddIssue(e.web, "high", "open", nil)
	apiIssue := e.f.AddIssue(e.api, "high", "open", nil)
	apiScan := e.f.AddScan(e.api, e.u[lead], "completed", 10)
	webScan := e.f.AddScan(e.web, e.u[owner], "completed", 10)

	// Default deny: anything outside the allow-list is TOKEN_SCOPE, for both tokens.
	for _, tok := range []string{scanTok, issueTok} {
		for _, c := range [][2]string{
			{"GET", "/api/v1/me"},
			{"GET", "/api/v1/orgs/" + e.org.String()},
			{"GET", "/api/v1/orgs/" + e.org.String() + "/projects"},
			{"GET", "/api/v1/orgs/" + e.org.String() + "/projects/" + e.web.String() + "/scans"},
			{"GET", "/api/v1/orgs/" + e.org.String() + "/projects/" + e.web.String() + "/tokens"},
			{"POST", "/api/v1/orgs/" + e.org.String() + "/projects/" + e.web.String() + "/tokens"},
			{"GET", "/api/v1/orgs/" + e.org.String() + "/members"},
			{"GET", "/api/v1/orgs/" + e.org.String() + "/audit-log"},
			{"POST", "/api/v1/orgs/" + e.org.String() + "/issues/" + webIssue.String() + "/transitions"},
			{"GET", "/api/v1/orgs/" + e.org.String() + "/issues/" + webIssue.String() + "/comments"},
		} {
			e.expect(e.callTok(c[0], c[1], tok, nil), 403, "TOKEN_SCOPE")
		}
	}
	// Each scope reaches only its own routes.
	e.expect(e.doTok("GET", "/issues", scanTok, nil), 403, "TOKEN_SCOPE")
	e.expect(e.doTok("GET", "/issues/"+webIssue.String(), scanTok, nil), 403, "TOKEN_SCOPE")
	e.expect(e.doTok("POST", "/projects/"+e.web.String()+"/scans", issueTok, scanBodyTok()), 403, "TOKEN_SCOPE")
	e.expect(e.doTok("GET", "/scans/"+webScan.String(), issueTok, nil), 403, "TOKEN_SCOPE")

	// issues:read: its project only, even though the lead who created it sees every project.
	r := e.doTok("GET", "/issues", issueTok, nil)
	if r.code != 200 || len(r.items()) != 1 || r.items()[0].(map[string]any)["id"] != webIssue.String() {
		t.Fatal(r.body)
	}
	e.expect(e.doTok("GET", "/issues?project_id="+e.web.String(), issueTok, nil), 200, "")
	e.expect(e.doTok("GET", "/issues?project_id="+e.api.String(), issueTok, nil), 404, "NOT_FOUND")
	e.expect(e.doTok("GET", "/issues/"+webIssue.String(), issueTok, nil), 200, "")
	e.expect(e.doTok("GET", "/issues/"+apiIssue.String(), issueTok, nil), 404, "NOT_FOUND")

	// scan:write: another project's scans don't exist for it.
	e.expect(e.doTok("POST", "/projects/"+e.api.String()+"/scans", scanTok, scanBodyTok()), 404, "NOT_FOUND")
	for _, p := range []string{"", "/gate"} {
		e.expect(e.doTok("GET", "/scans/"+apiScan.String()+p, scanTok, nil), 404, "NOT_FOUND")
	}
	e.expect(e.doTok("POST", "/scans/"+apiScan.String()+"/cancel", scanTok, nil), 404, "NOT_FOUND")

	// Another org: 404, whatever the route.
	other := e.f.AddOrg("Other")
	e.f.AddMember(other, e.u[owner], rbac.SecurityLead)
	otherProject := e.f.AddProject(other, "OTH")
	e.expect(e.callTok("POST", "/api/v1/orgs/"+other.String()+"/projects/"+otherProject.String()+"/scans", scanTok, scanBodyTok()), 404, "NOT_FOUND")
	e.expect(e.callTok("GET", "/api/v1/orgs/"+other.String()+"/scans/"+uuid.NewString(), scanTok, nil), 404, "NOT_FOUND")
}

func TestTokenUserMustStillRunScans(t *testing.T) {
	e := newEnv(t)
	_, tok := e.newToken(owner, e.web, "scan:write", "issues:read")
	sc := e.f.AddScan(e.web, e.u[owner], "completed", 10)
	e.expect(e.doTok("GET", "/scans/"+sc.String(), tok, nil), 200, "")
	// Demoted to viewer: can still see the project, but the token stops working.
	e.f.AddProjectMember(e.web, e.u[owner], rbac.Viewer)
	e.expect(e.doTok("GET", "/scans/"+sc.String(), tok, nil), 403, "FORBIDDEN")
	e.expect(e.doTok("GET", "/issues", tok, nil), 403, "FORBIDDEN")
	// Removed from the project: 404.
	e.expect(e.do("DELETE", "/projects/"+e.web.String()+"/members/"+e.u[owner].String(), lead, nil), 204, "")
	e.expect(e.doTok("GET", "/scans/"+sc.String(), tok, nil), 404, "NOT_FOUND")
}

var regexpToken = regexp.MustCompile(`^wdn_[a-z2-7]{8}_[a-z2-7]{52}$`)

func TestBadTokensGetTheGeneric401(t *testing.T) {
	e := newEnv(t)
	revokedID, revoked := e.newToken(owner, e.web, "scan:write")
	e.expect(e.do("DELETE", "/projects/"+e.web.String()+"/tokens/"+revokedID, owner, nil), 204, "")
	expiredID, expired := e.newToken(owner, e.web, "scan:write")
	e.f.SetTokenExpiry(uuid.MustParse(expiredID), e.f.Now)
	_, deactivated := e.newToken(dev2Owner(e), e.web, "scan:write")
	e.f.SetUserActive(e.u[dev2], false)
	_, removed := e.newToken(lead, e.web, "scan:write")
	e.expect(e.do("DELETE", "/members/"+e.u[lead].String(), admin, nil), 204, "")
	_, good := e.newToken(owner, e.web, "scan:write")
	wrongSecret := good[:13] + strings.Repeat("a", 52)
	if wrongSecret == good {
		wrongSecret = good[:13] + strings.Repeat("b", 52)
	}

	// The reference: a bad OIDC token.
	ref := e.callTok("GET", "/api/v1/orgs/"+e.org.String()+"/scans/"+uuid.NewString(), "not-a-jwt", nil)
	e.expect(ref, 401, "UNAUTHORIZED")
	path := "/scans/" + uuid.NewString()
	for name, tok := range map[string]string{
		"malformed": "wdn_short", "bad chars": "wdn_ABCDEFGH_" + strings.Repeat("A", 52), "unknown prefix": "wdn_zzzzzzzz_" + strings.Repeat("a", 52),
		"wrong secret": wrongSecret, "revoked": revoked, "expired": expired, "deactivated": deactivated, "removed from org": removed,
	} {
		r := e.doTok("GET", path, tok, nil)
		if r.code != 401 || r.Error.Code != ref.Error.Code || r.Error.Message != ref.Error.Message || len(r.Error.Metadata) != 0 ||
			r.header.Get("WWW-Authenticate") != ref.header.Get("WWW-Authenticate") {
			t.Errorf("%s: %d %s", name, r.code, r.body)
		}
	}
	e.expect(e.doTok("GET", path, good, nil), 404, "NOT_FOUND")

	e.f.Fail["LookupToken"] = errors.New("db down")
	e.expect(e.doTok("GET", path, good, nil), 500, "INTERNAL")
	delete(e.f.Fail, "LookupToken")
	e.f.Fail["TouchToken"] = errors.New("db down")
	e.expect(e.doTok("GET", path, good, nil), 500, "INTERNAL")
	delete(e.f.Fail, "TouchToken")
	e.f.Fail["UserByID"] = errors.New("db down")
	e.expect(e.doTok("GET", path, good, nil), 500, "INTERNAL")
}

// dev2Owner makes dev2 an owner of WEB (so they may create tokens) and returns their email.
func dev2Owner(e *env) string {
	e.f.AddProjectMember(e.web, e.u[dev2], rbac.Owner)
	return dev2
}

func TestTokenRateLimit(t *testing.T) {
	e := newEnv(t)
	_, tok := e.newToken(owner, e.web, "scan:write")
	_, other := e.newToken(owner, e.web, "scan:write")
	path := "/scans/" + uuid.NewString()
	for i := range tokenRequestsPerMinute {
		if r := e.doTok("GET", path, tok, nil); r.code != 404 {
			t.Fatalf("request %d: %d", i, r.code)
		}
	}
	r := e.doTok("GET", path, tok, nil)
	e.expect(r, 429, "RATE_LIMITED")
	if ra := r.header.Get("Retry-After"); ra == "" || ra == "0" {
		t.Fatal(r.header)
	}
	// Per token: another token is unaffected, and so are OIDC sign-ins.
	e.expect(e.doTok("GET", path, other, nil), 404, "NOT_FOUND")
	e.expect(e.do("GET", path, owner, nil), 404, "NOT_FOUND")
}

func TestRateLimiterWindow(t *testing.T) {
	now := time.Date(2026, 10, 26, 12, 0, 0, 0, time.UTC)
	l := newRateLimiter(2, time.Minute)
	l.now = func() time.Time { return now }
	k := uuid.New()
	for range 2 {
		if ok, _ := l.allow(k); !ok {
			t.Fatal("limited too early")
		}
	}
	now = now.Add(20 * time.Second)
	if ok, wait := l.allow(k); ok || wait != 40*time.Second {
		t.Fatal(ok, wait)
	}
	now = now.Add(40 * time.Second) // the first two fall out of the window
	if ok, _ := l.allow(k); !ok {
		t.Fatal("still limited")
	}
	// Idle keys are swept once there are many.
	for range sweepAt {
		l.allow(uuid.New())
	}
	now = now.Add(2 * time.Minute)
	l.allow(uuid.New())
	if len(l.hits) != 1 {
		t.Fatal(len(l.hits))
	}
	// Concurrent use is safe (run with -race).
	var wg sync.WaitGroup
	for range 8 {
		wg.Go(func() { l.allow(k) })
	}
	wg.Wait()
}

// serverWithLog is serverWith with a logger that writes to buf.
func serverWithLog(t *testing.T, svc *service.Service, buf *syncBuffer) http.Handler {
	t.Helper()
	var engine *gin.Engine
	log := slog.New(slog.NewJSONHandler(buf, &slog.HandlerOptions{Level: slog.LevelDebug}))
	app := fx.New(
		fx.NopLogger,
		fx.Supply(cgconfig.DefaultAppConfig(), log),
		fx.Provide(func() *logger.LevelControl { _, l := logger.NewWithControl(logger.Config{Level: "debug"}); return l }),
		health.Module,
		httpserver.Module(ServerOptions()...),
		fx.Invoke(func(e *gin.Engine) { Register(e, verifier(), svc) }),
		fx.Populate(&engine),
	)
	if err := app.Err(); err != nil {
		t.Fatal(err)
	}
	return engine
}

type syncBuffer struct {
	mu sync.Mutex
	b  bytes.Buffer
}

func (s *syncBuffer) Write(p []byte) (int, error) {
	s.mu.Lock()
	defer s.mu.Unlock()
	return s.b.Write(p)
}

func (s *syncBuffer) String() string {
	s.mu.Lock()
	defer s.mu.Unlock()
	return s.b.String()
}

func TestTokenIsNeverLogged(t *testing.T) {
	e := newEnv(t)
	_, tok := e.newToken(owner, e.web, "scan:write")
	var buf syncBuffer
	h := serverWithLog(t, service.New(e.f, e.objects, service.Config{UploadMaxBytes: 10 << 20}, slog.New(slog.NewJSONHandler(&buf, nil))), &buf)
	bad := tok[:13] + strings.Repeat("q", 52)
	for _, c := range []struct{ path, tok string }{
		{"/api/v1/orgs/" + e.org.String() + "/scans/" + uuid.NewString(), tok},          // 404
		{"/api/v1/orgs/" + e.org.String() + "/scans/" + uuid.NewString() + "?x=1", bad}, // 401
		{"/api/v1/me", tok}, // 403 TOKEN_SCOPE
	} {
		r := httptest.NewRequest("GET", c.path, nil)
		r.Header.Set("Authorization", "Bearer "+c.tok)
		h.ServeHTTP(httptest.NewRecorder(), r)
	}
	logs := buf.String()
	if !strings.Contains(logs, `"http request"`) || !strings.Contains(logs, "api token rejected") || !strings.Contains(logs, tok[4:12]) {
		t.Fatalf("expected request and rejection logs: %s", logs)
	}
	if strings.Contains(logs, tok[13:]) || strings.Contains(logs, bad[13:]) {
		t.Fatalf("token secret in logs: %s", logs)
	}
}

// A panic after authentication dumps the request into the log; the
// Authorization header is gone by then.
func TestPanicDumpHasNoCredential(t *testing.T) {
	e := newEnv(t)
	_, tok := e.newToken(owner, e.web, "scan:write")
	var buf syncBuffer
	srv, err := httpserver.New(slog.New(slog.NewJSONHandler(&buf, nil)), ServerOptions()...)
	if err != nil {
		t.Fatal(err)
	}
	svc := service.New(e.f, e.objects, service.Config{}, nil)
	jwtTok := token(t, nil)
	srv.Engine().POST(Prefix+"/orgs/:org_id/projects/:project_id/scans", authenticate(verifier(), svc, newRateLimiter(10, time.Minute)),
		func(*gin.Context) { panic("boom") })
	for _, cred := range []string{tok, jwtTok} {
		r := httptest.NewRequest("POST", Prefix+"/orgs/"+e.org.String()+"/projects/"+e.web.String()+"/scans", nil)
		r.Header.Set("Authorization", "Bearer "+cred)
		w := httptest.NewRecorder()
		srv.Engine().ServeHTTP(w, r)
		if w.Code != 500 {
			t.Fatal(w.Code, w.Body)
		}
	}
	logs := buf.String()
	if !strings.Contains(logs, "boom") || strings.Contains(logs, tok[13:]) || strings.Contains(logs, jwtTok[len(jwtTok)-20:]) {
		t.Fatalf("%s", logs)
	}
}

func TestMFAEnforcement(t *testing.T) {
	e := newEnv(t, func(c *service.Config) { c.RequireMFARoles = []rbac.Role{rbac.OrgAdmin, rbac.SecurityLead} })
	noMFA := jwt.MapClaims{"amr": []string{"pwd"}}
	r := e.call("GET", "/api/v1/orgs/"+e.org.String(), lead, nil, noMFA)
	e.expect(r, 403, "MFA_REQUIRED")
	if r.Error.Message != "Your role requires two-factor sign-in." {
		t.Fatal(r.body)
	}
	e.expect(e.call("GET", "/api/v1/orgs/"+e.org.String()+"/issues", admin, nil, noMFA), 403, "MFA_REQUIRED")
	e.expect(e.call("GET", "/api/v1/orgs/"+e.org.String(), lead, nil, nil), 200, "")  // amr has otp
	e.expect(e.call("GET", "/api/v1/orgs/"+e.org.String(), dev, nil, noMFA), 200, "") // members aren't listed
	// Non-members still get 404, not a hint that the org exists.
	e.expect(e.call("GET", "/api/v1/orgs/"+e.org.String(), stranger, nil, noMFA), 404, "NOT_FOUND")

	// /me says where the caller is blocked, so the UI can explain up front.
	r = e.call("GET", "/api/v1/me", lead, nil, noMFA)
	if orgs := r.obj()["mfa_required_orgs"].([]any); len(orgs) != 1 || orgs[0] != e.org.String() {
		t.Fatal(r.body)
	}
	for _, c := range []struct {
		email string
		over  jwt.MapClaims
	}{{lead, nil}, {dev, noMFA}} {
		r = e.call("GET", "/api/v1/me", c.email, nil, c.over)
		if orgs := r.obj()["mfa_required_orgs"].([]any); len(orgs) != 0 {
			t.Fatal(r.body)
		}
	}

	// API tokens are exempt: the lead created this one with a second factor.
	_, tok := e.newToken(lead, e.web, "scan:write")
	sc := e.f.AddScan(e.web, e.u[lead], "completed", 10)
	e.expect(e.doTok("GET", "/scans/"+sc.String(), tok, nil), 200, "")
}

func TestGate(t *testing.T) {
	e := newEnv(t)
	sc := e.f.AddScan(e.web, e.u[dev], "completed", 10)
	older := e.f.AddScan(e.web, e.u[dev], "completed", 10)
	seen := func(sev, status string) uuid.UUID {
		id := e.f.AddIssue(e.web, sev, status, nil)
		e.f.AddOccurrence(id, sc)
		return id
	}
	crit := seen("critical", "open")
	seen("high", "in_progress")
	seen("medium", "reopened")
	seen("low", "assigned")
	seen("info", "open")
	seen("critical", "false_positive") // never blocks, not counted
	seen("critical", "risk_accepted")
	seen("high", "fixed")
	notSeen := e.f.AddIssue(e.web, "critical", "open", nil) // not in this scan
	e.f.AddOccurrence(notSeen, older)

	path := "/scans/" + sc.String() + "/gate"
	r := e.do("GET", path, viewer, nil)
	e.expect(r, 200, "")
	g := r.obj()
	counts := g["counts"].(map[string]any)
	if g["pass"] != false || g["finished"] != true || g["fail_on"] != "high" || g["status"] != "completed" ||
		counts["critical"] != 1.0 || counts["high"] != 1.0 || counts["medium"] != 1.0 || counts["low"] != 1.0 || counts["info"] != 1.0 {
		t.Fatal(r.body)
	}
	blocking := g["blocking"].([]any)
	if len(blocking) != 2 || blocking[0].(map[string]any)["id"] != crit.String() || blocking[1].(map[string]any)["severity"] != "high" {
		t.Fatal(r.body)
	}
	for failOn, n := range map[string]int{"critical": 1, "medium": 3, "low": 4} {
		r := e.do("GET", path+"?fail_on="+failOn, dev, nil)
		if len(r.obj()["blocking"].([]any)) != n || r.obj()["fail_on"] != failOn {
			t.Fatalf("%s: %s", failOn, r.body)
		}
	}
	for _, bad := range []string{"info", "HIGH", "x"} {
		e.expect(e.do("GET", path+"?fail_on="+bad, dev, nil), 422, "VALIDATION_FAILED")
	}
	e.expect(e.do("GET", path, outsider, nil), 404, "NOT_FOUND")
	e.expect(e.do("GET", "/scans/"+uuid.NewString()+"/gate", lead, nil), 404, "NOT_FOUND")

	// Clean scans pass once finished; partial counts as finished; failed and cancelled never pass.
	for status, pass := range map[string]bool{"completed": true, "partial": true, "failed": false, "cancelled": false, "running": false, "queued": false} {
		clean := e.f.AddScan(e.web, e.u[dev], status, 10)
		r := e.do("GET", "/scans/"+clean.String()+"/gate", dev, nil)
		if r.code != 200 || r.obj()["pass"] != pass || len(r.obj()["blocking"].([]any)) != 0 {
			t.Fatalf("%s: %s", status, r.body)
		}
	}
	e.f.Fail["ScanIssueCounts"] = errors.New("db")
	e.expect(e.do("GET", path, dev, nil), 500, "INTERNAL")
	delete(e.f.Fail, "ScanIssueCounts")
	e.f.Fail["ScanIssues"] = errors.New("db")
	e.expect(e.do("GET", path, dev, nil), 500, "INTERNAL")
}
