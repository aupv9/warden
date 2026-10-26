package api

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"

	"github.com/golang-jwt/jwt/v5"
	"github.com/google/uuid"

	"github.com/aupv9/warden/backend/internal/domain/rbac"
	"github.com/aupv9/warden/backend/internal/service"
	"github.com/aupv9/warden/backend/internal/service/servicetest"
)

type fakeObjects struct {
	sizes      map[string]int64
	presignErr error
	headErr    error
}

func (o *fakeObjects) PresignPut(_ context.Context, key string, size int64, sum string, _ time.Duration) (string, map[string]string, error) {
	if o.presignErr != nil {
		return "", nil, o.presignErr
	}
	return "https://s3.test/" + key, map[string]string{"Content-Length": fmt.Sprint(size), "x-amz-checksum-sha256": sum}, nil
}

func (o *fakeObjects) Head(_ context.Context, key string) (int64, error) {
	if o.headErr != nil {
		return 0, o.headErr
	}
	n, ok := o.sizes[key]
	if !ok {
		return 0, ErrObjectNotFound
	}
	return n, nil
}

type env struct {
	t       *testing.T
	f       *servicetest.Fake
	objects *fakeObjects
	h       http.Handler
	org     uuid.UUID
	web     uuid.UUID // project WEB
	api     uuid.UUID // project API (only the lead and admin see it)
	u       map[string]uuid.UUID
}

const (
	admin    = "admin@acme.test"
	lead     = "lead@acme.test"
	owner    = "owner@acme.test"
	dev      = "dev@acme.test"
	dev2     = "dev2@acme.test"
	viewer   = "viewer@acme.test"
	outsider = "outsider@acme.test" // org member without projects
	stranger = "stranger@other.test"
)

func newEnv(t *testing.T) *env {
	t.Helper()
	f := servicetest.New()
	objects := &fakeObjects{sizes: map[string]int64{}}
	svc := service.New(f, objects, service.Config{
		UploadMaxBytes: 10 << 20, RateLimitPerHour: 3,
		Limits: service.Limits{UploadMaxMB: 10, UnzipMaxMB: 100, UnzipMaxFiles: 1000, ScanTimeoutMinutes: 30, ScansPerHour: 3},
	}, nil)
	svc.SetClock(func() time.Time { return f.Now })
	e := &env{t: t, f: f, objects: objects, h: serverWith(t, nil, svc), u: map[string]uuid.UUID{}}
	e.org = f.AddOrg("Acme")
	e.web = f.AddProject(e.org, "WEB")
	e.api = f.AddProject(e.org, "API")
	roles := map[string]rbac.Role{admin: rbac.OrgAdmin, lead: rbac.SecurityLead, owner: rbac.Member, dev: rbac.Member,
		dev2: rbac.Member, viewer: rbac.Member, outsider: rbac.Member}
	for email, role := range roles {
		e.u[email] = f.AddUser(email)
		f.AddMember(e.org, e.u[email], role)
	}
	e.u[stranger] = f.AddUser(stranger)
	f.AddProjectMember(e.web, e.u[owner], rbac.Owner)
	f.AddProjectMember(e.web, e.u[dev], rbac.Developer)
	f.AddProjectMember(e.web, e.u[dev2], rbac.Developer)
	f.AddProjectMember(e.web, e.u[viewer], rbac.Viewer)
	return e
}

type resp struct {
	code   int
	header http.Header
	body   string
	Data   any `json:"data"`
	Error  *struct {
		Code     string         `json:"code"`
		Message  string         `json:"message"`
		Metadata map[string]any `json:"metadata"`
	} `json:"error"`
}

func (r resp) obj() map[string]any { m, _ := r.Data.(map[string]any); return m }

func (r resp) items() []any { l, _ := r.obj()["items"].([]any); return l }

func (r resp) code_() string {
	if r.Error == nil {
		return ""
	}
	return r.Error.Code
}

func (e *env) tokenFor(email string, over jwt.MapClaims) string {
	c := jwt.MapClaims{"sub": "sub-" + email, "email": email}
	for k, v := range over {
		c[k] = v
	}
	return token(e.t, c)
}

func (e *env) call(method, path, email string, body any, over jwt.MapClaims) resp {
	e.t.Helper()
	var rd *bytes.Reader
	switch b := body.(type) {
	case nil:
		rd = bytes.NewReader(nil)
	case string:
		rd = bytes.NewReader([]byte(b))
	default:
		raw, _ := json.Marshal(b)
		rd = bytes.NewReader(raw)
	}
	r := httptest.NewRequest(method, path, rd)
	r.Header.Set("Authorization", "Bearer "+e.tokenFor(email, over))
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

func (e *env) do(method, path, email string, body any) resp {
	e.t.Helper()
	return e.call(method, "/api/v1/orgs/"+e.org.String()+path, email, body, nil)
}

func (e *env) expect(r resp, code int, errCode string) {
	e.t.Helper()
	if r.code != code || r.code_() != errCode {
		e.t.Fatalf("want %d %q, got %d: %s", code, errCode, r.code, r.body)
	}
}

func TestMeProvisionsAndRefreshesUser(t *testing.T) {
	e := newEnv(t)
	r := e.call("GET", "/api/v1/me", "new@acme.test", nil, jwt.MapClaims{"name": "New Person", "amr": []string{"pwd"}})
	e.expect(r, 200, "")
	m := r.obj()
	if m["email"] != "new@acme.test" || m["name"] != "New Person" || m["mfa"] != false || len(m["orgs"].([]any)) != 0 {
		t.Fatal(r.body)
	}
	if l := m["limits"].(map[string]any); l["upload_max_mb"] != 10.0 || l["scans_per_hour"] != 3.0 {
		t.Fatal(r.body)
	}
	id := m["id"].(string)
	// The profile follows the token.
	r = e.call("GET", "/api/v1/me", "new@acme.test", nil, jwt.MapClaims{"email": "New2@acme.test", "name": "Renamed\x00"})
	e.expect(r, 200, "")
	u := e.f.User(uuid.MustParse(id))
	if u.Email != "New2@acme.test" || u.DisplayName != "Renamed" || u.MFA == nil || !*u.MFA {
		t.Fatalf("%+v", u)
	}
	// A member sees their orgs.
	r = e.call("GET", "/api/v1/me", lead, nil, nil)
	if orgs := r.obj()["orgs"].([]any); len(orgs) != 1 || orgs[0].(map[string]any)["role"] != "security_lead" {
		t.Fatal(r.body)
	}
}

func TestMeRejectsBadIdentities(t *testing.T) {
	e := newEnv(t)
	e.expect(e.call("GET", "/api/v1/me", "x@acme.test", nil, jwt.MapClaims{"email": ""}), 401, "UNAUTHORIZED")
	e.expect(e.call("GET", "/api/v1/me", "x@acme.test", nil, jwt.MapClaims{"email": "not an email"}), 401, "UNAUTHORIZED")
	e.expect(e.call("GET", "/api/v1/me", "x@acme.test", nil, jwt.MapClaims{"email_verified": false}), 401, "UNAUTHORIZED")
	// Another identity with an existing user's email is not linked to that account.
	e.expect(e.call("GET", "/api/v1/me", "y@acme.test", nil, jwt.MapClaims{"email": lead}), 403, "FORBIDDEN")
	// An email change onto another account's address is ignored, not an error.
	e.expect(e.call("GET", "/api/v1/me", dev, nil, jwt.MapClaims{"email": lead}), 200, "")
	if e.f.User(e.u[dev]).Email != dev {
		t.Fatal("email hijacked")
	}
}

func TestInactiveUserIsForbiddenEverywhere(t *testing.T) {
	e := newEnv(t)
	u := e.f.User(e.u[dev])
	u.IsActive = false
	e.f.SetUser(u)
	e.expect(e.call("GET", "/api/v1/me", dev, nil, nil), 403, "FORBIDDEN")
	e.expect(e.do("GET", "", dev, nil), 403, "FORBIDDEN")
	e.expect(e.do("GET", "/issues", dev, nil), 403, "FORBIDDEN")
}

func TestOrgMembershipIsRequired(t *testing.T) {
	e := newEnv(t)
	r := e.do("GET", "", owner, nil)
	e.expect(r, 200, "")
	if r.obj()["my_role"] != "member" || r.obj()["sla_days"].(map[string]any)["critical"] != 7.0 {
		t.Fatal(r.body)
	}
	for _, p := range []string{"", "/summary", "/projects", "/issues", "/members", "/projects/" + e.web.String()} {
		e.expect(e.do("GET", p, stranger, nil), 404, "NOT_FOUND")
	}
	e.expect(e.call("GET", "/api/v1/orgs/not-a-uuid", lead, nil, nil), 404, "NOT_FOUND")
	e.expect(e.call("GET", "/api/v1/orgs/"+uuid.NewString(), lead, nil, nil), 404, "NOT_FOUND")
}

func TestInternalErrorsAreGeneric(t *testing.T) {
	e := newEnv(t)
	e.f.Fail["Org"] = errors.New(`ERROR: relation "organization" permission denied for warden_app`)
	r := e.do("GET", "", lead, nil)
	e.expect(r, 500, "INTERNAL")
	if strings.Contains(r.body, "warden_app") || strings.Contains(r.body, "relation") {
		t.Fatal(r.body)
	}
	delete(e.f.Fail, "Org")
	e.f.Fail["UserBySub"] = errors.New("boom")
	e.expect(e.do("GET", "", lead, nil), 500, "INTERNAL")
}

func TestSummary(t *testing.T) {
	e := newEnv(t)
	past := e.f.Now.Add(-time.Hour)
	i := e.f.AddIssue(e.web, "critical", "open", nil)
	e.f.SetIssue(i, func(r *servicetest.IssueRow) { r.DueAt = &past })
	e.f.AddIssue(e.web, "low", "assigned", nil)
	e.f.AddIssue(e.web, "high", "verified", nil)
	e.f.AddIssue(e.api, "high", "open", nil)
	e.f.AddException(i, e.u[dev], "false_positive", nil)

	r := e.do("GET", "/summary", lead, nil)
	want := map[string]any{"open_issues": 3.0, "critical_high_open": 2.0, "past_sla": 1.0, "exceptions_pending": 1.0}
	for k, v := range want {
		if r.obj()[k] != v {
			t.Fatalf("%s: %s", k, r.body)
		}
	}
	r = e.do("GET", "/summary", dev, nil)
	if r.obj()["open_issues"] != 2.0 || r.obj()["exceptions_pending"] != 0.0 {
		t.Fatal(r.body)
	}
}

func TestMembers(t *testing.T) {
	e := newEnv(t)
	r := e.do("GET", "/members", dev, nil)
	e.expect(r, 200, "")
	if len(r.items()) != 7 {
		t.Fatal(r.body)
	}
	newcomer := e.f.AddUser("newcomer@acme.test")

	e.expect(e.do("POST", "/members", dev, map[string]any{"email": "newcomer@acme.test", "role": "member"}), 403, "FORBIDDEN")
	e.expect(e.do("POST", "/members", admin, map[string]any{"email": "ghost@acme.test", "role": "member"}), 404, "USER_NOT_FOUND")
	r = e.do("POST", "/members", admin, map[string]any{"email": "bad", "role": "king"})
	e.expect(r, 422, "VALIDATION_FAILED")
	if f := r.Error.Metadata["fields"].(map[string]any); f["email"] == nil || f["role"] == nil {
		t.Fatal(r.body)
	}
	e.expect(e.do("POST", "/members", admin, map[string]any{"email": "x@acme.test", "role": "member", "admin": true}), 422, "VALIDATION_FAILED")
	r = e.do("POST", "/members", admin, map[string]any{"email": "NEWCOMER@acme.test", "role": "member"})
	e.expect(r, 201, "")
	if r.obj()["user"].(map[string]any)["id"] != newcomer.String() || r.obj()["role"] != "member" {
		t.Fatal(r.body)
	}
	e.expect(e.do("POST", "/members", admin, map[string]any{"email": "newcomer@acme.test", "role": "member"}), 409, "CONFLICT")

	path := "/members/" + newcomer.String()
	e.expect(e.do("PATCH", path, lead, map[string]any{"role": "security_lead"}), 403, "FORBIDDEN")
	e.expect(e.do("PATCH", path, admin, map[string]any{"role": "boss"}), 422, "VALIDATION_FAILED")
	r = e.do("PATCH", path, admin, map[string]any{"role": "security_lead"})
	if r.code != 200 || r.obj()["role"] != "security_lead" {
		t.Fatal(r.body)
	}
	e.expect(e.do("PATCH", path, admin, map[string]any{"role": "security_lead"}), 200, "") // no-op
	e.expect(e.do("PATCH", "/members/"+uuid.NewString(), admin, map[string]any{"role": "member"}), 404, "NOT_FOUND")
	e.expect(e.do("PATCH", "/members/bad", admin, map[string]any{"role": "member"}), 404, "NOT_FOUND")

	// The last admin can't be demoted or removed.
	adminPath := "/members/" + e.u[admin].String()
	e.expect(e.do("PATCH", adminPath, admin, map[string]any{"role": "member"}), 409, "CONFLICT")
	e.expect(e.do("DELETE", adminPath, admin, nil), 409, "CONFLICT")
	e.expect(e.do("PATCH", path, admin, map[string]any{"role": "org_admin"}), 200, "")
	e.expect(e.do("PATCH", adminPath, admin, map[string]any{"role": "member"}), 200, "")

	// Removing a member also removes their project memberships.
	r = e.do("DELETE", "/members/"+e.u[dev].String(), "newcomer@acme.test", nil)
	if r.code != 204 {
		t.Fatal(r.body)
	}
	e.expect(e.do("DELETE", "/members/"+e.u[dev].String(), "newcomer@acme.test", nil), 404, "NOT_FOUND")
	e.expect(e.do("GET", "/projects/"+e.web.String(), dev, nil), 404, "NOT_FOUND")

	var actions []string
	for _, a := range e.f.AuditLog() {
		actions = append(actions, a.Action)
	}
	if strings.Join(actions, ",") != "member.added,member.role_changed,member.role_changed,member.role_changed,member.removed" {
		t.Fatal(actions)
	}
}

func TestProjects(t *testing.T) {
	e := newEnv(t)
	e.f.AddScan(e.web, e.u[dev], "completed", 10)
	e.f.AddIssue(e.web, "high", "open", nil)
	r := e.do("GET", "/projects", dev, nil)
	if len(r.items()) != 1 {
		t.Fatal(r.body)
	}
	p := r.items()[0].(map[string]any)
	if p["key"] != "WEB" || p["my_role"] != "developer" || p["last_scan"] == nil || p["open_by_severity"].(map[string]any)["high"] != 1.0 {
		t.Fatal(r.body)
	}
	if r := e.do("GET", "/projects", lead, nil); len(r.items()) != 2 || r.items()[0].(map[string]any)["my_role"] != nil {
		t.Fatal(r.body)
	}
	if r := e.do("GET", "/projects", outsider, nil); len(r.items()) != 0 {
		t.Fatal(r.body)
	}
	e.expect(e.do("GET", "/projects/"+e.api.String(), dev, nil), 404, "NOT_FOUND")
	e.expect(e.do("GET", "/projects/"+e.web.String(), dev, nil), 200, "")

	body := map[string]any{"key": "PAY", "name": " Payments ", "description": "card flows", "default_tools": []string{"gitleaks", "trivy"}}
	e.expect(e.do("POST", "/projects", owner, body), 403, "FORBIDDEN")
	r = e.do("POST", "/projects", lead, body)
	e.expect(r, 201, "")
	if r.obj()["name"] != "Payments" || len(r.obj()["default_tools"].([]any)) != 2 {
		t.Fatal(r.body)
	}
	e.expect(e.do("POST", "/projects", admin, body), 409, "CONFLICT")
	r = e.do("POST", "/projects", admin, map[string]any{"key": "p", "name": "", "description": strings.Repeat("x", 2001), "default_tools": []string{"nmap"}})
	e.expect(r, 422, "VALIDATION_FAILED")
	if len(r.Error.Metadata["fields"].(map[string]any)) != 4 {
		t.Fatal(r.body)
	}
	e.expect(e.do("POST", "/projects", admin, map[string]any{"key": "DUP", "name": "x", "default_tools": []string{"trivy", "trivy"}}), 422, "VALIDATION_FAILED")
	e.expect(e.do("POST", "/projects", admin, map[string]any{"key": "OK2", "name": "x"}), 201, "")
}

func TestProjectMembers(t *testing.T) {
	e := newEnv(t)
	base := "/projects/" + e.web.String() + "/members"
	r := e.do("GET", base, viewer, nil)
	if r.code != 200 || len(r.items()) != 4 {
		t.Fatal(r.body)
	}
	e.expect(e.do("GET", "/projects/"+e.api.String()+"/members", dev, nil), 404, "NOT_FOUND")

	target := base + "/" + e.u[outsider].String()
	e.expect(e.do("PUT", target, dev, map[string]any{"role": "viewer"}), 403, "FORBIDDEN")
	e.expect(e.do("PUT", target, owner, map[string]any{"role": "admin"}), 422, "VALIDATION_FAILED")
	e.expect(e.do("PUT", base+"/"+e.u[stranger].String(), owner, map[string]any{"role": "viewer"}), 422, "VALIDATION_FAILED")
	r = e.do("PUT", target, owner, map[string]any{"role": "developer"})
	if r.code != 200 || r.obj()["role"] != "developer" || r.obj()["user"].(map[string]any)["email"] != outsider {
		t.Fatal(r.body)
	}
	e.expect(e.do("DELETE", target, dev, nil), 403, "FORBIDDEN")
	if r := e.do("DELETE", target, lead, nil); r.code != 204 {
		t.Fatal(r.body)
	}
	e.expect(e.do("DELETE", target, lead, nil), 404, "NOT_FOUND")
	e.expect(e.do("DELETE", base+"/nope", lead, nil), 404, "NOT_FOUND")
}

func scanBody() map[string]any {
	return map[string]any{"file_name": "src.zip", "file_size": 1234, "sha256": strings.Repeat("AB", 32)}
}

func TestCreateAndStartScan(t *testing.T) {
	e := newEnv(t)
	base := "/projects/" + e.web.String() + "/scans"
	e.expect(e.do("POST", base, viewer, scanBody()), 403, "FORBIDDEN")
	e.expect(e.do("POST", "/projects/"+e.api.String()+"/scans", dev, scanBody()), 404, "NOT_FOUND")
	r := e.do("POST", base, dev, map[string]any{"file_name": "../x.exe", "file_size": 0, "sha256": "zz", "tools": []string{}})
	e.expect(r, 422, "VALIDATION_FAILED")
	if len(r.Error.Metadata["fields"].(map[string]any)) != 4 {
		t.Fatal(r.body)
	}
	e.expect(e.do("POST", base, dev, map[string]any{"file_name": "a.zip", "file_size": 11 << 20, "sha256": strings.Repeat("a", 64)}), 422, "VALIDATION_FAILED")
	e.expect(e.do("POST", base, dev, `{"file_name":"a.zip","file_size":"big"}`), 422, "VALIDATION_FAILED")

	r = e.do("POST", base, dev, scanBody())
	e.expect(r, 201, "")
	sc := r.obj()["scan"].(map[string]any)
	up := r.obj()["upload"].(map[string]any)
	scanID := sc["id"].(string)
	key := "scans/" + e.org.String() + "/" + scanID + ".zip"
	if sc["status"] != "pending_upload" || len(sc["tools"].([]any)) != 4 || up["method"] != "PUT" ||
		up["url"] != "https://s3.test/"+key || up["headers"].(map[string]any)["x-amz-checksum-sha256"] != strings.Repeat("ab", 32) {
		t.Fatal(r.body)
	}
	if _, ok := sc["tool_runs"]; ok {
		t.Fatal("tool_runs in create response")
	}

	start := "/scans/" + scanID + "/start"
	e.expect(e.do("POST", start, viewer, nil), 403, "FORBIDDEN")
	e.expect(e.do("POST", start, dev, nil), 422, "UPLOAD_MISMATCH")
	e.objects.sizes[key] = 999
	e.expect(e.do("POST", start, dev, nil), 422, "UPLOAD_MISMATCH")
	e.objects.headErr = errors.New("s3 down")
	e.expect(e.do("POST", start, dev, nil), 500, "INTERNAL")
	e.objects.headErr = nil
	e.objects.sizes[key] = 1234
	e.f.Fail["EnqueueScan"] = errors.New("river down")
	e.expect(e.do("POST", start, dev, nil), 500, "INTERNAL")
	if e.f.ScanRow(uuid.MustParse(scanID)).Status != "pending_upload" {
		t.Fatal("status changed without a job")
	}
	delete(e.f.Fail, "EnqueueScan")
	r = e.do("POST", start, dev, nil)
	if r.code != 200 || r.obj()["status"] != "queued" || r.obj()["queued_at"] == nil {
		t.Fatal(r.body)
	}
	jobs := e.f.Jobs()
	if len(jobs) != 1 || jobs[0].ScanID != scanID || jobs[0].ObjectKey != key || jobs[0].SHA256 != strings.Repeat("ab", 32) || len(jobs[0].Tools) != 4 {
		t.Fatalf("%+v", jobs)
	}
	// Idempotent.
	e.expect(e.do("POST", start, dev, nil), 200, "")
	if len(e.f.Jobs()) != 1 {
		t.Fatal("enqueued twice")
	}

	r = e.do("GET", "/scans/"+scanID, viewer, nil)
	if r.code != 200 || r.obj()["tool_runs"] == nil || r.obj()["created_by"].(map[string]any)["email"] != dev {
		t.Fatal(r.body)
	}
	e.expect(e.do("GET", "/scans/"+scanID, outsider, nil), 404, "NOT_FOUND")
	e.expect(e.do("GET", "/scans/"+uuid.NewString(), lead, nil), 404, "NOT_FOUND")
}

func TestStartFinishedScan(t *testing.T) {
	e := newEnv(t)
	done := e.f.AddScan(e.web, e.u[dev], "completed", 10)
	e.expect(e.do("POST", "/scans/"+done.String()+"/start", dev, nil), 409, "CONFLICT")
	e.expect(e.do("POST", "/scans/"+done.String()+"/cancel", dev, nil), 409, "CONFLICT")
	running := e.f.AddScan(e.web, e.u[dev], "running", 10)
	e.expect(e.do("POST", "/scans/"+running.String()+"/start", dev, nil), 200, "")
	e.expect(e.do("POST", "/scans/"+running.String()+"/cancel", viewer, nil), 403, "FORBIDDEN")
	r := e.do("POST", "/scans/"+running.String()+"/cancel", owner, nil)
	if r.code != 200 || r.obj()["status"] != "cancelled" || r.obj()["finished_at"] == nil {
		t.Fatal(r.body)
	}
	e.expect(e.do("POST", "/scans/"+running.String()+"/cancel", owner, nil), 409, "CONFLICT")
}

func TestScanRateLimitAndPresignFailure(t *testing.T) {
	e := newEnv(t)
	base := "/projects/" + e.web.String() + "/scans"
	e.objects.presignErr = errors.New("no credentials")
	e.expect(e.do("POST", base, dev, scanBody()), 500, "INTERNAL")
	if r := e.do("GET", base, dev, nil); len(r.items()) != 0 {
		t.Fatal("scan left behind after presign failure", r.body)
	}
	e.objects.presignErr = nil
	for range 3 {
		e.expect(e.do("POST", base, dev, scanBody()), 201, "")
	}
	r := e.do("POST", base, dev, scanBody())
	e.expect(r, 429, "RATE_LIMITED")
	if r.header.Get("Retry-After") == "" || r.header.Get("Retry-After") == "0" {
		t.Fatal(r.header)
	}
	// Per user.
	e.expect(e.do("POST", base, owner, scanBody()), 201, "")
}

func TestListScansPaginates(t *testing.T) {
	e := newEnv(t)
	for range 3 {
		e.f.AddScan(e.web, e.u[dev], "completed", 1)
	}
	base := "/projects/" + e.web.String() + "/scans"
	seen := map[string]bool{}
	cursor := ""
	for page := 0; ; page++ {
		path := base + "?limit=2"
		if cursor != "" {
			path += "&cursor=" + cursor
		}
		r := e.do("GET", path, viewer, nil)
		e.expect(r, 200, "")
		for _, it := range r.items() {
			seen[it.(map[string]any)["id"].(string)] = true
			if _, ok := it.(map[string]any)["tool_runs"]; ok {
				t.Fatal("tool_runs in list")
			}
		}
		next, _ := r.obj()["next_cursor"].(string)
		if next == "" {
			break
		}
		cursor = next
		if page > 3 {
			t.Fatal("no progress")
		}
	}
	if len(seen) != 3 {
		t.Fatal(seen)
	}
	e.expect(e.do("GET", base+"?limit=0", viewer, nil), 422, "VALIDATION_FAILED")
	e.expect(e.do("GET", base+"?limit=201", viewer, nil), 422, "VALIDATION_FAILED")
	e.expect(e.do("GET", base+"?cursor=***", viewer, nil), 422, "VALIDATION_FAILED")
	e.expect(e.do("GET", "/projects/"+e.api.String()+"/scans", viewer, nil), 404, "NOT_FOUND")
}

func TestIssueList(t *testing.T) {
	e := newEnv(t)
	devID := e.u[dev]
	a := e.f.AddIssue(e.web, "critical", "assigned", &devID)
	e.f.AddIssue(e.web, "low", "open", nil)
	e.f.AddIssue(e.web, "high", "verified", nil)
	e.f.AddIssue(e.api, "high", "open", nil)

	r := e.do("GET", "/issues", dev, nil)
	e.expect(r, 200, "")
	if len(r.items()) != 2 || r.obj()["counts_by_severity"].(map[string]any)["critical"] != 1.0 {
		t.Fatal(r.body)
	}
	if r := e.do("GET", "/issues", lead, nil); len(r.items()) != 3 {
		t.Fatal(r.body)
	}
	if r := e.do("GET", "/issues?status=active&status=verified", dev, nil); len(r.items()) != 3 {
		t.Fatal(r.body)
	}
	r = e.do("GET", "/issues?severity=critical", dev, nil)
	if len(r.items()) != 1 || r.obj()["counts_by_severity"].(map[string]any)["low"] != 1.0 {
		t.Fatal("counts must ignore the severity filter", r.body)
	}
	if r := e.do("GET", "/issues?assignee=me", dev, nil); len(r.items()) != 1 || r.items()[0].(map[string]any)["id"] != a.String() {
		t.Fatal(r.body)
	}
	if r := e.do("GET", "/issues?assignee=none", dev, nil); len(r.items()) != 1 {
		t.Fatal(r.body)
	}
	if r := e.do("GET", "/issues?assignee="+devID.String()+"&tool=opengrep&past_sla=false", lead, nil); len(r.items()) != 1 {
		t.Fatal(r.body)
	}
	if r := e.do("GET", "/issues?q=web-1", dev, nil); len(r.items()) != 1 || r.items()[0].(map[string]any)["key"] != "WEB-1" {
		t.Fatal(r.body)
	}
	if r := e.do("GET", "/issues?q=rule.low", dev, nil); len(r.items()) != 1 {
		t.Fatal(r.body)
	}
	if r := e.do("GET", "/issues?project_id="+e.api.String(), dev, nil); len(r.items()) != 0 {
		t.Fatal(r.body)
	}
	for _, sort := range []string{"due_at", "-severity", "-updated_at"} {
		r := e.do("GET", "/issues?limit=1&sort="+sort, lead, nil)
		next, _ := r.obj()["next_cursor"].(string)
		if len(r.items()) != 1 || next == "" {
			t.Fatal(sort, r.body)
		}
		r2 := e.do("GET", "/issues?limit=1&sort="+sort+"&cursor="+next, lead, nil)
		if len(r2.items()) != 1 || r2.items()[0].(map[string]any)["id"] == r.items()[0].(map[string]any)["id"] {
			t.Fatal(sort, r2.body)
		}
		if sort != "due_at" {
			e.expect(e.do("GET", "/issues?cursor="+next, lead, nil), 422, "VALIDATION_FAILED") // cursor of another sort
		}
	}
	r = e.do("GET", "/issues?status=nope&severity=bad&assignee=x&tool=nmap&past_sla=maybe&sort=x&project_id=1&limit=x&q="+strings.Repeat("a", 201), lead, nil)
	e.expect(r, 422, "VALIDATION_FAILED")
	if len(r.Error.Metadata["fields"].(map[string]any)) != 9 {
		t.Fatal(r.body)
	}
	e.expect(e.do("GET", "/issues?q=%00", lead, nil), 422, "VALIDATION_FAILED")
}

func TestIssueDetailAndTransitions(t *testing.T) {
	e := newEnv(t)
	devID := e.u[dev]
	iss := e.f.AddIssue(e.web, "high", "assigned", &devID)
	path := "/issues/" + iss.String()

	r := e.do("GET", path, dev, nil)
	e.expect(r, 200, "")
	m := r.obj()
	if m["version"] != 1.0 || fmt.Sprint(m["allowed_transitions"]) != "[in_progress]" || m["can_assign"] != false ||
		m["can_request_exception"] != true || m["pending_exception_id"] != nil || len(m["cwe"].([]any)) != 0 {
		t.Fatal(r.body)
	}
	if r := e.do("GET", path, owner, nil); fmt.Sprint(r.obj()["allowed_transitions"]) != "[open]" || r.obj()["can_assign"] != true {
		t.Fatal(r.body)
	}
	if r := e.do("GET", path, dev2, nil); fmt.Sprint(r.obj()["allowed_transitions"]) != "[]" {
		t.Fatal(r.body)
	}
	e.expect(e.do("GET", path, outsider, nil), 404, "NOT_FOUND")
	e.expect(e.do("GET", "/issues/"+uuid.NewString(), lead, nil), 404, "NOT_FOUND")

	tr := path + "/transitions"
	// Developers may only move issues assigned to them.
	e.expect(e.do("POST", tr, dev2, map[string]any{"to": "in_progress", "version": 1}), 403, "FORBIDDEN")
	e.expect(e.do("POST", tr, viewer, map[string]any{"to": "in_progress", "version": 1}), 403, "FORBIDDEN")
	e.expect(e.do("POST", tr, dev, map[string]any{"to": "in_progress", "version": 7}), 409, "VERSION_CONFLICT")
	e.expect(e.do("POST", tr, dev, map[string]any{"to": "verified", "version": 1}), 422, "INVALID_TRANSITION")
	e.expect(e.do("POST", tr, lead, map[string]any{"to": "false_positive", "version": 1}), 422, "INVALID_TRANSITION")
	e.expect(e.do("POST", tr, dev, map[string]any{"to": "done"}), 422, "VALIDATION_FAILED")
	e.expect(e.do("POST", tr, dev, map[string]any{"to": "in_progress", "version": 1, "assignee_id": devID.String()}), 422, "VALIDATION_FAILED")
	r = e.do("POST", tr, dev, map[string]any{"to": "in_progress", "version": 1, "reason": "starting"})
	if r.code != 200 || r.obj()["status"] != "in_progress" || r.obj()["version"] != 2.0 {
		t.Fatal(r.body)
	}
	r = e.do("POST", tr, dev, map[string]any{"to": "fixed", "version": 2})
	if r.code != 200 || r.obj()["status"] != "fixed" {
		t.Fatal(r.body)
	}
	if got := strings.Join(e.f.EventTypes(iss), ","); got != "status_changed,status_changed" {
		t.Fatal(got)
	}
	audit := e.f.AuditLog()
	if len(audit) != 2 || audit[1].Action != "issue.transitioned" || audit[1].Data["to"] != "fixed" || audit[0].Data["reason"] != "starting" {
		t.Fatalf("%+v", audit)
	}
}

func TestAssignTransitions(t *testing.T) {
	e := newEnv(t)
	devID := e.u[dev]
	iss := e.f.AddIssue(e.web, "high", "open", nil)
	tr := "/issues/" + iss.String() + "/transitions"
	e.expect(e.do("POST", tr, owner, map[string]any{"to": "assigned", "version": 1}), 422, "VALIDATION_FAILED")
	e.expect(e.do("POST", tr, owner, map[string]any{"to": "assigned", "version": 1, "assignee_id": "x"}), 422, "VALIDATION_FAILED")
	e.expect(e.do("POST", tr, owner, map[string]any{"to": "assigned", "version": 1, "assignee_id": e.u[outsider].String()}), 422, "VALIDATION_FAILED")
	e.expect(e.do("POST", tr, dev, map[string]any{"to": "assigned", "version": 1, "assignee_id": devID.String()}), 403, "FORBIDDEN")
	r := e.do("POST", tr, owner, map[string]any{"to": "assigned", "version": 1, "assignee_id": devID.String()})
	if r.code != 200 || r.obj()["assignee"].(map[string]any)["id"] != devID.String() {
		t.Fatal(r.body)
	}
	r = e.do("POST", tr, lead, map[string]any{"to": "open", "version": 2})
	if r.code != 200 || r.obj()["assignee"] != nil {
		t.Fatal(r.body)
	}
	if got := strings.Join(e.f.EventTypes(iss), ","); got != "status_changed,assigned,status_changed,assigned" {
		t.Fatal(got)
	}
	// Reopening a false positive needs a reason and the security lead.
	fp := e.f.AddIssue(e.web, "low", "false_positive", nil)
	tr = "/issues/" + fp.String() + "/transitions"
	e.expect(e.do("POST", tr, owner, map[string]any{"to": "open", "version": 1, "reason": "x"}), 403, "FORBIDDEN")
	e.expect(e.do("POST", tr, lead, map[string]any{"to": "open", "version": 1, "reason": "  "}), 422, "VALIDATION_FAILED")
	e.expect(e.do("POST", tr, lead, map[string]any{"to": "open", "version": 1, "reason": "not really a false positive"}), 200, "")
	// Org admins can see but not change issues.
	e.expect(e.do("POST", tr, admin, map[string]any{"to": "assigned", "version": 2, "assignee_id": devID.String()}), 403, "FORBIDDEN")
}

func TestBulkAssign(t *testing.T) {
	e := newEnv(t)
	devID, dev2ID := e.u[dev], e.u[dev2]
	open := e.f.AddIssue(e.web, "high", "open", nil)
	assigned := e.f.AddIssue(e.web, "high", "assigned", &dev2ID)
	same := e.f.AddIssue(e.web, "high", "in_progress", &devID)
	fixed := e.f.AddIssue(e.web, "high", "fixed", nil)
	other := e.f.AddIssue(e.api, "high", "open", nil) // dev isn't in API
	ids := []string{open.String(), assigned.String(), same.String(), fixed.String(), other.String(), uuid.NewString(), open.String()}

	e.expect(e.do("POST", "/issues/assign", dev, map[string]any{"issue_ids": ids, "assignee_id": devID.String()}), 403, "FORBIDDEN")
	e.expect(e.do("POST", "/issues/assign", owner, map[string]any{"issue_ids": []string{}, "assignee_id": "x"}), 422, "VALIDATION_FAILED")
	e.expect(e.do("POST", "/issues/assign", owner, map[string]any{"issue_ids": []string{"x"}, "assignee_id": devID.String()}), 422, "VALIDATION_FAILED")
	r := e.do("POST", "/issues/assign", owner, map[string]any{"issue_ids": ids, "assignee_id": devID.String()})
	if r.code != 200 || r.obj()["updated"] != 2.0 {
		t.Fatal(r.body)
	}
	if s := e.f.IssueRow(open); s.Status != "assigned" || *s.AssigneeID != devID {
		t.Fatalf("%+v", s)
	}
	if s := e.f.IssueRow(assigned); s.Status != "assigned" || *s.AssigneeID != devID {
		t.Fatalf("%+v", s)
	}
	if s := e.f.IssueRow(other); s.Status != "open" {
		t.Fatal("assigned an issue outside the caller's projects")
	}
	audit := e.f.AuditLog()
	if len(audit) != 1 || audit[0].Action != "issue.assigned" {
		t.Fatalf("%+v", audit)
	}
	// Nothing to do: no audit entry.
	r = e.do("POST", "/issues/assign", lead, map[string]any{"issue_ids": []string{fixed.String()}, "assignee_id": devID.String()})
	if r.code != 200 || r.obj()["updated"] != 0.0 || len(e.f.AuditLog()) != 1 {
		t.Fatal(r.body)
	}
}

func TestEventsAndComments(t *testing.T) {
	e := newEnv(t)
	iss := e.f.AddIssue(e.web, "high", "open", nil)
	path := "/issues/" + iss.String()
	e.expect(e.do("POST", path+"/comments", viewer, map[string]any{"body": "hi"}), 403, "FORBIDDEN")
	e.expect(e.do("POST", path+"/comments", dev, map[string]any{"body": "   "}), 422, "VALIDATION_FAILED")
	e.expect(e.do("POST", path+"/comments", dev, map[string]any{"body": "a\u0000b"}), 422, "VALIDATION_FAILED")
	e.expect(e.do("POST", path+"/comments", dev, map[string]any{"body": strings.Repeat("é", 10001)}), 422, "VALIDATION_FAILED")
	r := e.do("POST", path+"/comments", dev, map[string]any{"body": "looking into it"}) // not the assignee: allowed
	if r.code != 201 || r.obj()["author"].(map[string]any)["email"] != dev || r.obj()["edited_at"] != nil {
		t.Fatal(r.body)
	}
	e.expect(e.do("POST", path+"/comments", owner, map[string]any{"body": "thanks"}), 201, "")
	r = e.do("GET", path+"/comments", viewer, nil)
	if len(r.items()) != 2 || r.items()[0].(map[string]any)["body"] != "looking into it" {
		t.Fatal(r.body)
	}
	r = e.do("GET", path+"/events", viewer, nil)
	if len(r.items()) != 2 || r.items()[0].(map[string]any)["type"] != "commented" || r.items()[0].(map[string]any)["actor"] == nil {
		t.Fatal(r.body)
	}
	e.expect(e.do("GET", path+"/events", outsider, nil), 404, "NOT_FOUND")
	e.expect(e.do("GET", path+"/comments", outsider, nil), 404, "NOT_FOUND")
	if a := e.f.AuditLog(); len(a) != 2 || a[0].Action != "comment.created" {
		t.Fatalf("%+v", a)
	}
}

func TestExceptionWorkflow(t *testing.T) {
	e := newEnv(t)
	iss := e.f.AddIssue(e.web, "high", "open", nil)
	base := "/issues/" + iss.String() + "/exceptions"
	reason := "the endpoint is internal and behind mTLS"
	exp := e.f.Now.Add(30 * 24 * time.Hour).Format(time.RFC3339)

	e.expect(e.do("POST", base, viewer, map[string]any{"type": "false_positive", "reason": reason}), 403, "FORBIDDEN")
	r := e.do("POST", base, dev, map[string]any{"type": "risk_accepted", "reason": "short"})
	e.expect(r, 422, "VALIDATION_FAILED")
	if f := r.Error.Metadata["fields"].(map[string]any); f["reason"] == nil || f["expires_at"] == nil {
		t.Fatal(r.body)
	}
	tooFar := e.f.Now.Add(181 * 24 * time.Hour).Format(time.RFC3339)
	e.expect(e.do("POST", base, dev, map[string]any{"type": "risk_accepted", "reason": reason, "expires_at": tooFar}), 422, "VALIDATION_FAILED")
	e.expect(e.do("POST", base, dev, map[string]any{"type": "false_positive", "reason": reason, "expires_at": exp}), 422, "VALIDATION_FAILED")
	e.expect(e.do("POST", base, dev, map[string]any{"type": "wontfix", "reason": reason}), 422, "VALIDATION_FAILED")
	e.expect(e.do("POST", base, dev, map[string]any{"type": "risk_accepted", "reason": reason, "expires_at": "tomorrow"}), 422, "VALIDATION_FAILED")

	r = e.do("POST", base, dev, map[string]any{"type": "risk_accepted", "reason": reason, "expires_at": exp})
	e.expect(r, 201, "")
	exID := r.obj()["id"].(string)
	if r.obj()["status"] != "pending" || r.obj()["issue"].(map[string]any)["key"] != "WEB-1" || r.obj()["decided_by"] != nil {
		t.Fatal(r.body)
	}
	e.expect(e.do("POST", base, owner, map[string]any{"type": "false_positive", "reason": reason}), 409, "CONFLICT")
	if r := e.do("GET", "/issues/"+iss.String(), dev, nil); r.obj()["pending_exception_id"] != exID || r.obj()["can_request_exception"] != false {
		t.Fatal(r.body)
	}

	// Lists: the lead sees everything, others only their own.
	if r := e.do("GET", "/exceptions?status=pending", lead, nil); len(r.items()) != 1 {
		t.Fatal(r.body)
	}
	if r := e.do("GET", "/exceptions", owner, nil); len(r.items()) != 0 {
		t.Fatal(r.body)
	}
	if r := e.do("GET", "/exceptions", dev, nil); len(r.items()) != 1 {
		t.Fatal(r.body)
	}
	e.expect(e.do("GET", "/exceptions?status=open", lead, nil), 422, "VALIDATION_FAILED")
	e.expect(e.do("GET", "/exceptions?cursor=x&limit=0", lead, nil), 422, "VALIDATION_FAILED")

	dec := "/exceptions/" + exID + "/decision"
	e.expect(e.do("POST", dec, owner, map[string]any{"decision": "approve"}), 403, "FORBIDDEN")
	e.expect(e.do("POST", dec, lead, map[string]any{"decision": "reject"}), 422, "VALIDATION_FAILED")
	e.expect(e.do("POST", dec, lead, map[string]any{"decision": "maybe"}), 422, "VALIDATION_FAILED")
	later := e.f.Now.Add(60 * 24 * time.Hour).Format(time.RFC3339)
	e.expect(e.do("POST", dec, lead, map[string]any{"decision": "approve", "expires_at": later}), 422, "VALIDATION_FAILED")
	e.expect(e.do("POST", "/exceptions/"+uuid.NewString()+"/decision", lead, map[string]any{"decision": "approve"}), 404, "NOT_FOUND")

	shorter := e.f.Now.Add(10 * 24 * time.Hour).Truncate(time.Second)
	r = e.do("POST", dec, lead, map[string]any{"decision": "approve", "note": "ok for now", "expires_at": shorter.Format(time.RFC3339)})
	e.expect(r, 200, "")
	if r.obj()["status"] != "approved" || r.obj()["decision_note"] != "ok for now" || r.obj()["issue"].(map[string]any)["status"] != "risk_accepted" ||
		r.obj()["expires_at"] != shorter.UTC().Format(time.RFC3339Nano) {
		t.Fatal(r.body)
	}
	if e.f.IssueRow(iss).Status != "risk_accepted" {
		t.Fatal("issue not moved")
	}
	e.expect(e.do("POST", dec, lead, map[string]any{"decision": "approve"}), 409, "CONFLICT")
	if r := e.do("GET", "/exceptions?status=expiring", lead, nil); len(r.items()) != 1 {
		t.Fatal(r.body)
	}
	if got := strings.Join(e.f.EventTypes(iss), ","); got != "exception_requested,exception_decided,status_changed" {
		t.Fatal(got)
	}
	// Exceptions only for active issues.
	e.expect(e.do("POST", base, dev, map[string]any{"type": "false_positive", "reason": reason}), 422, "INVALID_TRANSITION")
}

func TestExceptionDecisionRules(t *testing.T) {
	e := newEnv(t)
	iss := e.f.AddIssue(e.web, "high", "open", nil)
	own := e.f.AddException(iss, e.u[lead], "false_positive", nil)
	// The requester can't decide their own request.
	r := e.do("POST", "/exceptions/"+own.String()+"/decision", lead, map[string]any{"decision": "approve"})
	e.expect(r, 403, "FORBIDDEN")
	e.f.SetExceptionStatus(own, "rejected")

	ex := e.f.AddException(iss, e.u[dev], "false_positive", nil)
	dec := "/exceptions/" + ex.String() + "/decision"
	e.expect(e.do("POST", dec, lead, map[string]any{"decision": "approve", "expires_at": e.f.Now.Add(time.Hour).Format(time.RFC3339)}), 422, "VALIDATION_FAILED")
	e.expect(e.do("POST", dec, lead, map[string]any{"decision": "reject", "note": "no", "expires_at": e.f.Now.Format(time.RFC3339)}), 422, "VALIDATION_FAILED")
	r = e.do("POST", dec, lead, map[string]any{"decision": "reject", "note": "this is a real injection"})
	if r.code != 200 || r.obj()["status"] != "rejected" || r.obj()["decided_by"].(map[string]any)["email"] != lead {
		t.Fatal(r.body)
	}
	if e.f.IssueRow(iss).Status != "open" {
		t.Fatal("rejection moved the issue")
	}

	// Approval when the issue is no longer active.
	ex2 := e.f.AddException(iss, e.u[dev], "false_positive", nil)
	e.f.SetIssue(iss, func(r *servicetest.IssueRow) { r.Status = "fixed" })
	e.expect(e.do("POST", "/exceptions/"+ex2.String()+"/decision", lead, map[string]any{"decision": "approve"}), 422, "INVALID_TRANSITION")

	// A risk acceptance whose requested expiry has passed can't be approved as is.
	iss2 := e.f.AddIssue(e.web, "low", "open", nil)
	past := e.f.Now.Add(-time.Hour)
	ex3 := e.f.AddException(iss2, e.u[dev], "risk_accepted", &past)
	e.expect(e.do("POST", "/exceptions/"+ex3.String()+"/decision", lead, map[string]any{"decision": "approve"}), 422, "VALIDATION_FAILED")
	// False positive approval.
	iss3 := e.f.AddIssue(e.web, "low", "reopened", nil)
	ex4 := e.f.AddException(iss3, e.u[dev], "false_positive", nil)
	e.expect(e.do("POST", "/exceptions/"+ex4.String()+"/decision", lead, map[string]any{"decision": "approve"}), 200, "")
	if e.f.IssueRow(iss3).Status != "false_positive" {
		t.Fatal("not moved")
	}
}

func TestAuditLog(t *testing.T) {
	e := newEnv(t)
	e.expect(e.do("POST", "/projects", lead, map[string]any{"key": "AAA", "name": "a"}), 201, "")
	e.expect(e.do("POST", "/projects", lead, map[string]any{"key": "BBB", "name": "b"}), 201, "")
	e.expect(e.do("GET", "/audit-log", dev, nil), 403, "FORBIDDEN")
	r := e.do("GET", "/audit-log?limit=1", admin, nil)
	e.expect(r, 200, "")
	if len(r.items()) != 1 || r.items()[0].(map[string]any)["action"] != "project.created" ||
		r.items()[0].(map[string]any)["data"].(map[string]any)["key"] != "BBB" {
		t.Fatal(r.body)
	}
	next := r.obj()["next_cursor"].(string)
	r = e.do("GET", "/audit-log?cursor="+next, admin, nil)
	if len(r.items()) != 1 || r.items()[0].(map[string]any)["data"].(map[string]any)["key"] != "AAA" {
		t.Fatal(r.body)
	}
	if r := e.do("GET", "/audit-log?actor_id=system", lead, nil); len(r.items()) != 0 {
		t.Fatal(r.body)
	}
	if r := e.do("GET", "/audit-log?action=project.created&actor_id="+e.u[lead].String()+"&from=2026-01-01T00:00:00Z&to=2027-01-01T00:00:00Z", lead, nil); len(r.items()) != 2 {
		t.Fatal(r.body)
	}
	r = e.do("GET", "/audit-log?actor_id=x&from=yesterday&cursor=abc&limit=500", lead, nil)
	e.expect(r, 422, "VALIDATION_FAILED")
	e.expect(e.do("GET", "/audit-log?from=2027-01-01T00:00:00Z&to=2026-01-01T00:00:00Z", lead, nil), 422, "VALIDATION_FAILED")
	for _, a := range e.f.AuditLog() {
		if a.OrgID != e.org || a.ActorID == nil || *a.ActorID != e.u[lead] || a.IP == "" {
			t.Fatalf("%+v", a)
		}
	}
}

func TestStrictJSONBodies(t *testing.T) {
	e := newEnv(t)
	path := "/projects"
	for body, field := range map[string]string{
		``:                                  "body",
		`{"key":"ABC","name":"x"} {"x":1}`:  "body",
		`{"key":"ABC","name":"x","evil":1}`: "evil",
		`{"key":123,"name":"x"}`:            "key",
		`[1,2]`:                             "",
		`{"key":"ABC",`:                     "body",
		`{"key":"ABC","name":"x"} trailing`: "body",
	} {
		r := e.do("POST", path, lead, body)
		e.expect(r, 422, "VALIDATION_FAILED")
		if field != "" && r.Error.Metadata["fields"].(map[string]any)[field] == nil {
			t.Fatalf("%q: %s", body, r.body)
		}
	}
}

func TestErrorsInsideTransactionsRollBack(t *testing.T) {
	e := newEnv(t)
	e.f.Fail["AppendAudit"] = errors.New("audit down")
	e.expect(e.do("POST", "/projects", lead, map[string]any{"key": "ZZZ", "name": "z"}), 500, "INTERNAL")
	delete(e.f.Fail, "AppendAudit")
	if r := e.do("GET", "/projects", lead, nil); len(r.items()) != 2 {
		t.Fatal("write survived a failed audit append", r.body)
	}
}
