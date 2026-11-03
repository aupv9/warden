package api

import (
	"context"
	"encoding/json"
	"fmt"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/google/uuid"

	"github.com/aupv9/warden/backend/internal/domain/registry"
	"github.com/aupv9/warden/backend/internal/secretbox"
	"github.com/aupv9/warden/backend/internal/service"
	"github.com/aupv9/warden/backend/internal/service/servicetest"
)

// stubChecker stands in for the worker's guarded registry client.
type stubChecker struct {
	mu    sync.Mutex
	ok    bool
	kind  string
	calls []string // "host user password"
}

func (s *stubChecker) Check(_ context.Context, host, username, password string) (bool, string) {
	s.mu.Lock()
	defer s.mu.Unlock()
	s.calls = append(s.calls, host+" "+username+" "+password)
	return s.ok, s.kind
}

// A registry password, built at test time.
var registryPassword = "ghp_" + strings.Repeat("Q7", 18)

func registryEnv(t *testing.T, keys *secretbox.Keyring, checker service.RegistryChecker) *env {
	return newEnv(t, func(c *service.Config) {
		c.Registries = service.RegistryConfig{Keys: keys, Checker: checker, AllowHosts: []string{"localhost"}}
		c.RateLimitPerHour = 5
	})
}

func registryBody() map[string]any {
	return map[string]any{"host": "ghcr.io", "username": "ci-bot", "password": registryPassword}
}

// assertNoPassword: no response body, audit entry or stored column holds a
// password in clear.
func (e *env) assertNoPassword(bodies []string, passwords ...string) {
	e.t.Helper()
	raw, _ := json.Marshal(e.f.AuditLog())
	for _, p := range append(passwords, registryPassword) {
		if strings.Contains(string(raw), p) {
			e.t.Fatalf("audit log contains the password %q", p)
		}
		for _, b := range bodies {
			if strings.Contains(b, p) {
				e.t.Fatalf("response contains the password: %s", b)
			}
		}
	}
}

func TestRegistryPermissions(t *testing.T) {
	e := registryEnv(t, testKeys(t), &stubChecker{ok: true})
	r := e.do("POST", "/registries", admin, registryBody())
	e.expect(r, 201, "")
	id := r.obj()["id"].(string)
	for _, who := range []string{owner, dev, viewer, outsider} {
		e.expect(e.do("GET", "/registries", who, nil), 403, "FORBIDDEN")
		e.expect(e.do("POST", "/registries", who, registryBody()), 403, "FORBIDDEN")
		e.expect(e.do("PATCH", "/registries/"+id, who, map[string]any{"username": "x"}), 403, "FORBIDDEN")
		e.expect(e.do("DELETE", "/registries/"+id, who, nil), 403, "FORBIDDEN")
		e.expect(e.do("POST", "/registries/"+id+"/test", who, nil), 403, "FORBIDDEN")
	}
	e.expect(e.do("GET", "/registries", lead, nil), 200, "")
	// Not for API tokens, whatever their scopes.
	_, tok := e.newToken(owner, e.web, "scan:write", "issues:read")
	e.expect(e.doTok("GET", "/registries", tok, nil), 403, "TOKEN_SCOPE")
	e.expect(e.doTok("POST", "/registries", tok, registryBody()), 403, "TOKEN_SCOPE")
	e.expect(e.doTok("PATCH", "/registries/"+id, tok, map[string]any{"username": "x"}), 403, "TOKEN_SCOPE")
	e.expect(e.doTok("DELETE", "/registries/"+id, tok, nil), 403, "TOKEN_SCOPE")
	e.expect(e.doTok("POST", "/registries/"+id+"/test", tok, nil), 403, "TOKEN_SCOPE")
	// Another org's admin: the credential doesn't exist.
	other := e.f.AddOrg("Other")
	e.f.AddMember(other, e.u[lead], "org_admin")
	path := "/api/v1/orgs/" + other.String() + "/registries"
	e.expect(e.call("PATCH", path+"/"+id, lead, map[string]any{"username": "x"}, nil), 404, "NOT_FOUND")
	e.expect(e.call("DELETE", path+"/"+id, lead, nil, nil), 404, "NOT_FOUND")
	e.expect(e.call("POST", path+"/"+id+"/test", lead, nil, nil), 404, "NOT_FOUND")
	if r := e.call("GET", path, lead, nil, nil); r.code != 200 || len(r.items()) != 0 {
		t.Fatal(r.body)
	}
}

func TestRegistryCredentialLifecycle(t *testing.T) {
	keys := testKeys(t)
	e := registryEnv(t, keys, &stubChecker{ok: true})
	var bodies []string
	r := e.do("POST", "/registries", lead, registryBody())
	e.expect(r, 201, "")
	bodies = append(bodies, r.body)
	c := r.obj()
	id := uuid.MustParse(c["id"].(string))
	if c["host"] != "ghcr.io" || c["username"] != "ci-bot" || c["created_by"].(map[string]any)["email"] != lead ||
		c["last_used_at"] != nil || c["last_error"] != nil || c["password"] != nil || len(c) != 8 {
		t.Fatal(r.body)
	}
	// At rest: sealed for this org and row.
	row, _ := e.f.StoredRegistryCredential(id)
	if strings.Contains(string(row.PasswordEnc), registryPassword) || row.KeyID != "k1" {
		t.Fatal("stored in clear")
	}
	if pw, err := registry.OpenPassword(keys, e.org, id, row.KeyID, row.PasswordEnc); err != nil || pw != registryPassword {
		t.Fatal(pw, err)
	}
	if _, err := registry.OpenPassword(keys, e.org, uuid.New(), row.KeyID, row.PasswordEnc); err == nil {
		t.Fatal("opens for another row")
	}

	// One per host.
	b := registryBody()
	b["username"] = "other"
	e.expect(e.do("POST", "/registries", admin, b), 409, "CONFLICT")
	b["host"] = "registry.example.com:5000"
	r = e.do("POST", "/registries", admin, b)
	e.expect(r, 201, "")
	bodies = append(bodies, r.body)
	r = e.do("GET", "/registries", admin, nil)
	if len(r.items()) != 2 || r.items()[0].(map[string]any)["host"] != "ghcr.io" {
		t.Fatal(r.body)
	}
	bodies = append(bodies, r.body)

	// Update: username and password; the host is fixed, an empty body is refused.
	path := "/registries/" + id.String()
	e.expect(e.do("PATCH", path, admin, map[string]any{}), 422, "VALIDATION_FAILED")
	e.expect(e.do("PATCH", path, admin, map[string]any{"host": "evil.example"}), 422, "VALIDATION_FAILED")
	e.expect(e.do("PATCH", path, admin, map[string]any{"password": ""}), 422, "VALIDATION_FAILED")
	e.f.SetRegistryCredential(id, func(c *service.RegistryCredentialRecord) { kind := "unauthorized"; c.LastError = &kind })
	newPassword := "glpat-" + strings.Repeat("R", 20)
	r = e.do("PATCH", path, admin, map[string]any{"username": "ci-bot2", "password": newPassword})
	e.expect(r, 200, "")
	bodies = append(bodies, r.body)
	if r.obj()["username"] != "ci-bot2" || r.obj()["last_error"] != nil || r.obj()["host"] != "ghcr.io" {
		t.Fatal(r.body)
	}
	row, _ = e.f.StoredRegistryCredential(id)
	if pw, err := registry.OpenPassword(keys, e.org, id, row.KeyID, row.PasswordEnc); err != nil || pw != newPassword {
		t.Fatal(pw, err)
	}
	// Unchanged: no write, no audit entry.
	n := len(e.f.AuditLog())
	e.expect(e.do("PATCH", path, admin, map[string]any{"username": "ci-bot2"}), 200, "")
	if len(e.f.AuditLog()) != n {
		t.Fatal("audited a no-op")
	}

	e.expect(e.do("DELETE", path, admin, nil), 204, "")
	e.expect(e.do("DELETE", path, admin, nil), 404, "NOT_FOUND")
	e.expect(e.do("PATCH", path, admin, map[string]any{"username": "x"}), 404, "NOT_FOUND")
	e.expect(e.do("POST", "/registries/not-a-uuid/test", admin, nil), 404, "NOT_FOUND")

	// Audit: host and username, never the password.
	want := map[string]int{"registry.created": 2, "registry.updated": 1, "registry.deleted": 1}
	for _, a := range e.f.AuditLog() {
		if !strings.HasPrefix(a.Action, "registry.") {
			continue
		}
		want[a.Action]--
		if a.TargetType != "registry_credential" || a.Data["host"] == nil || a.Data["username"] == nil {
			t.Fatalf("%+v", a)
		}
		for k := range a.Data {
			if k != "host" && k != "username" && k != "changed" {
				t.Fatalf("audit holds %q: %+v", k, a)
			}
		}
		if a.Action == "registry.updated" && fmt.Sprint(a.Data["changed"]) != "[username password]" {
			t.Fatalf("%+v", a)
		}
	}
	for k, v := range want {
		if v != 0 {
			t.Errorf("%s: %d missing", k, v)
		}
	}
	e.assertNoPassword(bodies, newPassword)
}

func TestRegistryValidation(t *testing.T) {
	e := registryEnv(t, testKeys(t), nil)
	for name, c := range map[string]struct {
		change func(map[string]any)
		field  string
	}{
		"scheme":        {func(b map[string]any) { b["host"] = "https://ghcr.io" }, "host"},
		"path":          {func(b map[string]any) { b["host"] = "ghcr.io/acme" }, "host"},
		"upper case":    {func(b map[string]any) { b["host"] = "GHCR.io" }, "host"},
		"user info":     {func(b map[string]any) { b["host"] = "u:p@ghcr.io" }, "host"},
		"ipv4":          {func(b map[string]any) { b["host"] = "10.0.0.5:5000" }, "host"},
		"metadata":      {func(b map[string]any) { b["host"] = "169.254.169.254" }, "host"},
		"short ipv4":    {func(b map[string]any) { b["host"] = "127.1" }, "host"},
		"ipv6":          {func(b map[string]any) { b["host"] = "[::1]:5000" }, "host"},
		"single label":  {func(b map[string]any) { b["host"] = "localhost" }, "host"},
		"bad port":      {func(b map[string]any) { b["host"] = "ghcr.io:70000" }, "host"},
		"query":         {func(b map[string]any) { b["host"] = "ghcr.io?x=1" }, "host"},
		"newline":       {func(b map[string]any) { b["host"] = "ghcr.io\nx.io" }, "host"},
		"empty host":    {func(b map[string]any) { b["host"] = "" }, "host"},
		"no username":   {func(b map[string]any) { b["username"] = "" }, "username"},
		"long username": {func(b map[string]any) { b["username"] = strings.Repeat("u", 257) }, "username"},
		"ctrl username": {func(b map[string]any) { b["username"] = "a\x1bb" }, "username"},
		"no password":   {func(b map[string]any) { b["password"] = "" }, "password"},
		"long password": {func(b map[string]any) { b["password"] = strings.Repeat("p", 4097) }, "password"},
		"newline pw":    {func(b map[string]any) { b["password"] = registryPassword + "\n" }, "password"},
	} {
		b := registryBody()
		c.change(b)
		r := e.do("POST", "/registries", admin, b)
		if r.code != 422 || r.Error.Metadata["fields"].(map[string]any)[c.field] == nil {
			t.Errorf("%s: %s", name, r.body)
		}
		if strings.Contains(r.body, registryPassword) {
			t.Errorf("%s: the password is echoed: %s", name, r.body)
		}
	}
	e.expect(e.do("POST", "/registries", admin, map[string]any{"host": "ghcr.io", "username": "u"}), 422, "VALIDATION_FAILED")
	b := registryBody()
	b["password"] = strings.Repeat("p", 4096)
	e.expect(e.do("POST", "/registries", admin, b), 201, "")
}

func TestRegistryLimitAndKey(t *testing.T) {
	e := registryEnv(t, testKeys(t), nil)
	for i := range registry.MaxPerOrg {
		b := registryBody()
		b["host"] = fmt.Sprintf("r%d.example.com", i)
		e.expect(e.do("POST", "/registries", admin, b), 201, "")
	}
	r := e.do("POST", "/registries", admin, registryBody())
	e.expect(r, 409, "CONFLICT")
	if !strings.Contains(r.Error.Message, "20") {
		t.Fatal(r.body)
	}

	// Without secrets.key: listed, but nothing can be stored or tested.
	e = registryEnv(t, nil, &stubChecker{ok: true})
	e.expect(e.do("GET", "/registries", admin, nil), 200, "")
	e.expect(e.do("POST", "/registries", admin, registryBody()), 409, "SECRETS_KEY_MISSING")
	now := service.Time(e.f.Now)
	id := uuid.New()
	e.f.AddRegistryCredential(service.RegistryCredentialRecord{OrgID: e.org, KeyID: "k1", PasswordEnc: []byte{1, 2, 3},
		RegistryCredential: service.RegistryCredential{ID: id, Host: "ghcr.io", Username: "u", CreatedAt: now, UpdatedAt: now}})
	e.expect(e.do("PATCH", "/registries/"+id.String(), admin, map[string]any{"password": "x"}), 409, "SECRETS_KEY_MISSING")
	e.expect(e.do("PATCH", "/registries/"+id.String(), admin, map[string]any{"username": "v"}), 200, "")
	e.expect(e.do("POST", "/registries/"+id.String()+"/test", admin, nil), 409, "SECRETS_KEY_MISSING")

	// A key that can't open the row: a plain conflict, the registry is not called.
	checker := &stubChecker{ok: true}
	e = registryEnv(t, testKeys(t), checker)
	e.f.AddRegistryCredential(service.RegistryCredentialRecord{OrgID: e.org, KeyID: "k1", PasswordEnc: []byte("garbage-ciphertext-garbage-x"),
		RegistryCredential: service.RegistryCredential{ID: id, Host: "ghcr.io", Username: "u", CreatedAt: now, UpdatedAt: now}})
	e.expect(e.do("POST", "/registries/"+id.String()+"/test", admin, nil), 409, "CONFLICT")
	if len(checker.calls) != 0 {
		t.Fatal(checker.calls)
	}
}

func TestRegistryTest(t *testing.T) {
	checker := &stubChecker{ok: true}
	e := registryEnv(t, testKeys(t), checker)
	r := e.do("POST", "/registries", admin, registryBody())
	id := r.obj()["id"].(string)
	path := "/registries/" + id + "/test"

	r = e.do("POST", path, lead, nil)
	e.expect(r, 200, "")
	if r.obj()["ok"] != true || r.obj()["error"] != nil || len(checker.calls) != 1 ||
		checker.calls[0] != "ghcr.io ci-bot "+registryPassword {
		t.Fatal(r.body, checker.calls)
	}
	l := e.do("GET", "/registries", admin, nil).items()[0].(map[string]any)
	if l["last_used_at"] == nil || l["last_error"] != nil {
		t.Fatal(l)
	}
	for _, c := range []struct{ kind, want string }{
		{registry.ErrUnauthorized, "unauthorized"},
		{registry.ErrBlocked, "blocked"},
		{"connection refused to 10.0.0.1", "unreachable"}, // anything else is unreachable, never echoed
		{"", "unreachable"},
	} {
		checker.ok, checker.kind = false, c.kind
		r = e.do("POST", path, admin, nil)
		e.expect(r, 200, "")
		if r.obj()["ok"] != false || r.obj()["error"] != c.want {
			t.Fatal(c, r.body)
		}
		if l := e.do("GET", "/registries", admin, nil).items()[0].(map[string]any); l["last_error"] != c.want {
			t.Fatal(c, l)
		}
	}
	// A success clears the error.
	checker.ok, checker.kind = true, ""
	e.expect(e.do("POST", path, admin, nil), 200, "")
	if l := e.do("GET", "/registries", admin, nil).items()[0].(map[string]any); l["last_error"] != nil {
		t.Fatal(l)
	}

	// 10 per credential per hour, counted whether or not they succeed.
	for range 4 {
		e.expect(e.do("POST", path, admin, nil), 200, "")
	}
	r = e.do("POST", path, admin, nil)
	e.expect(r, 429, "RATE_LIMITED")
	if r.header.Get("Retry-After") == "" || len(checker.calls) != 10 {
		t.Fatal(r.header, len(checker.calls))
	}
	// Per credential.
	b := registryBody()
	b["host"] = "quay.io"
	other := e.do("POST", "/registries", admin, b).obj()["id"].(string)
	e.expect(e.do("POST", "/registries/"+other+"/test", admin, nil), 200, "")
	// An hour later, allowed again.
	e.f.Now = e.f.Now.Add(time.Hour)
	e.expect(e.do("POST", path, admin, nil), 200, "")

	tested := 0
	for _, a := range e.f.AuditLog() {
		if a.Action == "registry.tested" {
			tested++
			if a.Data["host"] == nil || a.Data["username"] != "ci-bot" {
				t.Fatalf("%+v", a)
			}
		}
	}
	if tested != 12 {
		t.Fatal(tested)
	}
	e.assertNoPassword(nil)

	// Without a checker the server reports every registry unreachable.
	e = registryEnv(t, testKeys(t), nil)
	id = e.do("POST", "/registries", admin, registryBody()).obj()["id"].(string)
	if r := e.do("POST", "/registries/"+id+"/test", admin, nil); r.obj()["ok"] != false || r.obj()["error"] != "unreachable" {
		t.Fatal(r.body)
	}
}

func pullBody() map[string]any {
	return map[string]any{"image_ref": "ghcr.io/acme/api@sha256:" + strings.Repeat("ab", 32)}
}

func TestPullScan(t *testing.T) {
	e := registryEnv(t, testKeys(t), nil)
	base := "/projects/" + e.web.String() + "/scans/pull"
	e.expect(e.do("POST", base, viewer, pullBody()), 403, "FORBIDDEN")
	e.expect(e.do("POST", base, outsider, pullBody()), 404, "NOT_FOUND")
	e.expect(e.do("POST", "/projects/"+e.api.String()+"/scans/pull", dev, pullBody()), 404, "NOT_FOUND")

	r := e.do("POST", base, dev, pullBody())
	e.expect(r, 201, "")
	sc := r.obj()
	id := sc["id"].(string)
	if sc["kind"] != "image" || sc["target"] != "ghcr.io/acme/api" || sc["image_ref"] != pullBody()["image_ref"] ||
		sc["pulled"] != true || sc["status"] != "queued" || sc["queued_at"] == nil || sc["file_name"] != "api.tar" ||
		fmt.Sprint(sc["tools"]) != "[trivy gitleaks]" || sc["via_token"] != nil {
		t.Fatal(r.body)
	}
	jobs := e.f.Jobs()
	if len(jobs) != 1 || jobs[0].ScanID != id || jobs[0].ObjectKey != "scans/"+e.org.String()+"/"+id+".tar" ||
		jobs[0].SHA256 != "" || fmt.Sprint(jobs[0].Tools) != "[trivy gitleaks]" {
		t.Fatalf("%+v", jobs)
	}
	// Already queued: start is a no-op, and it can be cancelled.
	e.expect(e.do("POST", "/scans/"+id+"/start", dev, nil), 200, "")
	if len(e.f.Jobs()) != 1 {
		t.Fatal("enqueued twice")
	}
	if r := e.do("GET", "/scans/"+id, viewer, nil); r.obj()["pulled"] != true {
		t.Fatal(r.body)
	}
	audited := false
	for _, a := range e.f.AuditLog() {
		if a.Action == "scan.created" && a.TargetID == id {
			audited = a.Data["pulled"] == true && a.Data["kind"] == "image" && a.Data["target"] == "ghcr.io/acme/api"
		}
	}
	if !audited {
		t.Fatal("not audited")
	}

	// Gitleaks or Trivy alone.
	b := pullBody()
	b["tools"] = []string{"gitleaks"}
	if r := e.do("POST", base, owner, b); r.code != 201 || fmt.Sprint(r.obj()["tools"]) != "[gitleaks]" {
		t.Fatal(r.body)
	}
	// Registry hosts in registry.allow_hosts may be local (development).
	b = pullBody()
	b["image_ref"] = "localhost:5000/acme/api@sha256:" + strings.Repeat("cd", 32)
	if r := e.do("POST", base, owner, b); r.code != 201 || r.obj()["target"] != "localhost:5000/acme/api" {
		t.Fatal(r.body)
	}

	digest := "@sha256:" + strings.Repeat("ab", 32)
	for name, c := range map[string]struct {
		change func(map[string]any)
		field  string
	}{
		"tag":             {func(b map[string]any) { b["image_ref"] = "ghcr.io/acme/api:latest" }, "image_ref"},
		"tag and digest":  {func(b map[string]any) { b["image_ref"] = "ghcr.io/acme/api:1.2" + digest }, "image_ref"},
		"short digest":    {func(b map[string]any) { b["image_ref"] = "ghcr.io/acme/api@sha256:abc" }, "image_ref"},
		"no host":         {func(b map[string]any) { b["image_ref"] = "acme/api" + digest }, "image_ref"},
		"docker hub path": {func(b map[string]any) { b["image_ref"] = "library/alpine" + digest }, "image_ref"},
		"one-label host":  {func(b map[string]any) { b["image_ref"] = "registry:5000/acme/api" + digest }, "image_ref"},
		"scheme":          {func(b map[string]any) { b["image_ref"] = "https://ghcr.io/acme/api" + digest }, "image_ref"},
		"user info":       {func(b map[string]any) { b["image_ref"] = "u:p@ghcr.io/acme/api" + digest }, "image_ref"},
		"private ip":      {func(b map[string]any) { b["image_ref"] = "10.0.0.5:5000/acme/api" + digest }, "image_ref"},
		"metadata ip":     {func(b map[string]any) { b["image_ref"] = "169.254.169.254/latest/x" + digest }, "image_ref"},
		"loopback":        {func(b map[string]any) { b["image_ref"] = "127.0.0.1:5000/acme/api" + digest }, "image_ref"},
		"traversal":       {func(b map[string]any) { b["image_ref"] = "ghcr.io/acme/../api" + digest }, "image_ref"},
		"upper case":      {func(b map[string]any) { b["image_ref"] = "ghcr.io/Acme/api" + digest }, "image_ref"},
		"newline":         {func(b map[string]any) { b["image_ref"] = "ghcr.io/acme/api" + digest + "\n" }, "image_ref"},
		"long":            {func(b map[string]any) { b["image_ref"] = "ghcr.io/" + strings.Repeat("a", 600) + digest }, "image_ref"},
		"double dash":     {func(b map[string]any) { b["image_ref"] = "xn--a.io/acme/api" + digest }, "image_ref"},
		"empty":           {func(b map[string]any) { b["image_ref"] = "" }, "image_ref"},
		"missing":         {func(b map[string]any) { delete(b, "image_ref") }, "image_ref"},
		"source tool":     {func(b map[string]any) { b["tools"] = []string{"trivy", "opengrep"} }, "tools"},
		"no tools":        {func(b map[string]any) { b["tools"] = []string{} }, "tools"},
		"duplicate tools": {func(b map[string]any) { b["tools"] = []string{"trivy", "trivy"} }, "tools"},
	} {
		b := pullBody()
		c.change(b)
		r := e.do("POST", base, lead, b)
		if r.code != 422 || r.Error.Metadata["fields"].(map[string]any)[c.field] == nil {
			t.Errorf("%s: %s", name, r.body)
		}
	}
	e.expect(e.do("POST", base, lead, map[string]any{"image_ref": pullBody()["image_ref"], "file_name": "x.tar"}), 422, "VALIDATION_FAILED")
	if n := len(e.f.Jobs()); n != 3 {
		t.Fatal("a refused pull was queued", n)
	}

	// Archived projects take no scans.
	e.f.ArchiveProject(e.web)
	e.expect(e.do("POST", base, dev, pullBody()), 409, "PROJECT_ARCHIVED")
}

func TestPullScanRateLimitAndRollback(t *testing.T) {
	e := registryEnv(t, testKeys(t), nil)
	base := "/projects/" + e.web.String() + "/scans"
	// A failing enqueue leaves no scan behind.
	e.f.Fail["EnqueueScan"] = fmt.Errorf("river down")
	e.expect(e.do("POST", base+"/pull", dev, pullBody()), 500, "INTERNAL")
	if r := e.do("GET", base, dev, nil); len(r.items()) != 0 {
		t.Fatal(r.body)
	}
	delete(e.f.Fail, "EnqueueScan")
	// Pulls and uploads share the hourly limit (5 in this env).
	for range 3 {
		e.expect(e.do("POST", base+"/pull", dev, pullBody()), 201, "")
	}
	for range 2 {
		e.expect(e.do("POST", base, dev, scanBody()), 201, "")
	}
	r := e.do("POST", base+"/pull", dev, pullBody())
	e.expect(r, 429, "RATE_LIMITED")
	if r.header.Get("Retry-After") == "" {
		t.Fatal(r.header)
	}
	e.expect(e.do("POST", base, dev, scanBody()), 429, "RATE_LIMITED")
}

func TestPullScanWithToken(t *testing.T) {
	e := registryEnv(t, testKeys(t), nil)
	tid, tok := e.newToken(owner, e.web, "scan:write")
	_, readTok := e.newToken(owner, e.web, "issues:read")
	r := e.doTok("POST", "/projects/"+e.web.String()+"/scans/pull", tok, pullBody())
	e.expect(r, 201, "")
	if vt, _ := r.obj()["via_token"].(map[string]any); vt == nil || vt["id"] != tid || r.obj()["pulled"] != true {
		t.Fatal(r.body)
	}
	id := r.obj()["id"].(string)
	if r := e.doTok("GET", "/scans/"+id, tok, nil); r.code != 200 || r.obj()["pulled"] != true {
		t.Fatal(r.body)
	}
	// Its own project only, and only with scan:write.
	e.expect(e.doTok("POST", "/projects/"+e.api.String()+"/scans/pull", tok, pullBody()), 404, "NOT_FOUND")
	e.expect(e.doTok("POST", "/projects/"+e.web.String()+"/scans/pull", readTok, pullBody()), 403, "TOKEN_SCOPE")
	for _, a := range e.f.AuditLog() {
		if a.Action == "scan.created" && a.TargetID == id && a.Data["via_token"] != tid {
			t.Fatalf("%+v", a)
		}
	}
}

func TestIssueImageLayer(t *testing.T) {
	e := newEnv(t)
	plain := e.f.AddIssue(e.web, "high", "open", nil)
	layered := e.f.AddIssue(e.web, "high", "open", nil)
	digest := "sha256:" + strings.Repeat("0f", 32)
	e.f.SetIssue(layered, func(i *servicetest.IssueRow) {
		i.Tool, i.Target, i.ImageLayer = "gitleaks", "ghcr.io/acme/api", &service.IssueImageLayer{Digest: digest, Index: 2, Count: 3}
	})
	r := e.do("GET", "/issues/"+plain.String(), dev, nil)
	if v, ok := r.obj()["image_layer"]; !ok || v != nil {
		t.Fatal(r.body)
	}
	r = e.do("GET", "/issues/"+layered.String(), dev, nil)
	l, _ := r.obj()["image_layer"].(map[string]any)
	if l == nil || l["digest"] != digest || l["index"] != 2.0 || l["count"] != 3.0 || len(l) != 3 {
		t.Fatal(r.body)
	}
}
