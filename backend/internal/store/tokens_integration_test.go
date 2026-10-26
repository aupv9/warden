//go:build integration

package store_test

import (
	"bytes"
	"crypto/rand"
	"crypto/rsa"
	"encoding/json"
	"errors"
	"fmt"
	"log/slog"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"

	"github.com/aupv9/common-go/transport/httpserver"
	"github.com/golang-jwt/jwt/v5"
	"github.com/google/uuid"
	"github.com/jackc/pgx/v5"

	"github.com/aupv9/warden/backend/internal/api"
	"github.com/aupv9/warden/backend/internal/auth"
	"github.com/aupv9/warden/backend/internal/db"
	"github.com/aupv9/warden/backend/internal/domain/rbac"
	"github.com/aupv9/warden/backend/internal/ids"
	"github.com/aupv9/warden/backend/internal/service"
	"github.com/aupv9/warden/backend/internal/store"
)

const (
	tIssuer   = "http://localhost:8180/realms/warden"
	tAudience = "warden-api"
)

// httpWorld is a world plus the real HTTP stack (api.Register on the real store)
// and an OIDC signer, with MFA required for admins and security leads.
type httpWorld struct {
	*world
	h   http.Handler
	key *rsa.PrivateKey
}

func newHTTPWorld(t *testing.T) *httpWorld {
	t.Helper()
	w := newWorld(t)
	w.svc = service.New(w.db, w.objs, service.Config{UploadMaxBytes: 1 << 20, RateLimitPerHour: 100,
		RequireMFARoles: []rbac.Role{rbac.OrgAdmin, rbac.SecurityLead}}, nil)
	key, err := rsa.GenerateKey(rand.Reader, 2048)
	if err != nil {
		t.Fatal(err)
	}
	srv, err := httpserver.New(slog.New(slog.DiscardHandler), api.ServerOptions()...)
	if err != nil {
		t.Fatal(err)
	}
	api.Register(srv.Engine(), auth.NewVerifier(tIssuer, tAudience, auth.StaticKeys{"k1": &key.PublicKey}), w.svc)
	return &httpWorld{world: w, h: srv.Engine(), key: key}
}

func (w *httpWorld) jwtFor(name string, mfa bool) string {
	w.t.Helper()
	u := w.users[name]
	amr := []string{"pwd"}
	if mfa {
		amr = append(amr, "otp")
	}
	now := time.Now().Unix()
	tok := jwt.NewWithClaims(jwt.SigningMethodRS256, jwt.MapClaims{"sub": u.Sub, "email": u.Email, "iss": tIssuer,
		"aud": tAudience, "iat": now, "exp": now + 300, "amr": amr})
	tok.Header["kid"] = "k1"
	s, err := tok.SignedString(w.key)
	if err != nil {
		w.t.Fatal(err)
	}
	return s
}

type hresp struct {
	code   int
	header http.Header
	Data   json.RawMessage `json:"data"`
	Error  *struct {
		Code    string `json:"code"`
		Message string `json:"message"`
	} `json:"error"`
}

func (r hresp) errCode() string {
	if r.Error == nil {
		return ""
	}
	return r.Error.Code
}

func (w *httpWorld) call(method, path, bearer string, body any) hresp {
	w.t.Helper()
	var raw []byte
	if body != nil {
		raw, _ = json.Marshal(body)
	}
	req := httptest.NewRequest(method, "/api/v1"+path, bytes.NewReader(raw))
	req.Header.Set("Authorization", "Bearer "+bearer)
	req.Header.Set("Content-Type", "application/json")
	rec := httptest.NewRecorder()
	w.h.ServeHTTP(rec, req)
	out := hresp{code: rec.Code, header: rec.Header()}
	if rec.Body.Len() > 0 {
		if err := json.Unmarshal(rec.Body.Bytes(), &out); err != nil {
			w.t.Fatalf("%s %s: %v: %s", method, path, err, rec.Body)
		}
	}
	return out
}

func (w *httpWorld) expect(r hresp, code int, errCode string) {
	w.t.Helper()
	if r.code != code || r.errCode() != errCode {
		w.t.Fatalf("want %d %q, got %d %q: %s", code, errCode, r.code, r.errCode(), r.Data)
	}
}

func (w *httpWorld) newToken(name string, org, project uuid.UUID, scopes ...string) service.CreatedToken {
	w.t.Helper()
	return must(w.svc.CreateToken(ctx, w.actor(name, org), project, service.CreateTokenInput{Name: "CI " + name, Scopes: scopes, ExpiresInDays: 30}))
}

func scanReq() map[string]any {
	return map[string]any{"file_name": "src.zip", "file_size": 10, "sha256": strings.Repeat("d", 64)}
}

func TestAPITokensEndToEnd(t *testing.T) {
	w := newHTTPWorld(t)
	f := w.org("TOK")
	other := w.org("TOO")
	orgP := "/orgs/" + f.id.String()
	ct := w.newToken("TOKowner", f.id, f.project, "scan:write")
	tok := ct.Secret

	// Happy path: create, upload (fake store), start, read, gate.
	r := w.call("POST", orgP+"/projects/"+f.project.String()+"/scans", tok, scanReq())
	w.expect(r, 201, "")
	var raw struct {
		Scan struct {
			ID       uuid.UUID         `json:"id"`
			ViaToken *service.TokenRef `json:"via_token"`
			By       service.UserRef   `json:"created_by"`
		} `json:"scan"`
	}
	_ = json.Unmarshal(r.Data, &raw)
	scanID := raw.Scan.ID
	if raw.Scan.ViaToken == nil || raw.Scan.ViaToken.ID != ct.Token.ID || raw.Scan.By.ID != w.users["TOKowner"].ID {
		t.Fatalf("%s", r.Data)
	}
	w.objs.sizes[service.ObjectKey(f.id, scanID)] = 10
	w.expect(w.call("POST", orgP+"/scans/"+scanID.String()+"/start", tok, nil), 200, "")
	w.expect(w.call("GET", orgP+"/scans/"+scanID.String(), tok, nil), 200, "")
	w.expect(w.call("GET", orgP+"/scans/"+scanID.String()+"/gate", tok, nil), 200, "")
	// The row and the audit log record the token.
	var via *uuid.UUID
	var auditVia int
	err := db.WithOrg(ctx, w.pool, f.id, func(tx pgx.Tx) error {
		if err := tx.QueryRow(ctx, `SELECT via_token FROM scan WHERE id = $1`, scanID).Scan(&via); err != nil {
			return err
		}
		return tx.QueryRow(ctx, `SELECT count(*) FROM audit_log WHERE org_id = $1 AND data->>'via_token' = $2`, f.id, ct.Token.ID.String()).Scan(&auditVia)
	})
	if err != nil || via == nil || *via != ct.Token.ID || auditVia != 2 {
		t.Fatal(via, auditVia, err)
	}
	list := must(w.svc.Tokens(ctx, w.actor("TOKlead", f.id), f.project))
	if len(list.Items) != 1 || list.Items[0].LastUsedAt == nil {
		t.Fatalf("%+v", list)
	}

	// Wrong project in the same org, and another org: 404.
	p2 := must(w.svc.CreateProject(ctx, w.actor("TOKlead", f.id), service.CreateProjectInput{Key: "TOK2", Name: "second"}))
	must(w.svc.SetProjectMember(ctx, w.actor("TOKlead", f.id), p2.ID, w.users["TOKowner"].ID, service.SetProjectMemberInput{Role: "owner"}))
	w.expect(w.call("POST", orgP+"/projects/"+p2.ID.String()+"/scans", tok, scanReq()), 404, "NOT_FOUND")
	w.expect(w.call("GET", "/orgs/"+other.id.String()+"/scans/"+other.scan.String(), tok, nil), 404, "NOT_FOUND")
	w.expect(w.call("GET", orgP+"/scans/"+other.scan.String(), tok, nil), 404, "NOT_FOUND")

	// Scope limits.
	w.expect(w.call("GET", "/me", tok, nil), 403, "TOKEN_SCOPE")
	w.expect(w.call("GET", orgP+"/issues", tok, nil), 403, "TOKEN_SCOPE")
	w.expect(w.call("GET", orgP+"/projects/"+f.project.String()+"/tokens", tok, nil), 403, "TOKEN_SCOPE")

	// Revoked and expired: the generic 401.
	revoked := w.newToken("TOKowner", f.id, f.project, "scan:write")
	must(0, w.svc.RevokeToken(ctx, w.actor("TOKlead", f.id), f.project, revoked.Token.ID))
	expired := w.newToken("TOKowner", f.id, f.project, "scan:write")
	ownerExec(t, f.id, `UPDATE api_token SET expires_at = now() - interval '1 second' WHERE id = $1`, expired.Token.ID)
	for _, s := range []string{revoked.Secret, expired.Secret, ct.Secret[:13] + strings.Repeat("a", 52)} {
		r := w.call("GET", orgP+"/scans/"+scanID.String(), s, nil)
		w.expect(r, 401, "UNAUTHORIZED")
		if r.Error.Message != "invalid or expired token" {
			t.Fatal(r.Error.Message)
		}
	}

	// Rate limit: 60 per minute per token.
	limited := w.newToken("TOKowner", f.id, f.project, "scan:write")
	for i := range 60 {
		if r := w.call("GET", orgP+"/scans/"+scanID.String(), limited.Secret, nil); r.code != 200 {
			t.Fatalf("request %d: %d", i, r.code)
		}
	}
	r = w.call("GET", orgP+"/scans/"+scanID.String(), limited.Secret, nil)
	w.expect(r, 429, "RATE_LIMITED")
	if r.header.Get("Retry-After") == "" {
		t.Fatal(r.header)
	}
}

func TestAPIGateCounts(t *testing.T) {
	w := newHTTPWorld(t)
	f := w.org("GAT")
	tok := w.newToken("GATowner", f.id, f.project, "scan:write", "issues:read").Secret
	orgP := "/orgs/" + f.id.String()
	gatePath := orgP + "/scans/" + f.scan.String() + "/gate"

	// Not finished yet: never passes.
	var g service.Gate
	r := w.call("GET", gatePath, tok, nil)
	w.expect(r, 200, "")
	_ = json.Unmarshal(r.Data, &g)
	if g.Pass || g.Finished {
		t.Fatalf("%+v", g)
	}

	older := must(w.svc.CreateScan(ctx, w.actor("GATdev", f.id), f.project, service.CreateScanInput{FileName: "b.zip", FileSize: 10, SHA256: strings.Repeat("e", 64)}))
	seen := func(n int, sev, status string, scans ...uuid.UUID) {
		id := w.issue(f, n, sev, status, nil, nil)
		for _, s := range scans {
			ownerExec(t, f.id, `INSERT INTO occurrence (org_id, issue_id, scan_id, raw) VALUES ($1, $2, $3, '{}')`, f.id, id, s)
		}
	}
	seen(1, "high", "open", f.scan)
	seen(2, "medium", "in_progress", f.scan)
	seen(3, "critical", "false_positive", f.scan)
	seen(4, "critical", "risk_accepted", f.scan)
	seen(5, "critical", "fixed", f.scan)
	seen(6, "critical", "open", older.Scan.ID) // not seen in this scan
	ownerExec(t, f.id, `UPDATE scan SET status = 'completed', finished_at = now() WHERE id = $1`, f.scan)

	for failOn, want := range map[string]struct {
		pass     bool
		blocking int
	}{"critical": {true, 0}, "high": {false, 1}, "medium": {false, 2}, "low": {false, 2}} {
		r := w.call("GET", gatePath+"?fail_on="+failOn, tok, nil)
		w.expect(r, 200, "")
		var g service.Gate
		_ = json.Unmarshal(r.Data, &g)
		if g.Pass != want.pass || len(g.Blocking) != want.blocking || !g.Finished ||
			g.Counts != (service.SeverityCounts{High: 1, Medium: 1}) {
			t.Fatalf("%s: %+v", failOn, g)
		}
	}
	// A failed scan never passes.
	ownerExec(t, f.id, `UPDATE scan SET status = 'failed' WHERE id = $1`, f.scan)
	r = w.call("GET", gatePath+"?fail_on=critical", tok, nil)
	_ = json.Unmarshal(r.Data, &g)
	if g.Pass {
		t.Fatalf("%+v", g)
	}
	// issues:read sees only its project.
	r = w.call("GET", orgP+"/issues", tok, nil)
	w.expect(r, 200, "")
}

func TestAPIMFAEnforcementAndTokenExemption(t *testing.T) {
	w := newHTTPWorld(t)
	f := w.org("MFA")
	orgP := "/orgs/" + f.id.String()
	w.expect(w.call("GET", orgP, w.jwtFor("MFAlead", false), nil), 403, "MFA_REQUIRED")
	w.expect(w.call("GET", orgP, w.jwtFor("MFAadmin", false), nil), 403, "MFA_REQUIRED")
	w.expect(w.call("GET", orgP, w.jwtFor("MFAlead", true), nil), 200, "")
	w.expect(w.call("GET", orgP, w.jwtFor("MFAdev", false), nil), 200, "")
	r := w.call("GET", "/me", w.jwtFor("MFAlead", false), nil)
	var me service.Me
	_ = json.Unmarshal(r.Data, &me)
	if len(me.MFARequiredOrgs) != 1 || me.MFARequiredOrgs[0] != f.id {
		t.Fatalf("%s", r.Data)
	}
	tok := w.newToken("MFAlead", f.id, f.project, "scan:write").Secret
	w.expect(w.call("GET", orgP+"/scans/"+f.scan.String(), tok, nil), 200, "")
}

// warden_lookup_token is the one way to read tokens across orgs. It must not
// be usable to list them, to see another org's rows otherwise, or be hijacked.
func TestTokenLookupFunctionCantBeAbused(t *testing.T) {
	w := newHTTPWorld(t)
	a, b := w.org("LKA"), w.org("LKB")
	ta := w.newToken("LKAowner", a.id, a.project, "scan:write")
	tb := w.newToken("LKBowner", b.id, b.project, "scan:write")
	pa, pb := ta.Token.Prefix, tb.Token.Prefix

	count := func(org uuid.UUID, sql string, args ...any) int {
		t.Helper()
		var n int
		err := db.WithOrg(ctx, w.pool, org, func(tx pgx.Tx) error { return tx.QueryRow(ctx, sql, args...).Scan(&n) })
		if err != nil {
			t.Fatalf("%s: %v", sql, err)
		}
		return n
	}
	// The table itself: nothing without an org, only the org's own rows with one.
	if n := count(uuid.Nil, `SELECT count(*) FROM api_token`); n != 0 {
		t.Fatal(n)
	}
	if n := count(a.id, `SELECT count(*) FROM api_token`); n != 1 {
		t.Fatal(n)
	}
	if n := count(a.id, `SELECT count(*) FROM api_token WHERE prefix = $1`, pb); n != 0 {
		t.Fatal(n)
	}
	// The function: exactly one row for an exact prefix, nothing for anything else.
	if n := count(uuid.Nil, `SELECT count(*) FROM warden_lookup_token($1)`, pb); n != 1 {
		t.Fatal(n)
	}
	for _, probe := range []any{"%", "", nil, pb[:7] + "%", pb[:7] + "_", strings.ToUpper(pb), pb + " ", " " + pb, pb + "' OR true --", pa + pb, ".*"} {
		if n := count(uuid.Nil, `SELECT count(*) FROM warden_lookup_token($1)`, probe); n != 0 {
			t.Fatalf("%v: %d rows", probe, n)
		}
	}
	// A temp table can't shadow api_token inside the function (pinned search_path).
	err := pgx.BeginFunc(ctx, w.pool, func(tx pgx.Tx) error {
		if _, err := tx.Exec(ctx, `CREATE TEMP TABLE api_token (id uuid, org_id uuid, project_id uuid, user_id uuid,
			token_hash char(64), scopes text[], expires_at timestamptz, revoked_at timestamptz, prefix char(8)) ON COMMIT DROP`); err != nil {
			return err
		}
		if _, err := tx.Exec(ctx, `INSERT INTO pg_temp.api_token VALUES ($1, $1, $1, $1, $2, '{scan:write}', now() + interval '1 day', NULL, 'evilevil')`,
			ids.New(), strings.Repeat("0", 64)); err != nil {
			return err
		}
		var n int
		if err := tx.QueryRow(ctx, `SELECT count(*) FROM warden_lookup_token('evilevil')`).Scan(&n); err != nil || n != 0 {
			return fmt.Errorf("shadowed: %d %v", n, err)
		}
		return tx.QueryRow(ctx, `SELECT count(*) FROM warden_lookup_token($1)`, pa).Scan(&n)
	})
	if err != nil {
		t.Fatal(err)
	}

	// Definition: SECURITY DEFINER, owned by the schema owner, search_path pinned,
	// and executable by warden_app but not by PUBLIC.
	conn, err := pgx.Connect(ctx, ownerURL)
	if err != nil {
		t.Fatal(err)
	}
	defer conn.Close(ctx)
	var (
		secdef  bool
		owner   string
		config  []string
		tblOwn  string
		appExec bool
	)
	if err := conn.QueryRow(ctx, `SELECT p.prosecdef, pg_get_userbyid(p.proowner), p.proconfig, pg_get_userbyid(c.relowner),
			has_function_privilege('warden_app', 'warden_lookup_token(text)', 'EXECUTE')
		FROM pg_proc p, pg_class c WHERE p.proname = 'warden_lookup_token' AND c.relname = 'api_token' AND c.relkind = 'r'`).
		Scan(&secdef, &owner, &config, &tblOwn, &appExec); err != nil {
		t.Fatal(err)
	}
	if !secdef || owner != "warden_owner" || owner != tblOwn || !appExec || len(config) != 1 || config[0] != "search_path=pg_catalog, pg_temp" {
		t.Fatal(secdef, owner, tblOwn, appExec, config)
	}
	// In production the owner isn't a superuser, so FORCEd RLS applies to it too:
	// the lookup works through a SELECT policy for the owner role only.
	var policyRoles []string
	if err := conn.QueryRow(ctx, `SELECT roles::text[] FROM pg_policies WHERE tablename = 'api_token' AND policyname = 'token_lookup' AND cmd = 'SELECT'`).
		Scan(&policyRoles); err != nil || len(policyRoles) != 1 || policyRoles[0] != owner {
		t.Fatal(policyRoles, err)
	}
	// Prove it with a non-superuser owner (the test container's owner is a
	// superuser, which bypasses RLS), in a transaction that is rolled back.
	err = pgx.BeginFunc(ctx, conn, func(tx pgx.Tx) error {
		for _, s := range []string{
			`CREATE ROLE warden_owner_nosu NOSUPERUSER NOBYPASSRLS`,
			`ALTER TABLE api_token OWNER TO warden_owner_nosu`,
			`ALTER FUNCTION warden_lookup_token(text) OWNER TO warden_owner_nosu`,
			`ALTER POLICY token_lookup ON api_token TO warden_owner_nosu`,
			`SET LOCAL ROLE warden_app`,
		} {
			if _, err := tx.Exec(ctx, s); err != nil {
				return fmt.Errorf("%s: %w", s, err)
			}
		}
		var n int
		if err := tx.QueryRow(ctx, `SELECT count(*) FROM warden_lookup_token($1)`, pb).Scan(&n); err != nil || n != 1 {
			return fmt.Errorf("lookup as a non-superuser owner: %d %v", n, err)
		}
		if _, err := tx.Exec(ctx, `RESET ROLE`); err != nil {
			return err
		}
		if _, err := tx.Exec(ctx, `DROP POLICY token_lookup ON api_token`); err != nil {
			return err
		}
		// Without the policy FORCEd RLS hides every row, even from the owner.
		if err := tx.QueryRow(ctx, `SELECT count(*) FROM warden_lookup_token($1)`, pb).Scan(&n); err != nil {
			return err
		}
		if _, err := tx.Exec(ctx, `SET LOCAL ROLE warden_app`); err != nil {
			return err
		}
		if err := tx.QueryRow(ctx, `SELECT count(*) FROM warden_lookup_token($1)`, pb).Scan(&n); err != nil || n != 0 {
			return fmt.Errorf("lookup without the policy: %d %v", n, err)
		}
		return errRollback
	})
	if err != errRollback {
		t.Fatal(err)
	}
	if _, err := conn.Exec(ctx, `DO $$ BEGIN IF NOT EXISTS (SELECT 1 FROM pg_roles WHERE rolname = 'warden_probe') THEN CREATE ROLE warden_probe NOLOGIN; END IF; END $$`); err != nil {
		t.Fatal(err)
	}
	var probeExec bool
	if err := conn.QueryRow(ctx, `SELECT has_function_privilege('warden_probe', 'warden_lookup_token(text)', 'EXECUTE')`).Scan(&probeExec); err != nil || probeExec {
		t.Fatal("PUBLIC can execute warden_lookup_token", err)
	}

	// warden_app can revoke and record use, but not rewrite or delete a token.
	for _, sql := range []string{
		`UPDATE api_token SET token_hash = repeat('0', 64) WHERE id = $1`,
		`UPDATE api_token SET scopes = '{scan:write,issues:read}' WHERE id = $1`,
		`UPDATE api_token SET expires_at = now() + interval '10 years' WHERE id = $1`,
		`UPDATE api_token SET org_id = org_id WHERE id = $1`,
		`DELETE FROM api_token WHERE id = $1`,
	} {
		err := db.WithOrg(ctx, w.pool, a.id, func(tx pgx.Tx) error { _, err := tx.Exec(ctx, sql, ta.Token.ID); return err })
		if err == nil || !strings.Contains(err.Error(), "permission denied") {
			t.Fatalf("%s: %v", sql, err)
		}
	}
	err = db.WithOrg(ctx, w.pool, a.id, func(tx pgx.Tx) error {
		_, err := tx.Exec(ctx, `UPDATE api_token SET last_used_at = now(), revoked_at = now() WHERE id = $1`, ta.Token.ID)
		return err
	})
	if err != nil {
		t.Fatal(err)
	}
	// And it can't insert a token into another org (RLS WITH CHECK).
	err = db.WithOrg(ctx, w.pool, a.id, func(tx pgx.Tx) error {
		_, err := tx.Exec(ctx, `INSERT INTO api_token (id, org_id, project_id, user_id, created_by, name, prefix, token_hash, scopes, expires_at)
			VALUES ($1, $2, $3, $4, $4, 'x', 'aaaaaaaa', repeat('1', 64), '{scan:write}', now() + interval '1 day')`,
			ids.New(), b.id, b.project, w.users["LKBowner"].ID)
		return err
	})
	if err == nil || !strings.Contains(err.Error(), "row-level security") {
		t.Fatal(err)
	}
}

var errRollback = errors.New("rollback")

func TestSetOrgRoleBreakGlass(t *testing.T) {
	w := newWorld(t)
	f := w.org("BRK")
	lead := w.users["BRKlead"]
	from, err := store.SetOrgRole(ctx, w.db, f.id, lead.Email, rbac.OrgAdmin)
	if err != nil || from != rbac.SecurityLead {
		t.Fatal(from, err)
	}
	if from, err := store.SetOrgRole(ctx, w.db, f.id, lead.Email, rbac.OrgAdmin); err != nil || from != rbac.OrgAdmin {
		t.Fatal(from, err) // no-op
	}
	entries := must(w.svc.AuditLog(ctx, w.actor("BRKadmin", f.id), service.AuditFilter{Action: "member.role_changed", ActorID: "system"}))
	if len(entries.Items) != 1 || entries.Items[0].Actor != nil || !strings.Contains(string(entries.Items[0].Data), `"via": "warden-admin"`) &&
		!strings.Contains(string(entries.Items[0].Data), `"via":"warden-admin"`) {
		t.Fatalf("%+v", entries.Items)
	}
	// The last admin can't be demoted; non-members and bad roles are refused.
	must(store.SetOrgRole(ctx, w.db, f.id, w.users["BRKadmin"].Email, rbac.Member))
	if _, err := store.SetOrgRole(ctx, w.db, f.id, lead.Email, rbac.Member); err == nil {
		t.Fatal("demoted the last org_admin")
	}
	if _, err := store.SetOrgRole(ctx, w.db, f.id, "nobody@test.example", rbac.Member); err != store.ErrNotMember {
		t.Fatal(err)
	}
	if _, err := store.SetOrgRole(ctx, w.db, f.id, lead.Email, rbac.Role("root")); err == nil {
		t.Fatal("bad role accepted")
	}
	if _, err := store.VerifyOrgAudit(ctx, w.db, f.id); err != nil {
		t.Fatal(err)
	}
}
