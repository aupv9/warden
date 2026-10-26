package main

import (
	"bytes"
	"context"
	"crypto/rand"
	"encoding/base32"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"net/http/httptest"
	"os"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/google/uuid"
)

// testToken is built at run time (no secret-looking literal in the repo).
func testToken(t *testing.T) string {
	t.Helper()
	b := make([]byte, 37)
	if _, err := rand.Read(b); err != nil {
		t.Fatal(err)
	}
	enc := strings.ToLower(base32.StdEncoding.WithPadding(base32.NoPadding).EncodeToString(b))
	return "wdn_" + enc[:8] + "_" + enc[8:60]
}

// fakeServer is a Warden API (and object store) good enough for the CLI.
type fakeServer struct {
	t        *testing.T
	srv      *httptest.Server
	token    string
	org, prj uuid.UUID
	scanID   string

	mu        sync.Mutex
	statuses  []string // returned by successive GET scan calls; the last one repeats
	errorCode *string
	gate      map[string]any
	createErr int // status for POST scans, 0 = OK
	pollErrs  []int
	uploadURL string // override
	uploaded  []byte
	uploadHdr http.Header
	started   bool
	cancelled bool
	failOn    string
	sawAuth   []string
}

func newFakeServer(t *testing.T) *fakeServer {
	f := &fakeServer{t: t, token: testToken(t), org: uuid.New(), prj: uuid.New(), scanID: uuid.NewString(),
		statuses: []string{"queued", "running", "completed"},
		gate:     map[string]any{"status": "completed", "finished": true, "pass": true, "fail_on": "high", "counts": map[string]int{}, "blocking": []any{}}}
	f.srv = httptest.NewServer(http.HandlerFunc(f.serve))
	t.Cleanup(f.srv.Close)
	return f
}

func (f *fakeServer) reply(w http.ResponseWriter, status int, data any, code string) {
	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(status)
	env := map[string]any{"data": data, "error": nil, "meta": map[string]any{"request_id": "r"}}
	if code != "" {
		env["data"] = nil
		env["error"] = map[string]any{"code": code, "message": "nope"}
	}
	_ = json.NewEncoder(w).Encode(env)
}

func (f *fakeServer) serve(w http.ResponseWriter, r *http.Request) {
	f.mu.Lock()
	defer f.mu.Unlock()
	if strings.HasPrefix(r.URL.Path, "/upload/") {
		if r.Method != http.MethodPut || r.Header.Get("Authorization") != "" || r.URL.Query().Get("X-Amz-Signature") == "" {
			w.WriteHeader(http.StatusForbidden)
			return
		}
		f.uploaded, _ = io.ReadAll(r.Body)
		f.uploadHdr = r.Header.Clone()
		if int64(len(f.uploaded)) != r.ContentLength {
			w.WriteHeader(http.StatusBadRequest)
			return
		}
		w.WriteHeader(http.StatusOK)
		return
	}
	f.sawAuth = append(f.sawAuth, r.Header.Get("Authorization"))
	if r.Header.Get("Authorization") != "Bearer "+f.token {
		f.reply(w, 401, nil, "UNAUTHORIZED")
		return
	}
	base := "/api/v1/orgs/" + f.org.String()
	scan := base + "/scans/" + f.scanID
	switch {
	case r.Method == "POST" && r.URL.Path == base+"/projects/"+f.prj.String()+"/scans":
		if f.createErr != 0 {
			f.reply(w, f.createErr, nil, "TOKEN_SCOPE")
			return
		}
		var in map[string]any
		if err := json.NewDecoder(r.Body).Decode(&in); err != nil || in["sha256"] == nil || in["file_name"] != "repo.zip" {
			f.reply(w, 422, nil, "VALIDATION_FAILED")
			return
		}
		up := f.uploadURL
		if up == "" {
			up = f.srv.URL + "/upload/" + f.scanID + "?X-Amz-Signature=presigned-signature"
		}
		f.reply(w, 201, map[string]any{
			"scan":   map[string]any{"id": f.scanID, "status": "pending_upload"},
			"upload": map[string]any{"method": "PUT", "url": up, "headers": map[string]string{"x-amz-checksum-sha256": "abc", "Authorization": "leak"}},
		}, "")
	case r.Method == "POST" && r.URL.Path == scan+"/start":
		f.started = true
		f.reply(w, 200, map[string]any{"id": f.scanID, "status": "queued"}, "")
	case r.Method == "POST" && r.URL.Path == scan+"/cancel":
		f.cancelled = true
		f.reply(w, 200, map[string]any{"id": f.scanID, "status": "cancelled"}, "")
	case r.Method == "GET" && r.URL.Path == scan:
		if len(f.pollErrs) > 0 {
			code := f.pollErrs[0]
			f.pollErrs = f.pollErrs[1:]
			w.Header().Set("Retry-After", "1")
			f.reply(w, code, nil, "RATE_LIMITED")
			return
		}
		st := f.statuses[0]
		if len(f.statuses) > 1 {
			f.statuses = f.statuses[1:]
		}
		f.reply(w, 200, map[string]any{"id": f.scanID, "status": st, "error_code": f.errorCode}, "")
	case r.Method == "GET" && r.URL.Path == scan+"/gate":
		f.failOn = r.URL.Query().Get("fail_on")
		f.reply(w, 200, f.gate, "")
	default:
		f.reply(w, 404, nil, "NOT_FOUND")
	}
}

func testDeps() deps {
	d := defaultDeps()
	d.pack = func(dir, dest, prefix string) (int, error) {
		return 3, os.WriteFile(dest, []byte("PK fake zip from "+prefix), 0o600)
	}
	d.sleep = func(ctx context.Context, _ time.Duration) error { return ctx.Err() }
	d.poll = time.Millisecond
	return d
}

type result struct {
	code           int
	stdout, stderr string
}

func (f *fakeServer) run(t *testing.T, token string, d deps, extra ...string) result {
	t.Helper()
	args := append([]string{"scan", "--url", f.srv.URL, "--org", f.org.String(), "--project", f.prj.String(), "--dir", t.TempDir() + "/repo"}, extra...)
	var out, errOut bytes.Buffer
	env := func(k string) string {
		if k == "WARDEN_TOKEN" {
			return token
		}
		return ""
	}
	code := run(context.Background(), args, env, &out, &errOut, d)
	r := result{code, out.String(), errOut.String()}
	// Whatever happened, the token is never printed.
	secret := token[strings.LastIndex(token, "_")+1:]
	if secret != "" && (strings.Contains(r.stdout, secret) || strings.Contains(r.stderr, secret)) {
		t.Fatalf("token printed:\n%s\n%s", r.stdout, r.stderr)
	}
	if strings.Contains(r.stdout+r.stderr, "presigned-signature") {
		t.Fatalf("presigned URL printed:\n%s\n%s", r.stdout, r.stderr)
	}
	return r
}

func TestScanPasses(t *testing.T) {
	f := newFakeServer(t)
	r := f.run(t, f.token, testDeps(), "--fail-on", "critical", "--tools", "gitleaks, trivy")
	if r.code != exitPass || !strings.Contains(r.stdout, "PASS") || !strings.Contains(r.stdout, "==> running") {
		t.Fatalf("%+v", r)
	}
	if !f.started || !strings.Contains(string(f.uploaded), "repo/") || f.failOn != "critical" {
		t.Fatalf("started=%v uploaded=%q fail_on=%q", f.started, f.uploaded, f.failOn)
	}
	// The upload carries the server's headers, never a credential.
	if f.uploadHdr.Get("x-amz-checksum-sha256") != "abc" || f.uploadHdr.Get("Authorization") != "" {
		t.Fatal(f.uploadHdr)
	}
}

func TestScanGateFails(t *testing.T) {
	f := newFakeServer(t)
	path, line := "src/\x1b[2Jevil\u202e.go", 12
	f.gate = map[string]any{"status": "partial", "finished": true, "pass": false, "fail_on": "high",
		"counts": map[string]int{"critical": 1, "high": 2, "medium": 5},
		"blocking": []map[string]any{
			{"id": "i-1", "key": "WEB-1", "title": "Hard-coded credential\nFAKE LOG LINE", "severity": "critical", "file_path": path, "start_line": line},
			{"id": "i-2", "key": "WEB-2", "title": strings.Repeat("long ", 40), "severity": "high"},
		}}
	r := f.run(t, f.token, testDeps())
	if r.code != exitGateFailed || !strings.Contains(r.stdout, "WEB-1") || !strings.Contains(r.stdout, "3 blocking issue(s) at or above high") {
		t.Fatalf("%+v", r)
	}
	if strings.ContainsAny(r.stdout, "\x1b\u202e") || strings.Contains(r.stdout, "\nFAKE LOG LINE") {
		t.Fatalf("unsanitized output: %q", r.stdout)
	}
	if !strings.Contains(r.stdout, f.srv.URL+"/orgs/"+f.org.String()+"/issues/i-1") || !strings.Contains(r.stdout, ".go:12") {
		t.Fatal(r.stdout)
	}
}

func TestScanFailed(t *testing.T) {
	f := newFakeServer(t)
	code := "ZIP_PATH_TRAVERSAL"
	f.statuses, f.errorCode = []string{"running", "failed"}, &code
	r := f.run(t, f.token, testDeps())
	if r.code != exitError || !strings.Contains(r.stderr, "failed (ZIP_PATH_TRAVERSAL)") {
		t.Fatalf("%+v", r)
	}
}

func TestAuthError(t *testing.T) {
	f := newFakeServer(t)
	r := f.run(t, testToken(t), testDeps()) // a token the server doesn't know
	if r.code != exitError || !strings.Contains(r.stderr, "401 UNAUTHORIZED") {
		t.Fatalf("%+v", r)
	}
	f.createErr = 403
	r = f.run(t, f.token, testDeps())
	if r.code != exitError || !strings.Contains(r.stderr, "403 TOKEN_SCOPE") {
		t.Fatalf("%+v", r)
	}
}

func TestPollingRetriesTransientErrors(t *testing.T) {
	f := newFakeServer(t)
	f.pollErrs = []int{429, 503}
	if r := f.run(t, f.token, testDeps()); r.code != exitPass {
		t.Fatalf("%+v", r)
	}
	f.pollErrs = []int{503, 503, 503, 503}
	f.statuses = []string{"running"}
	if r := f.run(t, f.token, testDeps()); r.code != exitError || !strings.Contains(r.stderr, "503") {
		t.Fatalf("%+v", r)
	}
}

func TestTimeoutCancelsTheScan(t *testing.T) {
	f := newFakeServer(t)
	f.statuses = []string{"running"}
	d := testDeps()
	d.sleep = sleep
	r := f.run(t, f.token, d, "--timeout", "50ms")
	if r.code != exitError || !f.cancelled || !strings.Contains(r.stderr, "cancelled it") {
		t.Fatalf("%+v cancelled=%v", r, f.cancelled)
	}
}

func TestUploadURLMustBeSafe(t *testing.T) {
	f := newFakeServer(t)
	f.uploadURL = "http://s3.example.com/upload/x?X-Amz-Signature=presigned-signature"
	r := f.run(t, f.token, testDeps())
	if r.code != exitError || !strings.Contains(r.stderr, "refusing the upload URL") || f.started {
		t.Fatalf("%+v", r)
	}
	// A transport error must not print the presigned URL either.
	f.uploadURL = "http://127.0.0.1:1/upload/x?X-Amz-Signature=presigned-signature"
	if r := f.run(t, f.token, testDeps()); r.code != exitError || !strings.Contains(r.stderr, "PUT upload") {
		t.Fatalf("%+v", r)
	}
}

func TestRedirectsAreNotFollowed(t *testing.T) {
	target := newFakeServer(t)
	redirector := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		http.Redirect(w, r, target.srv.URL+r.URL.Path, http.StatusTemporaryRedirect)
	}))
	defer redirector.Close()
	args := []string{"scan", "--url", redirector.URL, "--org", target.org.String(), "--project", target.prj.String(), "--dir", "."}
	var out, errOut bytes.Buffer
	code := run(context.Background(), args, func(string) string { return target.token }, &out, &errOut, testDeps())
	if code != exitError || len(target.sawAuth) != 0 || !strings.Contains(errOut.String(), "HTTP 307") {
		t.Fatalf("%d %s %v", code, errOut.String(), target.sawAuth)
	}
}

func TestBadArguments(t *testing.T) {
	tok := testToken(t)
	org, prj := uuid.NewString(), uuid.NewString()
	for name, c := range map[string]struct {
		args  []string
		token string
		want  string
	}{
		"no command":    {[]string{}, tok, "usage"},
		"http":          {[]string{"scan", "--url", "http://warden.example", "--org", org, "--project", prj}, tok, "https://"},
		"ftp":           {[]string{"scan", "--url", "ftp://warden.example", "--org", org, "--project", prj}, tok, "https://"},
		"credentials":   {[]string{"scan", "--url", "https://u:p@warden.example", "--org", org, "--project", prj}, tok, "credentials"},
		"query":         {[]string{"scan", "--url", "https://warden.example/?x=1", "--org", org, "--project", prj}, tok, "query"},
		"relative":      {[]string{"scan", "--url", "warden.example", "--org", org, "--project", prj}, tok, "absolute"},
		"org":           {[]string{"scan", "--url", "https://warden.example", "--org", "../x", "--project", prj}, tok, "--org"},
		"project":       {[]string{"scan", "--url", "https://warden.example", "--org", org}, tok, "--project"},
		"fail-on":       {[]string{"scan", "--url", "https://warden.example", "--org", org, "--project", prj, "--fail-on", "info"}, tok, "--fail-on"},
		"timeout":       {[]string{"scan", "--url", "https://warden.example", "--org", org, "--project", prj, "--timeout", "0s"}, tok, "--timeout"},
		"no token":      {[]string{"scan", "--url", "https://warden.example", "--org", org, "--project", prj}, "", "WARDEN_TOKEN is not set"},
		"not a token":   {[]string{"scan", "--url", "https://warden.example", "--org", org, "--project", prj}, "eyJhbGciOi.jwt", "doesn't look like"},
		"unknown flag":  {[]string{"scan", "--token", tok}, tok, "usage"},
		"token in flag": {[]string{"scan", "--url", "https://warden.example", "--org", org, "--project", prj, tok}, "", "WARDEN_TOKEN"},
	} {
		t.Run(name, func(t *testing.T) {
			var out, errOut bytes.Buffer
			d := testDeps()
			d.pack = func(string, string, string) (int, error) { t.Fatal("packed despite bad arguments"); return 0, nil }
			code := run(context.Background(), c.args, func(string) string { return c.token }, &out, &errOut, d)
			if code != exitError || !strings.Contains(errOut.String(), c.want) {
				t.Fatalf("%d %q", code, errOut.String())
			}
			if strings.Contains(out.String()+errOut.String(), tok[5:]) && name != "unknown flag" {
				t.Fatalf("token printed: %s", errOut.String())
			}
		})
	}
}

func TestPackagingError(t *testing.T) {
	f := newFakeServer(t)
	d := testDeps()
	d.pack = func(string, string, string) (int, error) { return 0, fmt.Errorf("not a git repository") }
	if r := f.run(t, f.token, d); r.code != exitError || !strings.Contains(r.stderr, "not a git repository") {
		t.Fatalf("%+v", r)
	}
}

func TestHelpers(t *testing.T) {
	if got := clean("a\x1b[31mb\r\nc\u202ed\u2066e\xff"); got != "a?[31mb??c?d?e?" {
		t.Fatalf("%q", got)
	}
	for in, want := range map[string]string{"/src/my repo": "my_repo", "/": "source", "/x/..hidden": "hidden", "/x/" + strings.Repeat("a", 300): strings.Repeat("a", 100)} {
		if got := archiveName(in); got != want {
			t.Errorf("%q: %q", in, got)
		}
	}
	for _, ok := range []string{"https://w.example", "https://w.example/base/", "http://localhost:8010", "http://127.0.0.1:8010", "http://[::1]:8010"} {
		if _, err := checkURL(ok); err != nil {
			t.Errorf("%s: %v", ok, err)
		}
	}
	if u, _ := checkURL("https://w.example/base/"); u.String() != "https://w.example/base" {
		t.Error(u)
	}
	if truncate("héllo", 3) != "hé…" || truncate("abc", 3) != "abc" {
		t.Error(truncate("héllo", 3))
	}
}
