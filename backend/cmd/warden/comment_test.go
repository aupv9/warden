package main

import (
	"bytes"
	"context"
	"encoding/json"
	"fmt"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"strconv"
	"strings"
	"sync"
	"testing"

	"github.com/google/uuid"
)

// fakeCI is the GitHub or GitLab REST API, as far as --comment uses it.
type fakeCI struct {
	t        *testing.T
	srv      *httptest.Server
	gitlab   bool
	prefix   string // API base path: /api/v3 (GHES), /gitlab/api/v4 (self-managed)
	token    string
	me       int64 // the token's user id; 0: GET /user is refused (the Actions GITHUB_TOKEN)
	userCode int   // status for GET /user, if not 200/403

	mu       sync.Mutex
	comments []fakeComment
	nextID   int64
	reqs     []string // "METHOD path"
	auth     []string // credentials seen
	listCode int      // status for listing, 0 = OK
	editCode int      // status for PATCH/PUT, 0 = OK
	postCode int      // status for POST, 0 = Created
	errMsg   string   // message in error responses
	redirect string   // answer writes with a redirect here
}

type fakeComment struct {
	id     int64
	body   string
	login  string
	userID int64
	typ    string // GitHub: User or Bot
	system bool   // GitLab system note
}

const (
	botLogin = githubActionsBot
	botID    = 41898282
)

func newFakeCI(t *testing.T, gitlab bool, prefix string) *fakeCI {
	f := &fakeCI{t: t, gitlab: gitlab, prefix: prefix, token: "ci-" + testToken(t)[4:], nextID: 1000}
	if gitlab {
		f.me = 77
	}
	f.srv = httptest.NewTLSServer(http.HandlerFunc(f.serve))
	t.Cleanup(f.srv.Close)
	return f
}

func (f *fakeCI) add(body, login string, userID int64, typ string) int64 {
	f.mu.Lock()
	defer f.mu.Unlock()
	f.nextID++
	f.comments = append(f.comments, fakeComment{id: f.nextID, body: body, login: login, userID: userID, typ: typ})
	return f.nextID
}

func (f *fakeCI) fail(w http.ResponseWriter, code int) {
	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(code)
	_ = json.NewEncoder(w).Encode(map[string]any{"message": f.errMsg})
}

func (f *fakeCI) author() (string, int64, string) {
	if f.gitlab {
		return "warden-bot", f.me, ""
	}
	if f.me == 0 {
		return botLogin, botID, "Bot"
	}
	return "ci-user", f.me, "User"
}

func (f *fakeCI) serve(w http.ResponseWriter, r *http.Request) {
	f.mu.Lock()
	defer f.mu.Unlock()
	f.reqs = append(f.reqs, r.Method+" "+r.URL.Path)
	cred := r.Header.Get("Authorization")
	if f.gitlab {
		cred = r.Header.Get("PRIVATE-TOKEN")
		if r.Header.Get("Authorization") != "" {
			f.t.Errorf("GitLab got an Authorization header")
		}
	}
	f.auth = append(f.auth, cred)
	want := "Bearer " + f.token
	if f.gitlab {
		want = f.token
	}
	if cred != want {
		f.fail(w, 401)
		return
	}
	if !f.gitlab && r.Header.Get("X-GitHub-Api-Version") == "" {
		f.t.Errorf("no API version header")
	}
	if !strings.HasPrefix(r.URL.Path, f.prefix+"/") {
		f.fail(w, 404)
		return
	}
	p := strings.TrimPrefix(r.URL.Path, f.prefix)
	list, item := "/repos/acme/web/issues/7/comments", "/repos/acme/web/issues/comments/"
	if f.gitlab {
		list, item = "/projects/42/merge_requests/7/notes", "/projects/42/merge_requests/7/notes/"
	}
	switch {
	case r.Method == "GET" && p == "/user":
		switch {
		case f.userCode != 0:
			f.fail(w, f.userCode)
		case f.me == 0:
			f.fail(w, 403) // Resource not accessible by integration
		default:
			_ = json.NewEncoder(w).Encode(map[string]any{"id": f.me, "login": "ci-user", "type": "User"})
		}
	case r.Method == "GET" && p == list:
		if f.listCode != 0 {
			f.fail(w, f.listCode)
			return
		}
		per, _ := strconv.Atoi(r.URL.Query().Get("per_page"))
		page, _ := strconv.Atoi(r.URL.Query().Get("page"))
		if per != commentsPerPage || page < 1 {
			f.fail(w, 400)
			return
		}
		out := []map[string]any{}
		for i := (page - 1) * per; i < len(f.comments) && i < page*per; i++ {
			c := f.comments[i]
			if f.gitlab {
				out = append(out, map[string]any{"id": c.id, "body": c.body, "system": c.system, "author": map[string]any{"id": c.userID, "username": c.login}})
			} else {
				out = append(out, map[string]any{"id": c.id, "body": c.body, "user": map[string]any{"id": c.userID, "login": c.login, "type": c.typ}})
			}
		}
		_ = json.NewEncoder(w).Encode(out)
	case (r.Method == "PATCH" && !f.gitlab || r.Method == "PUT" && f.gitlab) && strings.HasPrefix(p, item):
		if f.redirect != "" {
			http.Redirect(w, r, f.redirect, http.StatusTemporaryRedirect)
			return
		}
		if f.editCode != 0 {
			f.fail(w, f.editCode)
			return
		}
		id, _ := strconv.ParseInt(strings.TrimPrefix(p, item), 10, 64)
		var in struct{ Body string }
		_ = json.NewDecoder(r.Body).Decode(&in)
		for i, c := range f.comments {
			if c.id == id {
				f.comments[i].body = in.Body
				_ = json.NewEncoder(w).Encode(map[string]any{"id": id})
				return
			}
		}
		f.fail(w, 404)
	case r.Method == "POST" && p == list:
		if f.redirect != "" {
			http.Redirect(w, r, f.redirect, http.StatusTemporaryRedirect)
			return
		}
		if f.postCode != 0 {
			f.fail(w, f.postCode)
			return
		}
		var in struct{ Body string }
		_ = json.NewDecoder(r.Body).Decode(&in)
		login, id, typ := f.author()
		f.nextID++
		f.comments = append(f.comments, fakeComment{id: f.nextID, body: in.Body, login: login, userID: id, typ: typ})
		w.WriteHeader(201)
		_ = json.NewEncoder(w).Encode(map[string]any{"id": f.nextID})
	default:
		f.fail(w, 404)
	}
}

func (f *fakeCI) count(method string) int {
	f.mu.Lock()
	defer f.mu.Unlock()
	n := 0
	for _, r := range f.reqs {
		if strings.HasPrefix(r, method+" ") {
			n++
		}
	}
	return n
}

// env is a GitHub Actions or GitLab CI environment pointing at the fake.
func (f *fakeCI) env(t *testing.T) map[string]string {
	if f.gitlab {
		return map[string]string{"GITLAB_CI": "true", "CI_MERGE_REQUEST_IID": "7", "CI_PROJECT_ID": "42",
			"CI_API_V4_URL": f.srv.URL + f.prefix, "WARDEN_GITLAB_TOKEN": f.token, "CI_JOB_TOKEN": "job-token-unused"}
	}
	ev := filepath.Join(t.TempDir(), "event.json")
	if err := os.WriteFile(ev, []byte(`{"action":"synchronize","pull_request":{"number":7,"title":"x"}}`), 0o600); err != nil {
		t.Fatal(err)
	}
	return map[string]string{"GITHUB_ACTIONS": "true", "GITHUB_EVENT_PATH": ev, "GITHUB_REPOSITORY": "acme/web",
		"GITHUB_API_URL": f.srv.URL + f.prefix, "GITHUB_TOKEN": f.token}
}

func (f *fakeCI) deps() deps {
	d := testDeps()
	d.ci = f.srv.Client()
	d.ci.CheckRedirect = noRedirects
	return d
}

// runCI runs the CLI against the Warden fake w with a CI environment, and
// checks that neither token leaks: not printed, the CI token never sent to
// Warden and the Warden token never sent to the CI.
func runCI(t *testing.T, w *fakeServer, ci *fakeCI, env map[string]string, d deps, extra ...string) result {
	t.Helper()
	args := append([]string{"scan", "--url", w.srv.URL, "--org", w.org.String(), "--project", w.prj.String(), "--dir", t.TempDir() + "/repo"}, extra...)
	var out, errOut bytes.Buffer
	getenv := func(k string) string {
		if k == "WARDEN_TOKEN" {
			return w.token
		}
		return env[k]
	}
	code := run(context.Background(), args, getenv, &out, &errOut, d)
	r := result{code, out.String(), errOut.String()}
	for _, secret := range []string{w.token[strings.LastIndex(w.token, "_")+1:], ci.token} {
		if strings.Contains(r.stdout+r.stderr, secret) {
			t.Fatalf("token printed:\n%s\n%s", r.stdout, r.stderr)
		}
	}
	w.mu.Lock()
	for _, a := range w.sawAuth {
		if strings.Contains(a, ci.token) {
			t.Fatal("CI token sent to Warden")
		}
	}
	w.mu.Unlock()
	ci.mu.Lock()
	for _, a := range ci.auth {
		if strings.Contains(a, w.token) {
			t.Fatal("Warden token sent to the CI")
		}
	}
	ci.mu.Unlock()
	return r
}

func failingGate(w *fakeServer, newIDs ...string) {
	w.gate = map[string]any{"status": "completed", "finished": true, "pass": false, "fail_on": "high", "fail_on_kev": false, "kev": 0,
		"counts": map[string]int{"critical": 1, "high": 1},
		"blocking": []map[string]any{
			{"id": "11111111-1111-4111-8111-111111111111", "key": "WEB-1", "title": "Hard-coded <b>credential</b> @mallory", "severity": "critical",
				"rule_id": "gitleaks.aws", "file_path": "src/a.go", "start_line": 3, "description": "DESCRIPTION-NOT-SHOWN", "snippet": "SNIPPET-NOT-SHOWN"},
			{"id": "22222222-2222-4222-8222-222222222222", "key": "WEB-2", "title": "log4j", "severity": "high", "rule_id": "CVE-2021-44228",
				"package_name": "org.apache.logging.log4j:log4j-core", "package_version": "2.14.1", "kev": true},
		},
		"blocking_new": newIDs}
}

func TestCommentGitHubPostsThenUpdates(t *testing.T) {
	w := newFakeServer(t)
	failingGate(w, "22222222-2222-4222-8222-222222222222")
	ci := newFakeCI(t, false, "")
	env := ci.env(t)
	ci.add("LGTM", "alice", 5, "User")

	r := runCI(t, w, ci, env, ci.deps(), "--comment", "github")
	if r.code != exitGateFailed || !strings.Contains(r.stdout, "==> posted the Warden comment on pull request #7") || ci.count("POST") != 1 {
		t.Fatalf("%+v %v", r, ci.reqs)
	}
	body := ci.comments[1].body
	marker := "<!-- warden:" + w.prj.String() + " -->\n"
	for _, want := range []string{marker, "### Warden: failed", "2 blocking issue(s) at or above High", "| **New** KEV | High | [WEB\\-2](<" + w.srv.URL +
		"/orgs/" + w.org.String() + "/issues/22222222-2222-4222-8222-222222222222>) log4j | `CVE-2021-44228` | `org.apache.logging.log4j:log4j-core@2.14.1` |",
		"|  | Critical | [WEB\\-1]", "credential\\<\\/b\\> \\@" + wj + "mallory | `gitleaks.aws` | `src/a.go:3` |", "/scans?scan=" + w.scanID} {
		if !strings.Contains(body, want) {
			t.Errorf("missing %q in\n%s", want, body)
		}
	}
	if !strings.HasPrefix(body, marker) || strings.Contains(body, "NOT-SHOWN") {
		t.Fatal(body)
	}

	// The next run (the gate passes now) updates the same comment.
	w.gate = map[string]any{"status": "completed", "finished": true, "pass": true, "fail_on": "high", "counts": map[string]int{}, "blocking": []any{}, "blocking_new": []any{}}
	r = runCI(t, w, ci, env, ci.deps(), "--comment", "auto")
	if r.code != exitPass || !strings.Contains(r.stdout, "==> updated the Warden comment on pull request #7") || ci.count("POST") != 1 ||
		ci.count("PATCH") != 1 || len(ci.comments) != 2 || !strings.Contains(ci.comments[1].body, "### Warden: passed") {
		t.Fatalf("%+v %v", r, ci.reqs)
	}
}

func TestCommentGitHubIgnoresOthersMarkers(t *testing.T) {
	w := newFakeServer(t)
	failingGate(w)
	marker := "<!-- warden:" + w.prj.String() + " -->"
	fake := marker + "\n### Warden: passed\n"

	// The Actions token (no /user): only github-actions[bot] comments count.
	ci := newFakeCI(t, false, "")
	planted := ci.add(fake, "mallory", 666, "User")
	impostor := ci.add(fake, botLogin, 667, "User") // not a Bot: can't be the Actions bot
	for i := range 150 {                            // our comment is on page 2
		ci.add(fmt.Sprintf("comment %d", i), "alice", 5, "User")
	}
	ci.add(marker+"\r\nold", "other-app[bot]", 99, "Bot")
	ours := ci.add(marker+"\r\nold", botLogin, botID, "Bot")
	r := runCI(t, w, ci, ci.env(t), ci.deps(), "--comment", "github")
	if r.code != exitGateFailed || ci.count("PATCH") != 1 || ci.count("POST") != 0 || !strings.Contains(r.stdout, "updated") {
		t.Fatalf("%+v %v", r, ci.reqs)
	}
	for _, c := range ci.comments {
		if (c.id == planted || c.id == impostor) && c.body != fake || c.id == ours && !strings.Contains(c.body, "Warden: failed") {
			t.Fatalf("%d: %q", c.id, c.body)
		}
	}

	// Only someone else's marker: a new comment, theirs untouched.
	ci = newFakeCI(t, false, "")
	planted = ci.add(fake, "mallory", 666, "User")
	ci.add("<!-- warden:"+w.prj.String()+" --> not alone on the line", botLogin, botID, "Bot")
	r = runCI(t, w, ci, ci.env(t), ci.deps(), "--comment", "github")
	if r.code != exitGateFailed || ci.count("PATCH") != 0 || ci.count("POST") != 1 || ci.comments[0].id != planted || ci.comments[0].body != fake {
		t.Fatalf("%+v %v", r, ci.reqs)
	}

	// A token that can read /user (a PAT): comments by that user id only.
	ci = newFakeCI(t, false, "/api/v3")
	ci.me = 5
	ci.add(fake, botLogin, botID, "Bot")
	ci.add(fake, "ci-user-renamed", 6, "User")
	ours = ci.add(fake, "ci-user", 5, "User")
	r = runCI(t, w, ci, ci.env(t), ci.deps(), "--comment", "github")
	if r.code != exitGateFailed || ci.count("PATCH") != 1 || ci.count("POST") != 0 || ci.comments[2].id != ours || ci.comments[2].body == fake {
		t.Fatalf("%+v %v", r, ci.reqs)
	}
	// GHES: every call went under the API base path.
	for _, q := range ci.reqs {
		if !strings.Contains(q, " /api/v3/") {
			t.Fatal(ci.reqs)
		}
	}
}

func TestCommentPaginationIsCapped(t *testing.T) {
	w := newFakeServer(t)
	ci := newFakeCI(t, false, "")
	for i := range (maxCommentPages + 5) * commentsPerPage {
		ci.add("x"+strconv.Itoa(i), "alice", 5, "User")
	}
	ci.add("<!-- warden:"+w.prj.String()+" -->\nold", botLogin, botID, "Bot") // too far down
	r := runCI(t, w, ci, ci.env(t), ci.deps(), "--comment", "github")
	if r.code != exitPass || ci.count("GET") != 1+maxCommentPages || ci.count("POST") != 1 {
		t.Fatalf("%+v %d", r, len(ci.reqs))
	}
}

func TestCommentUpdateRefusedPostsNew(t *testing.T) {
	w := newFakeServer(t)
	ci := newFakeCI(t, false, "")
	ci.add("<!-- warden:"+w.prj.String()+" -->\nold", botLogin, botID, "Bot")
	ci.editCode, ci.errMsg = 403, "Resource not accessible by integration"
	r := runCI(t, w, ci, ci.env(t), ci.deps(), "--comment", "github")
	if r.code != exitPass || ci.count("PATCH") != 1 || ci.count("POST") != 1 || !strings.Contains(r.stderr, "couldn't update the comment (PATCH") ||
		!strings.Contains(r.stdout, "posted") {
		t.Fatalf("%+v %v", r, ci.reqs)
	}
	// A server error on update isn't a refusal: no duplicate comment.
	ci.editCode = 502
	r = runCI(t, w, ci, ci.env(t), ci.deps(), "--comment", "github")
	if r.code != exitPass || ci.count("POST") != 1 || !strings.Contains(r.stderr, "warning: couldn't comment on pull request #7") {
		t.Fatalf("%+v %v", r, ci.reqs)
	}
}

func TestCommentFailuresNeverChangeTheExitCode(t *testing.T) {
	for name, c := range map[string]struct {
		setup func(*fakeCI)
		want  string
	}{
		"fork (read-only token)": {func(ci *fakeCI) { ci.postCode = 403 }, "HTTP 403: Resource not accessible"},
		"bad token":              {func(ci *fakeCI) { ci.userCode = 401 }, "GET /user: HTTP 401"},
		"listing fails":          {func(ci *fakeCI) { ci.listCode = 500 }, "HTTP 500"},
		"redirect":               {func(ci *fakeCI) { ci.redirect = "https://elsewhere.example/x" }, "HTTP 307"},
		"unreachable":            {func(ci *fakeCI) { ci.srv.Close() }, "GET /user"},
	} {
		t.Run(name, func(t *testing.T) {
			for _, gateFails := range []bool{false, true} {
				w := newFakeServer(t)
				want := exitPass
				if gateFails {
					failingGate(w)
					want = exitGateFailed
				}
				ci := newFakeCI(t, false, "")
				// An API that echoes the token in its message still doesn't get it printed.
				ci.errMsg = "Resource not accessible by integration; token " + ci.token
				env := ci.env(t)
				c.setup(ci)
				r := runCI(t, w, ci, env, ci.deps(), "--comment", "github")
				if r.code != want || !strings.Contains(r.stderr, "warden: warning: couldn't comment on pull request #7") ||
					!strings.Contains(r.stderr, c.want) || strings.Contains(r.stderr, "https://") || strings.Contains(r.stderr, "elsewhere") {
					t.Fatalf("%+v", r)
				}
			}
		})
	}
	// A failed scan exits 2 as before, without commenting.
	w := newFakeServer(t)
	w.statuses = []string{"failed"}
	ci := newFakeCI(t, false, "")
	if r := runCI(t, w, ci, ci.env(t), ci.deps(), "--comment", "github"); r.code != exitError || len(ci.reqs) != 0 {
		t.Fatalf("%+v", r)
	}
}

func TestCommentRedirectIsNotFollowed(t *testing.T) {
	other := newFakeCI(t, false, "")
	w := newFakeServer(t)
	ci := newFakeCI(t, false, "")
	ci.redirect = other.srv.URL + "/repos/acme/web/issues/7/comments"
	r := runCI(t, w, ci, ci.env(t), ci.deps(), "--comment", "github")
	if r.code != exitPass || len(other.reqs) != 0 || !strings.Contains(r.stderr, "HTTP 307") {
		t.Fatalf("%+v %v", r, other.reqs)
	}
}

func TestCommentSkipsAndMisconfiguration(t *testing.T) {
	w := newFakeServer(t)
	ci := newFakeCI(t, false, "")
	gh := ci.env(t)
	with := func(base map[string]string, kv ...string) map[string]string {
		m := map[string]string{}
		for k, v := range base {
			m[k] = v
		}
		for i := 0; i < len(kv); i += 2 {
			m[kv[i]] = kv[i+1]
		}
		return m
	}
	push := filepath.Join(t.TempDir(), "push.json")
	_ = os.WriteFile(push, []byte(`{"ref":"refs/heads/main","issue":{"pull_request":{}}}`), 0o600)
	huge := filepath.Join(t.TempDir(), "huge.json")
	_ = os.WriteFile(huge, []byte(`{"pull_request":{"number":7},"pad":"`+strings.Repeat("a", maxEventFile)+`"}`), 0o600)
	for name, c := range map[string]struct {
		env  map[string]string
		mode string
		want string
	}{
		"off by default":          {gh, "", ""},
		"off":                     {gh, "off", ""},
		"not a pull request":      {with(gh, "GITHUB_EVENT_PATH", push), "github", "warden: no pull request comment: not a pull request event"},
		"auto outside CI":         {map[string]string{}, "auto", "warden: no pull request comment: not running in GitHub Actions or GitLab CI"},
		"no event file":           {with(gh, "GITHUB_EVENT_PATH", ""), "github", "warning: no pull request comment: GITHUB_EVENT_PATH is not set"},
		"event file too big":      {with(gh, "GITHUB_EVENT_PATH", huge), "github", "can't read the event file"},
		"http API":                {with(gh, "GITHUB_API_URL", strings.Replace(ci.srv.URL, "https", "http", 1)), "github", "GITHUB_API_URL: must use https://"},
		"API with credentials":    {with(gh, "GITHUB_API_URL", "https://u:p@api.github.example"), "github", "GITHUB_API_URL: must not have credentials"},
		"no token":                {with(gh, "GITHUB_TOKEN", ""), "github", "GITHUB_TOKEN is not set (the job needs permissions: pull-requests: write)"},
		"token with newline":      {with(gh, "GITHUB_TOKEN", "a\nX-Evil: 1"), "github", "GITHUB_TOKEN doesn't look like a token"},
		"bad repository":          {with(gh, "GITHUB_REPOSITORY", "acme/../../user"), "github", "GITHUB_REPOSITORY must be owner/name"},
		"no merge request":        {map[string]string{"GITLAB_CI": "true"}, "auto", "warden: no pull request comment: not a merge request pipeline"},
		"gitlab without token":    {map[string]string{"CI_MERGE_REQUEST_IID": "3", "CI_PROJECT_ID": "42", "CI_API_V4_URL": "https://gitlab.example/api/v4", "CI_JOB_TOKEN": "x"}, "gitlab", "WARDEN_GITLAB_TOKEN is not set"},
		"gitlab bad project":      {map[string]string{"CI_MERGE_REQUEST_IID": "3", "CI_PROJECT_ID": "42/../1"}, "gitlab", "CI_PROJECT_ID must be a number"},
		"gitlab bad IID":          {map[string]string{"CI_MERGE_REQUEST_IID": "3?x=1"}, "gitlab", "CI_MERGE_REQUEST_IID must be a number"},
		"gitlab http API":         {map[string]string{"CI_MERGE_REQUEST_IID": "3", "CI_PROJECT_ID": "42", "CI_API_V4_URL": "http://gitlab.example/api/v4"}, "gitlab", "CI_API_V4_URL: must use https://"},
		"gitlab API with a query": {map[string]string{"CI_MERGE_REQUEST_IID": "3", "CI_PROJECT_ID": "42", "CI_API_V4_URL": "https://gitlab.example/api/v4?x=1"}, "gitlab", "must not have credentials, a query"},
	} {
		t.Run(name, func(t *testing.T) {
			before := len(ci.reqs)
			var extra []string
			if c.mode != "" {
				extra = []string{"--comment", c.mode}
			}
			r := runCI(t, w, ci, c.env, ci.deps(), extra...)
			if r.code != exitPass || len(ci.reqs) != before || !strings.Contains(r.stderr, c.want) || c.want == "" && r.stderr != "" {
				t.Fatalf("%+v %v", r, ci.reqs)
			}
		})
	}
	r := runCI(t, w, ci, gh, ci.deps(), "--comment", "yes")
	if r.code != exitError || !strings.Contains(r.stderr, "--comment: must be auto, github, gitlab or off") {
		t.Fatalf("%+v", r)
	}
}

func TestCommentGitLab(t *testing.T) {
	w := newFakeServer(t)
	failingGate(w, "11111111-1111-4111-8111-111111111111")
	ci := newFakeCI(t, true, "/gitlab/api/v4") // self-managed under a path
	env := ci.env(t)
	marker := "<!-- warden:" + w.prj.String() + " -->"
	planted := ci.add(marker+"\n### Warden: passed", "mallory", 666, "")
	ci.comments = append(ci.comments, fakeComment{id: 5000, body: marker + "\nsystem", userID: 77, system: true})

	r := runCI(t, w, ci, env, ci.deps(), "--comment", "auto")
	if r.code != exitGateFailed || ci.count("POST") != 1 || ci.count("PUT") != 0 || !strings.Contains(r.stdout, "posted the Warden comment on merge request !7") {
		t.Fatalf("%+v %v", r, ci.reqs)
	}
	body := ci.comments[2].body
	if !strings.HasPrefix(body, marker+"\n") || !strings.Contains(body, "| **New** | Critical | [WEB\\-1]") || ci.comments[0].id != planted ||
		ci.comments[0].body != marker+"\n### Warden: passed" {
		t.Fatal(body)
	}
	for _, a := range ci.auth {
		if a != ci.token {
			t.Fatalf("sent %q, not the WARDEN_GITLAB_TOKEN", a)
		}
	}

	// Next run: the note is updated in place.
	w.gate = map[string]any{"status": "completed", "finished": true, "pass": true, "fail_on": "high", "counts": map[string]int{}, "blocking": []any{}, "blocking_new": []any{}}
	r = runCI(t, w, ci, env, ci.deps(), "--comment", "gitlab")
	if r.code != exitPass || ci.count("PUT") != 1 || ci.count("POST") != 1 || !strings.Contains(ci.comments[2].body, "Warden: passed") ||
		!strings.Contains(r.stdout, "updated the Warden comment on merge request !7") {
		t.Fatalf("%+v %v", r, ci.reqs)
	}
	for _, q := range ci.reqs {
		if !strings.Contains(q, " /gitlab/api/v4/") {
			t.Fatal(ci.reqs)
		}
	}

	// Refused update → a new note; a read-only token → a warning, exit unchanged.
	ci.editCode = 403
	if r := runCI(t, w, ci, env, ci.deps(), "--comment", "gitlab"); r.code != exitPass || ci.count("POST") != 2 {
		t.Fatalf("%+v %v", r, ci.reqs)
	}
	ci.postCode, ci.errMsg = 403, "403 Forbidden"
	ci.editCode = 403
	r = runCI(t, w, ci, env, ci.deps(), "--comment", "gitlab")
	if r.code != exitPass || !strings.Contains(r.stderr, "warning: couldn't comment on merge request !7") || !strings.Contains(r.stderr, "403 Forbidden") {
		t.Fatalf("%+v", r)
	}
	ci.userCode = 401
	if r := runCI(t, w, ci, env, ci.deps(), "--comment", "gitlab"); r.code != exitPass || !strings.Contains(r.stderr, "GET /user: HTTP 401") {
		t.Fatalf("%+v", r)
	}
}

func TestCommentImageScanHasItsOwnMarker(t *testing.T) {
	w := newFakeServer(t)
	ci := newFakeCI(t, false, "")
	ci.add("<!-- warden:"+w.prj.String()+" -->\nsource scan", botLogin, botID, "Bot")
	tar := filepath.Join(t.TempDir(), "api.tar")
	_ = os.WriteFile(tar, []byte("tar"), 0o600)
	args := []string{"scan", "--url", w.srv.URL, "--org", w.org.String(), "--project", w.prj.String(), "--image-tar", tar,
		"--target", "ghcr.io/acme/api", "--comment", "github"}
	env := ci.env(t)
	var out, errOut bytes.Buffer
	getenv := func(k string) string {
		if k == "WARDEN_TOKEN" {
			return w.token
		}
		return env[k]
	}
	code := run(context.Background(), args, getenv, &out, &errOut, ci.deps())
	if code != exitPass || ci.count("POST") != 1 || ci.count("PATCH") != 0 || ci.comments[0].body != "<!-- warden:"+w.prj.String()+" -->\nsource scan" ||
		!strings.HasPrefix(ci.comments[1].body, commentMarker(w.prj, "ghcr.io/acme/api")+"\n") {
		t.Fatalf("%d %s %s %v", code, out.String(), errOut.String(), ci.reqs)
	}
}

func TestCommentHistoryScanHasItsOwnMarker(t *testing.T) {
	prj := uuid.New()
	src, hist := (&options{}).commentTarget(), (&options{history: true}).commentTarget()
	if src != "" || hist != "(history)" || commentMarker(prj, src) == commentMarker(prj, hist) ||
		commentMarker(prj, hist) == commentMarker(prj, "ghcr.io/acme/api") {
		t.Fatal(src, hist)
	}
}
