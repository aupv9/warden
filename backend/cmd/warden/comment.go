package main

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net/http"
	"net/url"
	"os"
	"regexp"
	"strconv"
	"strings"
	"time"
	"unicode"
)

// --comment posts one summary comment on the pull request (GitHub Actions)
// or merge request (GitLab CI) and updates it in place on later runs. Where
// to comment comes only from the CI's own environment, and the CI token is
// sent only to the CI's API (https), never to the Warden server, and never
// printed. Commenting is best effort: a failure is a warning and never
// changes the exit status.
//
// The comment is found again by a marker on its first line, but only among
// comments written by the token's own identity: anyone who can comment on
// the pull request can post a body that starts with the marker, and updating
// (or deferring to) theirs would let them show a fake "passed".

const (
	commentOff    = "off"
	commentAuto   = "auto"
	commentGitHub = "github"
	commentGitLab = "gitlab"

	// maxCommentPages caps the comments read while looking for ours (100 per
	// page); past it a new comment is posted.
	maxCommentPages = 20
	commentsPerPage = 100
	// maxEventFile caps the GitHub event payload read from GITHUB_EVENT_PATH.
	maxEventFile = 32 << 20
	// commentTimeout: the comment gets its own budget, after the scan's.
	commentTimeout = time.Minute
	// githubActionsBot is the author of comments made with the Actions
	// GITHUB_TOKEN, which can't read /user. "[bot]" logins can't be
	// registered by users, and the type must be Bot as well.
	githubActionsBot = "github-actions[bot]"
)

// ciTarget is where the comment goes.
type ciTarget struct {
	platform string   // commentGitHub or commentGitLab
	api      *url.URL // API base, e.g. https://api.github.com or https://gitlab.example/api/v4
	token    string
	// GitHub: owner/name and the pull request number. GitLab: the numeric
	// project id and the merge request IID.
	repo   string
	number int
}

func (t ciTarget) where() string {
	if t.platform == commentGitHub {
		return "pull request #" + strconv.Itoa(t.number)
	}
	return "merge request !" + strconv.Itoa(t.number)
}

// skipComment is a reason not to comment that isn't a problem (not a pull
// request pipeline, not in CI).
type skipComment string

func (s skipComment) Error() string { return string(s) }

var githubRepo = regexp.MustCompile(`^[A-Za-z0-9_.-]{1,100}/[A-Za-z0-9_.-]{1,100}$`)

// commentTarget reads the CI environment for --comment mode.
func commentTarget(mode string, getenv func(string) string) (ciTarget, error) {
	if mode == commentAuto {
		switch {
		case getenv("GITHUB_ACTIONS") == "true":
			mode = commentGitHub
		case getenv("GITLAB_CI") == "true":
			mode = commentGitLab
		default:
			return ciTarget{}, skipComment("not running in GitHub Actions or GitLab CI")
		}
	}
	if mode == commentGitHub {
		return githubTarget(getenv)
	}
	return gitlabTarget(getenv)
}

func githubTarget(getenv func(string) string) (ciTarget, error) {
	t := ciTarget{platform: commentGitHub}
	path := getenv("GITHUB_EVENT_PATH")
	if path == "" {
		return t, errors.New("GITHUB_EVENT_PATH is not set (not in GitHub Actions?)")
	}
	f, err := os.Open(path)
	if err != nil {
		return t, errors.New("can't read the event file in GITHUB_EVENT_PATH")
	}
	defer f.Close()
	var ev struct {
		PullRequest *struct {
			Number int `json:"number"`
		} `json:"pull_request"`
	}
	if err := json.NewDecoder(io.LimitReader(f, maxEventFile)).Decode(&ev); err != nil {
		return t, errors.New("can't read the event file in GITHUB_EVENT_PATH")
	}
	if ev.PullRequest == nil || ev.PullRequest.Number <= 0 {
		return t, skipComment("not a pull request event")
	}
	t.number = ev.PullRequest.Number
	if t.repo = getenv("GITHUB_REPOSITORY"); !githubRepo.MatchString(t.repo) || strings.Contains(t.repo, "..") {
		return t, errors.New("GITHUB_REPOSITORY must be owner/name")
	}
	api := getenv("GITHUB_API_URL")
	if api == "" {
		api = "https://api.github.com"
	}
	if t.api, err = ciURL(api); err != nil {
		return t, fmt.Errorf("GITHUB_API_URL: %w", err)
	}
	if t.token, err = ciToken(getenv("GITHUB_TOKEN")); err != nil {
		return t, fmt.Errorf("GITHUB_TOKEN %w (the job needs permissions: pull-requests: write)", err)
	}
	return t, nil
}

func gitlabTarget(getenv func(string) string) (ciTarget, error) {
	t := ciTarget{platform: commentGitLab}
	iid := getenv("CI_MERGE_REQUEST_IID")
	if iid == "" {
		return t, skipComment("not a merge request pipeline")
	}
	var err error
	if t.number, err = strconv.Atoi(iid); err != nil || t.number <= 0 {
		return t, errors.New("CI_MERGE_REQUEST_IID must be a number")
	}
	if p, err := strconv.Atoi(getenv("CI_PROJECT_ID")); err != nil || p <= 0 {
		return t, errors.New("CI_PROJECT_ID must be a number")
	} else {
		t.repo = strconv.Itoa(p)
	}
	if t.api, err = ciURL(getenv("CI_API_V4_URL")); err != nil {
		return t, fmt.Errorf("CI_API_V4_URL: %w", err)
	}
	if t.token, err = ciToken(getenv("WARDEN_GITLAB_TOKEN")); err != nil {
		return t, fmt.Errorf("WARDEN_GITLAB_TOKEN %w (a project access token with api scope; CI_JOB_TOKEN can't write notes)", err)
	}
	return t, nil
}

// ciURL accepts the CI's API base URL: https only (the token goes there),
// without credentials, query or fragment.
func ciURL(raw string) (*url.URL, error) {
	u, err := url.Parse(strings.TrimSpace(raw))
	if err != nil || u.Host == "" || u.Opaque != "" {
		return nil, errors.New("must be an absolute https:// URL")
	}
	if u.Scheme != "https" {
		return nil, errors.New("must use https://")
	}
	if u.User != nil || u.RawQuery != "" || u.Fragment != "" {
		return nil, errors.New("must not have credentials, a query or a fragment")
	}
	return &url.URL{Scheme: u.Scheme, Host: u.Host, Path: strings.TrimRight(u.Path, "/")}, nil
}

func ciToken(tok string) (string, error) {
	tok = strings.TrimSpace(tok)
	switch {
	case tok == "":
		return "", errors.New("is not set")
	case len(tok) > 4096 || strings.ContainsFunc(tok, func(r rune) bool { return unicode.IsSpace(r) || unicode.IsControl(r) || r > 0x7e }):
		return "", errors.New("doesn't look like a token")
	}
	return tok, nil
}

// ciError is a failed call to the CI's API.
type ciError struct {
	status int
	msg    string
}

func (e *ciError) Error() string {
	if e.msg == "" {
		return fmt.Sprintf("HTTP %d", e.status)
	}
	return fmt.Sprintf("HTTP %d: %s", e.status, e.msg)
}

// refused: the API understood and said no (permissions, gone, locked), as
// opposed to failing.
func refused(err error) bool {
	var e *ciError
	return errors.As(err, &e) && e.status >= 400 && e.status < 500 && e.status != http.StatusTooManyRequests
}

// ciCall sends a JSON request to the CI's API. Errors carry the status and the
// API's message (cleaned, capped, with the token cut out should it ever be
// echoed), never the request URL or headers.
func (c client) ciCall(ctx context.Context, t ciTarget, method, path string, body, out any) error {
	var rd io.Reader
	if body != nil {
		b, err := json.Marshal(body)
		if err != nil {
			return err
		}
		rd = bytes.NewReader(b)
	}
	// path is built from validated numbers and owner/name; the base has no query.
	req, err := http.NewRequestWithContext(ctx, method, t.api.String()+path, rd)
	if err != nil {
		return errors.New("bad request")
	}
	if t.platform == commentGitHub {
		req.Header.Set("Authorization", "Bearer "+t.token)
		req.Header.Set("Accept", "application/vnd.github+json")
		req.Header.Set("X-GitHub-Api-Version", "2022-11-28")
	} else {
		req.Header.Set("PRIVATE-TOKEN", t.token)
		req.Header.Set("Accept", "application/json")
	}
	req.Header.Set("User-Agent", "warden-cli")
	if body != nil {
		req.Header.Set("Content-Type", "application/json")
	}
	what := strings.SplitN(path, "?", 2)[0]
	resp, err := c.d.ci.Do(req)
	if err != nil {
		return netError(method, what, err)
	}
	defer resp.Body.Close()
	raw, err := io.ReadAll(io.LimitReader(resp.Body, maxResponse))
	if err != nil {
		return netError(method, what, err)
	}
	if resp.StatusCode < 200 || resp.StatusCode > 299 {
		var e struct {
			Message any `json:"message"`
			Error   any `json:"error"`
		}
		_ = json.Unmarshal(raw, &e)
		msg := ""
		for _, m := range []any{e.Message, e.Error} {
			if s, ok := m.(string); ok && s != "" {
				msg = s
				break
			}
		}
		msg = strings.ReplaceAll(msg, t.token, "[token]")
		return fmt.Errorf("%s %s: %w", method, what, &ciError{status: resp.StatusCode, msg: clean(truncate(msg, 200))})
	}
	if out == nil {
		return nil
	}
	if err := json.Unmarshal(raw, out); err != nil {
		return fmt.Errorf("%s %s: unexpected response", method, what)
	}
	return nil
}

// comment posts or updates the summary; problems are warnings only.
func (c client) comment(ctx context.Context, g gate, scanID string) {
	if c.o.comment == "" || c.o.comment == commentOff {
		return
	}
	t, err := commentTarget(c.o.comment, c.o.getenv)
	var skip skipComment
	switch {
	case errors.As(err, &skip):
		fmt.Fprintf(c.o.stderr, "warden: no pull request comment: %s\n", clean(string(skip)))
		return
	case err != nil:
		fmt.Fprintf(c.o.stderr, "warden: warning: no pull request comment: %s\n", clean(err.Error()))
		return
	}
	ctx, cancel := context.WithTimeout(context.WithoutCancel(ctx), commentTimeout)
	defer cancel()
	marker := commentMarker(c.o.project, c.o.target)
	body := c.commentBody(g, scanID)
	var updated bool
	if t.platform == commentGitHub {
		updated, err = c.githubComment(ctx, t, marker, body)
	} else {
		updated, err = c.gitlabComment(ctx, t, marker, body)
	}
	if err != nil {
		msg := clean(strings.ReplaceAll(err.Error(), t.token, "[token]"))
		switch {
		case !refused(err):
		case t.platform == commentGitHub:
			msg += " (the job needs permissions: pull-requests: write; pull requests from forks get a read-only token)"
		default:
			msg += " (WARDEN_GITLAB_TOKEN needs the api scope and access to the project)"
		}
		fmt.Fprintf(c.o.stderr, "warden: warning: couldn't comment on %s: %s\n", t.where(), msg)
		return
	}
	verb := "posted"
	if updated {
		verb = "updated"
	}
	c.printf("==> %s the Warden comment on %s\n", verb, t.where())
}

// hasMarker: the body's first line is exactly the marker.
func hasMarker(body, marker string) bool {
	first, _, _ := strings.Cut(body, "\n")
	return strings.TrimSuffix(first, "\r") == marker
}

type githubUser struct {
	ID    int64  `json:"id"`
	Login string `json:"login"`
	Type  string `json:"type"`
}

// githubComment updates our comment, or posts one. updated reports which.
func (c client) githubComment(ctx context.Context, t ciTarget, marker, body string) (bool, error) {
	// Who are we? A personal or app user token can read /user; the Actions
	// GITHUB_TOKEN can't (403) and comments as github-actions[bot].
	var me githubUser
	err := c.ciCall(ctx, t, "GET", "/user", nil, &me)
	mine := func(u githubUser) bool { return me.ID != 0 && u.ID == me.ID }
	switch {
	case err == nil && me.ID == 0:
		return false, errors.New("GET /user: unexpected response")
	case err == nil:
	case refused(err) && !isStatus(err, http.StatusUnauthorized):
		mine = func(u githubUser) bool { return u.Login == githubActionsBot && u.Type == "Bot" }
	default:
		return false, err
	}
	issue := "/repos/" + t.repo + "/issues/" + strconv.Itoa(t.number)
	var found int64
	for page := 1; page <= maxCommentPages && found == 0; page++ {
		var list []struct {
			ID   int64      `json:"id"`
			Body string     `json:"body"`
			User githubUser `json:"user"`
		}
		q := fmt.Sprintf("/comments?per_page=%d&page=%d", commentsPerPage, page)
		if err := c.ciCall(ctx, t, "GET", issue+q, nil, &list); err != nil {
			return false, err
		}
		for _, cm := range list {
			if cm.ID > 0 && mine(cm.User) && hasMarker(cm.Body, marker) {
				found = cm.ID
				break
			}
		}
		if len(list) < commentsPerPage {
			break
		}
	}
	in := map[string]string{"body": body}
	if found != 0 {
		err := c.ciCall(ctx, t, "PATCH", "/repos/"+t.repo+"/issues/comments/"+strconv.FormatInt(found, 10), in, nil)
		if err == nil {
			return true, nil
		}
		if !refused(err) {
			return false, err
		}
		fmt.Fprintf(c.o.stderr, "warden: warning: couldn't update the comment (%s); posting a new one\n", clean(err.Error()))
	}
	return false, c.ciCall(ctx, t, "POST", issue+"/comments", in, nil)
}

// gitlabComment updates our note, or posts one. updated reports which.
func (c client) gitlabComment(ctx context.Context, t ciTarget, marker, body string) (bool, error) {
	var me struct {
		ID int64 `json:"id"`
	}
	if err := c.ciCall(ctx, t, "GET", "/user", nil, &me); err != nil {
		return false, err
	}
	if me.ID == 0 {
		return false, errors.New("GET /user: unexpected response")
	}
	notes := "/projects/" + t.repo + "/merge_requests/" + strconv.Itoa(t.number) + "/notes"
	var found int64
	for page := 1; page <= maxCommentPages && found == 0; page++ {
		var list []struct {
			ID     int64  `json:"id"`
			Body   string `json:"body"`
			System bool   `json:"system"`
			Author struct {
				ID int64 `json:"id"`
			} `json:"author"`
		}
		q := fmt.Sprintf("?sort=asc&order_by=created_at&per_page=%d&page=%d", commentsPerPage, page)
		if err := c.ciCall(ctx, t, "GET", notes+q, nil, &list); err != nil {
			return false, err
		}
		for _, n := range list {
			if n.ID > 0 && !n.System && n.Author.ID == me.ID && hasMarker(n.Body, marker) {
				found = n.ID
				break
			}
		}
		if len(list) < commentsPerPage {
			break
		}
	}
	in := map[string]string{"body": body}
	if found != 0 {
		err := c.ciCall(ctx, t, "PUT", notes+"/"+strconv.FormatInt(found, 10), in, nil)
		if err == nil {
			return true, nil
		}
		if !refused(err) {
			return false, err
		}
		fmt.Fprintf(c.o.stderr, "warden: warning: couldn't update the comment (%s); posting a new one\n", clean(err.Error()))
	}
	return false, c.ciCall(ctx, t, "POST", notes, in, nil)
}

func isStatus(err error, status int) bool {
	var e *ciError
	return errors.As(err, &e) && e.status == status
}
