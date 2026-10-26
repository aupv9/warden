// warden is the CI client: it zips a git working tree, uploads it to a Warden
// server as a scan, waits for the result and applies the scan gate.
//
//	export WARDEN_TOKEN=wdn_...        # an API token with scope scan:write
//	warden scan --url https://warden.example --org ORG_ID --project PROJECT_ID \
//	    [--dir .] [--tools gitleaks,opengrep] [--fail-on high] [--timeout 30m]
//
// Exit status: 0 the gate passed, 1 the gate failed (blocking issues), 2 any
// error (bad arguments, network, authentication, the scan failed or timed out).
//
// The token is read only from $WARDEN_TOKEN (a flag would show up in process
// listings and CI logs) and is never printed. Only https:// servers are
// accepted, except localhost for development.
package main

import (
	"context"
	"errors"
	"flag"
	"fmt"
	"io"
	"net"
	"net/http"
	"net/url"
	"os"
	"os/signal"
	"path/filepath"
	"strings"
	"syscall"
	"time"
	"unicode"

	"github.com/google/uuid"

	"github.com/aupv9/warden/backend/internal/pack"
)

const (
	exitPass       = 0
	exitGateFailed = 1
	exitError      = 2

	usage = `usage: warden scan --url URL --org ORG_ID --project PROJECT_ID [--dir DIR] [--tools a,b] [--fail-on high] [--timeout 30m]
The API token is read from $WARDEN_TOKEN.`
)

func main() {
	ctx, stop := signal.NotifyContext(context.Background(), os.Interrupt, syscall.SIGTERM)
	code := run(ctx, os.Args[1:], os.Getenv, os.Stdout, os.Stderr, defaultDeps())
	stop()
	os.Exit(code)
}

// deps are the pieces tests replace.
type deps struct {
	api    *http.Client // API calls: short timeout, no redirects
	upload *http.Client // the archive upload to object storage
	pack   func(dir, dest, prefix string) (int, error)
	sleep  func(ctx context.Context, d time.Duration) error
	poll   time.Duration // first polling interval (backs off to maxPoll)
}

const maxPoll = 15 * time.Second

func defaultDeps() deps {
	transport := &http.Transport{
		Proxy:                 http.ProxyFromEnvironment,
		DialContext:           (&net.Dialer{Timeout: 10 * time.Second, KeepAlive: 30 * time.Second}).DialContext,
		TLSHandshakeTimeout:   10 * time.Second,
		ResponseHeaderTimeout: 60 * time.Second,
		IdleConnTimeout:       90 * time.Second,
		ForceAttemptHTTP2:     true,
	}
	return deps{
		api:    &http.Client{Transport: transport, Timeout: 60 * time.Second, CheckRedirect: noRedirects},
		upload: &http.Client{Transport: transport, Timeout: 30 * time.Minute, CheckRedirect: noRedirects},
		pack:   pack.Repo,
		sleep:  sleep,
		poll:   2 * time.Second,
	}
}

// noRedirects: a redirect is an error, not something to follow with a bearer
// token (or a presigned upload) attached.
func noRedirects(*http.Request, []*http.Request) error { return http.ErrUseLastResponse }

func sleep(ctx context.Context, d time.Duration) error {
	t := time.NewTimer(d)
	defer t.Stop()
	select {
	case <-ctx.Done():
		return ctx.Err()
	case <-t.C:
		return nil
	}
}

type options struct {
	server         *url.URL
	org, project   uuid.UUID
	dir            string
	tools          []string
	failOn         string
	timeout        time.Duration
	token          string
	stdout, stderr io.Writer
}

func run(ctx context.Context, args []string, getenv func(string) string, stdout, stderr io.Writer, d deps) int {
	if len(args) == 0 || args[0] != "scan" {
		fmt.Fprintln(stderr, usage)
		return exitError
	}
	fs := flag.NewFlagSet("warden scan", flag.ContinueOnError)
	fs.SetOutput(stderr)
	server := fs.String("url", "", "Warden server, e.g. https://warden.example")
	org := fs.String("org", "", "organization id")
	project := fs.String("project", "", "project id")
	dir := fs.String("dir", ".", "git working tree to scan")
	tools := fs.String("tools", "", "comma-separated scanners (default: the project's)")
	failOn := fs.String("fail-on", "high", "critical|high|medium|low")
	timeout := fs.Duration("timeout", 30*time.Minute, "give up (and cancel the scan) after this long")
	if err := fs.Parse(args[1:]); err != nil {
		fmt.Fprintln(stderr, usage)
		return exitError
	}
	o := options{dir: *dir, failOn: *failOn, timeout: *timeout, stdout: stdout, stderr: stderr}
	var problems []string
	var err error
	if o.server, err = checkURL(*server); err != nil {
		problems = append(problems, "--url: "+err.Error())
	}
	if o.org, err = uuid.Parse(*org); err != nil {
		problems = append(problems, "--org: must be an organization id (UUID)")
	}
	if o.project, err = uuid.Parse(*project); err != nil {
		problems = append(problems, "--project: must be a project id (UUID)")
	}
	switch o.failOn {
	case "critical", "high", "medium", "low":
	default:
		problems = append(problems, "--fail-on: must be critical, high, medium or low")
	}
	if o.timeout <= 0 {
		problems = append(problems, "--timeout: must be positive")
	}
	for _, t := range strings.Split(*tools, ",") {
		if t = strings.TrimSpace(t); t != "" {
			o.tools = append(o.tools, t)
		}
	}
	o.token = strings.TrimSpace(getenv("WARDEN_TOKEN"))
	switch {
	case o.token == "":
		problems = append(problems, "WARDEN_TOKEN is not set")
	case !strings.HasPrefix(o.token, "wdn_") || strings.ContainsFunc(o.token, unicode.IsSpace):
		problems = append(problems, "WARDEN_TOKEN doesn't look like a Warden API token (wdn_...)")
	}
	if len(problems) > 0 {
		for _, p := range problems {
			fmt.Fprintln(stderr, "warden:", p)
		}
		fmt.Fprintln(stderr, usage)
		return exitError
	}

	ctx, cancel := context.WithTimeout(ctx, o.timeout)
	defer cancel()
	code, err := scan(ctx, o, d)
	if err != nil {
		fmt.Fprintln(stderr, "warden:", clean(err.Error()))
	}
	return code
}

// checkURL accepts the server URL: https://, or http:// only for localhost,
// without credentials, query or fragment.
func checkURL(raw string) (*url.URL, error) {
	u, err := parseURL(raw)
	if err != nil {
		return nil, err
	}
	if u.RawQuery != "" || u.Fragment != "" {
		return nil, errors.New("must not have a query or fragment")
	}
	return &url.URL{Scheme: u.Scheme, Host: u.Host, Path: strings.TrimRight(u.Path, "/")}, nil
}

// parseURL applies the transport rule to any URL the CLI sends data to (the
// server, and the presigned upload URL the server returns).
func parseURL(raw string) (*url.URL, error) {
	u, err := url.Parse(strings.TrimSpace(raw))
	if err != nil || u.Host == "" || u.Opaque != "" {
		return nil, errors.New("must be an absolute URL such as https://warden.example")
	}
	if u.User != nil {
		return nil, errors.New("must not contain credentials")
	}
	switch u.Scheme {
	case "https":
	case "http":
		if !isLocalhost(u.Hostname()) {
			return nil, errors.New("must use https:// (http:// is accepted only for localhost)")
		}
	default:
		return nil, errors.New("must use https://")
	}
	return u, nil
}

func isLocalhost(host string) bool {
	switch strings.ToLower(host) {
	case "localhost", "127.0.0.1", "::1":
		return true
	}
	return false
}

// clean makes server- or repository-supplied text safe to print in a CI log:
// control characters (terminal escapes, newlines) and bidirectional overrides
// (which can make a file name display as something else) become '?'.
func clean(s string) string {
	return strings.Map(func(r rune) rune {
		if unicode.IsControl(r) || unicode.Is(unicode.Bidi_Control, r) || r == '\u2028' || r == '\u2029' {
			return '?'
		}
		return r
	}, strings.ToValidUTF8(s, "?"))
}

// archiveName turns the directory's name into a file name the server accepts.
func archiveName(dir string) string {
	base := strings.Map(func(r rune) rune {
		if r < 0x80 && (unicode.IsLetter(r) || unicode.IsDigit(r) || r == '-' || r == '_' || r == '.') {
			return r
		}
		return '_'
	}, filepath.Base(dir))
	base = strings.Trim(base, "._")
	if base == "" {
		base = "source"
	}
	if len(base) > 100 {
		base = base[:100]
	}
	return base
}
