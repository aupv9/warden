package registry

import (
	"context"
	"crypto/tls"
	"crypto/x509"
	"encoding/base64"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net/http"
	"net/netip"
	"net/url"
	"regexp"
	"strings"
	"time"

	"golang.org/x/net/publicsuffix"

	"github.com/aupv9/warden/backend/internal/webhook"
)

const (
	maxRedirects    = 5
	maxTokenBytes   = 64 << 10
	maxErrorBody    = 64 << 10
	userAgent       = "Warden-Registry/1"
	defaultDial     = 10 * time.Second
	defaultHeader   = 30 * time.Second
	defaultIdle     = 60 * time.Second
	checkTimeout    = 30 * time.Second
	maxHeaderBytes  = 64 << 10
	maxChallengeLen = 4 << 10
)

// Options configure a Client.
type Options struct {
	// AllowHosts (registry.allow_hosts) may be reached over plain http and at
	// private addresses: exact host names or IP literals, without port.
	AllowHosts []string
	// RootCAs replaces the system roots (tests).
	RootCAs *x509.CertPool
	// Resolver replaces DNS (tests).
	Resolver webhook.Resolver
	// DialTimeout, HeaderTimeout (request sent to response headers) and
	// IdleTimeout (a body making no progress); 0 means the default.
	DialTimeout, HeaderTimeout, IdleTimeout time.Duration
}

// Client pulls images and checks credentials. Build it with NewClient; it is
// safe for concurrent use (each pull gets its own connections).
type Client struct {
	opts   Options
	policy webhook.Policy
}

func NewClient(o Options) *Client {
	if o.DialTimeout == 0 {
		o.DialTimeout = defaultDial
	}
	if o.HeaderTimeout == 0 {
		o.HeaderTimeout = defaultHeader
	}
	if o.IdleTimeout == 0 {
		o.IdleTimeout = defaultIdle
	}
	return &Client{opts: o, policy: webhook.Policy{AllowHosts: o.AllowHosts}}
}

// session is one pull or check against one registry: its own transport (so
// nothing is shared across orgs), the credentials, and the token it earned.
type session struct {
	c      *Client
	http   *http.Client
	tr     *http.Transport
	origin *url.URL // scheme://api host[:port]
	site   string   // the reference's host name: token realms must be on its site
	creds  *Credentials
	scope  string // token scope ("repository:<name>:pull"), "" for a check
	authz  string // Authorization for the origin, once earned
	probed bool   // the origin's scheme is settled
}

func (c *Client) session(host string, creds *Credentials, scope string) *session {
	guard := &webhook.Dialer{Allowed: c.policy.Allowed, Resolver: c.opts.Resolver, Timeout: c.opts.DialTimeout}
	tr := &http.Transport{
		// No proxy: HTTPS_PROXY in the worker's environment would make the
		// proxy, not the guard, choose the address.
		Proxy:                  nil,
		DialContext:            guard.DialContext,
		TLSClientConfig:        &tls.Config{MinVersion: tls.VersionTLS12, RootCAs: c.opts.RootCAs},
		TLSHandshakeTimeout:    c.opts.DialTimeout,
		ResponseHeaderTimeout:  c.opts.HeaderTimeout,
		MaxResponseHeaderBytes: maxHeaderBytes,
		MaxIdleConnsPerHost:    2,
		IdleConnTimeout:        30 * time.Second,
		// Blobs are compressed already; a transparently gunzipped body would
		// no longer match its digest.
		DisableCompression: true,
		ForceAttemptHTTP2:  true,
	}
	name, _, _ := strings.Cut(host, ":")
	return &session{
		c: c, tr: tr, creds: creds, scope: scope, site: name,
		origin: &url.URL{Scheme: "https", Host: apiHost(host)},
		http: &http.Client{Transport: tr, CheckRedirect: func(*http.Request, []*http.Request) error {
			return http.ErrUseLastResponse // followed by hand (follow)
		}},
	}
}

func (s *session) close() { s.tr.CloseIdleConnections() }

func (s *session) allowed(host string) bool { return s.c.policy.Allowed(host) }

// checkURL: https, or http to an allowed host; no user info. The address is
// the dialer's to check.
func (s *session) checkURL(u *url.URL) *Error {
	switch {
	case u.User != nil:
		return fail(CodeBlocked, "URL with user info")
	case u.Host == "" || u.Hostname() == "":
		return fail(CodeBlocked, "URL without host")
	case u.Scheme == "https":
		return nil
	case u.Scheme == "http" && s.allowed(u.Hostname()):
		return nil
	}
	return fail(CodeBlocked, fmt.Sprintf("%s URL to %s (only https)", truncate(u.Scheme), truncate(u.Host)))
}

func sameOrigin(a, b *url.URL) bool {
	return a.Scheme == b.Scheme && strings.EqualFold(a.Host, b.Host)
}

// where names a URL in errors: scheme, host and path, never the query.
func where(u *url.URL) string { return truncate(u.Scheme + "://" + u.Host + u.EscapedPath()) }

// response is an answer with its body guarded by the idle timeout; Close
// releases the request's context.
type response struct {
	*http.Response
	url *url.URL // where it came from (after redirects)
}

// idleBody cancels its request when a read makes no progress for d.
type idleBody struct {
	rc     io.ReadCloser
	timer  *time.Timer
	d      time.Duration
	cancel context.CancelFunc
}

func (b *idleBody) Read(p []byte) (int, error) {
	n, err := b.rc.Read(p)
	if n > 0 {
		b.timer.Reset(b.d)
	}
	return n, err
}

func (b *idleBody) Close() error {
	b.timer.Stop()
	err := b.rc.Close()
	b.cancel()
	return err
}

// follow GETs u and follows redirects by hand: every hop is re-checked
// (checkURL, then the dialer's address guard) and gets Authorization only
// when it is the registry's origin. Signed CDN URLs carry their own query
// credentials, which go only where the registry pointed.
func (s *session) follow(ctx context.Context, u *url.URL, accept []string) (*response, error) {
	for hop := 0; ; hop++ {
		if err := s.checkURL(u); err != nil {
			return nil, err
		}
		rctx, cancel := context.WithCancel(ctx)
		req, err := http.NewRequestWithContext(rctx, http.MethodGet, u.String(), nil)
		if err != nil {
			cancel()
			return nil, fail(CodeFailed, "bad URL "+where(u))
		}
		req.Header.Set("User-Agent", userAgent)
		if len(accept) > 0 {
			req.Header.Set("Accept", strings.Join(accept, ", "))
		}
		if s.authz != "" && sameOrigin(u, s.origin) {
			req.Header.Set("Authorization", s.authz)
		}
		resp, err := s.http.Do(req)
		if err != nil {
			cancel()
			if hop == 0 && s.downgrade(u, err) {
				u = &url.URL{Scheme: "http", Host: u.Host, Path: u.Path, RawPath: u.RawPath, RawQuery: u.RawQuery}
				hop--
				continue
			}
			return nil, s.transportError(ctx, u, err)
		}
		if sameOrigin(u, s.origin) {
			s.probed = true
		}
		switch resp.StatusCode {
		case http.StatusMovedPermanently, http.StatusFound, http.StatusSeeOther,
			http.StatusTemporaryRedirect, http.StatusPermanentRedirect:
			loc := resp.Header.Get("Location")
			drain(resp.Body)
			cancel()
			if hop >= maxRedirects {
				return nil, fail(CodeFailed, "too many redirects from "+where(u))
			}
			next, err := u.Parse(loc)
			if err != nil || loc == "" {
				return nil, fail(CodeFailed, "bad redirect from "+where(u))
			}
			u = next
			continue
		}
		t := time.AfterFunc(s.c.opts.IdleTimeout, cancel)
		resp.Body = &idleBody{rc: resp.Body, timer: t, d: s.c.opts.IdleTimeout, cancel: cancel}
		return &response{Response: resp, url: u}, nil
	}
}

// downgrade: an allowed host whose https attempt got a plain-http answer is
// tried once over http (Docker's insecure registries), before anything was
// sent to it.
func (s *session) downgrade(u *url.URL, err error) bool {
	var rec tls.RecordHeaderError
	// net/http replaces the RecordHeaderError of an answer that looks like
	// HTTP with this message.
	plain := errors.As(err, &rec) || strings.Contains(err.Error(), "server gave HTTP response to HTTPS client")
	if s.probed || u.Scheme != "https" || !sameOrigin(u, s.origin) || !s.allowed(u.Hostname()) || !plain {
		return false
	}
	s.origin = &url.URL{Scheme: "http", Host: s.origin.Host}
	s.probed = true
	return true
}

// transportError maps a failed request onto an Error.
func (s *session) transportError(ctx context.Context, u *url.URL, err error) *Error {
	if errors.Is(err, webhook.ErrRefused) {
		return fail(CodeBlocked, "refused address for "+truncate(u.Host))
	}
	e := fail(CodeFailed, fmt.Sprintf("%s: %v", where(u), redactURLError(err)))
	e.Unreachable = ctx.Err() == nil
	return e
}

// redactURLError drops the URL (and its query) from a *url.Error.
func redactURLError(err error) error {
	var ue *url.Error
	if errors.As(err, &ue) {
		return ue.Err
	}
	return err
}

func drain(rc io.ReadCloser) {
	_, _ = io.Copy(io.Discard, io.LimitReader(rc, maxErrorBody))
	_ = rc.Close()
}

// get requests path on the registry; a 401 from the registry itself starts
// the auth flow once per request (a token can expire during a long pull).
func (s *session) get(ctx context.Context, path string, accept []string) (*response, error) {
	for authed := false; ; authed = true {
		u := &url.URL{Scheme: s.origin.Scheme, Host: s.origin.Host, Path: path}
		resp, err := s.follow(ctx, u, accept)
		if err != nil {
			return nil, err
		}
		if resp.StatusCode != http.StatusUnauthorized || !sameOrigin(resp.url, s.origin) || authed {
			return resp, nil
		}
		challenges := resp.Header.Values("WWW-Authenticate")
		drain(resp.Body)
		if err := s.authenticate(ctx, challenges); err != nil {
			return nil, err
		}
	}
}

// statusError maps an unexpected answer onto an Error (and closes it). A
// refusal from a redirect hop (an expired CDN signature) isn't about the
// credentials.
func (s *session) statusError(resp *response, what string) *Error {
	drain(resp.Body)
	code := CodeFailed
	switch resp.StatusCode {
	case http.StatusUnauthorized, http.StatusForbidden:
		if sameOrigin(resp.url, s.origin) {
			code = CodeUnauthorized
		}
	case http.StatusNotFound:
		code = CodeNotFound
	}
	return fail(code, fmt.Sprintf("%s: HTTP %d from %s", what, resp.StatusCode, where(resp.url)))
}

type challenge struct {
	scheme string
	params map[string]string
}

var (
	tchar   = regexp.MustCompile("^[!#$%&'*+.^_`|~0-9A-Za-z-]+")
	token68 = regexp.MustCompile(`^[A-Za-z0-9._~+/-]+=*`)
)

// parseChallenges reads WWW-Authenticate values (RFC 9110 §11.6.1): schemes
// with auth-params, several per header. token68 forms are skipped.
func parseChallenges(headers []string) []challenge {
	var out []challenge
	for _, h := range headers {
		if len(h) > maxChallengeLen {
			continue
		}
		var cur *challenge
		rest := strings.TrimLeft(h, " \t,")
		for rest != "" {
			tok := tchar.FindString(rest)
			if tok == "" {
				break
			}
			r := strings.TrimLeft(rest[len(tok):], " \t")
			if strings.HasPrefix(r, "=") && cur != nil {
				val, r2, ok := paramValue(strings.TrimLeft(r[1:], " \t"))
				if !ok {
					break
				}
				cur.params[strings.ToLower(tok)] = val
				rest = r2
			} else {
				out = append(out, challenge{scheme: strings.ToLower(tok), params: map[string]string{}})
				cur = &out[len(out)-1]
				rest = r
				// "Negotiate abc==": a token68, not params; skipped.
				if m := token68.FindString(rest); m != "" {
					if after := strings.TrimLeft(rest[len(m):], " \t"); after == "" || after[0] == ',' {
						rest = after
					}
				}
			}
			rest = strings.TrimLeft(rest, " \t,")
		}
	}
	return out
}

// paramValue reads a token or a quoted-string.
func paramValue(s string) (string, string, bool) {
	if !strings.HasPrefix(s, `"`) {
		tok := tchar.FindString(s)
		return tok, s[len(tok):], tok != ""
	}
	var b strings.Builder
	for i := 1; i < len(s); i++ {
		switch c := s[i]; c {
		case '\\':
			if i+1 >= len(s) {
				return "", "", false
			}
			i++
			b.WriteByte(s[i])
		case '"':
			return b.String(), s[i+1:], true
		default:
			b.WriteByte(c)
		}
	}
	return "", "", false
}

// sameSite reports whether a token realm's host may receive the registry
// credentials: the registry's own host, or a host under the same registrable
// domain (eTLD+1 by the public suffix list). Registries pick their realm, and
// the big ones put it next door: Docker Hub (registry-1.docker.io →
// auth.docker.io), GitLab (registry.gitlab.com → gitlab.com, and
// self-hosted registry.example.com → gitlab.example.com). Whoever controls
// the domain controls both names, so the password stays with the party the
// org gave it to; a realm anywhere else (a compromised registry pointing it
// at a collector) gets nothing. IP literals and single-label names must match
// exactly.
func sameSite(realmHost, registryHost string) bool {
	a, b := strings.ToLower(strings.TrimSuffix(realmHost, ".")), strings.ToLower(strings.TrimSuffix(registryHost, "."))
	if a == b {
		return true
	}
	if _, err := netip.ParseAddr(a); err == nil {
		return false
	}
	if _, err := netip.ParseAddr(b); err == nil {
		return false
	}
	sa, err1 := publicsuffix.EffectiveTLDPlusOne(a)
	sb, err2 := publicsuffix.EffectiveTLDPlusOne(b)
	return err1 == nil && err2 == nil && sa == sb
}

var tokenChars = regexp.MustCompile(`^[\x21-\x7e]+$`)

// authenticate answers the registry's challenge: Bearer (a token from the
// realm, with the credentials only when the realm is on the registry's site)
// or Basic (the credentials, to the registry's origin only).
func (s *session) authenticate(ctx context.Context, headers []string) error {
	var bearer, basic *challenge
	cs := parseChallenges(headers)
	for i := range cs {
		switch {
		case cs[i].scheme == "bearer" && bearer == nil:
			bearer = &cs[i]
		case cs[i].scheme == "basic" && basic == nil:
			basic = &cs[i]
		}
	}
	switch {
	case bearer != nil:
		return s.token(ctx, bearer.params)
	case basic != nil && s.creds != nil:
		s.authz = basicAuth(s.creds)
		return nil
	case basic != nil:
		return fail(CodeUnauthorized, "the registry wants credentials and the org has none for "+truncate(s.origin.Host))
	}
	return fail(CodeUnauthorized, "401 without a supported challenge from "+truncate(s.origin.Host))
}

func basicAuth(c *Credentials) string {
	return "Basic " + base64.StdEncoding.EncodeToString([]byte(c.Username+":"+c.Password))
}

func (s *session) token(ctx context.Context, params map[string]string) error {
	realm, err := url.Parse(params["realm"])
	if err != nil || params["realm"] == "" || !realm.IsAbs() {
		return fail(CodeFailed, "bad token realm")
	}
	if e := s.checkURL(realm); e != nil {
		e.Detail = "token realm: " + e.Detail
		return e
	}
	send := s.creds != nil
	if send && !sameSite(realm.Hostname(), s.site) {
		return fail(CodeBlocked, fmt.Sprintf("token realm %s is not on the site of %s; credentials not sent",
			truncate(realm.Host), truncate(s.site)))
	}
	q := realm.Query()
	if v := params["service"]; v != "" {
		q.Set("service", v)
	}
	// Only ever pull: the challenge's own scope is ignored.
	if s.scope != "" {
		q.Set("scope", s.scope)
	}
	realm.RawQuery = q.Encode()
	rctx, cancel := context.WithTimeout(ctx, s.c.opts.HeaderTimeout+s.c.opts.IdleTimeout)
	defer cancel()
	req, err := http.NewRequestWithContext(rctx, http.MethodGet, realm.String(), nil)
	if err != nil {
		return fail(CodeFailed, "bad token realm")
	}
	req.Header.Set("User-Agent", userAgent)
	if send {
		req.Header.Set("Authorization", basicAuth(s.creds))
	}
	// Token endpoints don't redirect; one that does isn't followed (the
	// credentials were for this URL only).
	resp, err := s.http.Do(req)
	if err != nil {
		e := s.transportError(ctx, realm, err)
		e.Detail = "token realm: " + e.Detail
		return e
	}
	defer drain(resp.Body)
	switch {
	case resp.StatusCode == http.StatusUnauthorized || resp.StatusCode == http.StatusForbidden:
		return fail(CodeUnauthorized, fmt.Sprintf("token realm %s answered HTTP %d", truncate(realm.Host), resp.StatusCode))
	case resp.StatusCode != http.StatusOK:
		return fail(CodeFailed, fmt.Sprintf("token realm %s answered HTTP %d", truncate(realm.Host), resp.StatusCode))
	}
	raw, err := io.ReadAll(io.LimitReader(resp.Body, maxTokenBytes+1))
	if err != nil || len(raw) > maxTokenBytes {
		return fail(CodeFailed, "token response unreadable or too large")
	}
	var t struct {
		Token       string `json:"token"`
		AccessToken string `json:"access_token"`
	}
	if err := json.Unmarshal(raw, &t); err != nil {
		return fail(CodeFailed, "token response is not JSON")
	}
	tok := t.Token
	if tok == "" {
		tok = t.AccessToken
	}
	if len(tok) > 16<<10 || !tokenChars.MatchString(tok) {
		return fail(CodeFailed, "token response without a usable token")
	}
	s.authz = "Bearer " + tok
	return nil
}
