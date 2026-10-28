package webhook

import (
	"bytes"
	"context"
	"crypto/tls"
	"crypto/x509"
	"errors"
	"io"
	"net"
	"net/http"
	"net/netip"
	"syscall"
	"time"
)

const (
	// Timeout bounds one delivery attempt, connect to last header byte.
	Timeout = 10 * time.Second
	// maxResponse is how much of a response body is read (then discarded) so
	// the connection closes cleanly; the rest is never read.
	maxResponse = 64 << 10
	userAgent   = "Warden-Webhooks/1"
)

// errBlocked: the address to dial is refused (Blocked).
var errBlocked = errors.New("webhook: refused address")

// Client sends webhook requests. Build it with NewClient.
type Client struct {
	policy Policy
	http   *http.Client
	lookup func(ctx context.Context, host string) ([]netip.Addr, error)
}

// ClientOptions are for tests.
type ClientOptions struct {
	// RootCAs replaces the system roots (an httptest TLS server's certificate).
	RootCAs *x509.CertPool
	// Resolver replaces DNS (a rebinding stub).
	Resolver Resolver
}

// NewClient returns the SSRF-safe client:
//   - Proxy is nil: an HTTPS_PROXY in the worker's environment would otherwise
//     make the proxy, not Warden, connect, and the address check would see only
//     the proxy.
//   - DialContext resolves the host itself, refuses blocked addresses, and
//     dials the checked IP; the dialer's Control re-checks the socket address,
//     so nothing reaches a refused address whatever the resolver returned
//     (DNS rebinding: the check is on the address dialled, not one looked up
//     earlier).
//   - Redirects are never followed (a 3xx is a failed delivery), so a public
//     endpoint can't bounce Warden to an internal one.
//   - TLS 1.2 or later, certificates verified; one connection per delivery.
func NewClient(p Policy, o ClientOptions) *Client {
	c := &Client{policy: p}
	var r Resolver = net.DefaultResolver
	if o.Resolver != nil {
		r = o.Resolver
	}
	c.lookup = func(ctx context.Context, host string) ([]netip.Addr, error) {
		return r.LookupNetIP(ctx, "ip", host)
	}
	tr := &http.Transport{
		Proxy:                  nil,
		DialContext:            c.dial,
		TLSClientConfig:        &tls.Config{MinVersion: tls.VersionTLS12, RootCAs: o.RootCAs},
		TLSHandshakeTimeout:    Timeout,
		ResponseHeaderTimeout:  Timeout,
		MaxResponseHeaderBytes: 16 << 10,
		DisableKeepAlives:      true,
		DisableCompression:     true,
		ForceAttemptHTTP2:      true,
	}
	c.http = &http.Client{
		Transport: tr,
		Timeout:   Timeout,
		CheckRedirect: func(*http.Request, []*http.Request) error {
			return http.ErrUseLastResponse
		},
	}
	return c
}

// dial connects to addr ("host:port" from the request URL) through a checked IP.
func (c *Client) dial(ctx context.Context, network, addr string) (net.Conn, error) {
	host, port, err := net.SplitHostPort(addr)
	if err != nil {
		return nil, err
	}
	allowed := c.policy.Allowed(host)
	var ips []netip.Addr
	if ip, err := netip.ParseAddr(host); err == nil {
		ips = []netip.Addr{ip}
	} else if ips, err = c.lookup(ctx, host); err != nil {
		return nil, err
	}
	d := &net.Dialer{Control: func(_, address string, _ syscall.RawConn) error {
		ap, err := netip.ParseAddrPort(address)
		if err != nil || (!allowed && Blocked(ap.Addr())) {
			return errBlocked
		}
		return nil
	}}
	firstErr := error(&net.DNSError{Err: "no addresses", Name: host, IsNotFound: true})
	blocked := false
	for _, ip := range ips {
		if !allowed && Blocked(ip) {
			blocked = true
			continue
		}
		conn, err := d.DialContext(ctx, network, net.JoinHostPort(ip.Unmap().String(), port))
		if err == nil {
			return conn, nil
		}
		if ctx.Err() != nil {
			return nil, err
		}
		firstErr = err
	}
	if blocked {
		// Some address was refused: say so, even if another one failed to
		// connect, so the delivery log explains the real problem.
		return nil, errBlocked
	}
	return nil, firstErr
}

// Request is one delivery attempt.
type Request struct {
	URL     string
	Kind    string
	Headers map[string]string
	Body    []byte
}

// Result is the outcome of one attempt: StatusCode when an answer came, Error
// (a delivery error code) unless it was a 2xx.
type Result struct {
	StatusCode int
	Error      string
}

// Delivered reports a 2xx answer.
func (r Result) Delivered() bool { return r.Error == "" }

// Retryable: timeouts, DNS and connection failures, 429 and 5xx may succeed
// later. Refused addresses, redirects and other 4xx won't.
func (r Result) Retryable() bool {
	switch r.Error {
	case ErrTimeout, ErrDNS, ErrConnect, ErrTLS:
		return true
	case ErrHTTPStatus:
		return r.StatusCode == http.StatusTooManyRequests || r.StatusCode >= 500
	}
	return false
}

// Gone: the receiver answered 410, so the webhook is turned off.
func (r Result) Gone() bool { return r.StatusCode == http.StatusGone }

// Send POSTs the body. The URL is checked again (Parse) because the policy may
// have changed since it was stored.
func (c *Client) Send(ctx context.Context, req Request) Result {
	t, err := c.policy.Parse(req.Kind, req.URL)
	if err != nil {
		return Result{Error: ErrBlockedAddress}
	}
	ctx, cancel := context.WithTimeout(ctx, Timeout)
	defer cancel()
	hr, err := http.NewRequestWithContext(ctx, http.MethodPost, t.URL.String(), bytes.NewReader(req.Body))
	if err != nil {
		return Result{Error: ErrConnect}
	}
	hr.Header.Set("Content-Type", "application/json")
	hr.Header.Set("User-Agent", userAgent)
	for k, v := range req.Headers {
		hr.Header.Set(k, v)
	}
	resp, err := c.http.Do(hr)
	if err != nil {
		return Result{Error: classify(err)}
	}
	_, _ = io.Copy(io.Discard, io.LimitReader(resp.Body, maxResponse))
	_ = resp.Body.Close()
	switch {
	case resp.StatusCode >= 200 && resp.StatusCode < 300:
		return Result{StatusCode: resp.StatusCode}
	case resp.StatusCode >= 300 && resp.StatusCode < 400:
		return Result{StatusCode: resp.StatusCode, Error: ErrRedirect}
	default:
		return Result{StatusCode: resp.StatusCode, Error: ErrHTTPStatus}
	}
}

// classify maps a transport error onto a delivery error code.
func classify(err error) string {
	var (
		dnsErr   *net.DNSError
		netErr   net.Error
		certErr  *tls.CertificateVerificationError
		alertErr tls.AlertError
		recErr   tls.RecordHeaderError
		authErr  x509.UnknownAuthorityError
		hostErr  x509.HostnameError
		invErr   x509.CertificateInvalidError
	)
	switch {
	case errors.Is(err, errBlocked):
		return ErrBlockedAddress
	case errors.Is(err, context.DeadlineExceeded) || (errors.As(err, &netErr) && netErr.Timeout()):
		return ErrTimeout
	case errors.As(err, &dnsErr):
		return ErrDNS
	case errors.As(err, &certErr), errors.As(err, &alertErr), errors.As(err, &recErr),
		errors.As(err, &authErr), errors.As(err, &hostErr), errors.As(err, &invErr):
		return ErrTLS
	}
	return ErrConnect
}
