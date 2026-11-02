package webhook

import (
	"context"
	"crypto/x509"
	"errors"
	"io"
	"net"
	"net/http"
	"net/http/httptest"
	"net/netip"
	"net/url"
	"strings"
	"sync/atomic"
	"testing"
	"time"
)

// stubResolver answers DNS from a map; a missing name is NXDOMAIN. calls
// counts lookups, so a rebinding stub can answer differently each time.
type stubResolver struct {
	answers map[string][]netip.Addr
	then    map[string][]netip.Addr // after the first lookup of a name
	calls   map[string]int
}

func (s *stubResolver) LookupNetIP(_ context.Context, _, host string) ([]netip.Addr, error) {
	if s.calls == nil {
		s.calls = map[string]int{}
	}
	s.calls[host]++
	if a, ok := s.then[host]; ok && s.calls[host] > 1 {
		return a, nil
	}
	if a, ok := s.answers[host]; ok {
		return a, nil
	}
	return nil, &net.DNSError{Err: "no such host", Name: host, IsNotFound: true}
}

func addrs(s ...string) []netip.Addr {
	var out []netip.Addr
	for _, a := range s {
		out = append(out, netip.MustParseAddr(a))
	}
	return out
}

func TestCheckerResolves(t *testing.T) {
	r := &stubResolver{answers: map[string][]netip.Addr{
		"public.example":   addrs("8.8.8.8", "2606:4700:4700::1111"),
		"internal.example": addrs("10.0.0.5"),
		"mixed.example":    addrs("8.8.8.8", "127.0.0.1"),
		"mapped.example":   addrs("::ffff:169.254.169.254"),
		"metadata.example": addrs("fd00:ec2::254"),
	}}
	c := &Checker{Policy: Policy{AllowHosts: []string{"dev.local"}}, Resolver: r}
	ctx := context.Background()
	if hint, err := c.Check(ctx, KindGeneric, "https://public.example/hook"); err != nil || hint != "https://public.example/…" {
		t.Fatal(hint, err)
	}
	for host, msg := range map[string]string{
		"internal.example": MsgPrivate, "mixed.example": MsgPrivate, "mapped.example": MsgPrivate,
		"metadata.example": MsgPrivate, "nowhere.example": MsgNoResolve, "localhost": MsgNoResolve,
	} {
		_, err := c.Check(ctx, KindGeneric, "https://"+host+"/hook")
		var ue *URLError
		if !errors.As(err, &ue) || ue.Msg != msg {
			t.Errorf("%s: %v", host, err)
		}
	}
	// Allowed hosts and IP literals aren't looked up.
	if _, err := c.Check(ctx, KindGeneric, "http://dev.local/x"); err != nil || r.calls["dev.local"] != 0 {
		t.Fatal(err)
	}
}

// receiver is a test endpoint that counts requests and answers status.
type receiver struct {
	*httptest.Server
	hits   atomic.Int32
	status atomic.Int32
	last   atomic.Pointer[http.Request]
	body   atomic.Pointer[string]
}

func newReceiver(t *testing.T, tlsServer bool) *receiver {
	r := &receiver{}
	r.status.Store(204)
	h := http.HandlerFunc(func(w http.ResponseWriter, req *http.Request) {
		r.hits.Add(1)
		b, _ := io.ReadAll(req.Body)
		s := string(b)
		r.body.Store(&s)
		r.last.Store(req)
		if loc := req.URL.Query().Get("redirect"); loc != "" {
			w.Header().Set("Location", loc)
		}
		w.WriteHeader(int(r.status.Load()))
		_, _ = w.Write([]byte(strings.Repeat("x", 1<<20))) // never stored, read up to the cap
	})
	if tlsServer {
		r.Server = httptest.NewTLSServer(h)
	} else {
		r.Server = httptest.NewServer(h)
	}
	t.Cleanup(r.Close)
	return r
}

func (r *receiver) port() string { u, _ := url.Parse(r.URL); return u.Port() }

func (r *receiver) pool() *x509.CertPool {
	p := x509.NewCertPool()
	p.AddCert(r.Certificate())
	return p
}

func send(c *Client, raw string) Result {
	return c.Send(context.Background(), Request{URL: raw, Kind: KindGeneric, Body: []byte(`{}`),
		Headers: map[string]string{"webhook-id": "d1"}})
}

func TestClientDeliversToAllowedHost(t *testing.T) {
	r := newReceiver(t, false)
	c := NewClient(Policy{AllowHosts: []string{"127.0.0.1"}}, ClientOptions{})
	res := send(c, r.URL+"/hook")
	if !res.Delivered() || res.StatusCode != 204 || r.hits.Load() != 1 {
		t.Fatal(res, r.hits.Load())
	}
	req := r.last.Load()
	if req.Method != "POST" || req.Header.Get("Content-Type") != "application/json" || req.Header.Get("webhook-id") != "d1" ||
		req.Header.Get("User-Agent") != userAgent || *r.body.Load() != `{}` {
		t.Fatal(req.Header)
	}
	for status, want := range map[int32]struct {
		err   string
		retry bool
		gone  bool
	}{
		200: {"", false, false}, 299: {"", false, false},
		400: {ErrHTTPStatus, false, false}, 401: {ErrHTTPStatus, false, false}, 404: {ErrHTTPStatus, false, false},
		410: {ErrHTTPStatus, false, true}, 429: {ErrHTTPStatus, true, false},
		500: {ErrHTTPStatus, true, false}, 503: {ErrHTTPStatus, true, false},
	} {
		r.status.Store(status)
		res := send(c, r.URL+"/hook")
		if res.Error != want.err || res.Retryable() != want.retry || res.Gone() != want.gone || res.StatusCode != int(status) {
			t.Errorf("%d: %+v", status, res)
		}
	}
}

// Without allow_hosts, nothing reaches a loopback receiver: not as an IP
// literal, not through a name that resolves (or later rebinds) to it, not
// through an IPv4-mapped answer, and not over http at all.
func TestClientRefusesInternalAddresses(t *testing.T) {
	r := newReceiver(t, true)
	port := r.port()
	res := &stubResolver{
		answers: map[string][]netip.Addr{
			"loopback.example.com": addrs("127.0.0.1"),
			"mapped.example.com":   addrs("::ffff:127.0.0.1"),
			"rebind.example.com":   addrs("8.8.8.8"),
		},
		// Rebinding: public when checked, loopback when the sender looks again.
		then: map[string][]netip.Addr{"rebind.example.com": addrs("127.0.0.1")},
	}
	checker := &Checker{Resolver: res}
	if _, err := checker.Check(context.Background(), KindGeneric, "https://rebind.example.com:"+port+"/x"); err != nil {
		t.Fatal("the first answer is public:", err)
	}
	c := NewClient(Policy{}, ClientOptions{RootCAs: r.pool(), Resolver: res})
	for _, raw := range []string{
		"https://127.0.0.1:" + port + "/x",
		"https://[::1]:" + port + "/x",
		"https://[::ffff:127.0.0.1]:" + port + "/x",
		"https://loopback.example.com:" + port + "/x",
		"https://mapped.example.com:" + port + "/x",
		"https://rebind.example.com:" + port + "/x",
		"http://loopback.example.com:" + port + "/x",
		"https://0x7f.0.0.1:" + port + "/x",
		"https://2130706433:" + port + "/x",
	} {
		if got := send(c, raw); got.Error != ErrBlockedAddress || got.Retryable() {
			t.Errorf("%s: %+v", raw, got)
		}
	}
	if r.hits.Load() != 0 {
		t.Fatalf("receiver reached %d times", r.hits.Load())
	}
	// The dialer's own check, should the resolver step ever be bypassed.
	if _, err := c.dial(context.Background(), "tcp", "127.0.0.1:"+port); !errors.Is(err, errBlocked) {
		t.Fatal(err)
	}
}

// A redirect is a failed delivery: Warden never follows it, so a public
// endpoint can't bounce it to an internal one.
func TestClientNeverFollowsRedirects(t *testing.T) {
	internal := newReceiver(t, false)
	r := newReceiver(t, false)
	r.status.Store(302)
	c := NewClient(Policy{AllowHosts: []string{"127.0.0.1"}}, ClientOptions{})
	got := send(c, r.URL+"/x?redirect="+url.QueryEscape(internal.URL+"/admin"))
	if got.Error != ErrRedirect || got.StatusCode != 302 || got.Retryable() || internal.hits.Load() != 0 {
		t.Fatal(got, internal.hits.Load())
	}
}

// Proxy settings in the environment are ignored: a proxy would connect on
// Warden's behalf, past the address check.
func TestClientIgnoresProxyEnvironment(t *testing.T) {
	var proxied atomic.Int32
	proxy := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		proxied.Add(1)
		w.WriteHeader(200)
	}))
	defer proxy.Close()
	for _, k := range []string{"HTTP_PROXY", "HTTPS_PROXY", "http_proxy", "https_proxy", "ALL_PROXY"} {
		t.Setenv(k, proxy.URL)
	}
	t.Setenv("NO_PROXY", "")
	r := newReceiver(t, true)
	// example.com is in the test certificate; the stub resolves it to the receiver.
	res := &stubResolver{answers: map[string][]netip.Addr{"example.com": addrs("127.0.0.1")}}
	c := NewClient(Policy{AllowHosts: []string{"example.com"}}, ClientOptions{RootCAs: r.pool(), Resolver: res})
	if c.http.Transport.(*http.Transport).Proxy != nil {
		t.Fatal("transport has a proxy func")
	}
	got := send(c, "https://example.com:"+r.port()+"/x")
	if !got.Delivered() || r.hits.Load() != 1 || proxied.Load() != 0 {
		t.Fatal(got, r.hits.Load(), proxied.Load())
	}
}

func TestClientErrors(t *testing.T) {
	r := newReceiver(t, true)
	res := &stubResolver{answers: map[string][]netip.Addr{"example.com": addrs("127.0.0.1")}}
	allowed := Policy{AllowHosts: []string{"example.com", "127.0.0.1", "nowhere.example"}}

	// Untrusted certificate.
	c := NewClient(allowed, ClientOptions{Resolver: res})
	if got := send(c, "https://example.com:"+r.port()+"/x"); got.Error != ErrTLS || !got.Retryable() {
		t.Fatal(got)
	}
	// Unknown host.
	if got := send(c, "https://nowhere.example/x"); got.Error != ErrDNS || !got.Retryable() {
		t.Fatal(got)
	}
	// Nothing listening.
	l, _ := net.Listen("tcp", "127.0.0.1:0")
	closed := l.Addr().String()
	l.Close()
	if got := send(c, "http://"+closed+"/x"); got.Error != ErrConnect || !got.Retryable() {
		t.Fatal(got)
	}
	// Too slow.
	slow := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, req *http.Request) {
		select {
		case <-req.Context().Done():
		case <-time.After(time.Second):
		}
	}))
	defer slow.Close()
	ctx, cancel := context.WithTimeout(context.Background(), 200*time.Millisecond)
	defer cancel()
	if got := c.Send(ctx, Request{URL: slow.URL, Kind: KindGeneric, Body: []byte(`{}`)}); got.Error != ErrTimeout || !got.Retryable() {
		t.Fatal(got)
	}
	// TLS below 1.2 is refused.
	if NewClient(allowed, ClientOptions{}).http.Transport.(*http.Transport).TLSClientConfig.MinVersion < 0x0303 {
		t.Fatal("TLS minimum below 1.2")
	}
}
