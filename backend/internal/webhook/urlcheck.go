package webhook

import (
	"context"
	"errors"
	"net"
	"net/netip"
	"net/url"
	"regexp"
	"slices"
	"strconv"
	"strings"
	"time"
)

// Policy is the operator's say over where webhooks may go.
type Policy struct {
	// AllowHosts (webhook.allow_hosts) may use http and private addresses, and
	// may receive Slack messages: exact host names or IP literals, compared
	// case-insensitively, without port. For development and tests only.
	AllowHosts []string
}

// Allowed reports whether host is in AllowHosts.
func (p Policy) Allowed(host string) bool {
	host = strings.ToLower(strings.Trim(host, "[]"))
	return slices.ContainsFunc(p.AllowHosts, func(h string) bool { return strings.ToLower(h) == host })
}

// ValidAllowHost reports whether an allow_hosts entry is a bare host name or
// IP literal (no scheme, port, path or wildcard).
func ValidAllowHost(h string) bool {
	if _, err := netip.ParseAddr(h); err == nil {
		return !strings.Contains(h, "%")
	}
	return len(h) <= 253 && hostName.MatchString(strings.ToLower(h))
}

// Messages for the url field (the web UI shows them as they are).
const (
	MsgInvalid     = "must be a valid URL"
	MsgTooLong     = "must be at most 2048 characters"
	MsgHTTPS       = "must use https"
	MsgUserInfo    = "must not contain a user name or password"
	MsgFragment    = "must not contain a #fragment"
	MsgPrivate     = "resolves to a private address"
	MsgNoResolve   = "the host name doesn't resolve"
	MsgSlack       = "Slack URLs start with https://hooks.slack.com/services/"
	maxURLLen      = 2048
	slackHost      = "hooks.slack.com"
	slackPath      = "/services/"
	resolveTimeout = 5 * time.Second
)

// URLError is a URL the checks refuse; Msg is for the url field.
type URLError struct{ Msg string }

func (e *URLError) Error() string { return "webhook url " + e.Msg }

func refuse(msg string) error { return &URLError{Msg: msg} }

var (
	hostName = regexp.MustCompile(`^[a-z0-9_]([a-z0-9_-]*[a-z0-9_])?(\.[a-z0-9_]([a-z0-9_-]*[a-z0-9_])?)*\.?$`)
	// numericLabel: a host whose last label is a number is an IPv4 address to
	// URL parsers and to getaddrinfo (0x7f.1, 2130706433, 0177.0.0.1); only
	// the canonical dotted form is accepted, so it is checked as an address.
	numericLabel = regexp.MustCompile(`^(0x[0-9a-f]*|[0-9]+)$`)
)

// Target is a parsed, statically checked webhook URL.
type Target struct {
	URL     *url.URL
	Host    string     // lower case, without brackets or port
	IP      netip.Addr // valid when the host is an IP literal
	Allowed bool       // in Policy.AllowHosts
}

// Parse checks a webhook URL without touching the network: https (http only
// for allowed hosts), no user info or fragment, a well-formed host, a refused
// IP literal, and for Slack the Incoming Webhook prefix. Every send repeats it.
func (p Policy) Parse(kind, raw string) (Target, error) {
	if len(raw) > maxURLLen {
		return Target{}, refuse(MsgTooLong)
	}
	for _, c := range []byte(raw) {
		if c <= 0x20 || c >= 0x7f { // IDNs must be given in punycode
			return Target{}, refuse(MsgInvalid)
		}
	}
	u, err := url.Parse(raw)
	if err != nil || u.Opaque != "" || u.Host == "" || (u.Scheme != "https" && u.Scheme != "http") {
		if err == nil && u.Scheme != "" && u.Scheme != "https" && u.Scheme != "http" {
			return Target{}, refuse(MsgHTTPS)
		}
		return Target{}, refuse(MsgInvalid)
	}
	if u.User != nil || strings.Contains(u.Host, "@") {
		return Target{}, refuse(MsgUserInfo)
	}
	if u.Fragment != "" || strings.Contains(raw, "#") {
		return Target{}, refuse(MsgFragment)
	}
	t := Target{URL: u, Host: strings.ToLower(u.Hostname())}
	if port := u.Port(); port != "" {
		if n, err := strconv.Atoi(port); err != nil || n < 1 || n > 65535 || port[0] == '0' {
			return Target{}, refuse(MsgInvalid)
		}
	} else if strings.HasSuffix(u.Host, ":") {
		return Target{}, refuse(MsgInvalid)
	}
	if ip, err := netip.ParseAddr(t.Host); err == nil {
		if ip.Zone() != "" || (ip.Is6() && !strings.HasPrefix(u.Host, "[")) {
			return Target{}, refuse(MsgInvalid)
		}
		t.IP = ip
	} else {
		labels := strings.Split(strings.TrimSuffix(t.Host, "."), ".")
		if len(t.Host) > 253 || !hostName.MatchString(t.Host) || numericLabel.MatchString(labels[len(labels)-1]) {
			return Target{}, refuse(MsgInvalid)
		}
	}
	t.Allowed = p.Allowed(t.Host)
	if u.Scheme != "https" && !t.Allowed {
		return Target{}, refuse(MsgHTTPS)
	}
	if kind == KindSlack && !t.Allowed &&
		(u.Scheme != "https" || t.Host != slackHost || (u.Port() != "" && u.Port() != "443") ||
			!strings.HasPrefix(u.EscapedPath(), slackPath) || len(u.EscapedPath()) == len(slackPath)) {
		return Target{}, refuse(MsgSlack)
	}
	if t.IP.IsValid() && !t.Allowed && Blocked(t.IP) {
		return Target{}, refuse(MsgPrivate)
	}
	return t, nil
}

// Hint is what the API shows of a URL: scheme and host, and "/…" when there
// is more (for Slack the path is the credential).
func (t Target) Hint() string {
	h := t.URL.Scheme + "://" + strings.ToLower(t.URL.Host)
	if (t.URL.Path != "" && t.URL.Path != "/") || t.URL.RawQuery != "" || t.URL.ForceQuery {
		h += "/…"
	}
	return h
}

// Resolver looks up a host's addresses (*net.Resolver).
type Resolver interface {
	LookupNetIP(ctx context.Context, network, host string) ([]netip.Addr, error)
}

// Checker validates URLs at create and update time: Parse, then a DNS lookup,
// so a host that resolves to a private address gets a clear error instead of
// failed deliveries. The lookup is only for the message: Client checks the
// address it actually dials on every delivery, which is what counts.
type Checker struct {
	Policy   Policy
	Resolver Resolver // nil: net.DefaultResolver
}

// Check returns the URL's hint, or a *URLError.
func (c *Checker) Check(ctx context.Context, kind, raw string) (string, error) {
	t, err := c.Policy.Parse(kind, raw)
	if err != nil {
		return "", err
	}
	if t.Allowed || t.IP.IsValid() {
		return t.Hint(), nil
	}
	var r Resolver = net.DefaultResolver
	if c.Resolver != nil {
		r = c.Resolver
	}
	ctx, cancel := context.WithTimeout(ctx, resolveTimeout)
	defer cancel()
	addrs, err := r.LookupNetIP(ctx, "ip", t.Host)
	if err != nil || len(addrs) == 0 {
		var dnsErr *net.DNSError
		if err != nil && !errors.As(err, &dnsErr) && ctx.Err() == nil {
			return "", err
		}
		return "", refuse(MsgNoResolve)
	}
	for _, a := range addrs {
		if Blocked(a) {
			return "", refuse(MsgPrivate)
		}
	}
	return t.Hint(), nil
}
