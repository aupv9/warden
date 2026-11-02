package webhook

import (
	"errors"
	"net/netip"
	"net/url"
	"strconv"
	"strings"
	"testing"
)

// mustBlock is the oracle for Blocked, written from the address ranges
// rather than the prefix list: the IPv4 address an IPv6 address embeds
// (mapped, compatible, NAT64, 6to4) is judged as itself, and anything
// loopback, private, link-local, unspecified, multicast or a known cloud
// metadata address is refused.
func mustBlock(ip netip.Addr) bool {
	if !ip.IsValid() || ip.Zone() != "" {
		return true
	}
	if ip.Is6() {
		b := ip.As16()
		var v4 [4]byte
		embeds := true
		switch {
		case ip.Is4In6(), netip.MustParsePrefix("::/96").Contains(ip), netip.MustParsePrefix("64:ff9b::/96").Contains(ip):
			v4 = [4]byte(b[12:16])
		case netip.MustParsePrefix("2002::/16").Contains(ip):
			v4 = [4]byte(b[2:6])
		default:
			embeds = false
		}
		if embeds {
			if mustBlock(netip.AddrFrom4(v4)) {
				return true
			}
			// The embedding prefix itself (::/96 is deprecated) may still be refused.
			return false
		}
	}
	for _, s := range []string{"169.254.169.254", "100.100.100.200", "192.0.0.192", "fd00:ec2::254"} {
		if ip == netip.MustParseAddr(s) {
			return true
		}
	}
	return ip.IsLoopback() || ip.IsPrivate() || ip.IsUnspecified() || ip.IsMulticast() || ip.IsLinkLocalUnicast() ||
		ip.IsLinkLocalMulticast() || ip.IsInterfaceLocalMulticast() || !ip.IsGlobalUnicast()
}

// FuzzBlocked: every address the oracle says is internal is blocked,
// whatever form it is written in.
func FuzzBlocked(f *testing.F) {
	for _, s := range []string{"127.0.0.1", "::1", "::ffff:127.0.0.1", "::ffff:7f00:1", "64:ff9b::a9fe:a9fe", "2002:7f00:1::",
		"::127.0.0.1", "169.254.169.254", "fd00:ec2::254", "100.100.100.200", "8.8.8.8", "2606:4700:4700::1111", "64:ff9b::808:808",
		"2002:808:808::1", "fe80::1", "64:ff9b:1::1", "::"} {
		a := netip.MustParseAddr(s).As16()
		f.Add(a[:], netip.MustParseAddr(s).Is4())
	}
	f.Fuzz(func(t *testing.T, b []byte, as4 bool) {
		if len(b) != 16 {
			return
		}
		ip := netip.AddrFrom16([16]byte(b))
		if as4 {
			ip = netip.AddrFrom4([4]byte(b[12:16]))
		}
		if mustBlock(ip) && !Blocked(ip) {
			t.Fatalf("%v not blocked", ip)
		}
		if Blocked(ip) != Blocked(ip.Unmap()) && ip.Is4In6() {
			t.Fatalf("%v and %v judged differently", ip, ip.Unmap())
		}
		if !Blocked(ip.WithZone("eth0")) && ip.Is6() {
			t.Fatalf("%v with a zone allowed", ip)
		}
	})
}

// inetAton reports whether getaddrinfo (inet_aton) would read host as an
// IPv4 address: 1 to 4 parts, each decimal, octal (0...) or hex (0x...).
func inetAton(host string) bool {
	parts := strings.Split(strings.TrimSuffix(host, "."), ".")
	if len(parts) > 4 {
		return false
	}
	for _, p := range parts {
		if p == "" {
			return false
		}
		base, digits := 10, p
		switch {
		case strings.HasPrefix(p, "0x") || strings.HasPrefix(p, "0X"):
			base, digits = 16, p[2:]
			if digits == "" {
				continue // "0x" is 0 to glibc
			}
		case len(p) > 1 && p[0] == '0':
			base, digits = 8, p[1:]
		}
		if _, err := strconv.ParseUint(digits, base, 64); err != nil {
			return false
		}
	}
	return true
}

// FuzzParseURL: an accepted URL is https (or http to an allowed host), has
// no user info or fragment, a host that no resolver reads as a numeric IPv4
// address, an IP literal that isn't internal (unless allowed), and a hint
// that shows nothing past the host.
func FuzzParseURL(f *testing.F) {
	for _, s := range []string{"https://hooks.example.com/in/abc?x=1", "https://[2606:4700:4700::1111]/x", "http://127.0.0.1:9000/hook",
		"https://hooks.slack.com/services/T0/B0/xyz", "https://user@hooks.example.com/x", "https://[::ffff:127.0.0.1]/x",
		"https://0x7f.0.0.1/x", "https://2130706433/x", "https://127.1/x", "https://[fe80::1%25eth0]/x", "https://hooks.example.com:080/x",
		"https://evil.example/https://hooks.slack.com/services/T", "https://a.b/%2e%2e/x#f", "https://example.com./", "https://1.2.3.4.5/"} {
		f.Add(s, false, "")
		f.Add(s, true, "receiver.local")
	}
	f.Add("http://Receiver.Local./x", false, "receiver.local")
	f.Fuzz(func(t *testing.T, raw string, slack bool, allow string) {
		kind := KindGeneric
		if slack {
			kind = KindSlack
		}
		p := Policy{}
		if ValidAllowHost(allow) {
			p.AllowHosts = []string{allow}
		}
		tg, err := p.Parse(kind, raw)
		if err != nil {
			var ue *URLError
			if !errors.As(err, &ue) {
				t.Fatalf("error that isn't a *URLError: %v", err)
			}
			return
		}
		u, err := url.Parse(raw)
		if err != nil {
			t.Fatalf("accepted %q that net/url refuses: %v", raw, err)
		}
		host := strings.ToLower(u.Hostname())
		// A backslash in the authority is where parsers disagree on the host
		// (WHATWG reads it as "/"); in the path it is only a character Go
		// escapes when it sends the request.
		_, rest, _ := strings.Cut(raw, "://")
		authority, _, _ := strings.Cut(rest, "/")
		authority, _, _ = strings.Cut(authority, "?")
		if tg.Host != host || u.User != nil || u.Fragment != "" || strings.ContainsAny(raw, "# \t\r\n") || strings.Contains(authority, `\`) {
			t.Fatalf("accepted %q (host %q)", raw, tg.Host)
		}
		if tg.Allowed != p.Allowed(host) || (tg.Allowed && !strings.EqualFold(strings.Trim(host, "[]"), allow)) {
			t.Fatalf("%q allowed=%v with allow_hosts %q", raw, tg.Allowed, allow)
		}
		if !tg.Allowed {
			if u.Scheme != "https" {
				t.Fatalf("accepted %q without https", raw)
			}
			if ip, err := netip.ParseAddr(host); err == nil && mustBlock(ip) {
				t.Fatalf("accepted internal address %q", raw)
			}
			if _, err := netip.ParseAddr(host); err != nil && inetAton(host) {
				t.Fatalf("accepted numeric host %q", raw)
			}
			if kind == KindSlack && (host != slackHost || !strings.HasPrefix(u.EscapedPath(), slackPath)) {
				t.Fatalf("accepted Slack URL %q", raw)
			}
		}
		hint := tg.Hint()
		want := u.Scheme + "://" + strings.ToLower(u.Host)
		if hint != want && hint != want+"/…" {
			t.Fatalf("hint %q for %q", hint, raw)
		}
	})
}

// FuzzValidAllowHost: an accepted entry is a bare host or IP literal.
func FuzzValidAllowHost(f *testing.F) {
	for _, s := range []string{"127.0.0.1", "Receiver.Local", "::1", "fe80::1%eth0", "*.example.com", "http://x", "x:80", "a/b", "a..b", "_x_.y."} {
		f.Add(s)
	}
	f.Fuzz(func(t *testing.T, h string) {
		if !ValidAllowHost(h) {
			return
		}
		if ip, err := netip.ParseAddr(h); err == nil {
			if ip.Zone() != "" {
				t.Fatalf("accepted %q with a zone", h)
			}
			return
		}
		if h == "" || len(h) > 253 || strings.ContainsAny(h, ":/@*?#[]% \\") || strings.Contains(h, "..") {
			t.Fatalf("accepted %q", h)
		}
	})
}
