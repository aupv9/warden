package webhook

import (
	"net/netip"
)

// blockedPrefixes are the address ranges a webhook may never reach (unless its
// host is in webhook.allow_hosts): anything that isn't a public unicast
// address on the internet. Cloud metadata services live in link-local
// (169.254.169.254, AWS, GCP, Azure), CGNAT (100.100.100.200, Alibaba),
// 192.0.0.0/24 (Oracle's 192.0.0.192) and unique-local IPv6 (fd00:ec2::254),
// all covered here.
var blockedPrefixes = func() []netip.Prefix {
	var out []netip.Prefix
	for _, s := range []string{
		// IPv4
		"0.0.0.0/8",       // "this network", unspecified
		"10.0.0.0/8",      // private
		"100.64.0.0/10",   // CGNAT (shared address space)
		"127.0.0.0/8",     // loopback
		"169.254.0.0/16",  // link-local, cloud metadata
		"172.16.0.0/12",   // private
		"192.0.0.0/24",    // IETF protocol assignments
		"192.0.2.0/24",    // documentation (TEST-NET-1)
		"192.88.99.0/24",  // 6to4 relay anycast
		"192.168.0.0/16",  // private
		"198.18.0.0/15",   // benchmarking
		"198.51.100.0/24", // documentation (TEST-NET-2)
		"203.0.113.0/24",  // documentation (TEST-NET-3)
		"224.0.0.0/4",     // multicast
		"240.0.0.0/4",     // reserved, and 255.255.255.255 broadcast
		// IPv6
		"::/128",         // unspecified
		"::1/128",        // loopback
		"::/96",          // IPv4-compatible (deprecated)
		"64:ff9b:1::/48", // local-use NAT64
		"100::/64",       // discard-only
		"2001::/23",      // IETF protocol assignments (Teredo, benchmarking, ORCHID)
		"2001:db8::/32",  // documentation
		"3fff::/20",      // documentation
		"5f00::/16",      // segment routing SIDs
		"fc00::/7",       // unique local
		"fe80::/10",      // link-local
		"fec0::/10",      // site-local (deprecated)
		"ff00::/8",       // multicast
	} {
		out = append(out, netip.MustParsePrefix(s))
	}
	return out
}()

var (
	nat64   = netip.MustParsePrefix("64:ff9b::/96")
	sixTo4  = netip.MustParsePrefix("2002::/16")
	mapped4 = netip.MustParsePrefix("::ffff:0:0/96")
)

// Blocked reports whether a webhook must not connect to ip. Addresses that
// embed an IPv4 address (IPv4-mapped, NAT64, 6to4) are judged by that address,
// so ::ffff:127.0.0.1 or 2002:7f00:1:: can't reach loopback.
func Blocked(ip netip.Addr) bool {
	if !ip.IsValid() || ip.Zone() != "" {
		return true
	}
	ip = ip.WithZone("")
	if mapped4.Contains(ip) {
		ip = ip.Unmap()
	}
	if ip.Is6() {
		b := ip.As16()
		switch {
		case nat64.Contains(ip):
			return Blocked(netip.AddrFrom4([4]byte(b[12:16])))
		case sixTo4.Contains(ip):
			return Blocked(netip.AddrFrom4([4]byte(b[2:6])))
		}
	}
	for _, p := range blockedPrefixes {
		if p.Contains(ip) {
			return true
		}
	}
	// Belt and braces: whatever the list misses, the standard library's
	// classification still refuses.
	return !ip.IsGlobalUnicast() || ip.IsPrivate()
}
