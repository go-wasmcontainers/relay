// SPDX-License-Identifier: BSD-3-Clause

// Package egress is the relay's outbound-internet policy: which names a class
// may reach, which addresses are never dialled, and the checks that stand
// between guest code and the network the relay runs on. It holds no sockets
// and no goroutines; the relay applies its verdicts.
//
// The design is the playground egress threat model (sections 5 to 8): deny by
// default, exact host:443 allowlist, every address of an answer vetted, the
// vetted address pinned and dialled as a literal, the TLS server name checked.
package egress

import "net/netip"

// denied4 is every row of the IANA IPv4 Special-Purpose Address Registry whose
// "Globally Reachable" is not True, plus the rows that contain such addresses
// (192.0.0.0/24 and 192.88.99.0/24 whole, so their globally reachable
// anycast sub-rows are refused too) and multicast, which that registry does
// not list. Opened 2026-11-27 (iana-ipv4-special-registry-1.csv).
var denied4 = prefixes(
	"0.0.0.0/8",          // "This network", "This host on this network"
	"10.0.0.0/8",         // Private-Use
	"100.64.0.0/10",      // Shared Address Space
	"127.0.0.0/8",        // Loopback
	"169.254.0.0/16",     // Link Local (cloud metadata lives here)
	"172.16.0.0/12",      // Private-Use
	"192.0.0.0/24",       // IETF Protocol Assignments, with all its sub-rows
	"192.0.2.0/24",       // TEST-NET-1
	"192.88.99.0/24",     // Deprecated 6to4 relay anycast, 6a44-relay
	"192.168.0.0/16",     // Private-Use
	"198.18.0.0/15",      // Benchmarking
	"198.51.100.0/24",    // TEST-NET-2
	"203.0.113.0/24",     // TEST-NET-3
	"224.0.0.0/4",        // Multicast (added; not in the registry)
	"240.0.0.0/4",        // Reserved
	"255.255.255.255/32", // Limited Broadcast
)

// denied6 is the same for the IANA IPv6 Special-Purpose Address Registry:
// every non-globally-reachable row, the whole of 2001::/23 (its few
// reachable sub-rows are refused too), the prefixes that embed an IPv4
// address (64:ff9b::/96, 2002::/16, 2001::/32: denied outright in v1) and
// multicast ff00::/8 (added). ::ffff:0:0/96 is handled by unmapping.
var denied6 = prefixes(
	"::/128",         // Unspecified
	"::1/128",        // Loopback
	"64:ff9b::/96",   // NAT64, embeds an IPv4 address
	"64:ff9b:1::/48", // Local-use NAT64
	"100::/64",       // Discard-Only
	"100:0:0:1::/64", // Dummy IPv6 Prefix
	"2001::/23",      // IETF Protocol Assignments, with Teredo 2001::/32
	"2001:db8::/32",  // Documentation
	"2002::/16",      // 6to4, embeds an IPv4 address
	"3fff::/20",      // Documentation
	"5f00::/16",      // SRv6 SIDs
	"fc00::/7",       // Unique-Local
	"fe80::/10",      // Link-Local Unicast
	"ff00::/8",       // Multicast (added)
)

func prefixes(s ...string) []netip.Prefix {
	out := make([]netip.Prefix, len(s))
	for i, p := range s {
		out[i] = netip.MustParsePrefix(p)
	}
	return out
}

// Denied reports why a is never dialled, or "" when it is globally
// reachable unicast. An IPv4-mapped IPv6 address is unmapped and judged as
// IPv4; a zone is refused outright.
func Denied(a netip.Addr) string {
	if !a.IsValid() {
		return "not an address"
	}
	if a.Zone() != "" {
		return "address with a zone"
	}
	a = a.Unmap()
	table := denied6
	if a.Is4() {
		table = denied4
	}
	for _, p := range table {
		if p.Contains(a) {
			return "special-purpose address " + p.String()
		}
	}
	return ""
}

// DeniedPrefixes returns the IPv4 and IPv6 deny tables (copies), for tests
// and for documentation.
func DeniedPrefixes() (v4, v6 []netip.Prefix) {
	return append([]netip.Prefix(nil), denied4...), append([]netip.Prefix(nil), denied6...)
}
