// SPDX-License-Identifier: BSD-3-Clause

package cli

import (
	"fmt"
	"net"
	"net/netip"
	"strings"
)

// parseDeny reads one --egress-deny value: a prefix, or a bare address (a /32
// or /128).
func parseDeny(s string) (netip.Prefix, error) {
	s = strings.TrimSpace(s)
	if p, err := netip.ParsePrefix(s); err == nil {
		return p.Masked(), nil
	}
	a, err := netip.ParseAddr(s)
	if err != nil {
		return netip.Prefix{}, fmt.Errorf("--egress-deny %q: not an address or prefix", s)
	}
	return netip.PrefixFrom(a.Unmap(), a.Unmap().BitLen()), nil
}

// egressDeny builds the prefixes the egress gateway never dials: the operator's
// --egress-deny values, every address of this machine (ifaces), and the
// addresses the relay itself is told to serve (--listen, --admin-listen,
// --host), so a guest cannot reach the relay's own listeners, admin API or
// cloud metadata through the gateway.
func egressDeny(flags []string, listen, adminListen string, hosts []string,
	ifaces func() ([]net.Addr, error)) ([]netip.Prefix, error) {
	var out []netip.Prefix
	for _, s := range flags {
		p, err := parseDeny(s)
		if err != nil {
			return nil, err
		}
		out = append(out, p)
	}
	own := func(a netip.Addr) {
		a = a.Unmap().WithZone("")
		if a.IsValid() && !a.IsUnspecified() {
			out = append(out, netip.PrefixFrom(a, a.BitLen()))
		}
	}
	for _, l := range []string{listen, adminListen} {
		if l == "" {
			continue
		}
		h, _, err := net.SplitHostPort(l)
		if err != nil {
			continue
		}
		if a, err := netip.ParseAddr(h); err == nil {
			own(a)
		}
	}
	for _, h := range hosts {
		h = strings.Trim(h, "[]")
		if a, err := netip.ParseAddr(h); err == nil {
			own(a)
		} else if hh, _, err := net.SplitHostPort(h); err == nil {
			if a, err := netip.ParseAddr(strings.Trim(hh, "[]")); err == nil {
				own(a)
			}
		}
	}
	if ifaces != nil {
		addrs, err := ifaces()
		if err != nil {
			return nil, fmt.Errorf("listing this machine's addresses: %w", err)
		}
		for _, a := range addrs {
			var ip net.IP
			switch v := a.(type) {
			case *net.IPNet:
				ip = v.IP
			case *net.IPAddr:
				ip = v.IP
			}
			if x, ok := netip.AddrFromSlice(ip); ok {
				own(x)
			}
		}
	}
	return out, nil
}
