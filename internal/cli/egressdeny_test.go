// SPDX-License-Identifier: BSD-3-Clause

package cli

import (
	"errors"
	"net"
	"net/netip"
	"testing"
)

func TestEgressDenyCollectsOperatorAndOwnAddresses(t *testing.T) {
	ifaces := func() ([]net.Addr, error) {
		return []net.Addr{
			&net.IPNet{IP: net.ParseIP("192.0.2.7"), Mask: net.CIDRMask(24, 32)},
			&net.IPAddr{IP: net.ParseIP("2001:db8::7")},
		}, nil
	}
	got, err := egressDeny([]string{"203.0.113.0/24", "198.51.100.9"}, "198.51.100.20:8443", "[2001:db8::20]:9443",
		[]string{"relay.example", "198.51.100.30", "198.51.100.31:8443"}, ifaces)
	if err != nil {
		t.Fatal(err)
	}
	have := map[netip.Prefix]bool{}
	for _, p := range got {
		have[p] = true
	}
	for _, w := range []string{"203.0.113.0/24", "198.51.100.9/32", "198.51.100.20/32", "2001:db8::20/128",
		"198.51.100.30/32", "198.51.100.31/32", "192.0.2.7/32", "2001:db8::7/128"} {
		if !have[netip.MustParsePrefix(w)] {
			t.Errorf("%s is not denied: %v", w, got)
		}
	}
	if len(got) != 8 {
		t.Errorf("%d prefixes, want 8: %v", len(got), got)
	}
}

func TestEgressDenyRefusesJunkAndAListingFailure(t *testing.T) {
	if _, err := egressDeny([]string{"not-an-address"}, "", "", nil, nil); err == nil {
		t.Error("a junk --egress-deny was accepted")
	}
	if _, err := egressDeny(nil, "", "", nil, func() ([]net.Addr, error) { return nil, errors.New("boom") }); err == nil {
		t.Error("an interface listing failure was swallowed")
	}
	got, err := egressDeny(nil, ":8443", "", nil, nil)
	if err != nil || len(got) != 0 {
		t.Errorf("a wildcard listen denied %v, %v", got, err)
	}
}
