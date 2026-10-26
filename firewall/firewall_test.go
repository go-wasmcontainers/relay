// SPDX-License-Identifier: BSD-3-Clause

package firewall

import (
	"net/netip"
	"testing"
)

func ap(s string) netip.AddrPort { return netip.MustParseAddrPort(s) }

func policy(groups ...*Group) *Policy {
	p := &Policy{Groups: map[string]*Group{}}
	for _, g := range groups {
		p.Groups[g.ID] = g
	}
	return p
}

func TestDefaultDeny(t *testing.T) {
	empty := &Group{ID: "g", Stateful: true}
	pol := policy(empty)
	a := &Port{ID: "a", Addr: netip.MustParseAddr("10.42.1.2"), Groups: []string{"g"}, PortSecurity: true}
	b := &Port{ID: "b", Addr: netip.MustParseAddr("10.42.2.2"), Groups: []string{"g"}, PortSecurity: true}
	d := pol.Evaluate(Flow{TCP, ap("10.42.1.2:5000"), ap("10.42.2.2:80")}, a, b)
	if d.Allowed {
		t.Fatal("a group with no rule allowed a flow")
	}
	if d.Reason == "" {
		t.Fatal("no reason")
	}
}

func TestBothEnds(t *testing.T) {
	out := &Group{ID: "out", Stateful: true, Rules: []Rule{{ID: "e1", Direction: Egress}}}
	web := &Group{ID: "web", Stateful: true, Rules: []Rule{{ID: "i80", Direction: Ingress, Protocol: TCP, PortMin: 80, PortMax: 80}}}
	pol := policy(out, web)
	a := &Port{ID: "a", Addr: netip.MustParseAddr("10.42.1.2"), Groups: []string{"out"}, PortSecurity: true}
	b := &Port{ID: "b", Addr: netip.MustParseAddr("10.42.2.2"), Groups: []string{"out", "web"}, PortSecurity: true}
	f := Flow{TCP, ap("10.42.1.2:5000"), ap("10.42.2.2:80")}
	d := pol.Evaluate(f, a, b)
	if !d.Allowed || d.EgressRule != "e1" || d.IngressRule != "i80" {
		t.Fatalf("%+v", d)
	}
	// Port 81: ingress has no rule.
	f.Dst = ap("10.42.2.2:81")
	if pol.Evaluate(f, a, b).Allowed {
		t.Fatal("port 81 allowed")
	}
	// Reverse (b to a): a has no ingress.
	if pol.Evaluate(Flow{TCP, ap("10.42.2.2:5000"), ap("10.42.1.2:80")}, b, a).Allowed {
		t.Fatal("a accepted ingress without a rule")
	}
	// UDP to 80 is not TCP.
	if pol.Evaluate(Flow{UDP, ap("10.42.1.2:5000"), ap("10.42.2.2:80")}, a, b).Allowed {
		t.Fatal("udp matched a tcp rule")
	}
}

func TestRemotePrefixAndGroup(t *testing.T) {
	out := &Group{ID: "out", Stateful: true, Rules: []Rule{{ID: "e", Direction: Egress}}}
	db := &Group{ID: "db", Stateful: true, Rules: []Rule{
		{ID: "from-web", Direction: Ingress, Protocol: TCP, PortMin: 5432, PortMax: 5432, RemoteGroup: "web"},
		{ID: "from-teacher", Direction: Ingress, Protocol: TCP, RemotePrefix: netip.MustParsePrefix("10.42.0.0/24")},
	}}
	web := &Group{ID: "web", Stateful: true}
	webAddr := netip.MustParseAddr("10.42.1.2")
	pol := policy(out, db, web)
	pol.Members = func(g string) []netip.Addr {
		if g == "web" {
			return []netip.Addr{webAddr}
		}
		return nil
	}
	w := &Port{ID: "w", Addr: webAddr, Groups: []string{"out", "web"}, PortSecurity: true}
	other := &Port{ID: "o", Addr: netip.MustParseAddr("10.42.3.2"), Groups: []string{"out"}, PortSecurity: true}
	teacher := &Port{ID: "t", Addr: netip.MustParseAddr("10.42.0.2"), Groups: []string{"out"}, PortSecurity: true}
	dbp := &Port{ID: "d", Addr: netip.MustParseAddr("10.42.2.2"), Groups: []string{"db"}, PortSecurity: true}
	if d := pol.Evaluate(Flow{TCP, ap("10.42.1.2:40000"), ap("10.42.2.2:5432")}, w, dbp); !d.Allowed || d.IngressRule != "from-web" {
		t.Fatalf("web member refused: %+v", d)
	}
	if pol.Evaluate(Flow{TCP, ap("10.42.3.2:40000"), ap("10.42.2.2:5432")}, other, dbp).Allowed {
		t.Fatal("non-member allowed by remote_group_id")
	}
	if d := pol.Evaluate(Flow{TCP, ap("10.42.0.2:40000"), ap("10.42.2.2:22")}, teacher, dbp); !d.Allowed || d.IngressRule != "from-teacher" {
		t.Fatalf("teacher prefix: %+v", d)
	}
}

func TestStateless(t *testing.T) {
	// Forward allowed both ends, reverse not: a stateless end refuses.
	sl := &Group{ID: "sl", Stateful: false, Rules: []Rule{
		{ID: "e", Direction: Egress, Protocol: TCP, PortMin: 80, PortMax: 80},
		{ID: "i", Direction: Ingress, Protocol: TCP, PortMin: 80, PortMax: 80},
	}}
	pol := policy(sl)
	a := &Port{ID: "a", Addr: netip.MustParseAddr("10.42.1.2"), Groups: []string{"sl"}, PortSecurity: true}
	b := &Port{ID: "b", Addr: netip.MustParseAddr("10.42.2.2"), Groups: []string{"sl"}, PortSecurity: true}
	f := Flow{TCP, ap("10.42.1.2:40000"), ap("10.42.2.2:80")}
	if pol.Stateful(a) {
		t.Fatal("stateless group reported stateful")
	}
	if d := pol.Evaluate(f, a, b); d.Allowed {
		t.Fatal("stateless: reverse to port 40000 is not allowed, yet the flow was")
	}
	// Add the reverse rules (any port): now allowed.
	sl.Rules = append(sl.Rules, Rule{ID: "e-any", Direction: Egress, Protocol: TCP}, Rule{ID: "i-any", Direction: Ingress, Protocol: TCP})
	if d := pol.Evaluate(f, a, b); !d.Allowed {
		t.Fatalf("both directions allowed but refused: %+v", d)
	}
}

func TestPortSecurityOff(t *testing.T) {
	pol := policy()
	a := &Port{ID: "a", PortSecurity: false}
	b := &Port{ID: "b", PortSecurity: false}
	if !pol.Evaluate(Flow{TCP, ap("10.42.1.2:1"), ap("10.42.2.2:2")}, a, b).Allowed {
		t.Fatal("port security off still filtered")
	}
}

func TestICMP(t *testing.T) {
	g := &Group{ID: "g", Stateful: true, Rules: []Rule{
		{ID: "e", Direction: Egress},
		{ID: "echo", Direction: Ingress, Protocol: ICMP, PortMin: 8},
	}}
	pol := policy(g)
	a := &Port{ID: "a", Groups: []string{"g"}, PortSecurity: true}
	if !pol.Evaluate(Flow{ICMP, ap("10.42.1.2:0"), ap("10.42.2.2:8")}, a, a).Allowed {
		t.Fatal("echo refused")
	}
	if pol.Evaluate(Flow{ICMP, ap("10.42.1.2:0"), ap("10.42.2.2:13")}, a, a).Allowed {
		t.Fatal("timestamp allowed by an echo rule")
	}
}

func TestValidate(t *testing.T) {
	bad := []Rule{
		{Direction: 0},
		{Direction: Ingress, PortMin: 1, PortMax: 2},
		{Direction: Ingress, Protocol: TCP, PortMin: 9, PortMax: 8},
		{Direction: Ingress, Protocol: TCP, PortMin: 0, PortMax: 8},
		{Direction: Ingress, Protocol: ICMP, PortMin: 300},
		{Direction: Ingress, Protocol: 47},
		{Direction: Ingress, RemoteGroup: "x", RemotePrefix: netip.MustParsePrefix("10.0.0.0/8")},
		{Direction: Ingress, RemotePrefix: netip.MustParsePrefix("fc00::/7")},
	}
	for i, r := range bad {
		if r.Validate() == nil {
			t.Errorf("rule %d accepted: %+v", i, r)
		}
	}
	if err := (Rule{Direction: Egress, Protocol: UDP, PortMin: 53, PortMax: 53}).Validate(); err != nil {
		t.Fatal(err)
	}
}

func TestParsePortRange(t *testing.T) {
	for in, want := range map[string][2]uint16{"": {0, 0}, "any": {0, 0}, "80": {80, 80}, "8000-8080": {8000, 8080}, " 22 ": {22, 22}} {
		a, b, err := ParsePortRange(in)
		if err != nil || a != want[0] || b != want[1] {
			t.Errorf("%q: %d %d %v", in, a, b, err)
		}
	}
	for _, in := range []string{"0", "65536", "9-8", "a", "1-", "-1", "80-90-100"} {
		if _, _, err := ParsePortRange(in); err == nil {
			t.Errorf("%q accepted", in)
		}
	}
}

func FuzzParsePortRange(f *testing.F) {
	for _, s := range []string{"80", "1-65535", "any", "9-8", "", "-"} {
		f.Add(s)
	}
	f.Fuzz(func(t *testing.T, s string) {
		a, b, err := ParsePortRange(s)
		if err != nil {
			return
		}
		if a > b || (a == 0) != (b == 0) {
			t.Fatalf("%q gave %d-%d", s, a, b)
		}
	})
}

func FuzzParseProtocol(f *testing.F) {
	for _, s := range []string{"tcp", "UDP", "1", "any", "gre"} {
		f.Add(s)
	}
	f.Fuzz(func(t *testing.T, s string) {
		p, err := ParseProtocol(s)
		if err != nil {
			return
		}
		switch p {
		case Any, TCP, UDP, ICMP:
		default:
			t.Fatalf("%q gave %d", s, p)
		}
	})
}
