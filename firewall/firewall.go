// SPDX-License-Identifier: BSD-3-Clause

// Package firewall is the relay's security-group model, after OpenStack
// Neutron's networking API: ports carry security groups, groups hold rules,
// rules only allow, and everything not allowed is denied.
//
// A flow from port S to port D is allowed iff one of S's EGRESS rules allows
// it AND one of D's INGRESS rules allows it, as Neutron filters at each port.
// Groups on a port are a union and rules have no order, so the result does
// not depend on the order anything was added in.
//
// Statefulness: a port is stateful unless every group on it is stateless
// (Neutron's "stateful" attribute). A stateful port lets replies of an allowed
// flow through without a rule (the relay's connection tracking). For a
// stateless port the reverse direction must be allowed too: a TCP connect
// whose source or destination port is stateless also needs D's egress and S's
// ingress to allow the reverse flow, and every UDP datagram is checked on its
// own.
package firewall

import (
	"errors"
	"fmt"
	"net/netip"
	"strconv"
	"strings"
)

// Direction is where a rule applies, seen from the port.
type Direction uint8

const (
	Ingress Direction = 1
	Egress  Direction = 2
)

func (d Direction) String() string {
	switch d {
	case Ingress:
		return "ingress"
	case Egress:
		return "egress"
	}
	return "direction(" + strconv.Itoa(int(d)) + ")"
}

// Protocol numbers, IANA's (as Neutron's protocol attribute accepts them).
type Protocol uint8

const (
	Any  Protocol = 0
	ICMP Protocol = 1
	TCP  Protocol = 6
	UDP  Protocol = 17
)

func (p Protocol) String() string {
	switch p {
	case Any:
		return "any"
	case ICMP:
		return "icmp"
	case TCP:
		return "tcp"
	case UDP:
		return "udp"
	}
	return strconv.Itoa(int(p))
}

// ParseProtocol reads "tcp", "udp", "icmp", "any" or a number of one of them.
func ParseProtocol(s string) (Protocol, error) {
	switch strings.ToLower(strings.TrimSpace(s)) {
	case "", "any", "0":
		return Any, nil
	case "tcp", "6":
		return TCP, nil
	case "udp", "17":
		return UDP, nil
	case "icmp", "1":
		return ICMP, nil
	}
	return 0, fmt.Errorf("protocol %q: want tcp, udp, icmp or any", s)
}

// Rule is one security group rule. PortMin/PortMax are a TCP/UDP port range
// (0,0 = every port) or, for ICMP, a type and a code (0 meaning any when
// AnyICMP is set). Remote is at most one of RemotePrefix and RemoteGroup;
// neither means any remote.
type Rule struct {
	ID           string
	GroupID      string
	Direction    Direction
	Protocol     Protocol
	PortMin      uint16
	PortMax      uint16
	RemotePrefix netip.Prefix // zero value: unset
	RemoteGroup  string
	Description  string
	Log          bool
}

// Validate checks a rule the way Neutron's API does.
func (r Rule) Validate() error {
	switch r.Direction {
	case Ingress, Egress:
	default:
		return errors.New("direction must be ingress or egress")
	}
	switch r.Protocol {
	case Any:
		if r.PortMin != 0 || r.PortMax != 0 {
			return errors.New("a port range needs a protocol")
		}
	case TCP, UDP:
		if r.PortMin > r.PortMax {
			return errors.New("port_range_min is above port_range_max")
		}
		if r.PortMin == 0 && r.PortMax != 0 {
			return errors.New("port_range_min 0 with a maximum: give both")
		}
	case ICMP:
		if r.PortMin > 255 || r.PortMax > 255 {
			return errors.New("ICMP type and code are 0..255")
		}
	default:
		return fmt.Errorf("protocol %d is not supported (tcp, udp, icmp, any)", r.Protocol)
	}
	if r.RemotePrefix.IsValid() && r.RemoteGroup != "" {
		return errors.New("give remote_ip_prefix or remote_group_id, not both")
	}
	if r.RemotePrefix.IsValid() && !r.RemotePrefix.Addr().Is4() {
		return errors.New("only IPv4 for now")
	}
	if len(r.Description) > 255 {
		return errors.New("description longer than 255 bytes")
	}
	return nil
}

// Group is a security group.
type Group struct {
	ID          string
	Name        string
	Description string
	Stateful    bool
	Rules       []Rule
}

// Port is one container endpoint as the firewall sees it.
type Port struct {
	ID           string
	Addr         netip.Addr
	Groups       []string // group ids
	PortSecurity bool     // false: no filtering at all (teacher only)
}

// Flow is one L4 flow from Src to Dst.
type Flow struct {
	Protocol Protocol
	Src, Dst netip.AddrPort
}

// Reverse is the flow of the replies.
func (f Flow) Reverse() Flow { return Flow{Protocol: f.Protocol, Src: f.Dst, Dst: f.Src} }

// Decision says whether a flow is allowed, and by which rules.
type Decision struct {
	Allowed     bool
	EgressRule  string // the rule at the source that allowed it
	IngressRule string // the rule at the destination that allowed it
	Log         bool   // one of the matching rules asked for a log line
	Reason      string // why not, when not
}

// Policy is the set of groups of one class and the lookups a decision needs.
type Policy struct {
	Groups map[string]*Group
	// Members returns the addresses of every port that carries the group,
	// for remote_group_id.
	Members func(groupID string) []netip.Addr
}

// Stateful reports whether p is tracked: some group on it is stateful.
func (pol *Policy) Stateful(p *Port) bool {
	if !p.PortSecurity {
		return true
	}
	for _, id := range p.Groups {
		if g := pol.Groups[id]; g != nil && g.Stateful {
			return true
		}
	}
	return false
}

// Evaluate decides a flow from port src to port dst. It checks the forward
// direction, and for a stateless end the reverse one too (see the package
// comment). Replies of an already-tracked flow are not decided here.
func (pol *Policy) Evaluate(f Flow, src, dst *Port) Decision {
	d := pol.oneWay(f, src, dst)
	if !d.Allowed {
		return d
	}
	if !pol.Stateful(src) || !pol.Stateful(dst) {
		r := pol.oneWay(f.Reverse(), dst, src)
		if !r.Allowed {
			return Decision{Reason: "stateless: the reverse direction is not allowed (" + r.Reason + ")"}
		}
		d.Log = d.Log || r.Log
	}
	return d
}

func (pol *Policy) oneWay(f Flow, src, dst *Port) Decision {
	var d Decision
	if src.PortSecurity {
		id, log, ok := pol.match(src, Egress, f.Protocol, f.Dst.Port(), f.Dst.Addr())
		if !ok {
			return Decision{Reason: "no egress rule of " + src.ID + " allows it"}
		}
		d.EgressRule, d.Log = id, log
	}
	if dst.PortSecurity {
		id, log, ok := pol.match(dst, Ingress, f.Protocol, f.Dst.Port(), f.Src.Addr())
		if !ok {
			return Decision{Reason: "no ingress rule of " + dst.ID + " allows it"}
		}
		d.IngressRule, d.Log = id, d.Log || log
	}
	d.Allowed = true
	return d
}

// match finds a rule of p in direction dir that allows protocol proto to
// port (the destination port of the flow) with remote address remote.
// The first match in group then rule order is reported; any match allows.
func (pol *Policy) match(p *Port, dir Direction, proto Protocol, port uint16, remote netip.Addr) (string, bool, bool) {
	for _, gid := range p.Groups {
		g := pol.Groups[gid]
		if g == nil {
			continue
		}
		for i := range g.Rules {
			r := &g.Rules[i]
			if r.Direction != dir || !r.matchesProto(proto, port) || !pol.matchesRemote(r, remote) {
				continue
			}
			return r.ID, r.Log, true
		}
	}
	return "", false, false
}

func (r *Rule) matchesProto(proto Protocol, port uint16) bool {
	if r.Protocol == Any {
		return true
	}
	if r.Protocol != proto {
		return false
	}
	if proto == ICMP {
		// port carries the ICMP type for an echo; 0,0 is any type.
		return (r.PortMin == 0 && r.PortMax == 0) || uint16(r.PortMin) == port
	}
	if r.PortMin == 0 && r.PortMax == 0 {
		return true
	}
	return port >= r.PortMin && port <= r.PortMax
}

func (pol *Policy) matchesRemote(r *Rule, remote netip.Addr) bool {
	switch {
	case r.RemotePrefix.IsValid():
		return r.RemotePrefix.Contains(remote)
	case r.RemoteGroup != "":
		if pol.Members == nil {
			return false
		}
		for _, a := range pol.Members(r.RemoteGroup) {
			if a == remote {
				return true
			}
		}
		return false
	}
	return true
}

// ParsePortRange reads a CLI port spec: "80", "8000-8080", "" or "any".
func ParsePortRange(s string) (uint16, uint16, error) {
	s = strings.TrimSpace(s)
	if s == "" || s == "any" {
		return 0, 0, nil
	}
	lo, hi, found := strings.Cut(s, "-")
	a, err := parsePort(lo)
	if err != nil {
		return 0, 0, err
	}
	if !found {
		return a, a, nil
	}
	b, err := parsePort(hi)
	if err != nil {
		return 0, 0, err
	}
	if a > b {
		return 0, 0, fmt.Errorf("port range %q: minimum above maximum", s)
	}
	return a, b, nil
}

func parsePort(s string) (uint16, error) {
	n, err := strconv.ParseUint(strings.TrimSpace(s), 10, 16)
	if err != nil || n == 0 {
		return 0, fmt.Errorf("port %q: want 1..65535", s)
	}
	return uint16(n), nil
}
