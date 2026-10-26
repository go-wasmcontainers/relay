// SPDX-License-Identifier: BSD-3-Clause

package relay

import (
	"fmt"
	"net/netip"
	"slices"
	"strings"
	"time"

	"github.com/go-wasmcontainers/relay/auth"
	"github.com/go-wasmcontainers/relay/firewall"
	v1 "github.com/go-wasmcontainers/relay/gen/relayv1"
)

// class is a class at run time: its persisted part plus live connections,
// listeners, streams and connection tracking. Guarded by Relay.mu.
type class struct {
	r   *Relay
	s   *sClass
	net netip.Prefix

	pol    *firewall.Policy // compiled from s.Groups; rebuilt on change
	byAddr map[netip.Addr]string

	conns     map[string]*conn // session id -> its live connection
	listeners map[lkey]*listener
	links     map[*link]struct{}
	track     map[flowKey]time.Time // UDP flows allowed, by forward flow
	ephemeral map[string]uint16     // port id -> next ephemeral port

	log      *flowLog
	subs     map[*subscriber]struct{}
	denySeen map[flowKey]time.Time // last deny logged per UDP flow
	edges    map[edgeKey]*edgeStat // the flow map's counters
}

type lkey struct {
	addr  netip.Addr
	proto firewall.Protocol
	port  uint16
}

type listener struct {
	portID string
	conn   *conn
	auto   bool // the implicit UDP port of a sender that never bound one
}

type flowKey struct {
	proto    firewall.Protocol
	src, dst netip.AddrPort
}

func newClass(r *Relay, sc *sClass) (*class, error) {
	pfx, err := netip.ParsePrefix(sc.CIDR)
	if err != nil {
		return nil, err
	}
	c := &class{r: r, s: sc, net: pfx, conns: map[string]*conn{}, listeners: map[lkey]*listener{},
		links: map[*link]struct{}{}, track: map[flowKey]time.Time{}, ephemeral: map[string]uint16{},
		byAddr: map[netip.Addr]string{}, log: newFlowLog(1000), subs: map[*subscriber]struct{}{},
		denySeen: map[flowKey]time.Time{}}
	if sc.Groups == nil {
		sc.Groups = map[string]*sGroup{}
	}
	if sc.Sessions == nil {
		sc.Sessions = map[string]*sSess{}
	}
	if sc.Ports == nil {
		sc.Ports = map[string]*sPort{}
	}
	for id, p := range sc.Ports {
		c.byAddr[c.portAddr(p)] = id
	}
	if err := c.compile(); err != nil {
		return nil, err
	}
	return c, nil
}

func (c *class) maxSessions() int { return 1 << (c.s.SessionBits - c.net.Bits()) }

// hostsPerSession: addresses .2 .. .(2^n - 2); .0 network, .1 gateway, last
// broadcast, kept unused as on a real subnet.
func (c *class) hostsPerSession() int { return 1<<(32-c.s.SessionBits) - 3 }

func (c *class) sessionNet(s *sSess) netip.Prefix { return subnet(c.net, c.s.SessionBits, s.Index) }

func (c *class) portAddr(p *sPort) netip.Addr {
	s := c.s.Sessions[p.Session]
	if s == nil {
		return netip.Addr{}
	}
	return host(c.sessionNet(s), p.Host)
}

func (c *class) addSession(display string, teacher bool, identity string) (*sSess, error) {
	used := map[int]bool{}
	labels := map[string]bool{}
	for _, s := range c.s.Sessions {
		used[s.Index] = true
		labels[s.Label] = true
	}
	idx := -1
	if teacher {
		idx = 0
	} else {
		for i := 1; i < c.maxSessions(); i++ {
			if !used[i] {
				idx = i
				break
			}
		}
	}
	if idx < 0 || used[idx] {
		return nil, errf(KindLimit, "the class network has no subnet left (%d sessions)", c.maxSessions()-1)
	}
	label := "teacher"
	if !teacher {
		base := auth.Label(display)
		if base == "teacher" {
			base = "s-teacher"
		}
		label = base
		for n := 2; labels[label]; n++ {
			label = fmt.Sprintf("%s-%d", base, n)
		}
	}
	s := &sSess{ID: c.s.newID("s-"), Label: label, Display: display, Index: idx, Teacher: teacher,
		Identity: identity, Created: c.r.cfg.Now().Unix()}
	c.s.Sessions[s.ID] = s
	return s, nil
}

func (c *class) findSession(who string) *sSess {
	if s, ok := c.s.Sessions[who]; ok {
		return s
	}
	for _, s := range c.s.Sessions {
		if s.Label == who {
			return s
		}
	}
	return nil
}

func (c *class) allConns() []*conn {
	var out []*conn
	for _, cn := range c.conns {
		out = append(out, cn)
	}
	return out
}

func (c *class) proto(withCode bool) *v1.Class {
	pc := &v1.Class{Id: c.s.ID, Name: c.s.Name, Network: c.networkProto(), Template: v1.Template(c.s.Template),
		CreatedUnix: c.s.Created, RequireIdentity: c.s.RequireID, RelayId: c.r.cfg.RelayID, Epoch: c.s.Epoch}
	if withCode {
		pc.JoinCode = c.s.JoinCode
		pc.Allowed = slices.Clone(c.s.Allowed)
	}
	return pc
}

func (c *class) networkProto() *v1.Network {
	return &v1.Network{Cidr: c.s.CIDR, SessionBits: uint32(c.s.SessionBits), DnsDomain: c.s.DNSDomain}
}

func (c *class) sessionProto(s *sSess) *v1.Session {
	ps := &v1.Session{Id: s.ID, ClassId: c.s.ID, Label: s.Label, DisplayName: s.Display,
		Subnet: c.sessionNet(s).String(), Teacher: s.Teacher}
	if cn := c.conns[s.ID]; cn != nil {
		ps.Connected = true
		ps.LastSeenUnix = cn.lastSeen.Load()
	}
	return ps
}

func (c *class) portProto(id string) *v1.Port {
	p := c.s.Ports[id]
	s := c.s.Sessions[p.Session]
	return &v1.Port{Id: p.ID, ClassId: c.s.ID, SessionId: p.Session, Container: p.Container,
		Ip: c.portAddr(p).String(), DnsName: p.Container + "." + s.Label + "." + c.s.DNSDomain,
		SecurityGroups: slices.Clone(p.Groups), PortSecurityEnabled: p.PortSecurity}
}

// ------------------------------------------------------------------- ports

// attach gives a session's container a port, or returns the one it had.
func (c *class) attach(s *sSess, container string) (string, error) {
	if !validContainerName(container) {
		return "", errf(KindInvalid, "container name %q: lower-case letters, digits and hyphens, 1 to 63", container)
	}
	n := 0
	usedHost := map[int]bool{}
	for id, p := range c.s.Ports {
		if p.Session != s.ID {
			continue
		}
		if p.Container == container {
			return id, nil
		}
		n++
		usedHost[p.Host] = true
	}
	if n >= c.r.limits.MaxPorts {
		return "", errf(KindLimit, "at most %d containers per session", c.r.limits.MaxPorts)
	}
	h := -1
	for i := 2; i < 2+c.hostsPerSession(); i++ {
		if !usedHost[i] {
			h = i
			break
		}
	}
	if h < 0 {
		return "", errf(KindLimit, "the session subnet is full")
	}
	p := &sPort{ID: c.s.newID("p-"), Session: s.ID, Container: container, Host: h,
		Groups: []string{c.s.DefaultSG}, PortSecurity: true}
	c.s.Ports[p.ID] = p
	c.byAddr[c.portAddr(p)] = p.ID
	return p.ID, nil
}

func validContainerName(n string) bool {
	if n == "" || len(n) > 63 || n[0] == '-' || n[len(n)-1] == '-' {
		return false
	}
	for _, ch := range n {
		if !(ch >= 'a' && ch <= 'z' || ch >= '0' && ch <= '9' || ch == '-') {
			return false
		}
	}
	return true
}

// removePort forgets a port: its listeners close, its streams reset.
func (c *class) removePort(id string) {
	p := c.s.Ports[id]
	if p == nil {
		return
	}
	addr := c.portAddr(p)
	for k, l := range c.listeners {
		if l.portID == id {
			delete(c.listeners, k)
		}
	}
	for l := range c.links {
		if l.aPort == id || l.bPort == id {
			c.dropLink(l, v1.Code_CODE_RESET, "the container left the network", v1.Verdict_VERDICT_CLOSED)
		}
	}
	delete(c.byAddr, addr)
	delete(c.s.Ports, id)
	delete(c.ephemeral, id)
}

// findPort resolves a port by id, DNS name or "label/container".
func (c *class) findPort(ref string) (string, *sPort) {
	if p, ok := c.s.Ports[ref]; ok {
		return ref, p
	}
	label, ctr, ok := strings.Cut(ref, "/")
	if !ok {
		parts := strings.Split(strings.TrimSuffix(ref, "."+c.s.DNSDomain), ".")
		if len(parts) != 2 {
			return "", nil
		}
		ctr, label = parts[0], parts[1]
	}
	for id, p := range c.s.Ports {
		if s := c.s.Sessions[p.Session]; s != nil && s.Label == label && p.Container == ctr {
			return id, p
		}
	}
	return "", nil
}

func (c *class) fwPort(id string) *firewall.Port {
	p := c.s.Ports[id]
	return &firewall.Port{ID: id, Addr: c.portAddr(p), Groups: p.Groups, PortSecurity: p.PortSecurity}
}

// resolve answers a container's name lookup.
func (c *class) resolve(from *sSess, name string) []netip.Addr {
	name = strings.TrimSuffix(strings.ToLower(name), ".")
	if a, err := netip.ParseAddr(name); err == nil {
		return []netip.Addr{a}
	}
	name = strings.TrimSuffix(name, "."+c.s.DNSDomain)
	ctr, label, ok := strings.Cut(name, ".")
	if !ok {
		label = from.Label
	}
	for _, p := range c.s.Ports {
		if p.Container != ctr {
			continue
		}
		if s := c.s.Sessions[p.Session]; s != nil && s.Label == label {
			return []netip.Addr{c.portAddr(p)}
		}
	}
	return nil
}

// ------------------------------------------------------- groups and rules

// compile rebuilds the firewall policy from the persisted groups.
func (c *class) compile() error {
	pol := &firewall.Policy{Groups: map[string]*firewall.Group{}}
	for id, g := range c.s.Groups {
		fg := &firewall.Group{ID: id, Name: g.Name, Description: g.Description, Stateful: g.Stateful}
		for _, sr := range g.Rules {
			r, err := sr.rule(id)
			if err != nil {
				return err
			}
			fg.Rules = append(fg.Rules, r)
		}
		pol.Groups[id] = fg
	}
	members := map[string][]netip.Addr{}
	for _, p := range c.s.Ports {
		for _, g := range p.Groups {
			members[g] = append(members[g], c.portAddr(p))
		}
	}
	pol.Members = func(g string) []netip.Addr { return members[g] }
	c.pol = pol
	return nil
}

func (sr sRule) rule(group string) (firewall.Rule, error) {
	r := firewall.Rule{ID: sr.ID, GroupID: group, Direction: firewall.Direction(sr.Direction), Protocol: firewall.Protocol(sr.Protocol),
		PortMin: sr.PortMin, PortMax: sr.PortMax, RemoteGroup: sr.RemoteGroup, Description: sr.Description, Log: sr.Log}
	if sr.RemotePrefix != "" {
		p, err := netip.ParsePrefix(sr.RemotePrefix)
		if err != nil {
			return r, err
		}
		r.RemotePrefix = p.Masked()
	}
	return r, r.Validate()
}

func (c *class) findGroup(ref string) *sGroup {
	if g, ok := c.s.Groups[ref]; ok {
		return g
	}
	for _, g := range c.s.Groups {
		if g.Name == ref {
			return g
		}
	}
	return nil
}

func (c *class) groupProto(g *sGroup) *v1.SecurityGroup {
	pg := &v1.SecurityGroup{Id: g.ID, ClassId: c.s.ID, Name: g.Name, Description: g.Description, Stateful: g.Stateful}
	for _, sr := range g.Rules {
		pg.Rules = append(pg.Rules, ruleProto(g.ID, sr))
	}
	return pg
}

func ruleProto(group string, sr sRule) *v1.SecurityGroupRule {
	pr := &v1.SecurityGroupRule{Id: sr.ID, SecurityGroupId: group, Direction: v1.Direction(sr.Direction), Ethertype: "IPv4",
		Protocol: v1.Protocol(sr.Protocol), PortRangeMin: uint32(sr.PortMin), PortRangeMax: uint32(sr.PortMax),
		Description: sr.Description, Log: sr.Log}
	switch {
	case sr.RemotePrefix != "":
		pr.Remote = &v1.SecurityGroupRule_RemoteIpPrefix{RemoteIpPrefix: sr.RemotePrefix}
	case sr.RemoteGroup != "":
		pr.Remote = &v1.SecurityGroupRule_RemoteGroupId{RemoteGroupId: sr.RemoteGroup}
	}
	return pr
}

func (c *class) ruleCount() int {
	n := 0
	for _, g := range c.s.Groups {
		n += len(g.Rules)
	}
	return n
}
