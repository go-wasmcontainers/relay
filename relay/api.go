// SPDX-License-Identifier: BSD-3-Clause

package relay

import (
	"net/netip"
	"slices"
	"strings"

	"github.com/go-wasmcontainers/relay/firewall"
	v1 "github.com/go-wasmcontainers/relay/gen/relayv1"
)

func (r *Relay) class(id string) (*class, error) {
	c, ok := r.classes[id]
	if !ok {
		return nil, errf(KindNotFound, "no class %s", id)
	}
	return c, nil
}

// policyChanged recompiles a class's policy, saves, and resets the flows the
// new policy no longer allows. Relay.mu held.
func (r *Relay) policyChanged(c *class) error {
	if err := c.compile(); err != nil {
		return err
	}
	c.revalidate()
	return r.save()
}

// ListSecurityGroups lists a class's groups with their rules.
func (r *Relay) ListSecurityGroups(classID string) ([]*v1.SecurityGroup, error) {
	r.mu.Lock()
	defer r.mu.Unlock()
	c, err := r.class(classID)
	if err != nil {
		return nil, err
	}
	var out []*v1.SecurityGroup
	for _, g := range c.s.Groups {
		out = append(out, c.groupProto(g))
	}
	slices.SortFunc(out, func(a, b *v1.SecurityGroup) int { return strings.Compare(a.Name, b.Name) })
	return out, nil
}

// CreateSecurityGroup adds an empty group (no rule: it allows nothing).
func (r *Relay) CreateSecurityGroup(classID, name, desc string, stateless bool) (*v1.SecurityGroup, error) {
	if !validContainerName(name) {
		return nil, errf(KindInvalid, "group name %q: lower-case letters, digits and hyphens", name)
	}
	if len(desc) > 255 {
		return nil, errf(KindInvalid, "description longer than 255 bytes")
	}
	r.mu.Lock()
	defer r.mu.Unlock()
	c, err := r.class(classID)
	if err != nil {
		return nil, err
	}
	if c.findGroup(name) != nil {
		return nil, errf(KindExists, "group %s exists", name)
	}
	if len(c.s.Groups) >= r.cfg.MaxGroups {
		return nil, errf(KindLimit, "quota: %d security groups per class", r.cfg.MaxGroups)
	}
	g := &sGroup{ID: c.s.newID("sg-"), Name: name, Description: desc, Stateful: !stateless}
	c.s.Groups[g.ID] = g
	if err := r.policyChanged(c); err != nil {
		return nil, err
	}
	r.audit("sg.create", "class", classID, "group", g.ID, "name", name)
	return c.groupProto(g), nil
}

// DeleteSecurityGroup removes a group no port uses and no rule names.
func (r *Relay) DeleteSecurityGroup(classID, ref string) error {
	r.mu.Lock()
	defer r.mu.Unlock()
	c, err := r.class(classID)
	if err != nil {
		return err
	}
	g := c.findGroup(ref)
	if g == nil {
		return errf(KindNotFound, "no group %s", ref)
	}
	if g.ID == c.s.DefaultSG {
		return errf(KindInvalid, "the default group cannot be deleted")
	}
	for _, p := range c.s.Ports {
		if slices.Contains(p.Groups, g.ID) {
			return errf(KindInvalid, "group %s is in use by port %s", g.Name, p.ID)
		}
	}
	for _, o := range c.s.Groups {
		for _, sr := range o.Rules {
			if sr.RemoteGroup == g.ID && o.ID != g.ID {
				return errf(KindInvalid, "rule %s of group %s names group %s", sr.ID, o.Name, g.Name)
			}
		}
	}
	delete(c.s.Groups, g.ID)
	r.audit("sg.delete", "class", classID, "group", g.ID)
	return r.policyChanged(c)
}

// CreateRule adds a rule to a group; flows it allows start being allowed at
// once.
func (r *Relay) CreateRule(classID, groupRef string, pr *v1.SecurityGroupRule) (*v1.SecurityGroupRule, error) {
	if pr == nil {
		return nil, errf(KindInvalid, "no rule")
	}
	if pr.Ethertype != "" && pr.Ethertype != "IPv4" {
		return nil, errf(KindInvalid, "ethertype %q: only IPv4 for now", pr.Ethertype)
	}
	if pr.PortRangeMin > 65535 || pr.PortRangeMax > 65535 {
		return nil, errf(KindInvalid, "port above 65535")
	}
	r.mu.Lock()
	defer r.mu.Unlock()
	c, err := r.class(classID)
	if err != nil {
		return nil, err
	}
	g := c.findGroup(groupRef)
	if g == nil {
		return nil, errf(KindNotFound, "no group %s", groupRef)
	}
	if c.ruleCount() >= r.cfg.MaxRules {
		return nil, errf(KindLimit, "quota: %d security group rules per class", r.cfg.MaxRules)
	}
	sr := sRule{Direction: uint8(pr.Direction), Protocol: uint8(pr.Protocol), PortMin: uint16(pr.PortRangeMin),
		PortMax: uint16(pr.PortRangeMax), Description: pr.Description, Log: pr.Log}
	if sr.Protocol == uint8(firewall.TCP) || sr.Protocol == uint8(firewall.UDP) {
		if sr.PortMin != 0 && sr.PortMax == 0 {
			sr.PortMax = sr.PortMin
		}
	}
	switch rem := pr.Remote.(type) {
	case *v1.SecurityGroupRule_RemoteIpPrefix:
		p, err := netip.ParsePrefix(rem.RemoteIpPrefix)
		if err != nil {
			a, aerr := netip.ParseAddr(rem.RemoteIpPrefix)
			if aerr != nil {
				return nil, errf(KindInvalid, "remote_ip_prefix %q: %v", rem.RemoteIpPrefix, err)
			}
			p = netip.PrefixFrom(a, a.BitLen())
		}
		sr.RemotePrefix = p.Masked().String()
	case *v1.SecurityGroupRule_RemoteGroupId:
		rg := c.findGroup(rem.RemoteGroupId)
		if rg == nil {
			return nil, errf(KindNotFound, "no group %s", rem.RemoteGroupId)
		}
		sr.RemoteGroup = rg.ID
	}
	if _, err := sr.rule(g.ID); err != nil {
		return nil, errf(KindInvalid, "%v", err)
	}
	for _, o := range g.Rules {
		o2 := o
		o2.ID = ""
		n := sr
		n.ID = ""
		if o2 == n {
			return nil, errf(KindExists, "the same rule exists: %s", o.ID)
		}
	}
	sr.ID = c.s.newID("r-")
	g.Rules = append(g.Rules, sr)
	if err := r.policyChanged(c); err != nil {
		return nil, err
	}
	r.audit("rule.create", "class", classID, "group", g.ID, "rule", sr.ID)
	return ruleProto(g.ID, sr), nil
}

// DeleteRule removes a rule; the flows only it allowed are reset.
func (r *Relay) DeleteRule(classID, ruleID string) error {
	r.mu.Lock()
	defer r.mu.Unlock()
	c, err := r.class(classID)
	if err != nil {
		return err
	}
	for _, g := range c.s.Groups {
		for i, sr := range g.Rules {
			if sr.ID == ruleID {
				g.Rules = slices.Delete(g.Rules, i, i+1)
				r.audit("rule.delete", "class", classID, "group", g.ID, "rule", ruleID)
				return r.policyChanged(c)
			}
		}
	}
	return errf(KindNotFound, "no rule %s", ruleID)
}

// ListPorts lists a class's ports, or one session's.
func (r *Relay) ListPorts(classID, session string) ([]*v1.Port, error) {
	r.mu.Lock()
	defer r.mu.Unlock()
	c, err := r.class(classID)
	if err != nil {
		return nil, err
	}
	var sid string
	if session != "" {
		s := c.findSession(session)
		if s == nil {
			return nil, errf(KindNotFound, "no session %s", session)
		}
		sid = s.ID
	}
	var out []*v1.Port
	for id, p := range c.s.Ports {
		if sid == "" || p.Session == sid {
			out = append(out, c.portProto(id))
		}
	}
	slices.SortFunc(out, func(a, b *v1.Port) int {
		aa, _ := netip.ParseAddr(a.Ip)
		bb, _ := netip.ParseAddr(b.Ip)
		return aa.Compare(bb)
	})
	return out, nil
}

// UpdatePort replaces a port's groups and/or its port security flag.
func (r *Relay) UpdatePort(classID, ref string, groups []string, setGroups bool, portSecurity *bool) (*v1.Port, error) {
	r.mu.Lock()
	defer r.mu.Unlock()
	c, err := r.class(classID)
	if err != nil {
		return nil, err
	}
	id, p := c.findPort(ref)
	if p == nil {
		return nil, errf(KindNotFound, "no port %s", ref)
	}
	if setGroups {
		var ids []string
		for _, gr := range groups {
			g := c.findGroup(gr)
			if g == nil {
				return nil, errf(KindNotFound, "no group %s", gr)
			}
			if !slices.Contains(ids, g.ID) {
				ids = append(ids, g.ID)
			}
		}
		p.Groups = ids
	}
	if portSecurity != nil {
		p.PortSecurity = *portSecurity
	}
	if err := r.policyChanged(c); err != nil {
		return nil, err
	}
	r.audit("port.update", "class", classID, "port", id)
	return c.portProto(id), nil
}

// ExplainFlow says what the firewall would decide for a flow, without one.
func (r *Relay) ExplainFlow(classID, src, dst string, proto firewall.Protocol, port uint16) (*v1.FlowEvent, error) {
	r.mu.Lock()
	defer r.mu.Unlock()
	c, err := r.class(classID)
	if err != nil {
		return nil, err
	}
	sid, sp := c.findPort(src)
	did, dp := c.findPort(dst)
	if sp == nil || dp == nil {
		return nil, errf(KindNotFound, "both ends must be ports (id, name or label/container)")
	}
	f := firewall.Flow{Protocol: proto, Src: netip.AddrPortFrom(c.portAddr(sp), 49152), Dst: netip.AddrPortFrom(c.portAddr(dp), port)}
	d := c.pol.Evaluate(f, c.fwPort(sid), c.fwPort(did))
	v := v1.Verdict_VERDICT_DENY
	if d.Allowed {
		v = v1.Verdict_VERDICT_ALLOW
	}
	return &v1.FlowEvent{TimeUnixNano: r.cfg.Now().UnixNano(), ClassId: classID, SrcSession: sp.Session, SrcPortId: sid,
		Src: f.Src.String(), DstSession: dp.Session, DstPortId: did, Dst: f.Dst.String(), Protocol: v1.Protocol(proto),
		Verdict: v, EgressRuleId: d.EgressRule, IngressRuleId: d.IngressRule, Reason: d.Reason}, nil
}

// SessionOf returns a session's id from an id or a label.
func (r *Relay) SessionOf(classID, who string) (string, error) {
	r.mu.Lock()
	defer r.mu.Unlock()
	c, err := r.class(classID)
	if err != nil {
		return "", err
	}
	s := c.findSession(who)
	if s == nil {
		return "", errf(KindNotFound, "no session %s", who)
	}
	return s.ID, nil
}
