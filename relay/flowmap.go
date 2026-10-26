// SPDX-License-Identifier: BSD-3-Clause

package relay

import (
	"cmp"
	"context"
	"crypto/rand"
	"encoding/hex"
	"fmt"
	"slices"
	"strings"
	"time"

	"github.com/go-wasmcontainers/relay/auth"
	"github.com/go-wasmcontainers/relay/firewall"
	v1 "github.com/go-wasmcontainers/relay/gen/relayv1"
)

// Flow-map bounds: what one update may carry.
const (
	MapMaxNodes  = 400
	MapMaxEdges  = 2000
	MapMaxEvents = 200
	// mapEdgeLinger keeps an edge on the map this long after its last flow.
	mapEdgeLinger = 60 * time.Second
	// mapDeniedRecent is how long a refusal makes an edge flash.
	mapDeniedRecent = 3 * time.Second
	// mapForget drops an edge's counters this long after its last flow.
	mapForget = 5 * time.Minute
)

// edgeKey is one edge of the map: who talks to whom, on which port.
type edgeKey struct {
	src, dst string // port ids
	proto    firewall.Protocol
	port     uint16
}

func (k edgeKey) id() string {
	return fmt.Sprintf("%s>%s/%s/%d", k.src, k.dst, k.proto, k.port)
}

// edgeStat aggregates the flows of one edge. Relay.mu guards it.
type edgeStat struct {
	bytes            uint64 // closed streams and datagrams
	opened, denied   uint32
	lastSeen, denyAt time.Time
	reason           string
	egress, ingress  string
}

func (c *class) stat(k edgeKey) *edgeStat {
	if c.edges == nil {
		c.edges = map[edgeKey]*edgeStat{}
	}
	s := c.edges[k]
	if s == nil {
		if len(c.edges) >= 4*MapMaxEdges {
			c.pruneEdges(c.r.cfg.Now(), true)
		}
		s = &edgeStat{}
		c.edges[k] = s
	}
	return s
}

// account updates the map's counters for one logged decision. Relay.mu held.
func (c *class) account(e *v1.FlowEvent, f firewall.Flow) {
	if e.SrcPortId == "" || e.DstPortId == "" {
		return
	}
	now := time.Unix(0, e.TimeUnixNano)
	s := c.stat(edgeKey{e.SrcPortId, e.DstPortId, f.Protocol, f.Dst.Port()})
	s.lastSeen = now
	switch e.Verdict {
	case v1.Verdict_VERDICT_ALLOW:
		s.opened++
		s.egress, s.ingress = e.EgressRuleId, e.IngressRuleId
		s.bytes += e.BytesOut
	case v1.Verdict_VERDICT_DENY, v1.Verdict_VERDICT_REVOKED:
		s.denied++
		s.denyAt = now
		s.reason = e.Reason
		s.bytes += e.BytesOut + e.BytesIn // a revoked stream had carried some
	case v1.Verdict_VERDICT_CLOSED:
		s.bytes += e.BytesOut + e.BytesIn
	}
}

// pruneEdges forgets edges idle for mapForget (all idle ones when force).
func (c *class) pruneEdges(now time.Time, force bool) {
	for k, s := range c.edges {
		if now.Sub(s.lastSeen) > mapForget || (force && now.Sub(s.lastSeen) > mapEdgeLinger) {
			delete(c.edges, k)
		}
	}
}

// MapTicket issues a read-only flow-map ticket for a class (12 hours).
func (r *Relay) MapTicket(classID string) (string, time.Time, error) {
	r.mu.Lock()
	_, ok := r.classes[classID]
	r.mu.Unlock()
	if !ok {
		return "", time.Time{}, errf(KindNotFound, "no class %s", classID)
	}
	var b [8]byte
	_, _ = rand.Read(b[:])
	exp := r.cfg.Now().Add(12 * time.Hour)
	tok, err := r.cfg.Keys.Sign(auth.Claims{Expiry: exp, Class: classID, Session: "map:" + hex.EncodeToString(b[:])})
	if err != nil {
		return "", time.Time{}, err
	}
	r.audit("flowmap.ticket", "class", classID)
	return tok, exp, nil
}

// VerifyMapTicket checks a flow-map ticket and returns its class.
func (r *Relay) VerifyMapTicket(tok string) (string, error) {
	cl, err := r.cfg.Keys.Verify(tok, r.cfg.Now())
	if err != nil || !strings.HasPrefix(cl.Session, "map:") {
		return "", errf(KindUnauthenticated, "unauthenticated")
	}
	r.mu.Lock()
	_, ok := r.classes[cl.Class]
	r.mu.Unlock()
	if !ok {
		return "", errf(KindUnauthenticated, "unauthenticated")
	}
	return cl.Class, nil
}

// MapWatcher produces successive flow-map updates for one viewer.
type MapWatcher struct {
	r       *Relay
	classID string
	session string // empty: the whole class
	sub     *subscriber
	c       *class
	seq     uint64
	prev    map[string]uint64
	prevAt  time.Time
}

// WatchMap starts a watcher; session limits it to one session's flows.
// Close it when done.
func (r *Relay) WatchMap(classID, session string) (*MapWatcher, error) {
	r.mu.Lock()
	defer r.mu.Unlock()
	c, err := r.class(classID)
	if err != nil {
		return nil, err
	}
	sub := &subscriber{ch: make(chan *v1.FlowEvent, MapMaxEvents), session: session, closed: make(chan struct{})}
	c.subs[sub] = struct{}{}
	return &MapWatcher{r: r, classID: classID, session: session, sub: sub, c: c, prev: map[string]uint64{}}, nil
}

// Close stops the watcher's event subscription.
func (w *MapWatcher) Close() {
	w.r.mu.Lock()
	delete(w.c.subs, w.sub)
	w.r.mu.Unlock()
}

// Done is closed when the class goes away.
func (w *MapWatcher) Done() <-chan struct{} { return w.sub.closed }

// Next builds the current map and drains the events since the last call.
func (w *MapWatcher) Next(ctx context.Context) (*v1.FlowMapUpdate, error) {
	if err := ctx.Err(); err != nil {
		return nil, err
	}
	r := w.r
	r.mu.Lock()
	c, ok := r.classes[w.classID]
	if !ok {
		r.mu.Unlock()
		return nil, errf(KindNotFound, "the class was deleted")
	}
	now := r.cfg.Now()
	u := c.snapshot(now, w.session)
	r.mu.Unlock()

	w.seq++
	u.Seq = w.seq
	u.TimeUnixNano = now.UnixNano()
	dt := now.Sub(w.prevAt).Seconds()
	next := make(map[string]uint64, len(u.Edges))
	for _, e := range u.Edges {
		// An edge new since the last update carried all its bytes since then.
		if p := w.prev[e.Id]; !w.prevAt.IsZero() && dt > 0 && e.Bytes >= p {
			e.BytesPerSecond = float64(e.Bytes-p) / dt
		}
		next[e.Id] = e.Bytes
	}
	w.prev, w.prevAt = next, now
	for len(u.Events) < MapMaxEvents {
		select {
		case e := <-w.sub.ch:
			u.Events = append(u.Events, e)
			continue
		default:
		}
		break
	}
	u.DroppedEvents = uint32(w.sub.dropped.Swap(0))
	return u, nil
}

// snapshot is the current map of a class, or of one session's flows.
// Relay.mu held.
func (c *class) snapshot(now time.Time, session string) *v1.FlowMapUpdate {
	c.pruneEdges(now, false)
	// Live streams: their bytes so far and how many are open, per edge.
	type live struct {
		bytes uint64
		open  uint32
	}
	lives := map[edgeKey]*live{}
	for l := range c.links {
		if !l.open.Load() {
			continue
		}
		k := edgeKey{l.aPort, l.bPort, l.flow.Protocol, l.flow.Dst.Port()}
		lv := lives[k]
		if lv == nil {
			lv = &live{}
			lives[k] = lv
		}
		lv.bytes += l.sent[0].Load() + l.sent[1].Load()
		lv.open++
	}
	keys := make([]edgeKey, 0, len(c.edges))
	for k := range c.edges {
		keys = append(keys, k)
	}
	for k := range lives {
		if c.edges[k] == nil {
			keys = append(keys, k)
		}
	}
	slices.SortFunc(keys, func(a, b edgeKey) int {
		return cmp.Or(cmp.Compare(a.src, b.src), cmp.Compare(a.dst, b.dst), cmp.Compare(a.proto, b.proto), cmp.Compare(a.port, b.port))
	})
	u := &v1.FlowMapUpdate{}
	touched := map[string]bool{}
	mine := func(portID string) bool {
		p := c.s.Ports[portID]
		return p != nil && p.Session == session
	}
	for _, k := range keys {
		s := c.edges[k]
		if s == nil {
			s = &edgeStat{lastSeen: now}
		}
		lv := lives[k]
		if lv == nil {
			lv = &live{}
		}
		if lv.open == 0 && now.Sub(s.lastSeen) > mapEdgeLinger {
			continue
		}
		if c.s.Ports[k.src] == nil || c.s.Ports[k.dst] == nil {
			continue
		}
		if session != "" && !mine(k.src) && !mine(k.dst) {
			continue
		}
		if len(u.Edges) >= MapMaxEdges {
			u.Truncated = true
			break
		}
		u.Edges = append(u.Edges, &v1.MapEdge{Id: k.id(), SrcPort: k.src, DstPort: k.dst, Protocol: v1.Protocol(k.proto),
			Port: uint32(k.port), Bytes: s.bytes + lv.bytes, Open: lv.open, Opened: s.opened, Denied: s.denied,
			DeniedRecently: !s.denyAt.IsZero() && now.Sub(s.denyAt) < mapDeniedRecent, LastReason: s.reason,
			EgressRuleId: s.egress, IngressRuleId: s.ingress})
		touched[k.src], touched[k.dst] = true, true
	}
	// Nodes: every port of the class (the teacher's view), or the session's
	// own ports and the peers its edges reach (a student's view).
	ids := make([]string, 0, len(c.s.Ports))
	for id, p := range c.s.Ports {
		if session == "" || p.Session == session || touched[id] {
			ids = append(ids, id)
		}
	}
	slices.SortFunc(ids, func(a, b string) int { return c.portAddr(c.s.Ports[a]).Compare(c.portAddr(c.s.Ports[b])) })
	sessions := map[string]bool{}
	for _, id := range ids {
		if len(u.Nodes) >= MapMaxNodes {
			u.Truncated = true
			break
		}
		p := c.s.Ports[id]
		n := &v1.MapNode{Id: id, Label: p.Container, Cluster: p.Session, Ip: c.portAddr(p).String()}
		for _, g := range p.Groups {
			if sg := c.s.Groups[g]; sg != nil {
				n.Groups = append(n.Groups, sg.Name)
			}
		}
		u.Nodes = append(u.Nodes, n)
		sessions[p.Session] = true
	}
	if session != "" {
		sessions[session] = true
	}
	ss := make([]*sSess, 0, len(sessions))
	for id := range sessions {
		if s := c.s.Sessions[id]; s != nil {
			ss = append(ss, s)
		}
	}
	slices.SortFunc(ss, func(a, b *sSess) int { return cmp.Compare(a.Index, b.Index) })
	for _, s := range ss {
		u.Clusters = append(u.Clusters, &v1.MapCluster{Id: s.ID, Label: s.Label, Teacher: s.Teacher})
	}
	return u
}
