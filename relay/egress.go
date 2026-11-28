// SPDX-License-Identifier: BSD-3-Clause

package relay

import (
	"context"
	"errors"
	"net"
	"net/netip"
	"slices"
	"strings"
	"sync"
	"sync/atomic"
	"time"

	"github.com/go-wasmcontainers/relay/egress"
	"github.com/go-wasmcontainers/relay/firewall"
	"github.com/go-wasmcontainers/relay/frame"
	v1 "github.com/go-wasmcontainers/relay/gen/relayv1"
)

// EgressLimits bounds what an egress-enabled class may do outside (threat
// model section 10). Zero fields take the defaults; nothing here can be
// raised past a hard ceiling by a class, only by the operator.
type EgressLimits struct {
	StreamsPerSession     int           // open egress streams per session (16)
	ConnectsPerSecond     float64       // new egress connections per second per session (2)
	ConnectBurst          float64       // (20)
	StreamsPerDestination int           // open streams to one allowlisted name across the class (64)
	ClassBytesPerSecond   float64       // aggregate egress rate of the class (8 MiB/s)
	SessionBytesPerDay    uint64        // bytes per session per 24 h, both directions (1 GiB)
	Idle                  time.Duration // a stream with no data for this long is reset (5 min)
	Lifetime              time.Duration // no stream lives longer than this (1 h)
	LookupsPerSecond      float64       // outside name lookups per second per session (8)
	HelloTimeout          time.Duration // the TLS ClientHello must arrive within this (10 s)
}

func (l EgressLimits) withDefaults() EgressLimits {
	if l.StreamsPerSession == 0 {
		l.StreamsPerSession = 16
	}
	if l.ConnectsPerSecond == 0 {
		l.ConnectsPerSecond = 2
	}
	if l.ConnectBurst == 0 {
		l.ConnectBurst = 20
	}
	if l.StreamsPerDestination == 0 {
		l.StreamsPerDestination = 64
	}
	if l.ClassBytesPerSecond == 0 {
		l.ClassBytesPerSecond = 8 << 20
	}
	if l.SessionBytesPerDay == 0 {
		l.SessionBytesPerDay = 1 << 30
	}
	if l.Idle == 0 {
		l.Idle = 5 * time.Minute
	}
	if l.Lifetime == 0 {
		l.Lifetime = time.Hour
	}
	if l.LookupsPerSecond == 0 {
		l.LookupsPerSecond = 8
	}
	if l.HelloTimeout == 0 {
		l.HelloTimeout = 10 * time.Second
	}
	return l
}

// EgressConfig configures the egress gateway of every egress-enabled class
// of a relay. A class with no allowlist has no egress whatever this holds.
type EgressConfig struct {
	// Resolver does the outside lookups; the default is the system resolver.
	Resolver egress.Resolver
	// Dial opens the TCP connection to an address the gateway authorised.
	// The default dials the literal with the gateway's connect-time check;
	// tests replace it to reach a local server.
	Dial func(ctx context.Context, ip netip.Addr, port uint16) (net.Conn, error)
	// Operator is the label shown to every member of an egress class.
	Operator string
	// Deny lists prefixes that are never dialled either, besides the built-in
	// table and the class network.
	Deny   []netip.Prefix
	Limits EgressLimits
}

type netResolver struct{}

func (netResolver) LookupAddrs(ctx context.Context, name string) ([]netip.Addr, error) {
	return net.DefaultResolver.LookupNetIP(ctx, "ip", name)
}

// egressClass is the egress state of one class. Maps are guarded by
// Relay.mu; counters are atomic.
type egressClass struct {
	r      *Relay
	c      *class
	gw     *egress.Gateway
	lim    EgressLimits
	dial   func(ctx context.Context, ip netip.Addr, port uint16) (net.Conn, error)
	allow  []string
	bytes  *bucket
	sess   map[string]*egressSess
	dest   map[string]int
	ctr    egressCounters
	lastMu sync.Mutex
	last   struct {
		host, reason string
		unix         int64
	}
}

type egressCounters struct {
	allowed, notAllowed, private, tls, limit, udp, up, down atomic.Uint64
	active                                                  atomic.Int64
}

// egressSess is one session's egress state.
type egressSess struct {
	id      string
	pins    *egress.Pins
	streams int
	connect *bucket
	lookup  *bucket
	agent   *agent

	dayMu    sync.Mutex
	dayStart time.Time
	day      uint64
}

// addBytes counts n bytes against the day's allowance and reports whether
// the session is still within it.
func (s *egressSess) addBytes(n uint64, now time.Time, limit uint64) bool {
	s.dayMu.Lock()
	defer s.dayMu.Unlock()
	if now.Sub(s.dayStart) >= 24*time.Hour {
		s.dayStart, s.day = now, 0
	}
	s.day += n
	return s.day <= limit
}

func (s *egressSess) overDay(now time.Time, limit uint64) bool {
	s.dayMu.Lock()
	defer s.dayMu.Unlock()
	if now.Sub(s.dayStart) >= 24*time.Hour {
		s.dayStart, s.day = now, 0
	}
	return s.day >= limit
}

// egressLink is what a link to the outside carries.
type egressLink struct {
	sess *egressSess
	// names are the allowlisted names the address was pinned for; the stream
	// is counted against each of them.
	names []string
}

// newEgressClass builds the gateway of a class. It refuses what decision D2
// and D5 refuse: egress without identity and a named audience, and an empty,
// wildcard or IP allowlist. There is no switch to waive any of it.
func newEgressClass(c *class) (*egressClass, error) {
	sc := c.s
	if len(sc.Egress) == 0 {
		return nil, nil
	}
	if !sc.RequireID || len(sc.Allowed) == 0 {
		return nil, errors.New("relay: egress needs require-identity and a non-empty allowed list of groups or people; an open class never gets outbound access")
	}
	al, err := egress.ParseAllowlist(sc.Egress)
	if err != nil {
		return nil, err
	}
	cfg := c.r.cfg.Egress
	res := cfg.Resolver
	if res == nil {
		res = netResolver{}
	}
	extra := append([]netip.Prefix{c.net}, cfg.Deny...)
	// al is non-empty and res is set here, which is all NewGateway checks.
	gw := &egress.Gateway{Allow: al, Resolver: res, Now: time.Now, Extra: slices.Clone(extra)}
	lim := cfg.Limits.withDefaults()
	e := &egressClass{r: c.r, c: c, gw: gw, lim: lim, dial: cfg.Dial,
		bytes: newBucket(lim.ClassBytesPerSecond, lim.ClassBytesPerSecond, time.Now),
		sess:  map[string]*egressSess{}, dest: map[string]int{}}
	if e.dial == nil {
		d := &net.Dialer{Timeout: dialTimeout, Control: gw.Control}
		e.dial = func(ctx context.Context, ip netip.Addr, port uint16) (net.Conn, error) {
			return d.DialContext(ctx, "tcp4", netip.AddrPortFrom(ip, port).String())
		}
	}
	for _, d := range al.Hosts() {
		e.allow = append(e.allow, d.String())
	}
	return e, nil
}

// dialTimeout is under connectTimeout so the dial's own error is the one the
// guest sees.
const dialTimeout = 8 * time.Second

// session returns (creating) the egress state of a session. Relay.mu held.
func (e *egressClass) session(id string) *egressSess {
	s := e.sess[id]
	if s == nil {
		now := e.r.cfg.Now
		s = &egressSess{id: id, pins: egress.NewPins(), dayStart: now(),
			connect: newBucket(e.lim.ConnectsPerSecond, e.lim.ConnectBurst, now),
			lookup:  newBucket(e.lim.LookupsPerSecond, e.lim.LookupsPerSecond, now)}
		e.sess[id] = s
	}
	return s
}

// deny records the last refusal every member is shown. A host is shown only
// when it is an allowlisted name or an address (which the guest cannot make
// say anything but itself): a name another member asked for is theirs, and
// goes to the flow log only.
func (e *egressClass) deny(host, reason string) {
	if _, err := netip.ParseAddr(host); err != nil && !e.gw.Allow.Has(host, egress.Port) {
		host = ""
	}
	e.lastMu.Lock()
	e.last.host, e.last.reason, e.last.unix = cleanLabel(host, 253), cleanLabel(reason, 200), e.r.cfg.Now().Unix()
	e.lastMu.Unlock()
}

// cleanLabel makes a guest-influenced string safe to show or log: printable
// ASCII only (anything else, and the characters markup uses, becomes '?'),
// at most max bytes.
func cleanLabel(s string, max int) string {
	b := make([]byte, 0, min(len(s), max)+3)
	for i := 0; i < len(s); i++ {
		if len(b) >= max {
			return string(append(b, "..."...))
		}
		c := s[i]
		if c < 0x20 || c >= 0x7f || c == '<' || c == '>' || c == '"' || c == '&' {
			c = '?'
		}
		b = append(b, c)
	}
	return string(b)
}

// proto is the state every member sees: what is allowed, who runs it, what
// is logged, the limits and the counters.
func (e *egressClass) proto() *v1.EgressState {
	if e == nil {
		return &v1.EgressState{Policy: "none", Reason: "this class has no outbound internet access"}
	}
	l := e.lim
	op := e.r.cfg.Egress.Operator
	if op == "" {
		op = e.r.cfg.RelayID
	}
	st := &v1.EgressState{Policy: "gateway", Operator: op, Logs: true,
		Allowlist: slices.Clone(e.allow),
		Limits: &v1.EgressLimits{StreamsPerSession: uint32(l.StreamsPerSession), ConnectsPerSecond: l.ConnectsPerSecond,
			ConnectBurst: uint32(l.ConnectBurst), StreamsPerDestination: uint32(l.StreamsPerDestination),
			ClassBytesPerSecond: uint64(l.ClassBytesPerSecond), SessionBytesPerDay: l.SessionBytesPerDay,
			IdleSeconds: uint32(l.Idle / time.Second), LifetimeSeconds: uint32(l.Lifetime / time.Second),
			LookupsPerSecond: l.LookupsPerSecond}}
	cn := &v1.EgressCounters{Allowed: e.ctr.allowed.Load(), DeniedNotAllowlisted: e.ctr.notAllowed.Load(),
		DeniedPrivateRange: e.ctr.private.Load(), DeniedTlsName: e.ctr.tls.Load(), DeniedLimit: e.ctr.limit.Load(),
		DroppedUdp: e.ctr.udp.Load(), BytesUp: e.ctr.up.Load(), BytesDown: e.ctr.down.Load(),
		ActiveStreams: uint32(max(e.ctr.active.Load(), 0))}
	e.lastMu.Lock()
	cn.LastDeniedHost, cn.LastDeniedReason, cn.LastDeniedUnix = e.last.host, e.last.reason, e.last.unix
	e.lastMu.Unlock()
	st.Counters = cn
	return st
}

// EgressState is what members of the class are told about outbound access,
// with the live counters.
func (r *Relay) EgressState(classID string) (*v1.EgressState, error) {
	r.mu.Lock()
	c, ok := r.classes[classID]
	if !ok {
		r.mu.Unlock()
		return nil, errf(KindNotFound, "no class %s", classID)
	}
	eg := c.eg
	r.mu.Unlock()
	return eg.proto(), nil
}

// denyKind classifies a gateway refusal for the counters.
func (e *egressClass) count(err error) {
	var de *egress.DeniedError
	switch {
	case errors.As(err, &de):
		e.ctr.private.Add(1)
	case errors.Is(err, egress.ErrLimit):
		e.ctr.limit.Add(1)
	default:
		e.ctr.notAllowed.Add(1)
	}
}

// connectEgress is the connect() branch for a destination that is no
// container of the class. Relay.mu held. Without egress it is the old
// answer; with it, every refusal is a policy verdict (ECONNREFUSED) except a
// limit (ENOBUFS).
func (cn *conn) connectEgress(id uint32, m *v1.Connect, dst, srcAddr netip.Addr, refuse func(v1.Code, string) error) error {
	c := cn.c
	e := c.eg
	if e == nil {
		return refuse(v1.Code_CODE_UNREACHABLE, "no container has this address")
	}
	r := cn.r
	s := e.session(cn.session)
	flow := firewall.Flow{Protocol: firewall.TCP, Src: netip.AddrPortFrom(srcAddr, 0), Dst: netip.AddrPortFrom(dst, uint16(m.DstPort))}
	denied := func(code v1.Code, why string) error {
		e.deny(dst.String(), why)
		c.logFlow(flow, m.PortId, "", v1.Verdict_VERDICT_DENY, firewall.Decision{Reason: "egress: " + why}, 0, 0)
		return refuse(code, "egress refused: "+why)
	}
	limited := func(why string) error {
		e.ctr.limit.Add(1)
		return denied(v1.Code_CODE_LIMIT, why)
	}
	if !s.connect.take(1) {
		return limited("too many new outside connections; slow down")
	}
	// The class firewall judges the outside like any other destination: an
	// "outside" port with no port security, so the guest's egress rules
	// decide (a class that removed them has no way out).
	if d := c.pol.Evaluate(flow, c.fwPort(m.PortId), &firewall.Port{ID: "outside", Addr: dst}); !d.Allowed {
		e.ctr.notAllowed.Add(1)
		return denied(v1.Code_CODE_REFUSED, "refused by the firewall: "+d.Reason)
	}
	names, err := e.gw.Authorize(s.pins, dst, uint16(m.DstPort))
	if err != nil {
		e.count(err)
		return denied(v1.Code_CODE_REFUSED, err.Error())
	}
	name := strings.Join(names, ",")
	switch {
	case s.streams >= e.lim.StreamsPerSession:
		return limited("too many open outside streams for this session")
	case e.destFull(names):
		return limited("too many open streams to " + name + " across the class")
	case s.overDay(r.cfg.Now(), e.lim.SessionBytesPerDay):
		return limited("this session used its outside traffic for the day")
	}
	srcPort := c.freeEphemeral(m.PortId, srcAddr, firewall.TCP)
	if srcPort == 0 {
		return refuse(v1.Code_CODE_LIMIT, "no ephemeral port left")
	}
	flow.Src = netip.AddrPortFrom(srcAddr, srcPort)
	ag := s.agentFor(e, cn)
	b := ag.cn
	b.mu.Lock()
	bid := b.nextID
	b.nextID += 2
	lk := &link{c: c, flow: flow, a: cn, b: b, aID: id, bID: bid, aPort: m.PortId, bPort: "", opened: r.cfg.Now(),
		eg: &egressLink{sess: s, names: names}}
	lk.credit[0].Store(int64(r.limits.StreamWindow))
	lk.credit[1].Store(int64(r.limits.StreamWindow))
	b.streams[bid] = &end{l: lk, side: 1}
	b.mu.Unlock()
	cn.mu.Lock()
	cn.streams[id] = &end{l: lk, side: 0}
	cn.pending++
	cn.mu.Unlock()
	c.links[lk] = struct{}{}
	s.streams++
	for _, n := range names {
		e.dest[n]++
	}
	e.ctr.active.Add(1)
	e.ctr.allowed.Add(1)
	ag.expect(bid, expect{ip: dst, names: names, flow: flow, aPort: m.PortId})
	lk.timer = time.AfterFunc(connectTimeout, func() {
		r.mu.Lock()
		defer r.mu.Unlock()
		if !lk.open.Load() && !lk.gone.Load() {
			c.dropLink(lk, v1.Code_CODE_REFUSED, "the outside did not answer", v1.Verdict_VERDICT_CLOSED)
		}
	})
	b.sendMsg(frame.TypeConnect, bid, &v1.Incoming{PortId: "egress", ListenPort: m.DstPort,
		SrcIp: srcAddr.String(), SrcPort: uint32(srcPort)})
	c.logFlow(flow, m.PortId, "", v1.Verdict_VERDICT_ALLOW, firewall.Decision{Allowed: true, Reason: "egress to " + name}, 0, 0)
	return nil
}

// destFull reports whether a new stream would take any of the names over the
// per-destination bound. Relay.mu held.
func (e *egressClass) destFull(names []string) bool {
	for _, n := range names {
		if e.dest[n] >= e.lim.StreamsPerDestination {
			return true
		}
	}
	return false
}

// release gives back what a finished egress link held. Relay.mu held.
func (e *egressClass) release(l *link) {
	el := l.eg
	el.sess.streams--
	for _, n := range el.names {
		if e.dest[n]--; e.dest[n] <= 0 {
			delete(e.dest, n)
		}
	}
	e.ctr.active.Add(-1)
	e.ctr.up.Add(l.sent[0].Load())
	e.ctr.down.Add(l.sent[1].Load())
}

// dropLinks ends every egress link of one session ("" for the class).
// Relay.mu held.
func (e *egressClass) dropLinks(session string, why string) {
	for l := range e.c.links {
		if l.eg != nil && (session == "" || l.a.session == session) {
			e.c.dropLink(l, v1.Code_CODE_UNAUTHENTICATED, why, v1.Verdict_VERDICT_REVOKED)
		}
	}
}

// dropSession forgets one session's egress state and ends its streams.
// Relay.mu held.
func (e *egressClass) dropSession(id string) {
	e.dropLinks(id, "the session was removed from the class")
	if s := e.sess[id]; s != nil {
		if s.agent != nil {
			go s.agent.stop()
		}
		delete(e.sess, id)
	}
}

// dropAll ends every egress stream of the class and forgets every pinned
// address: a rotated join code revokes what the old one allowed. Relay.mu held.
func (e *egressClass) dropAll(why string) {
	e.dropLinks("", why)
	for _, s := range e.sess {
		s.pins.Clear()
	}
}

// stopAll ends the agents of a deleted class. Relay.mu held.
func (e *egressClass) stopAll() {
	e.dropLinks("", "the class was deleted")
	for id, s := range e.sess {
		if s.agent != nil {
			go s.agent.stop()
		}
		delete(e.sess, id)
	}
}

// guestGone stops the agent of a session whose last connection ended.
// Relay.mu held.
func (e *egressClass) guestGone(session string) {
	if s := e.sess[session]; s != nil && s.agent != nil {
		go s.agent.stop()
		s.agent = nil
	}
}

// agentGone forgets an agent whose connection ended. Relay.mu held.
func (e *egressClass) agentGone(cn *conn) {
	for _, s := range e.sess {
		if s.agent != nil && s.agent.cn == cn {
			go s.agent.stop()
			s.agent = nil
		}
	}
}

// lookup answers a guest's name lookup for an allowlisted name: the only
// outside DNS the relay does (threat model rule 1), rate limited per session.
// It does not hold Relay.mu. A refusal comes back as why (non-empty) for the
// caller to put in the flow log, which needs the lock.
func (e *egressClass) lookup(s *egressSess, name string) (addrs []netip.Addr, why string) {
	name = egress.Normalize(name)
	refuse := func(reason string) ([]netip.Addr, string) {
		e.deny(name, reason)
		return nil, reason
	}
	if !e.gw.Allow.Has(name, egress.Port) {
		e.ctr.notAllowed.Add(1)
		return refuse("not allowlisted")
	}
	if !s.lookup.take(1) {
		e.ctr.limit.Add(1)
		return refuse("too many outside lookups")
	}
	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()
	addrs, err := e.gw.Resolve(ctx, s.pins, name)
	if err != nil {
		var de *egress.DeniedError
		if errors.As(err, &de) {
			e.ctr.private.Add(1)
		}
		return refuse(err.Error())
	}
	return addrs, ""
}

// isClassName reports whether name is for the class's own DNS, which never
// goes outside. (An IP literal is answered by the class's own resolver, so it
// never reaches the gateway, and would be refused there as not allowlisted.)
func (c *class) isClassName(name string) bool {
	name = strings.TrimSuffix(strings.ToLower(name), ".")
	return strings.HasSuffix(name, "."+c.s.DNSDomain)
}
