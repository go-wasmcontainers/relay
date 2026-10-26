// SPDX-License-Identifier: BSD-3-Clause

package relay

import (
	"context"
	"errors"
	"net/netip"
	"sync"
	"sync/atomic"
	"time"

	"google.golang.org/protobuf/proto"

	"github.com/go-wasmcontainers/relay/auth"
	"github.com/go-wasmcontainers/relay/firewall"
	"github.com/go-wasmcontainers/relay/frame"
	v1 "github.com/go-wasmcontainers/relay/gen/relayv1"
)

// Transport carries whole messages, one frame each. The server's WebSocket
// and the tests' in-memory pipe implement it.
type Transport interface {
	ReadMessage(ctx context.Context) ([]byte, error)
	WriteMessage(ctx context.Context, msg []byte) error
	Close(reason string) error
}

// HelloTimeout bounds the wait for the first frame.
const HelloTimeout = 10 * time.Second

// connectTimeout bounds how long a listener may take to accept.
const connectTimeout = 10 * time.Second

// conn is one data connection: one browser (or engine) of one session.
type conn struct {
	r       *Relay
	c       *class
	session string
	label   string
	t       Transport

	out    chan []byte
	queued atomic.Int64
	done   chan struct{}
	once   sync.Once
	reason atomic.Value // string

	mu      sync.Mutex
	streams map[uint32]*end
	nextID  uint32 // even ids, allocated by the relay
	pending int

	expiry   atomic.Int64 // unix seconds of the session token
	lastSeen atomic.Int64
	bytes    *bucket
	frames   *bucket
}

// end is one side of a link as one connection sees it.
type end struct {
	l    *link
	side int // 0: the caller (a), 1: the listener (b)
}

// link is one TCP-like stream between two ports.
type link struct {
	c            *class
	flow         firewall.Flow
	a, b         *conn
	aID, bID     uint32
	aPort, bPort string
	open         atomic.Bool
	credit       [2]atomic.Int64 // bytes side i may still send
	sent         [2]atomic.Uint64
	closed       [2]atomic.Bool
	gone         atomic.Bool
	egress, ingr string
	timer        *time.Timer
	opened       time.Time
}

var errClosed = errors.New("relay: connection closed")

// Serve runs one authenticated data connection until it ends. The caller has
// checked the session token (Authenticate) before accepting the transport.
func (r *Relay) Serve(ctx context.Context, t Transport, claims auth.Claims) error {
	ctx, cancel := context.WithCancel(ctx)
	defer cancel()
	hctx, hcancel := context.WithTimeout(ctx, HelloTimeout)
	msg, err := t.ReadMessage(hctx)
	hcancel()
	if err != nil {
		t.Close("no hello")
		return err
	}
	f, err := frame.Decode(msg)
	if err != nil || f.Type != frame.TypeHello {
		t.Close("the first frame must be HELLO")
		return errors.New("relay: first frame is not HELLO")
	}
	var hello v1.Hello
	if err := proto.Unmarshal(f.Payload, &hello); err != nil {
		t.Close("malformed HELLO")
		return err
	}
	if hello.Version != frame.Version {
		b, _ := encodeMsg(frame.TypeGoAway, 0, &v1.Result{Code: v1.Code_CODE_VERSION, Message: "this relay speaks frame protocol version 1"})
		_ = t.WriteMessage(ctx, b)
		t.Close("version")
		return errors.New("relay: unsupported version")
	}

	r.mu.Lock()
	c, ok := r.classes[claims.Class]
	var s *sSess
	if ok {
		s = c.s.Sessions[claims.Session]
	}
	if s == nil {
		r.mu.Unlock()
		t.Close("unauthenticated")
		return errors.New("relay: session gone")
	}
	lim := r.limits
	cn := &conn{r: r, c: c, session: s.ID, label: s.Label, t: t, out: make(chan []byte, 4096), done: make(chan struct{}),
		streams: map[uint32]*end{}, nextID: 2,
		// Rate limits run on the wall clock, whatever clock tokens use.
		bytes:  newBucket(lim.BytesPerSecond, lim.BurstBytes, time.Now),
		frames: newBucket(lim.FramesPerSecond, lim.BurstFrames, time.Now)}
	cn.expiry.Store(claims.Expiry.Unix())
	cn.lastSeen.Store(r.cfg.Now().Unix())
	old := c.conns[s.ID]
	c.conns[s.ID] = cn
	welcome := &v1.Welcome{Version: frame.Version, Session: c.sessionProto(s), Network: c.networkProto(),
		RelayId: r.cfg.RelayID, Epoch: c.s.Epoch, TokenExpiresUnix: claims.Expiry.Unix(),
		Limits: &v1.Limits{MaxStreams: uint32(lim.MaxStreams), MaxListeners: uint32(lim.MaxListeners),
			MaxPorts: uint32(lim.MaxPorts), StreamWindow: lim.StreamWindow, MaxPayload: frame.MaxPayload,
			BytesPerSecond: uint64(lim.BytesPerSecond), FramesPerSecond: uint32(lim.FramesPerSecond)}}
	r.mu.Unlock()
	if old != nil {
		old.goAway(v1.Code_CODE_RESET, "replaced by a newer connection of the same session")
	}

	go cn.writer(ctx)
	cn.sendMsg(frame.TypeWelcome, 0, welcome)

	expiryCheck := time.NewTicker(time.Second)
	defer expiryCheck.Stop()
	go func() {
		for {
			select {
			case <-cn.done:
				return
			case <-expiryCheck.C:
				if r.cfg.Now().Unix() >= cn.expiry.Load() {
					cn.goAway(v1.Code_CODE_UNAUTHENTICATED, "the session token expired; send REAUTH before it does")
					return
				}
			}
		}
	}()

	err = cn.readLoop(ctx)
	cn.shutdown(errString(err))
	return err
}

func errString(err error) string {
	if err == nil {
		return "closed"
	}
	return err.Error()
}

func (cn *conn) readLoop(ctx context.Context) error {
	for {
		msg, err := cn.t.ReadMessage(ctx)
		if err != nil {
			return err
		}
		if err := cn.frames.wait(ctx, 1); err != nil {
			return err
		}
		f, err := frame.Decode(msg)
		if err != nil {
			cn.goAway(v1.Code_CODE_PROTOCOL, err.Error())
			return err
		}
		if f.Type == frame.TypeData {
			if err := cn.bytes.wait(ctx, float64(len(f.Payload))); err != nil {
				return err
			}
		}
		cn.lastSeen.Store(cn.r.cfg.Now().Unix())
		if err := cn.handle(f); err != nil {
			cn.goAway(v1.Code_CODE_PROTOCOL, err.Error())
			return err
		}
		select {
		case <-cn.done:
			return errClosed
		default:
		}
	}
}

// writer sends queued messages in order.
func (cn *conn) writer(ctx context.Context) {
	for {
		select {
		case <-cn.done:
			return
		case b := <-cn.out:
			cn.queued.Add(-int64(len(b)))
			if err := cn.t.WriteMessage(ctx, b); err != nil {
				cn.shutdown("write: " + err.Error())
				return
			}
		}
	}
}

func encodeMsg(t frame.Type, stream uint32, m proto.Message) ([]byte, error) {
	var p []byte
	if m != nil {
		var err error
		if p, err = proto.Marshal(m); err != nil {
			return nil, err
		}
	}
	return frame.Encode(frame.Frame{Type: t, Stream: stream, Payload: p})
}

// enqueue queues an encoded frame. A connection whose queue outgrows the
// limit is closed: its reader is not keeping up, and the relay will not hold
// the memory for it.
func (cn *conn) enqueue(b []byte) {
	select {
	case <-cn.done:
		return
	default:
	}
	if cn.queued.Add(int64(len(b))) > int64(cn.r.limits.MaxQueue) {
		go cn.shutdown("too slow: send queue over its limit")
		return
	}
	select {
	case cn.out <- b:
	default:
		go cn.shutdown("too slow: send queue full")
	}
}

func (cn *conn) sendMsg(t frame.Type, stream uint32, m proto.Message) {
	b, err := encodeMsg(t, stream, m)
	if err != nil {
		return
	}
	cn.enqueue(b)
}

func (cn *conn) sendRaw(t frame.Type, stream uint32, p []byte) {
	b, err := frame.Encode(frame.Frame{Type: t, Stream: stream, Payload: p})
	if err != nil {
		return
	}
	cn.enqueue(b)
}

func (cn *conn) result(stream uint32, code v1.Code, msg string) {
	cn.sendMsg(frame.TypeResult, stream, &v1.Result{Code: code, Message: msg})
}

// goAway tells the peer why and closes. Safe to call more than once.
func (cn *conn) goAway(code v1.Code, msg string) {
	b, err := encodeMsg(frame.TypeGoAway, 0, &v1.Result{Code: code, Message: msg})
	if err == nil {
		ctx, cancel := context.WithTimeout(context.Background(), time.Second)
		_ = cn.t.WriteMessage(ctx, b)
		cancel()
	}
	cn.shutdown(msg)
}

// shutdown releases everything the connection holds; its streams' peers are
// reset, its listeners go, its ports stay (the session reconnects to them).
func (cn *conn) shutdown(reason string) {
	cn.once.Do(func() {
		cn.reason.Store(reason)
		close(cn.done)
		cn.t.Close(reason)
		r := cn.r
		r.mu.Lock()
		c := cn.c
		for l := range c.links {
			if l.a == cn || l.b == cn {
				c.dropLink(l, v1.Code_CODE_RESET, "the peer disconnected", v1.Verdict_VERDICT_CLOSED)
			}
		}
		for k, l := range c.listeners {
			if l.conn == cn {
				delete(c.listeners, k)
			}
		}
		if c.conns[cn.session] == cn {
			delete(c.conns, cn.session)
		}
		r.mu.Unlock()
	})
}

func unmarshal(p []byte, m proto.Message) error {
	if err := proto.Unmarshal(p, m); err != nil {
		return errors.New("malformed " + string(m.ProtoReflect().Descriptor().Name()))
	}
	return nil
}

// handle processes one frame. An error is a protocol violation and closes
// the connection; refusals the client should expect are answered instead.
func (cn *conn) handle(f frame.Frame) error {
	switch f.Type {
	case frame.TypeData, frame.TypeWindow, frame.TypeClose, frame.TypeReset, frame.TypeAccept, frame.TypeRefuse:
		return cn.streamFrame(f)
	case frame.TypeConnect:
		var m v1.Connect
		if err := unmarshal(f.Payload, &m); err != nil {
			return err
		}
		return cn.connect(f.Stream, &m)
	case frame.TypeDatagram:
		var m v1.Datagram
		if err := unmarshal(f.Payload, &m); err != nil {
			return err
		}
		cn.datagram(&m)
		return nil
	case frame.TypeAttach:
		var m v1.Attach
		if err := unmarshal(f.Payload, &m); err != nil {
			return err
		}
		cn.attach(f.Stream, &m)
		return nil
	case frame.TypeDetach:
		var m v1.Detach
		if err := unmarshal(f.Payload, &m); err != nil {
			return err
		}
		cn.detach(&m)
		return nil
	case frame.TypeListen:
		var m v1.Listen
		if err := unmarshal(f.Payload, &m); err != nil {
			return err
		}
		cn.listen(f.Stream, &m)
		return nil
	case frame.TypeUnlisten:
		var m v1.Unlisten
		if err := unmarshal(f.Payload, &m); err != nil {
			return err
		}
		cn.unlisten(&m)
		return nil
	case frame.TypeResolve:
		var m v1.Resolve
		if err := unmarshal(f.Payload, &m); err != nil {
			return err
		}
		cn.resolve(f.Stream, &m)
		return nil
	case frame.TypeReauth:
		var m v1.Hello
		if err := unmarshal(f.Payload, &m); err != nil {
			return err
		}
		cl, err := cn.r.Authenticate(m.SessionToken)
		if err != nil || cl.Session != cn.session || cl.Class != cn.c.s.ID {
			cn.goAway(v1.Code_CODE_UNAUTHENTICATED, "REAUTH refused")
			return errClosed
		}
		cn.expiry.Store(cl.Expiry.Unix())
		return nil
	}
	return errors.New("frame " + f.Type.String() + " is not for the relay")
}

// ------------------------------------------------------------- ports, names

func (cn *conn) session0() *sSess { return cn.c.s.Sessions[cn.session] }

func (cn *conn) attach(id uint32, m *v1.Attach) {
	r := cn.r
	r.mu.Lock()
	s := cn.session0()
	if s == nil {
		r.mu.Unlock()
		cn.result(id, v1.Code_CODE_UNAUTHENTICATED, "session gone")
		return
	}
	pid, err := cn.c.attach(s, m.Container)
	if err != nil {
		r.mu.Unlock()
		cn.result(id, codeOf(err), err.Error())
		return
	}
	_ = cn.c.compile()
	_ = r.save()
	p := cn.c.portProto(pid)
	r.mu.Unlock()
	cn.sendMsg(frame.TypeAttached, id, &v1.Attached{Port: p})
}

func codeOf(err error) v1.Code {
	switch ErrKind(err) {
	case KindLimit:
		return v1.Code_CODE_LIMIT
	case KindNotFound:
		return v1.Code_CODE_NOT_FOUND
	case KindUnauthenticated:
		return v1.Code_CODE_UNAUTHENTICATED
	}
	return v1.Code_CODE_INVALID
}

// ownPort checks that a port id belongs to this connection's session.
func (cn *conn) ownPort(id string) *sPort {
	p := cn.c.s.Ports[id]
	if p == nil || p.Session != cn.session {
		return nil
	}
	return p
}

func (cn *conn) detach(m *v1.Detach) {
	r := cn.r
	r.mu.Lock()
	defer r.mu.Unlock()
	if cn.ownPort(m.PortId) == nil {
		return
	}
	cn.c.removePort(m.PortId)
	_ = cn.c.compile()
	_ = r.save()
}

func (cn *conn) listen(id uint32, m *v1.Listen) {
	proto := firewall.Protocol(m.Protocol)
	if proto != firewall.TCP && proto != firewall.UDP {
		cn.result(id, v1.Code_CODE_INVALID, "listen: tcp or udp")
		return
	}
	if m.Port > 65535 {
		cn.result(id, v1.Code_CODE_INVALID, "port above 65535")
		return
	}
	r := cn.r
	r.mu.Lock()
	defer r.mu.Unlock()
	p := cn.ownPort(m.PortId)
	if p == nil {
		cn.result(id, v1.Code_CODE_NOT_FOUND, "not your port")
		return
	}
	n := 0
	for _, l := range cn.c.listeners {
		if l.conn == cn {
			n++
		}
	}
	if n >= r.limits.MaxListeners {
		cn.result(id, v1.Code_CODE_LIMIT, "too many listening sockets")
		return
	}
	addr := cn.c.portAddr(p)
	port := uint16(m.Port)
	if port == 0 {
		port = cn.c.freeEphemeral(m.PortId, addr, proto)
		if port == 0 {
			cn.result(id, v1.Code_CODE_LIMIT, "no ephemeral port left")
			return
		}
	}
	k := lkey{addr, proto, port}
	if _, ok := cn.c.listeners[k]; ok {
		cn.result(id, v1.Code_CODE_IN_USE, "address in use")
		return
	}
	cn.c.listeners[k] = &listener{portID: m.PortId, conn: cn}
	cn.sendMsg(frame.TypeListening, id, &v1.Listening{Port: uint32(port)})
}

func (cn *conn) unlisten(m *v1.Unlisten) {
	r := cn.r
	r.mu.Lock()
	defer r.mu.Unlock()
	p := cn.ownPort(m.PortId)
	if p == nil || m.Port > 65535 {
		return
	}
	k := lkey{cn.c.portAddr(p), firewall.Protocol(m.Protocol), uint16(m.Port)}
	if l, ok := cn.c.listeners[k]; ok && l.conn == cn {
		delete(cn.c.listeners, k)
	}
}

// freeEphemeral picks an unused port in 49152..65535 for a port's address.
func (c *class) freeEphemeral(portID string, addr netip.Addr, proto firewall.Protocol) uint16 {
	next := c.ephemeral[portID]
	if next < 49152 {
		next = 49152
	}
	for range 16384 {
		p := next
		next++
		if next == 0 {
			next = 49152
		}
		if _, used := c.listeners[lkey{addr, proto, p}]; !used && !c.ephemeralInUse(addr, p) {
			c.ephemeral[portID] = next
			return p
		}
	}
	return 0
}

func (c *class) ephemeralInUse(addr netip.Addr, port uint16) bool {
	for l := range c.links {
		if l.flow.Src.Addr() == addr && l.flow.Src.Port() == port {
			return true
		}
	}
	return false
}

func (cn *conn) resolve(id uint32, m *v1.Resolve) {
	if len(m.Name) > 253 {
		cn.sendMsg(frame.TypeResolved, id, &v1.Resolved{})
		return
	}
	r := cn.r
	r.mu.Lock()
	s := cn.session0()
	var addrs []netip.Addr
	if s != nil {
		addrs = cn.c.resolve(s, m.Name)
	}
	r.mu.Unlock()
	out := &v1.Resolved{}
	for _, a := range addrs {
		out.Ips = append(out.Ips, a.String())
	}
	cn.sendMsg(frame.TypeResolved, id, out)
}

// ------------------------------------------------------------------ streams

func (cn *conn) connect(id uint32, m *v1.Connect) error {
	if !frame.ClientStream(id) {
		return errors.New("CONNECT on a relay-allocated stream id")
	}
	r := cn.r
	r.mu.Lock()
	defer r.mu.Unlock()
	cn.mu.Lock()
	_, inUse := cn.streams[id]
	nStreams, pending := len(cn.streams), cn.pending
	cn.mu.Unlock()
	if inUse {
		return errors.New("CONNECT on a stream id in use")
	}
	refuse := func(code v1.Code, msg string) error {
		cn.sendMsg(frame.TypeRefuse, id, &v1.Result{Code: code, Message: msg})
		return nil
	}
	if nStreams >= r.limits.MaxStreams || pending >= r.limits.MaxPending {
		return refuse(v1.Code_CODE_LIMIT, "too many open streams")
	}
	c := cn.c
	p := cn.ownPort(m.PortId)
	if p == nil {
		return refuse(v1.Code_CODE_NOT_FOUND, "not your port")
	}
	dst, err := netip.ParseAddr(m.DstIp)
	if err != nil || m.DstPort == 0 || m.DstPort > 65535 {
		return refuse(v1.Code_CODE_INVALID, "bad destination")
	}
	srcAddr := c.portAddr(p)
	dstPortID, ok := c.byAddr[dst]
	if !ok {
		return refuse(v1.Code_CODE_UNREACHABLE, "no container has this address")
	}
	srcPort := c.freeEphemeral(m.PortId, srcAddr, firewall.TCP)
	if srcPort == 0 {
		return refuse(v1.Code_CODE_LIMIT, "no ephemeral port left")
	}
	flow := firewall.Flow{Protocol: firewall.TCP, Src: netip.AddrPortFrom(srcAddr, srcPort), Dst: netip.AddrPortFrom(dst, uint16(m.DstPort))}
	d := c.pol.Evaluate(flow, c.fwPort(m.PortId), c.fwPort(dstPortID))
	if !d.Allowed {
		c.logFlow(flow, m.PortId, dstPortID, v1.Verdict_VERDICT_DENY, d, 0, 0)
		return refuse(v1.Code_CODE_REFUSED, "refused by the firewall: "+d.Reason)
	}
	l := c.listeners[lkey{dst, firewall.TCP, uint16(m.DstPort)}]
	if l == nil {
		d.Reason = "nothing listens on this port"
		c.logFlow(flow, m.PortId, dstPortID, v1.Verdict_VERDICT_DENY, d, 0, 0)
		return refuse(v1.Code_CODE_REFUSED, "connection refused: nothing listens")
	}
	b := l.conn
	b.mu.Lock()
	if len(b.streams) >= r.limits.MaxStreams {
		b.mu.Unlock()
		return refuse(v1.Code_CODE_LIMIT, "the listener has too many open streams")
	}
	bid := b.nextID
	b.nextID += 2
	lk := &link{c: c, flow: flow, a: cn, b: b, aID: id, bID: bid, aPort: m.PortId, bPort: l.portID,
		egress: d.EgressRule, ingr: d.IngressRule, opened: r.cfg.Now()}
	lk.credit[0].Store(int64(r.limits.StreamWindow))
	lk.credit[1].Store(int64(r.limits.StreamWindow))
	b.streams[bid] = &end{l: lk, side: 1}
	b.mu.Unlock()
	cn.mu.Lock()
	cn.streams[id] = &end{l: lk, side: 0}
	cn.pending++
	cn.mu.Unlock()
	c.links[lk] = struct{}{}
	lk.timer = time.AfterFunc(connectTimeout, func() {
		r.mu.Lock()
		defer r.mu.Unlock()
		if !lk.open.Load() && !lk.gone.Load() {
			c.dropLink(lk, v1.Code_CODE_REFUSED, "the listener did not answer", v1.Verdict_VERDICT_CLOSED)
		}
	})
	b.sendMsg(frame.TypeConnect, bid, &v1.Incoming{PortId: l.portID, ListenPort: m.DstPort,
		SrcIp: srcAddr.String(), SrcPort: uint32(srcPort)})
	// Every connection is logged when it opens and when it ends: one event
	// each, cheap, and what the flow map draws.
	c.logFlow(flow, m.PortId, dstPortID, v1.Verdict_VERDICT_ALLOW, d, 0, 0)
	return nil
}

// streamFrame handles a frame on an existing stream.
func (cn *conn) streamFrame(f frame.Frame) error {
	cn.mu.Lock()
	e := cn.streams[f.Stream]
	cn.mu.Unlock()
	if e == nil {
		// A frame for a stream that just went away (reset crossing): ignore.
		return nil
	}
	l := e.l
	peer, peerID := l.b, l.bID
	if e.side == 1 {
		peer, peerID = l.a, l.aID
	}
	switch f.Type {
	case frame.TypeAccept:
		if e.side != 1 || l.open.Load() {
			return errors.New("ACCEPT out of place")
		}
		r := cn.r
		r.mu.Lock()
		if l.gone.Load() {
			r.mu.Unlock()
			return nil
		}
		l.open.Store(true)
		l.timer.Stop()
		l.a.mu.Lock()
		l.a.pending--
		l.a.mu.Unlock()
		r.mu.Unlock()
		l.a.sendMsg(frame.TypeAccept, l.aID, &v1.Accepted{SrcIp: l.flow.Src.Addr().String(), SrcPort: uint32(l.flow.Src.Port())})
		return nil
	case frame.TypeRefuse:
		if e.side != 1 || l.open.Load() {
			return errors.New("REFUSE out of place")
		}
		r := cn.r
		r.mu.Lock()
		l.c.dropLink(l, v1.Code_CODE_REFUSED, "the listener refused", v1.Verdict_VERDICT_CLOSED)
		r.mu.Unlock()
		return nil
	case frame.TypeData:
		if !l.open.Load() {
			return errors.New("DATA before ACCEPT")
		}
		if l.closed[e.side].Load() {
			return errors.New("DATA after CLOSE")
		}
		n := int64(len(f.Payload))
		if l.credit[e.side].Add(-n) < 0 {
			return errors.New("DATA beyond the stream's window")
		}
		l.sent[e.side].Add(uint64(n))
		peer.sendRaw(frame.TypeData, peerID, f.Payload)
		return nil
	case frame.TypeWindow:
		k, err := frame.ParseCredit(f.Payload)
		if err != nil {
			return err
		}
		// Credit for the other side's sending.
		if l.credit[1-e.side].Add(int64(k)) > 64<<20 {
			return errors.New("WINDOW credit beyond 64 MiB")
		}
		peer.sendRaw(frame.TypeWindow, peerID, f.Payload)
		return nil
	case frame.TypeClose:
		if !l.open.Load() {
			return errors.New("CLOSE before ACCEPT")
		}
		l.closed[e.side].Store(true)
		peer.sendRaw(frame.TypeClose, peerID, nil)
		if l.closed[1-e.side].Load() {
			r := cn.r
			r.mu.Lock()
			l.c.finish(l, v1.Verdict_VERDICT_CLOSED, "closed")
			r.mu.Unlock()
		}
		return nil
	case frame.TypeReset:
		r := cn.r
		r.mu.Lock()
		l.c.dropLink(l, v1.Code_CODE_RESET, "reset by the peer", v1.Verdict_VERDICT_CLOSED)
		r.mu.Unlock()
		return nil
	}
	return nil
}

// finish forgets a link whose both sides closed. Relay.mu held.
func (c *class) finish(l *link, verdict v1.Verdict, why string) {
	if !l.gone.CompareAndSwap(false, true) {
		return
	}
	if l.timer != nil {
		l.timer.Stop()
	}
	l.a.mu.Lock()
	delete(l.a.streams, l.aID)
	if !l.open.Load() {
		l.a.pending--
	}
	l.a.mu.Unlock()
	l.b.mu.Lock()
	delete(l.b.streams, l.bID)
	l.b.mu.Unlock()
	delete(c.links, l)
	c.logFlow(l.flow, l.aPort, l.bPort, verdict, firewall.Decision{Allowed: verdict != v1.Verdict_VERDICT_REVOKED,
		EgressRule: l.egress, IngressRule: l.ingr, Reason: why}, l.sent[0].Load(), l.sent[1].Load())
}

// dropLink resets both ends of a link and forgets it. Relay.mu held.
func (c *class) dropLink(l *link, code v1.Code, why string, verdict v1.Verdict) {
	if l.gone.Load() {
		return
	}
	res := &v1.Result{Code: code, Message: why}
	if !l.open.Load() {
		l.a.sendMsg(frame.TypeRefuse, l.aID, res)
		l.b.sendMsg(frame.TypeReset, l.bID, res)
	} else {
		l.a.sendMsg(frame.TypeReset, l.aID, res)
		l.b.sendMsg(frame.TypeReset, l.bID, res)
	}
	c.finish(l, verdict, why)
}

// --------------------------------------------------------------- datagrams

func (cn *conn) datagram(m *v1.Datagram) {
	r := cn.r
	if len(m.Payload) > r.limits.MaxDatagram || m.DstPort == 0 || m.DstPort > 65535 || m.SrcPort > 65535 {
		return
	}
	dst, err := netip.ParseAddr(m.DstIp)
	if err != nil {
		return
	}
	r.mu.Lock()
	defer r.mu.Unlock()
	c := cn.c
	p := cn.ownPort(m.PortId)
	if p == nil {
		return
	}
	srcAddr := c.portAddr(p)
	srcPort := uint16(m.SrcPort)
	if srcPort == 0 {
		srcPort = c.udpEphemeral(cn, m.PortId, srcAddr)
		if srcPort == 0 {
			return
		}
	} else if l := c.listeners[lkey{srcAddr, firewall.UDP, srcPort}]; l == nil || l.conn != cn {
		// A source port the sender has not bound: spoofed or stale.
		return
	}
	dstPortID, ok := c.byAddr[dst]
	if !ok {
		return
	}
	flow := firewall.Flow{Protocol: firewall.UDP, Src: netip.AddrPortFrom(srcAddr, srcPort), Dst: netip.AddrPortFrom(dst, uint16(m.DstPort))}
	now := r.cfg.Now()
	srcFW, dstFW := c.fwPort(m.PortId), c.fwPort(dstPortID)
	stateful := c.pol.Stateful(srcFW) && c.pol.Stateful(dstFW)
	allowed := false
	if stateful {
		if exp, ok := c.track[flowKey{firewall.UDP, flow.Dst, flow.Src}]; ok && now.Before(exp) {
			allowed = true // a reply to a tracked flow
			c.track[flowKey{firewall.UDP, flow.Dst, flow.Src}] = now.Add(r.cfg.UDPIdle)
		}
		if exp, ok := c.track[flowKey{firewall.UDP, flow.Src, flow.Dst}]; ok && now.Before(exp) {
			allowed = true
			c.track[flowKey{firewall.UDP, flow.Src, flow.Dst}] = now.Add(r.cfg.UDPIdle)
		}
	}
	if !allowed {
		d := c.pol.Evaluate(flow, srcFW, dstFW)
		if !d.Allowed {
			c.logDenyOnce(flow, m.PortId, dstPortID, d, now)
			return
		}
		if stateful {
			c.gcTrack(now)
			c.track[flowKey{firewall.UDP, flow.Src, flow.Dst}] = now.Add(r.cfg.UDPIdle)
		}
		c.logFlow(flow, m.PortId, dstPortID, v1.Verdict_VERDICT_ALLOW, d, uint64(len(m.Payload)), 0)
	}
	l := c.listeners[lkey{dst, firewall.UDP, uint16(m.DstPort)}]
	if l == nil {
		return
	}
	l.conn.sendMsg(frame.TypeDatagram, 0, &v1.Datagram{PortId: l.portID, SrcPort: uint32(srcPort), SrcIp: srcAddr.String(),
		DstIp: dst.String(), DstPort: m.DstPort, Payload: m.Payload})
}

// udpEphemeral gives a port one stable ephemeral UDP port, bound to the
// sender's connection so that replies reach it.
func (c *class) udpEphemeral(cn *conn, portID string, addr netip.Addr) uint16 {
	for k, l := range c.listeners {
		if l.portID == portID && l.conn == cn && k.proto == firewall.UDP && k.port >= 49152 && l.implicit() {
			return k.port
		}
	}
	p := c.freeEphemeral(portID, addr, firewall.UDP)
	if p != 0 {
		c.listeners[lkey{addr, firewall.UDP, p}] = &listener{portID: portID, conn: cn, auto: true}
	}
	return p
}

func (l *listener) implicit() bool { return l.auto }

func (c *class) gcTrack(now time.Time) {
	if len(c.track) < 4096 {
		return
	}
	for k, exp := range c.track {
		if !now.Before(exp) {
			delete(c.track, k)
		}
	}
}

// ------------------------------------------------------------- revalidation

// revalidate re-checks every live flow after a policy change and resets
// the ones no longer allowed. Relay.mu held.
func (c *class) revalidate() {
	for l := range c.links {
		if c.s.Ports[l.aPort] == nil || c.s.Ports[l.bPort] == nil {
			continue
		}
		d := c.pol.Evaluate(l.flow, c.fwPort(l.aPort), c.fwPort(l.bPort))
		if !d.Allowed {
			c.dropLink(l, v1.Code_CODE_RESET, "revoked by a rule change: "+d.Reason, v1.Verdict_VERDICT_REVOKED)
		}
	}
	for k := range c.track {
		src, sok := c.byAddr[k.src.Addr()]
		dst, dok := c.byAddr[k.dst.Addr()]
		if !sok || !dok {
			delete(c.track, k)
			continue
		}
		f := firewall.Flow{Protocol: k.proto, Src: k.src, Dst: k.dst}
		if d := c.pol.Evaluate(f, c.fwPort(src), c.fwPort(dst)); !d.Allowed {
			delete(c.track, k)
			c.logFlow(f, src, dst, v1.Verdict_VERDICT_REVOKED, d, 0, 0)
		}
	}
}
