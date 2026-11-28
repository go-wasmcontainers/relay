// SPDX-License-Identifier: BSD-3-Clause

package relay

import (
	"context"
	"errors"
	"net"
	"net/netip"
	"strings"
	"sync"
	"sync/atomic"
	"time"

	"github.com/go-wasmcontainers/relay/egress"
	"github.com/go-wasmcontainers/relay/firewall"
	"github.com/go-wasmcontainers/relay/frame"
	v1 "github.com/go-wasmcontainers/relay/gen/relayv1"
)

// An agent is the outside end of one session's egress streams. It is a real
// connection of the relay (so credit, ordering, kick and rotation work as
// they do for every stream) whose peer is this code instead of a browser:
// the relay end runs the ordinary reader and writer over an in-memory pipe,
// the agent end speaks the frame protocol and holds the TCP sockets.
//
// It dials only an address the gateway authorised for the stream, and it
// forwards nothing until the TLS ClientHello has named the pinned host.
type agent struct {
	e      *egressClass
	sess   *egressSess
	cn     *conn // the relay end
	t      Transport
	ctx    context.Context
	cancel context.CancelFunc

	mu      sync.Mutex
	pending map[uint32]expect
	st      map[uint32]*estream
	stopped bool
	// stopOnce makes stop safe to call from the relay (kick, rotation) and
	// from the read loop at the same time.
	stopOnce sync.Once
	// runDone is closed when the read loop returns.
	runDone chan struct{}
}

// expect is what the relay decided about a stream before it asked the agent
// to open it.
type expect struct {
	ip netip.Addr
	// names are the allowlisted names the address was pinned for; the
	// ClientHello must carry one of them.
	names []string
	flow  firewall.Flow
	// aPort is the guest's port id, for the log.
	aPort string
}

// agentFor returns the session's agent, starting it. Relay.mu held.
func (s *egressSess) agentFor(e *egressClass, guest *conn) *agent {
	if s.agent != nil {
		return s.agent
	}
	r := e.r
	ta, tb := Pipe()
	lim := r.limits
	cn := &conn{r: r, c: e.c, label: "egress:" + guest.label, t: tb, out: make(chan []byte, 4096), done: make(chan struct{}),
		streams: map[uint32]*end{}, nextID: 2,
		// Everything the class sends through an agent shares one byte rate.
		bytes:  e.bytes,
		frames: newBucket(lim.FramesPerSecond, lim.BurstFrames, time.Now)}
	cn.lastSeen.Store(r.cfg.Now().Unix())
	ctx, cancel := context.WithCancel(context.Background())
	a := &agent{e: e, sess: s, cn: cn, t: ta, ctx: ctx, cancel: cancel,
		pending: map[uint32]expect{}, st: map[uint32]*estream{}, runDone: make(chan struct{})}
	s.agent = a
	go cn.writer(ctx)
	go func() {
		err := cn.readLoop(ctx)
		cn.shutdown(errString(err))
	}()
	go a.run()
	go a.janitor()
	return a
}

func (a *agent) expect(id uint32, x expect) {
	a.mu.Lock()
	a.pending[id] = x
	a.mu.Unlock()
}

func (a *agent) send(t frame.Type, id uint32, payload []byte) {
	b, err := frame.Encode(frame.Frame{Type: t, Stream: id, Payload: payload})
	if err == nil {
		_ = a.t.WriteMessage(a.ctx, b)
	}
}

func (a *agent) sendResult(t frame.Type, id uint32, code v1.Code, msg string) {
	if b, err := encodeMsg(t, id, &v1.Result{Code: code, Message: msg}); err == nil {
		_ = a.t.WriteMessage(a.ctx, b)
	}
}

// stop closes every outside socket and the pipe.
func (a *agent) stop() { a.stopOnce.Do(a.doStop) }

func (a *agent) doStop() {
	a.mu.Lock()
	a.stopped = true
	streams := make([]*estream, 0, len(a.st))
	for _, s := range a.st {
		streams = append(streams, s)
	}
	a.mu.Unlock()
	a.cancel()
	for _, s := range streams {
		s.kill()
	}
	_ = a.t.Close("egress agent stopped")
	a.cn.shutdown("egress agent stopped")
}

func (a *agent) run() {
	defer close(a.runDone)
	for {
		msg, err := a.t.ReadMessage(a.ctx)
		if err != nil {
			a.stop()
			return
		}
		f, err := frame.Decode(msg)
		if err != nil {
			continue
		}
		switch f.Type {
		case frame.TypeConnect:
			a.onConnect(f.Stream)
		case frame.TypeData:
			if s := a.stream(f.Stream); s != nil {
				s.onData(f.Payload)
			}
		case frame.TypeWindow:
			if s := a.stream(f.Stream); s != nil {
				if k, err := frame.ParseCredit(f.Payload); err == nil {
					s.credit.Add(int64(k))
					s.poke()
				}
			}
		case frame.TypeClose:
			if s := a.stream(f.Stream); s != nil {
				s.guestClosed()
			}
		case frame.TypeReset:
			if s := a.stream(f.Stream); s != nil {
				s.kill()
			}
		}
	}
}

func (a *agent) stream(id uint32) *estream {
	a.mu.Lock()
	defer a.mu.Unlock()
	return a.st[id]
}

func (a *agent) forget(id uint32) {
	a.mu.Lock()
	delete(a.st, id)
	a.mu.Unlock()
}

func (a *agent) onConnect(id uint32) {
	a.mu.Lock()
	x, ok := a.pending[id]
	delete(a.pending, id)
	if !ok || a.stopped {
		a.mu.Unlock()
		go a.sendResult(frame.TypeRefuse, id, v1.Code_CODE_UNREACHABLE, "no such outside stream")
		return
	}
	s := &estream{a: a, id: id, x: x, wake: make(chan struct{}, 1), qwake: make(chan struct{}, 1),
		done: make(chan struct{}), born: time.Now()}
	s.ctx, s.cancel = context.WithCancel(a.ctx)
	s.credit.Store(int64(a.e.r.limits.StreamWindow))
	s.touch()
	a.st[id] = s
	a.mu.Unlock()
	go s.open()
}

// janitor resets streams that sat idle, outlived the lifetime bound or did
// not send their ClientHello in time.
func (a *agent) janitor() {
	lim := a.e.lim
	tick := min(lim.Idle, lim.Lifetime, lim.HelloTimeout) / 4
	tick = max(tick, 5*time.Millisecond)
	tk := time.NewTicker(min(tick, 5*time.Second))
	defer tk.Stop()
	for {
		select {
		case <-a.ctx.Done():
			return
		case <-tk.C:
		}
		now := time.Now()
		a.mu.Lock()
		var victims []*estream
		var why []string
		for _, s := range a.st {
			switch {
			case now.Sub(s.born) > lim.Lifetime:
				victims, why = append(victims, s), append(why, "the stream reached its lifetime")
			case now.Sub(time.Unix(0, s.last.Load())) > lim.Idle:
				victims, why = append(victims, s), append(why, "the stream was idle")
			case !s.checked.Load() && now.Sub(s.born) > lim.HelloTimeout:
				victims, why = append(victims, s), append(why, "no TLS ClientHello in time")
			}
		}
		a.mu.Unlock()
		for i, s := range victims {
			s.abort(v1.Code_CODE_RESET, why[i])
		}
	}
}

// estream is one outside connection.
type estream struct {
	a    *agent
	id   uint32
	x    expect
	born time.Time

	// ctx ends with the stream: a killed stream's goroutines stop waiting.
	ctx    context.Context
	cancel context.CancelFunc

	nc     net.Conn
	ncMu   sync.Mutex
	dead   bool
	done   chan struct{}
	wake   chan struct{}
	credit atomic.Int64 // bytes this side may still send to the guest
	last   atomic.Int64 // unix nanoseconds of the last data

	// checked: the ClientHello named a pinned host. readStarted: the read
	// loop runs (only after checked, so nothing from the outside reaches the
	// guest before the hello is judged).
	checked     atomic.Bool
	readStarted atomic.Bool

	// The guest-to-outside queue is counted in bytes, like the credit the
	// guest holds: a guest cannot queue more than the window, however small
	// its writes. qclose is the guest's CLOSE, after the queued bytes.
	qmu    sync.Mutex
	qbuf   []byte
	qclose bool
	qwake  chan struct{}

	hello []byte // run goroutine only

	outEOF, guestEOF atomic.Bool
}

// enqueue queues guest bytes for the outside; false when the queue would
// exceed the window.
func (s *estream) enqueue(p []byte) bool {
	s.qmu.Lock()
	if len(s.qbuf)+len(p) > int(s.a.e.r.limits.StreamWindow) {
		s.qmu.Unlock()
		return false
	}
	s.qbuf = append(s.qbuf, p...)
	s.qmu.Unlock()
	s.qsignal()
	return true
}

func (s *estream) enqueueClose() {
	s.qmu.Lock()
	s.qclose = true
	s.qmu.Unlock()
	s.qsignal()
}

func (s *estream) qsignal() {
	select {
	case s.qwake <- struct{}{}:
	default:
	}
}

// take waits for the next chunk (at most one frame) or the guest's CLOSE,
// once the chunks before it were taken. ok is false when the stream ended.
func (s *estream) take() (chunk []byte, closing, ok bool) {
	for {
		s.qmu.Lock()
		if n := min(len(s.qbuf), frame.MaxPayload); n > 0 {
			chunk = append([]byte(nil), s.qbuf[:n]...)
			s.qbuf = s.qbuf[n:]
			if len(s.qbuf) == 0 {
				s.qbuf = nil
			}
			s.qmu.Unlock()
			return chunk, false, true
		}
		if s.qclose {
			s.qclose = false
			s.qmu.Unlock()
			return nil, true, true
		}
		s.qmu.Unlock()
		select {
		case <-s.qwake:
		case <-s.ctx.Done():
			return nil, false, false
		}
	}
}

func (s *estream) touch() { s.last.Store(time.Now().UnixNano()) }

func (s *estream) poke() {
	select {
	case s.wake <- struct{}{}:
	default:
	}
}

// open dials the pinned literal and answers the relay.
func (s *estream) open() {
	a := s.a
	ctx, cancel := context.WithTimeout(s.ctx, dialTimeout)
	defer cancel()
	nc, err := a.e.dial(ctx, s.x.ip, egress.Port)
	if err != nil {
		if s.kill() {
			a.sendResult(frame.TypeRefuse, s.id, v1.Code_CODE_UNREACHABLE, "the outside host did not answer")
		}
		return
	}
	s.ncMu.Lock()
	if s.dead {
		s.ncMu.Unlock()
		_ = nc.Close()
		return
	}
	s.nc = nc
	s.ncMu.Unlock()
	a.send(frame.TypeAccept, s.id, nil)
	go s.writeLoop()
	s.maybeStartRead()
}

// maybeStartRead starts the read loop once the socket is open and the
// ClientHello was judged: nothing the outside says reaches the guest before.
func (s *estream) maybeStartRead() {
	s.ncMu.Lock()
	open := s.nc != nil && !s.dead
	s.ncMu.Unlock()
	if open && s.checked.Load() && s.readStarted.CompareAndSwap(false, true) {
		go s.readLoop()
	}
}

// kill closes the outside socket and forgets the stream; it reports whether
// this call ended it. It never talks to the relay.
func (s *estream) kill() bool {
	s.ncMu.Lock()
	if s.dead {
		s.ncMu.Unlock()
		return false
	}
	s.dead = true
	nc := s.nc
	close(s.done)
	s.ncMu.Unlock()
	s.cancel()
	if nc != nil {
		_ = nc.Close()
	}
	s.a.forget(s.id)
	return true
}

// abort resets the stream towards the guest and closes the outside. The
// reset is sent from its own goroutine: a stalled pipe must not stop the
// agent's read loop (which would overflow the relay's queue and take every
// stream with it).
func (s *estream) abort(code v1.Code, why string) {
	if s.kill() {
		go s.a.sendResult(frame.TypeReset, s.id, code, why)
	}
}

// onData runs on the agent's read goroutine: the first bytes must be a
// ClientHello for the pinned name before anything reaches the outside.
func (s *estream) onData(p []byte) {
	if s.isDead() {
		return
	}
	s.touch()
	if !s.checked.Load() {
		s.hello = append(s.hello, p...)
		err := egress.CheckHello(s.x.names, s.hello)
		switch {
		case errors.Is(err, egress.ErrNeedMore) && len(s.hello) <= egress.MaxRecord+5:
			return
		case err != nil:
			s.a.e.deniedTLS(s, "TLS server name: "+err.Error())
			return
		}
		p, s.hello = s.hello, nil
		if !s.enqueue(p) {
			s.abort(v1.Code_CODE_LIMIT, "the outside write queue is full")
			return
		}
		// Only now may the outside speak to the guest.
		s.checked.Store(true)
		s.maybeStartRead()
		return
	}
	if !s.enqueue(p) {
		s.abort(v1.Code_CODE_LIMIT, "the outside write queue is full")
	}
}

func (s *estream) isDead() bool {
	s.ncMu.Lock()
	defer s.ncMu.Unlock()
	return s.dead
}

func (s *estream) guestClosed() {
	if !s.checked.Load() {
		s.abort(v1.Code_CODE_RESET, "closed before a TLS ClientHello")
		return
	}
	s.enqueueClose()
}

type closeWriter interface{ CloseWrite() error }

// writeLoop sends the guest's bytes outside, under the class rate, and gives
// the guest its credit back once they are written. It ends with the stream:
// a killed stream charges nothing and writes nothing more.
func (s *estream) writeLoop() {
	a := s.a
	for {
		b, closing, ok := s.take()
		if !ok || s.isDead() {
			return
		}
		if closing {
			if cw, ok := s.nc.(closeWriter); ok {
				_ = cw.CloseWrite()
			}
			s.guestEOF.Store(true)
			s.maybeFinish()
			continue
		}
		if a.e.bytes.wait(s.ctx, float64(len(b))) != nil || s.isDead() {
			return
		}
		if !s.account(len(b)) {
			return
		}
		if _, err := s.nc.Write(b); err != nil {
			s.abort(v1.Code_CODE_RESET, "the outside connection failed")
			return
		}
		s.touch()
		a.send(frame.TypeWindow, s.id, frame.Credit(uint32(len(b))))
	}
}

// account counts n bytes against the session's day; over the allowance the
// stream is reset.
func (s *estream) account(n int) bool {
	a := s.a
	if !a.sess.addBytes(uint64(n), a.e.r.cfg.Now(), a.e.lim.SessionBytesPerDay) {
		a.e.ctr.limit.Add(1)
		s.abort(v1.Code_CODE_LIMIT, "this session used its outside traffic for the day")
		return false
	}
	return true
}

// readLoop sends what the outside says to the guest, within the credit the
// guest granted.
func (s *estream) readLoop() {
	a := s.a
	buf := make([]byte, frame.MaxPayload)
	// head holds the first bytes of the outside's answer until they show
	// whether it is a HelloRetryRequest (a second ClientHello the gateway
	// would never see: refused, decision D4).
	var head []byte
	decided := false
	for {
		for s.credit.Load() <= 0 {
			select {
			case <-s.wake:
			case <-s.done:
				return
			}
		}
		n := int(min(int64(len(buf)), s.credit.Load()))
		nr, err := s.nc.Read(buf[:n])
		if nr > 0 {
			s.credit.Add(-int64(nr))
			if !s.account(nr) {
				return
			}
			s.touch()
			out := buf[:nr]
			if !decided {
				head = append(head, out...)
				hrr, dec := egress.IsHelloRetryRequest(head)
				if hrr {
					a.e.deniedTLS(s, "TLS: the outside sent a HelloRetryRequest, whose second ClientHello is not checked")
					return
				}
				if dec {
					decided, out, head = true, head, nil
				} else {
					out = nil
				}
			}
			for len(out) > 0 {
				k := min(len(out), frame.MaxPayload)
				a.send(frame.TypeData, s.id, out[:k])
				out = out[k:]
			}
		}
		if err != nil {
			select {
			case <-s.done:
				return
			default:
			}
			if len(head) > 0 {
				a.send(frame.TypeData, s.id, head) // the short answer of a server that hung up
			}
			a.send(frame.TypeClose, s.id, nil)
			s.outEOF.Store(true)
			s.maybeFinish()
			return
		}
	}
}

// maybeFinish closes the socket once both directions are done.
func (s *estream) maybeFinish() {
	if s.outEOF.Load() && s.guestEOF.Load() {
		s.kill()
	}
}

// deniedTLS refuses a stream whose first bytes did not name the pinned host.
func (e *egressClass) deniedTLS(s *estream, why string) {
	e.ctr.tls.Add(1)
	e.deny(s.x.names[0], why)
	r := e.r
	r.mu.Lock()
	e.c.logFlow(s.x.flow, s.x.aPort, "", v1.Verdict_VERDICT_DENY, firewall.Decision{Reason: "egress to " + strings.Join(s.x.names, ",") + ": " + why}, 0, 0)
	r.mu.Unlock()
	s.abort(v1.Code_CODE_REFUSED, why)
}
