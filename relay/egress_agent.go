// SPDX-License-Identifier: BSD-3-Clause

package relay

import (
	"context"
	"errors"
	"net"
	"net/netip"
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
}

// expect is what the relay decided about a stream before it asked the agent
// to open it.
type expect struct {
	ip   netip.Addr
	name string
	flow firewall.Flow
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
		pending: map[uint32]expect{}, st: map[uint32]*estream{}}
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
func (a *agent) stop() {
	a.mu.Lock()
	if a.stopped {
		a.mu.Unlock()
		return
	}
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
	s := &estream{a: a, id: id, x: x, wake: make(chan struct{}, 1), wq: make(chan []byte, 256),
		done: make(chan struct{}), born: time.Now()}
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

	nc      net.Conn
	ncMu    sync.Mutex
	dead    bool
	done    chan struct{}
	wq      chan []byte // guest to outside; a nil element is the guest's CLOSE
	wake    chan struct{}
	credit  atomic.Int64 // bytes this side may still send to the guest
	last    atomic.Int64 // unix nanoseconds of the last data
	checked atomic.Bool  // the ClientHello named the pinned host

	hello []byte // run goroutine only

	outEOF, guestEOF atomic.Bool
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
	ctx, cancel := context.WithTimeout(a.ctx, dialTimeout)
	defer cancel()
	nc, err := a.e.dial(ctx, s.x.ip, egress.Port)
	if err != nil {
		a.forget(s.id)
		s.kill()
		a.sendResult(frame.TypeRefuse, s.id, v1.Code_CODE_UNREACHABLE, "the outside host did not answer")
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
	go s.readLoop()
}

// kill closes the outside socket and forgets the stream. It never talks to
// the relay.
func (s *estream) kill() {
	s.ncMu.Lock()
	if s.dead {
		s.ncMu.Unlock()
		return
	}
	s.dead = true
	nc := s.nc
	close(s.done)
	s.ncMu.Unlock()
	if nc != nil {
		_ = nc.Close()
	}
	s.a.forget(s.id)
}

// abort resets the stream towards the guest and closes the outside.
func (s *estream) abort(code v1.Code, why string) {
	s.kill()
	s.a.sendResult(frame.TypeReset, s.id, code, why)
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
		err := egress.CheckHello(s.x.name, s.hello)
		switch {
		case errors.Is(err, egress.ErrNeedMore) && len(s.hello) <= egress.MaxRecord+5:
			return
		case err != nil:
			s.a.e.deniedTLS(s, err)
			return
		}
		s.checked.Store(true)
		p, s.hello = s.hello, nil
	}
	select {
	case s.wq <- append([]byte(nil), p...):
	default:
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
	select {
	case s.wq <- nil:
	default:
		s.abort(v1.Code_CODE_LIMIT, "the outside write queue is full")
	}
}

type closeWriter interface{ CloseWrite() error }

// writeLoop sends the guest's bytes outside, under the class rate, and gives
// the guest its credit back once they are written.
func (s *estream) writeLoop() {
	a := s.a
	for {
		var b []byte
		select {
		case b = <-s.wq:
		case <-s.done:
			return
		}
		if b == nil {
			if cw, ok := s.nc.(closeWriter); ok {
				_ = cw.CloseWrite()
			}
			s.guestEOF.Store(true)
			s.maybeFinish()
			continue
		}
		if a.e.bytes.wait(a.ctx, float64(len(b))) != nil {
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
			a.send(frame.TypeData, s.id, buf[:nr])
		}
		if err != nil {
			select {
			case <-s.done:
				return
			default:
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
func (e *egressClass) deniedTLS(s *estream, err error) {
	e.ctr.tls.Add(1)
	why := "TLS server name: " + err.Error()
	e.deny(s.x.name, why)
	r := e.r
	r.mu.Lock()
	e.c.logFlow(s.x.flow, s.x.aPort, "", v1.Verdict_VERDICT_DENY, firewall.Decision{Reason: "egress to " + s.x.name + ": " + why}, 0, 0)
	r.mu.Unlock()
	s.abort(v1.Code_CODE_REFUSED, why)
}
