// SPDX-License-Identifier: BSD-3-Clause

package driver

import (
	"context"
	"errors"
	"io"
	"net"
	"net/netip"
	"os"
	"sync"
	"syscall"
	"time"

	"google.golang.org/protobuf/proto"

	"github.com/go-wasmcontainers/relay/frame"
	v1 "github.com/go-wasmcontainers/relay/gen/relayv1"
)

// stream is one TCP-like connection through the relay. It implements
// net.Conn. Flow control: the peer may send at most the window the relay
// announced before this side returns credit, which it does as the
// application reads.
type stream struct {
	s       *Session
	id      uint32
	local   netip.AddrPort
	remote  netip.AddrPort
	window  int64
	accepted chan error // the CONNECT's answer, for a dialled stream

	mu       sync.Mutex
	notify   chan struct{} // closed and replaced on every state change
	buf      [][]byte
	unacked  int64 // bytes read by the application, not yet credited back
	credit   int64 // bytes we may still send
	peerEOF  bool
	closedLocal bool
	err      error
	rdl, wdl time.Time
}

func newStream(s *Session, id uint32) *stream {
	w := int64(s.welcome.GetLimits().GetStreamWindow())
	if w == 0 {
		w = 64 << 10
	}
	return &stream{s: s, id: id, window: w, credit: w, notify: make(chan struct{}), accepted: make(chan error, 1)}
}

func (st *stream) wake() {
	close(st.notify)
	st.notify = make(chan struct{})
}

func (st *stream) onFrame(f frame.Frame) {
	switch f.Type {
	case frame.TypeAccept:
		var m v1.Accepted
		if proto.Unmarshal(f.Payload, &m) == nil {
			if a, err := netip.ParseAddr(m.SrcIp); err == nil {
				st.mu.Lock()
				st.local = netip.AddrPortFrom(a, uint16(m.SrcPort))
				st.mu.Unlock()
			}
		}
		st.accepted <- nil
	case frame.TypeRefuse:
		var r v1.Result
		_ = proto.Unmarshal(f.Payload, &r)
		err := resultError(&r)
		st.s.forget(st.id)
		select {
		case st.accepted <- err:
		default:
		}
		st.fail(err)
	case frame.TypeData:
		st.mu.Lock()
		st.buf = append(st.buf, f.Payload)
		st.wake()
		st.mu.Unlock()
	case frame.TypeWindow:
		if k, err := frame.ParseCredit(f.Payload); err == nil {
			st.mu.Lock()
			st.credit += int64(k)
			st.wake()
			st.mu.Unlock()
		}
	case frame.TypeClose:
		st.mu.Lock()
		st.peerEOF = true
		st.wake()
		done := st.closedLocal
		st.mu.Unlock()
		if done {
			st.s.forget(st.id)
		}
	case frame.TypeReset:
		st.s.forget(st.id)
		st.reset(syscall.ECONNRESET)
	}
}

func (st *stream) fail(err error) {
	st.mu.Lock()
	if st.err == nil {
		st.err = err
	}
	st.wake()
	st.mu.Unlock()
}

func (st *stream) reset(errno syscall.Errno) {
	st.fail(&net.OpError{Op: "read", Net: "tcp", Err: os.NewSyscallError("relay", errno)})
	select {
	case st.accepted <- &Error{Code: v1.Code_CODE_RESET, Msg: "reset", Errno: errno}:
	default:
	}
}

func (s *Session) forget(id uint32) {
	s.mu.Lock()
	delete(s.streams, id)
	s.mu.Unlock()
}

// wait blocks until notify fires or the deadline passes. st.mu held on entry
// and exit.
func (st *stream) wait(deadline time.Time) error {
	ch := st.notify
	st.mu.Unlock()
	defer st.mu.Lock()
	if deadline.IsZero() {
		<-ch
		return nil
	}
	d := time.Until(deadline)
	if d <= 0 {
		return os.ErrDeadlineExceeded
	}
	t := time.NewTimer(d)
	defer t.Stop()
	select {
	case <-ch:
		return nil
	case <-t.C:
		return os.ErrDeadlineExceeded
	}
}

func (st *stream) Read(p []byte) (int, error) {
	st.mu.Lock()
	defer st.mu.Unlock()
	for len(st.buf) == 0 {
		if st.err != nil {
			return 0, st.err
		}
		if st.peerEOF {
			return 0, io.EOF
		}
		if err := st.wait(st.rdl); err != nil {
			return 0, err
		}
	}
	n := 0
	for n < len(p) && len(st.buf) > 0 {
		c := copy(p[n:], st.buf[0])
		n += c
		if c == len(st.buf[0]) {
			st.buf = st.buf[1:]
		} else {
			st.buf[0] = st.buf[0][c:]
		}
	}
	st.unacked += int64(n)
	if st.unacked >= st.window/2 {
		k := st.unacked
		st.unacked = 0
		go st.s.write(frame.TypeWindow, st.id, frame.Credit(uint32(k)))
	}
	return n, nil
}

func (st *stream) Write(p []byte) (int, error) {
	total := 0
	st.mu.Lock()
	defer st.mu.Unlock()
	for len(p) > 0 {
		if st.err != nil {
			return total, st.err
		}
		if st.closedLocal {
			return total, net.ErrClosed
		}
		if st.credit <= 0 {
			if err := st.wait(st.wdl); err != nil {
				return total, err
			}
			continue
		}
		n := int64(len(p))
		if n > st.credit {
			n = st.credit
		}
		if n > frame.MaxPayload {
			n = frame.MaxPayload
		}
		st.credit -= n
		chunk := p[:n]
		st.mu.Unlock()
		err := st.s.write(frame.TypeData, st.id, chunk)
		st.mu.Lock()
		if err != nil {
			return total, err
		}
		total += int(n)
		p = p[n:]
	}
	return total, nil
}

// Close sends CLOSE: this side sends no more. Reading after it fails.
func (st *stream) Close() error {
	st.mu.Lock()
	if st.closedLocal {
		st.mu.Unlock()
		return nil
	}
	st.closedLocal = true
	peerDone := st.peerEOF
	if st.err == nil {
		st.err = net.ErrClosed
	}
	st.wake()
	st.mu.Unlock()
	err := st.s.write(frame.TypeClose, st.id, nil)
	if peerDone {
		st.s.forget(st.id)
	}
	return err
}

// CloseWrite half-closes: the peer reads EOF, this side can still read.
func (st *stream) CloseWrite() error {
	st.mu.Lock()
	if st.closedLocal {
		st.mu.Unlock()
		return nil
	}
	st.closedLocal = true
	peerDone := st.peerEOF
	st.mu.Unlock()
	err := st.s.write(frame.TypeClose, st.id, nil)
	if peerDone {
		st.s.forget(st.id)
	}
	return err
}

func (st *stream) LocalAddr() net.Addr  { return net.TCPAddrFromAddrPort(st.local) }
func (st *stream) RemoteAddr() net.Addr { return net.TCPAddrFromAddrPort(st.remote) }

func (st *stream) SetDeadline(t time.Time) error {
	st.mu.Lock()
	st.rdl, st.wdl = t, t
	st.wake()
	st.mu.Unlock()
	return nil
}

func (st *stream) SetReadDeadline(t time.Time) error {
	st.mu.Lock()
	st.rdl = t
	st.wake()
	st.mu.Unlock()
	return nil
}

func (st *stream) SetWriteDeadline(t time.Time) error {
	st.mu.Lock()
	st.wdl = t
	st.wake()
	st.mu.Unlock()
	return nil
}

// Dial connects to addr ("tcp") or returns a connected datagram socket
// ("udp").
func (e *Endpoint) Dial(ctx context.Context, network string, addr netip.AddrPort) (net.Conn, error) {
	p, err := protoOf(network)
	if err != nil {
		return nil, err
	}
	if p == v1.Protocol_PROTOCOL_UDP {
		return e.dialUDP(addr), nil
	}
	s := e.s
	s.mu.Lock()
	if s.err != nil {
		s.mu.Unlock()
		return nil, s.err
	}
	id := s.allocID()
	st := newStream(s, id)
	st.remote = addr
	s.streams[id] = st
	s.mu.Unlock()
	if err := s.writeMsg(frame.TypeConnect, id, &v1.Connect{PortId: e.port.Id, DstIp: addr.Addr().String(), DstPort: uint32(addr.Port())}); err != nil {
		s.forget(id)
		return nil, err
	}
	select {
	case err := <-st.accepted:
		if err != nil {
			return nil, &net.OpError{Op: "dial", Net: "tcp", Addr: net.TCPAddrFromAddrPort(addr), Err: err}
		}
		return st, nil
	case <-ctx.Done():
		s.forget(id)
		_ = s.write(frame.TypeReset, id, nil)
		return nil, ctx.Err()
	case <-s.done:
		return nil, s.Err()
	}
}

// Listener accepts streams on one port. It implements net.Listener.
type Listener struct {
	e     *Endpoint
	key   lkey
	addr  netip.AddrPort
	queue chan *stream
	once  sync.Once
	done  chan struct{}
}

// Listen listens on port ("tcp"; 0 picks an ephemeral one).
func (e *Endpoint) Listen(ctx context.Context, network string, port uint16) (*Listener, error) {
	p, err := protoOf(network)
	if err != nil || p != v1.Protocol_PROTOCOL_TCP {
		return nil, errors.New("Listen: tcp only; ListenPacket for udp")
	}
	n, err := e.listen(ctx, p, port)
	if err != nil {
		return nil, err
	}
	l := &Listener{e: e, key: lkey{e.port.Id, p, n}, addr: netip.AddrPortFrom(e.addr, uint16(n)),
		queue: make(chan *stream, 64), done: make(chan struct{})}
	e.s.mu.Lock()
	e.s.listeners[l.key] = l
	e.s.mu.Unlock()
	return l, nil
}

func (s *Session) incoming(id uint32, m *v1.Incoming) {
	s.mu.Lock()
	l := s.listeners[lkey{m.PortId, v1.Protocol_PROTOCOL_TCP, m.ListenPort}]
	if l == nil {
		s.mu.Unlock()
		go s.writeMsg(frame.TypeRefuse, id, &v1.Result{Code: v1.Code_CODE_REFUSED, Message: "not listening"})
		return
	}
	st := newStream(s, id)
	if a, err := netip.ParseAddr(m.SrcIp); err == nil {
		st.remote = netip.AddrPortFrom(a, uint16(m.SrcPort))
	}
	st.local = l.addr
	if len(l.queue) == cap(l.queue) {
		// Backlog full: refuse, as a full SYN queue would. Only this
		// goroutine (the read loop) adds to the queue, so the test holds.
		s.mu.Unlock()
		go s.writeMsg(frame.TypeRefuse, id, &v1.Result{Code: v1.Code_CODE_REFUSED, Message: "backlog full"})
		return
	}
	s.streams[id] = st
	s.mu.Unlock()
	// ACCEPT goes out before the application can write on the stream: the
	// relay refuses DATA before ACCEPT.
	if err := s.write(frame.TypeAccept, id, nil); err != nil {
		s.forget(id)
		return
	}
	l.queue <- st
}

// Accept waits for the next connection.
func (l *Listener) Accept() (net.Conn, error) {
	select {
	case st := <-l.queue:
		return st, nil
	case <-l.done:
		return nil, net.ErrClosed
	case <-l.e.s.done:
		return nil, l.e.s.Err()
	}
}

func (l *Listener) closeLocal() { l.once.Do(func() { close(l.done) }) }

// Close stops listening.
func (l *Listener) Close() error {
	l.closeLocal()
	s := l.e.s
	s.mu.Lock()
	delete(s.listeners, l.key)
	s.mu.Unlock()
	return s.writeMsg(frame.TypeUnlisten, 0, &v1.Unlisten{PortId: l.key.port, Protocol: l.key.proto, Port: l.key.num})
}

// Addr is the listening address.
func (l *Listener) Addr() net.Addr { return net.TCPAddrFromAddrPort(l.addr) }

// Port is the listening port.
func (l *Listener) Port() uint16 { return l.addr.Port() }

var _ net.Listener = (*Listener)(nil)
var _ net.Conn = (*stream)(nil)

// ensure context import is used in every build.
var _ = context.Background
