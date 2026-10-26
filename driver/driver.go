// SPDX-License-Identifier: BSD-3-Clause

// Package driver is the client side of the relay's data plane: what an
// engine uses to give its containers a network through the relay. One
// Session is one connection (one browser, or one native engine); each
// container attached to the class network is an Endpoint with Listen, Dial,
// ListenPacket and Resolve, returning ordinary net.Conn, net.Listener and
// net.PacketConn values that the engine maps the WasmEdge socket calls onto.
//
// Errors carry the errno a socket call should return: a refused connect
// wraps syscall.ECONNREFUSED, a reset syscall.ECONNRESET, an unknown address
// syscall.EHOSTUNREACH, a port in use syscall.EADDRINUSE.
package driver

import (
	"context"
	"errors"
	"fmt"
	"net"
	"net/netip"
	"sync"
	"syscall"

	"google.golang.org/protobuf/proto"

	"github.com/go-wasmcontainers/relay/frame"
	v1 "github.com/go-wasmcontainers/relay/gen/relayv1"
)

// Transport is the message transport (relay.Transport has the same shape).
type Transport interface {
	ReadMessage(ctx context.Context) ([]byte, error)
	WriteMessage(ctx context.Context, msg []byte) error
	Close(reason string) error
}

// Session is one data connection to the relay.
type Session struct {
	t       Transport
	welcome *v1.Welcome
	ctx     context.Context
	cancel  context.CancelFunc

	wmu sync.Mutex // serialises writes

	mu        sync.Mutex
	nextID    uint32 // odd
	requests  map[uint32]chan frame.Frame
	streams   map[uint32]*stream
	listeners map[lkey]*Listener
	packets   map[lkey]*PacketConn
	dialed    map[string][]*udpConn // port id -> connected UDP sockets
	err       error
	done      chan struct{}
	goAway    *v1.Result
}

type lkey struct {
	port  string
	proto v1.Protocol
	num   uint32
}

// Dial starts a session over t (already authenticated by its transport:
// the WebSocket carries the session token in its handshake).
func Dial(ctx context.Context, t Transport) (*Session, error) {
	hello, _ := proto.Marshal(&v1.Hello{Version: frame.Version})
	b, _ := frame.Encode(frame.Frame{Type: frame.TypeHello, Payload: hello})
	if err := t.WriteMessage(ctx, b); err != nil {
		return nil, err
	}
	msg, err := t.ReadMessage(ctx)
	if err != nil {
		return nil, err
	}
	f, err := frame.Decode(msg)
	if err != nil {
		return nil, err
	}
	if f.Type == frame.TypeGoAway {
		var r v1.Result
		_ = proto.Unmarshal(f.Payload, &r)
		return nil, fmt.Errorf("relay refused the session: %s", r.Message)
	}
	if f.Type != frame.TypeWelcome {
		return nil, fmt.Errorf("relay answered %v, not WELCOME", f.Type)
	}
	var w v1.Welcome
	if err := proto.Unmarshal(f.Payload, &w); err != nil {
		return nil, err
	}
	sctx, cancel := context.WithCancel(context.Background())
	s := &Session{t: t, welcome: &w, ctx: sctx, cancel: cancel, nextID: 1,
		requests: map[uint32]chan frame.Frame{}, streams: map[uint32]*stream{}, listeners: map[lkey]*Listener{},
		packets: map[lkey]*PacketConn{}, dialed: map[string][]*udpConn{}, done: make(chan struct{})}
	go s.readLoop()
	return s, nil
}

// Welcome is what the relay said about this session.
func (s *Session) Welcome() *v1.Welcome { return s.welcome }

// Done is closed when the session ends; Err then says why.
func (s *Session) Done() <-chan struct{} { return s.done }

// Err is why the session ended, or nil while it runs.
func (s *Session) Err() error {
	s.mu.Lock()
	defer s.mu.Unlock()
	return s.err
}

// Close ends the session.
func (s *Session) Close() error {
	s.fail(errors.New("session closed"))
	return nil
}

func (s *Session) fail(err error) {
	s.mu.Lock()
	if s.err != nil {
		s.mu.Unlock()
		return
	}
	s.err = err
	streams := s.streams
	s.streams = map[uint32]*stream{}
	ls := s.listeners
	ps := s.packets
	dl := s.dialed
	for _, ch := range s.requests {
		close(ch)
	}
	s.requests = map[uint32]chan frame.Frame{}
	close(s.done)
	s.mu.Unlock()
	s.cancel()
	s.t.Close(err.Error())
	for _, st := range streams {
		st.reset(syscall.ECONNRESET)
	}
	for _, l := range ls {
		l.closeLocal()
	}
	for _, p := range ps {
		p.closeLocal()
	}
	for _, us := range dl {
		for _, u := range us {
			u.closeLocal()
		}
	}
}

func (s *Session) write(t frame.Type, id uint32, payload []byte) error {
	b, err := frame.Encode(frame.Frame{Type: t, Stream: id, Payload: payload})
	if err != nil {
		return err
	}
	s.wmu.Lock()
	defer s.wmu.Unlock()
	if err := s.Err(); err != nil {
		return err
	}
	return s.t.WriteMessage(s.ctx, b)
}

func (s *Session) writeMsg(t frame.Type, id uint32, m proto.Message) error {
	p, err := proto.Marshal(m)
	if err != nil {
		return err
	}
	return s.write(t, id, p)
}

func (s *Session) allocID() uint32 {
	id := s.nextID
	s.nextID += 2
	return id
}

// request sends a request frame and waits for its answer.
func (s *Session) request(ctx context.Context, t frame.Type, m proto.Message) (frame.Frame, error) {
	s.mu.Lock()
	if s.err != nil {
		s.mu.Unlock()
		return frame.Frame{}, s.err
	}
	id := s.allocID()
	ch := make(chan frame.Frame, 1)
	s.requests[id] = ch
	s.mu.Unlock()
	defer func() {
		s.mu.Lock()
		delete(s.requests, id)
		s.mu.Unlock()
	}()
	if err := s.writeMsg(t, id, m); err != nil {
		return frame.Frame{}, err
	}
	select {
	case f, ok := <-ch:
		if !ok {
			return frame.Frame{}, s.Err()
		}
		if f.Type == frame.TypeResult {
			var r v1.Result
			_ = proto.Unmarshal(f.Payload, &r)
			return frame.Frame{}, resultError(&r)
		}
		return f, nil
	case <-ctx.Done():
		return frame.Frame{}, ctx.Err()
	}
}

// Error is a refusal from the relay, with the errno a socket call returns.
type Error struct {
	Code  v1.Code
	Msg   string
	Errno syscall.Errno
}

func (e *Error) Error() string { return e.Msg }
func (e *Error) Unwrap() error { return e.Errno }

func resultError(r *v1.Result) error {
	errno := syscall.EINVAL
	switch r.Code {
	case v1.Code_CODE_REFUSED:
		errno = syscall.ECONNREFUSED
	case v1.Code_CODE_UNREACHABLE:
		errno = syscall.EHOSTUNREACH
	case v1.Code_CODE_RESET:
		errno = syscall.ECONNRESET
	case v1.Code_CODE_IN_USE:
		errno = syscall.EADDRINUSE
	case v1.Code_CODE_LIMIT:
		errno = syscall.ENOBUFS
	case v1.Code_CODE_NOT_FOUND:
		errno = syscall.ENOENT
	case v1.Code_CODE_UNAUTHENTICATED:
		errno = syscall.EACCES
	}
	return &Error{Code: r.Code, Msg: r.Message, Errno: errno}
}

// Reauth hands the relay a fresh session token; open flows stay.
func (s *Session) Reauth(token string) error {
	return s.writeMsg(frame.TypeReauth, 0, &v1.Hello{Version: frame.Version, SessionToken: token})
}

// GoAway is the relay's last word, when it closed the session.
func (s *Session) GoAway() *v1.Result {
	s.mu.Lock()
	defer s.mu.Unlock()
	return s.goAway
}

func (s *Session) readLoop() {
	for {
		msg, err := s.t.ReadMessage(s.ctx)
		if err != nil {
			s.fail(err)
			return
		}
		f, err := frame.Decode(msg)
		if err != nil {
			s.fail(err)
			return
		}
		// Payload aliases msg, which is ours: keep it.
		s.dispatch(f)
	}
}

func (s *Session) dispatch(f frame.Frame) {
	switch f.Type {
	case frame.TypeAttached, frame.TypeListening, frame.TypeResolved, frame.TypeResult:
		s.mu.Lock()
		ch := s.requests[f.Stream]
		s.mu.Unlock()
		if ch != nil {
			ch <- f
		}
	case frame.TypeConnect:
		var m v1.Incoming
		if proto.Unmarshal(f.Payload, &m) != nil {
			return
		}
		s.incoming(f.Stream, &m)
	case frame.TypeAccept, frame.TypeRefuse, frame.TypeData, frame.TypeWindow, frame.TypeClose, frame.TypeReset:
		s.mu.Lock()
		st := s.streams[f.Stream]
		s.mu.Unlock()
		if st != nil {
			st.onFrame(f)
		}
	case frame.TypeDatagram:
		var m v1.Datagram
		if proto.Unmarshal(f.Payload, &m) != nil {
			return
		}
		s.onDatagram(&m)
	case frame.TypeGoAway:
		var r v1.Result
		_ = proto.Unmarshal(f.Payload, &r)
		s.mu.Lock()
		s.goAway = &r
		s.mu.Unlock()
		s.fail(resultError(&r))
	}
}

// --------------------------------------------------------------- endpoints

// Endpoint is one container's place on the class network.
type Endpoint struct {
	s    *Session
	port *v1.Port
	addr netip.Addr
}

// Attach gives a container an address on the class network (the same one
// it had, if it was attached before).
func (s *Session) Attach(ctx context.Context, container string) (*Endpoint, error) {
	f, err := s.request(ctx, frame.TypeAttach, &v1.Attach{Container: container})
	if err != nil {
		return nil, err
	}
	var m v1.Attached
	if err := proto.Unmarshal(f.Payload, &m); err != nil {
		return nil, err
	}
	a, err := netip.ParseAddr(m.Port.GetIp())
	if err != nil {
		return nil, err
	}
	return &Endpoint{s: s, port: m.Port, addr: a}, nil
}

// Addr is the container's address.
func (e *Endpoint) Addr() netip.Addr { return e.addr }

// Port is the relay's description of the endpoint.
func (e *Endpoint) Port() *v1.Port { return e.port }

// Detach takes the container off the network.
func (e *Endpoint) Detach() error {
	return e.s.writeMsg(frame.TypeDetach, 0, &v1.Detach{PortId: e.port.Id})
}

// Resolve looks a name up: "<container>", "<container>.<student>" or
// "<container>.<student>.<domain>".
func (e *Endpoint) Resolve(ctx context.Context, name string) ([]netip.Addr, error) {
	f, err := e.s.request(ctx, frame.TypeResolve, &v1.Resolve{Name: name, PortId: e.port.Id})
	if err != nil {
		return nil, err
	}
	var m v1.Resolved
	if err := proto.Unmarshal(f.Payload, &m); err != nil {
		return nil, err
	}
	var out []netip.Addr
	for _, s := range m.Ips {
		if a, err := netip.ParseAddr(s); err == nil {
			out = append(out, a)
		}
	}
	if len(out) == 0 {
		return nil, &net.DNSError{Err: "no such host", Name: name, IsNotFound: true}
	}
	return out, nil
}

func protoOf(network string) (v1.Protocol, error) {
	switch network {
	case "tcp", "tcp4":
		return v1.Protocol_PROTOCOL_TCP, nil
	case "udp", "udp4":
		return v1.Protocol_PROTOCOL_UDP, nil
	}
	return 0, fmt.Errorf("network %q: tcp or udp", network)
}

func (e *Endpoint) listen(ctx context.Context, p v1.Protocol, port uint16) (uint32, error) {
	f, err := e.s.request(ctx, frame.TypeListen, &v1.Listen{PortId: e.port.Id, Protocol: p, Port: uint32(port)})
	if err != nil {
		return 0, err
	}
	var m v1.Listening
	if err := proto.Unmarshal(f.Payload, &m); err != nil {
		return 0, err
	}
	return m.Port, nil
}
