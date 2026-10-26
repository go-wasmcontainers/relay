// SPDX-License-Identifier: BSD-3-Clause

package driver

import (
	"context"
	"errors"
	"net"
	"net/netip"
	"os"
	"sync"
	"time"

	"github.com/go-wasmcontainers/relay/frame"
	v1 "github.com/go-wasmcontainers/relay/gen/relayv1"
)

type datagram struct {
	from    netip.AddrPort
	payload []byte
}

// dgramQueue is a bounded queue of received datagrams: when it is full,
// new datagrams are dropped, as a socket's receive buffer would.
type dgramQueue struct {
	mu     sync.Mutex
	q      []datagram
	notify chan struct{}
	closed bool
	rdl    time.Time
}

const maxQueued = 256

func newDgramQueue() *dgramQueue { return &dgramQueue{notify: make(chan struct{})} }

func (d *dgramQueue) push(g datagram) {
	d.mu.Lock()
	defer d.mu.Unlock()
	if d.closed || len(d.q) >= maxQueued {
		return
	}
	d.q = append(d.q, g)
	close(d.notify)
	d.notify = make(chan struct{})
}

func (d *dgramQueue) close() {
	d.mu.Lock()
	defer d.mu.Unlock()
	if !d.closed {
		d.closed = true
		close(d.notify)
		d.notify = make(chan struct{})
	}
}

func (d *dgramQueue) pop() (datagram, error) {
	d.mu.Lock()
	defer d.mu.Unlock()
	for len(d.q) == 0 {
		if d.closed {
			return datagram{}, net.ErrClosed
		}
		ch, dl := d.notify, d.rdl
		d.mu.Unlock()
		var err error
		if dl.IsZero() {
			<-ch
		} else if wait := time.Until(dl); wait <= 0 {
			err = os.ErrDeadlineExceeded
		} else {
			t := time.NewTimer(wait)
			select {
			case <-ch:
			case <-t.C:
				err = os.ErrDeadlineExceeded
			}
			t.Stop()
		}
		d.mu.Lock()
		if err != nil {
			return datagram{}, err
		}
	}
	g := d.q[0]
	d.q = d.q[1:]
	return g, nil
}

func (d *dgramQueue) setReadDeadline(t time.Time) {
	d.mu.Lock()
	d.rdl = t
	close(d.notify)
	d.notify = make(chan struct{})
	d.mu.Unlock()
}

// PacketConn is a bound UDP socket. It implements net.PacketConn.
type PacketConn struct {
	e    *Endpoint
	key  lkey
	addr netip.AddrPort
	q    *dgramQueue
}

// ListenPacket binds a UDP port (0 picks an ephemeral one).
func (e *Endpoint) ListenPacket(ctx context.Context, network string, port uint16) (*PacketConn, error) {
	p, err := protoOf(network)
	if err != nil || p != v1.Protocol_PROTOCOL_UDP {
		return nil, errors.New("ListenPacket: udp only")
	}
	n, err := e.listen(ctx, p, port)
	if err != nil {
		return nil, err
	}
	pc := &PacketConn{e: e, key: lkey{e.port.Id, p, n}, addr: netip.AddrPortFrom(e.addr, uint16(n)), q: newDgramQueue()}
	e.s.mu.Lock()
	e.s.packets[pc.key] = pc
	e.s.mu.Unlock()
	return pc, nil
}

func (s *Session) onDatagram(m *v1.Datagram) {
	src, err := netip.ParseAddr(m.SrcIp)
	if err != nil {
		return
	}
	g := datagram{from: netip.AddrPortFrom(src, uint16(m.SrcPort)), payload: m.Payload}
	s.mu.Lock()
	pc := s.packets[lkey{m.PortId, v1.Protocol_PROTOCOL_UDP, m.DstPort}]
	var dialed []*udpConn
	if pc == nil {
		dialed = s.dialed[m.PortId]
	}
	s.mu.Unlock()
	if pc != nil {
		pc.q.push(g)
		return
	}
	// A reply to a connected socket (sent from the relay-chosen port).
	for _, u := range dialed {
		if u.remote == g.from {
			u.q.push(g)
			return
		}
	}
}

func (e *Endpoint) send(srcPort uint16, to netip.AddrPort, p []byte) (int, error) {
	if len(p) > frame.MaxPayload-128 {
		return 0, errors.New("datagram too large")
	}
	err := e.s.writeMsg(frame.TypeDatagram, 0, &v1.Datagram{PortId: e.port.Id, SrcPort: uint32(srcPort),
		DstIp: to.Addr().String(), DstPort: uint32(to.Port()), Payload: p})
	if err != nil {
		return 0, err
	}
	return len(p), nil
}

// ReadFrom reads one datagram.
func (pc *PacketConn) ReadFrom(p []byte) (int, net.Addr, error) {
	g, err := pc.q.pop()
	if err != nil {
		return 0, nil, err
	}
	return copy(p, g.payload), net.UDPAddrFromAddrPort(g.from), nil
}

// WriteTo sends one datagram.
func (pc *PacketConn) WriteTo(p []byte, addr net.Addr) (int, error) {
	ua, ok := addr.(*net.UDPAddr)
	if !ok {
		return 0, errors.New("WriteTo: a *net.UDPAddr")
	}
	return pc.e.send(pc.addr.Port(), ua.AddrPort(), p)
}

func (pc *PacketConn) closeLocal() { pc.q.close() }

// Close unbinds the port.
func (pc *PacketConn) Close() error {
	pc.q.close()
	s := pc.e.s
	s.mu.Lock()
	delete(s.packets, pc.key)
	s.mu.Unlock()
	return s.writeMsg(frame.TypeUnlisten, 0, &v1.Unlisten{PortId: pc.key.port, Protocol: pc.key.proto, Port: pc.key.num})
}

func (pc *PacketConn) LocalAddr() net.Addr                { return net.UDPAddrFromAddrPort(pc.addr) }
func (pc *PacketConn) SetDeadline(t time.Time) error      { pc.q.setReadDeadline(t); return nil }
func (pc *PacketConn) SetReadDeadline(t time.Time) error  { pc.q.setReadDeadline(t); return nil }
func (pc *PacketConn) SetWriteDeadline(t time.Time) error { return nil }

var _ net.PacketConn = (*PacketConn)(nil)

// udpConn is a connected UDP socket: it sends from the relay-chosen
// ephemeral port of the endpoint and reads replies from its peer only.
type udpConn struct {
	e      *Endpoint
	remote netip.AddrPort
	q      *dgramQueue
}

func (e *Endpoint) dialUDP(to netip.AddrPort) *udpConn {
	u := &udpConn{e: e, remote: to, q: newDgramQueue()}
	e.s.mu.Lock()
	e.s.dialed[e.port.Id] = append(e.s.dialed[e.port.Id], u)
	e.s.mu.Unlock()
	return u
}

func (u *udpConn) Read(p []byte) (int, error) {
	g, err := u.q.pop()
	if err != nil {
		return 0, err
	}
	return copy(p, g.payload), nil
}

func (u *udpConn) Write(p []byte) (int, error) { return u.e.send(0, u.remote, p) }

func (u *udpConn) closeLocal() { u.q.close() }

func (u *udpConn) Close() error {
	u.q.close()
	s := u.e.s
	s.mu.Lock()
	list := s.dialed[u.e.port.Id]
	for i, x := range list {
		if x == u {
			s.dialed[u.e.port.Id] = append(list[:i:i], list[i+1:]...)
			break
		}
	}
	s.mu.Unlock()
	return nil
}

func (u *udpConn) LocalAddr() net.Addr {
	return net.UDPAddrFromAddrPort(netip.AddrPortFrom(u.e.addr, 0))
}
func (u *udpConn) RemoteAddr() net.Addr               { return net.UDPAddrFromAddrPort(u.remote) }
func (u *udpConn) SetDeadline(t time.Time) error      { u.q.setReadDeadline(t); return nil }
func (u *udpConn) SetReadDeadline(t time.Time) error  { u.q.setReadDeadline(t); return nil }
func (u *udpConn) SetWriteDeadline(t time.Time) error { return nil }

var _ net.Conn = (*udpConn)(nil)
