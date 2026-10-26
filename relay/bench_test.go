// SPDX-License-Identifier: BSD-3-Clause

package relay_test

import (
	"context"
	"io"
	"net"
	"net/netip"
	"sync"
	"testing"
	"time"

	"github.com/go-wasmcontainers/relay/driver"
	"github.com/go-wasmcontainers/relay/frame"
	v1 "github.com/go-wasmcontainers/relay/gen/relayv1"
	"github.com/go-wasmcontainers/relay/relay"
)

// unlimited lifts the per-session rate limits so a benchmark measures the
// relay, not its policing.
var unlimited = relay.Limits{BytesPerSecond: 1 << 40, BurstBytes: 1 << 40, FramesPerSecond: 1e9, BurstFrames: 1e9, MaxQueue: 64 << 20}

func benchPair(b *testing.B) (net.Conn, net.Conn) {
	e := newEnv(b, v1.Template_TEMPLATE_NEUTRON_DEFAULT, unlimited)
	alice, bob := e.student("Alice"), e.student("Bob")
	ctx := context.Background()
	srv, _ := alice.Attach(ctx, "srv")
	cli, _ := bob.Attach(ctx, "cli")
	l, err := srv.Listen(ctx, "tcp", 9)
	if err != nil {
		b.Fatal(err)
	}
	accepted := make(chan net.Conn, 1)
	go func() {
		c, _ := l.Accept()
		accepted <- c
	}()
	c, err := cli.Dial(ctx, "tcp", netip.AddrPortFrom(srv.Addr(), 9))
	if err != nil {
		b.Fatal(err)
	}
	return c, <-accepted
}

// BenchmarkStreamThroughput: one stream through the relay (in-memory
// transport): the relay's forwarding and framing cost.
func BenchmarkStreamThroughput(b *testing.B) {
	c, s := benchPair(b)
	buf := make([]byte, 1<<20)
	b.SetBytes(int64(len(buf)))
	done := make(chan struct{})
	go func() {
		io.CopyN(io.Discard, s, int64(b.N)*int64(len(buf)))
		close(done)
	}()
	b.ResetTimer()
	for range b.N {
		c.Write(buf)
	}
	<-done
}

// BenchmarkDirectTCP is the reference: the same bytes over a loopback TCP
// connection, no relay.
func BenchmarkDirectTCP(b *testing.B) {
	l, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		b.Fatal(err)
	}
	defer l.Close()
	acc := make(chan net.Conn, 1)
	go func() {
		c, _ := l.Accept()
		acc <- c
	}()
	c, err := net.Dial("tcp", l.Addr().String())
	if err != nil {
		b.Fatal(err)
	}
	s := <-acc
	buf := make([]byte, 1<<20)
	b.SetBytes(int64(len(buf)))
	done := make(chan struct{})
	go func() {
		io.CopyN(io.Discard, s, int64(b.N)*int64(len(buf)))
		close(done)
	}()
	b.ResetTimer()
	for range b.N {
		c.Write(buf)
	}
	<-done
}

// BenchmarkRoundTrip: a 64-byte request and its echo through the relay.
func BenchmarkRoundTrip(b *testing.B) {
	c, s := benchPair(b)
	go io.Copy(s, s)
	msg := make([]byte, 64)
	got := make([]byte, 64)
	b.ResetTimer()
	for range b.N {
		c.Write(msg)
		io.ReadFull(c, got)
	}
}

// BenchmarkClass40: 40 sessions, each echoing 64-byte messages with its
// neighbour at the same time; reports the round-trip time per message.
func BenchmarkClass40(b *testing.B) {
	e := newEnv(b, v1.Template_TEMPLATE_NEUTRON_DEFAULT, unlimited)
	ctx := context.Background()
	const n = 40
	eps := make([]*driver.Endpoint, n)
	for i := range n {
		s := e.student("student " + string(rune('a'+i%26)) + string(rune('a'+i/26)))
		eps[i], _ = s.Attach(ctx, "c")
		l, err := eps[i].Listen(ctx, "tcp", 7)
		if err != nil {
			b.Fatal(err)
		}
		go echoServer(l)
	}
	conns := make([]net.Conn, n)
	for i := range n {
		c, err := eps[i].Dial(ctx, "tcp", netip.AddrPortFrom(eps[(i+1)%n].Addr(), 7))
		if err != nil {
			b.Fatal(err)
		}
		conns[i] = c
	}
	b.ResetTimer()
	start := time.Now()
	var wg sync.WaitGroup
	per := b.N/n + 1
	for i := range n {
		wg.Add(1)
		go func(c net.Conn) {
			defer wg.Done()
			msg, got := make([]byte, 64), make([]byte, 64)
			for range per {
				c.Write(msg)
				io.ReadFull(c, got)
			}
		}(conns[i])
	}
	wg.Wait()
	b.ReportMetric(float64(time.Since(start).Nanoseconds())/float64(per), "ns/roundtrip-per-session")
}

// FuzzServe feeds arbitrary frames to the relay after a valid HELLO: it must
// neither panic nor hang, whatever arrives.
func FuzzServe(f *testing.F) {
	seed := func(t frame.Type, stream uint32, p []byte) []byte {
		b, _ := frame.Encode(frame.Frame{Type: t, Stream: stream, Payload: p})
		return b
	}
	f.Add(seed(frame.TypeAttach, 1, []byte{10, 3, 'w', 'e', 'b'}))
	f.Add(seed(frame.TypeConnect, 3, []byte{10, 1, 'x'}))
	f.Add(seed(frame.TypeData, 5, []byte("data")))
	f.Add(seed(frame.TypeWindow, 2, frame.Credit(1<<31)))
	f.Add(seed(frame.TypeDatagram, 0, []byte{0xff, 0xff}))
	f.Add([]byte{0, 1, 2})
	e := newEnv(f, v1.Template_TEMPLATE_NEUTRON_DEFAULT, relay.Limits{})
	f.Fuzz(func(t *testing.T, msg []byte) {
		j, err := e.r.Join(e.class.JoinCode, "fuzz", nil)
		if err != nil {
			t.Skip()
		}
		cl, _ := e.r.Authenticate(j.Token)
		a, b := relay.Pipe()
		done := make(chan struct{})
		go func() {
			e.r.Serve(context.Background(), b, cl)
			close(done)
		}()
		ctx, cancel := context.WithTimeout(context.Background(), 2*time.Second)
		defer cancel()
		s, err := driver.Dial(ctx, a)
		if err != nil {
			t.Fatal(err)
		}
		a.WriteMessage(ctx, msg)
		// The relay still answers, or closed the connection.
		_, rerr := s.Attach(ctx, "probe")
		select {
		case <-s.Done():
		default:
			if rerr != nil && ctx.Err() != nil {
				t.Fatalf("relay hung after %x", msg)
			}
		}
		s.Close()
		<-done
		e.r.KickSession(e.class.Id, j.Session.Id)
	})
}
