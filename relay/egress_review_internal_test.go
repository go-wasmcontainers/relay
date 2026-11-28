// SPDX-License-Identifier: BSD-3-Clause

package relay

import (
	"context"
	"net"
	"net/netip"
	"sync/atomic"
	"testing"
	"time"

	"github.com/go-wasmcontainers/relay/frame"
	v1 "github.com/go-wasmcontainers/relay/gen/relayv1"
)

// Review findings of PR 19, each held by a test that failed first.

// A killed stream's write loop stops waiting for the class rate and charges
// nothing: it ends with the stream, not with the agent.
func TestKilledStreamWriteLoopDoesNotLinger(t *testing.T) {
	x := newAgentEnv(t, EgressLimits{ClassBytesPerSecond: 1})
	s := x.stream(t, 21)
	s.checked.Store(true)
	s.nc = failingConn()
	x.e.bytes.take(x.e.bytes.burst) // empty: the write must wait for the rate
	s.enqueue([]byte("data"))
	done := make(chan struct{})
	go func() { s.writeLoop(); close(done) }()
	time.Sleep(50 * time.Millisecond)
	s.kill()
	// The wait for the rate is capped near a second, so a loop that waited on
	// the agent's context instead would still end, but not within this.
	select {
	case <-done:
	case <-time.After(300 * time.Millisecond):
		t.Fatal("the write loop of a killed stream is still waiting")
	}
	if d := x.s.day; d != 0 {
		t.Fatalf("%d bytes charged by a killed stream", d)
	}
}

// stallT is a transport whose writes never complete until released.
type stallT struct {
	Transport
	release chan struct{}
}

func (s stallT) WriteMessage(ctx context.Context, _ []byte) error {
	select {
	case <-s.release:
	case <-ctx.Done():
	}
	return nil
}

// A reset that cannot be written must not stop the agent's read loop: a
// stalled sendResult would back the relay's queue up until it shuts the whole
// agent down.
func TestAbortDoesNotBlockOnAStalledPipe(t *testing.T) {
	x := newAgentEnv(t, EgressLimits{})
	rel := make(chan struct{})
	t.Cleanup(func() { close(rel) })
	a := &agent{e: x.e, sess: x.s, t: stallT{release: rel}, pending: map[uint32]expect{}, st: map[uint32]*estream{}}
	a.ctx, a.cancel = context.WithCancel(context.Background())
	t.Cleanup(a.cancel)
	a.expect(1, expect{ip: netip.MustParseAddr("93.184.216.34"), names: []string{"api.example.org"}})
	a.onConnect(1)
	s := a.stream(1)
	done := make(chan struct{})
	go func() { s.abort(v1.Code_CODE_RESET, "test"); close(done) }()
	select {
	case <-done:
	case <-time.After(2 * time.Second):
		t.Fatal("abort waited for the pipe")
	}
	if !s.isDead() {
		t.Fatal("the stream is not dead")
	}
}

// The queue towards the outside is counted in bytes, like the credit: 300
// tiny writes under the window are not a reason to reset the stream, and the
// window is the bound.
func TestWriteQueueIsCountedInBytes(t *testing.T) {
	x := newAgentEnv(t, EgressLimits{})
	s := x.stream(t, 23)
	s.checked.Store(true)
	for i := 0; i < 300; i++ {
		s.onData([]byte{byte(i)})
	}
	if s.isDead() {
		t.Fatal("300 one-byte writes reset the stream")
	}
	s.onData(make([]byte, x.e.r.limits.StreamWindow))
	if !s.isDead() {
		t.Fatal("a queue past the window was accepted")
	}
}

// The queue yields frame-sized chunks and the CLOSE after the data.
func TestWriteQueueOrderAndChunks(t *testing.T) {
	x := newAgentEnv(t, EgressLimits{})
	s := x.stream(t, 25)
	big := make([]byte, 2*frame.MaxPayload+10)
	for i := range big {
		big[i] = byte(i)
	}
	if !s.enqueue(big) {
		t.Fatal("refused under the window")
	}
	s.enqueueClose()
	var got []byte
	for {
		b, closing, ok := s.take()
		if !ok {
			t.Fatal("take ended")
		}
		if closing {
			break
		}
		if len(b) > frame.MaxPayload {
			t.Fatalf("a chunk of %d bytes", len(b))
		}
		got = append(got, b...)
	}
	if string(got) != string(big) {
		t.Fatal("bytes lost or reordered")
	}
}

// With the guest gone, the agent that served it stops; a guest replaced by a
// reconnect keeps its agent.
func TestGuestDisconnectStopsItsAgent(t *testing.T) {
	x := newAgentEnv(t, EgressLimits{})
	r := x.e.r
	newGuest := func() *conn {
		ta, _ := Pipe()
		return &conn{r: r, c: x.e.c, session: "s1", t: ta, done: make(chan struct{}), streams: map[uint32]*end{}}
	}
	old, cur := newGuest(), newGuest()
	r.mu.Lock()
	x.e.c.conns["s1"] = cur
	r.mu.Unlock()
	old.shutdown("replaced")
	r.mu.Lock()
	kept := x.s.agent != nil
	r.mu.Unlock()
	if !kept {
		t.Fatal("a replaced connection stopped the agent of the live one")
	}
	cur.shutdown("gone")
	select {
	case <-x.ag.runDone:
	case <-time.After(5 * time.Second):
		t.Fatal("the agent outlived its guest")
	}
	r.mu.Lock()
	left := x.s.agent
	r.mu.Unlock()
	if left != nil {
		t.Fatal("the session still points at the agent")
	}
}

// cwConn counts the half-closes it is given.
type cwConn struct {
	net.Conn
	closeWrites atomic.Int32
}

func (c *cwConn) Close() error      { return nil }
func (c *cwConn) CloseWrite() error { c.closeWrites.Add(1); return nil }

// A stream that was killed with the guest's CLOSE still queued half-closes
// nothing: the loop ends with the stream, whatever is left in its queue.
func TestKilledStreamDoesNotHalfCloseFromItsQueue(t *testing.T) {
	x := newAgentEnv(t, EgressLimits{})
	s := x.stream(t, 23)
	s.checked.Store(true)
	nc := &cwConn{}
	s.nc = nc
	s.enqueueClose()
	s.kill()
	done := make(chan struct{})
	go func() { s.writeLoop(); close(done) }()
	select {
	case <-done:
	case <-time.After(2 * time.Second):
		t.Fatal("the write loop of a killed stream did not end")
	}
	if n := nc.closeWrites.Load(); n != 0 {
		t.Fatalf("a killed stream half-closed the outside socket %d times", n)
	}
	if s.guestEOF.Load() {
		t.Fatal("a killed stream recorded the guest's EOF")
	}
}
