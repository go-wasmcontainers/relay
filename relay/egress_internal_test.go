// SPDX-License-Identifier: BSD-3-Clause

package relay

import (
	"context"
	"errors"
	"net"
	"net/netip"
	"testing"
	"time"

	"github.com/go-wasmcontainers/relay/auth"
	"github.com/go-wasmcontainers/relay/firewall"
	v1 "github.com/go-wasmcontainers/relay/gen/relayv1"
)

// agentEnv is a relay with one egress class and an agent for one session, with
// a dial that blocks until the test lets it go, so no stream ever reaches an
// outside socket.
type agentEnv struct {
	e     *egressClass
	s     *egressSess
	ag    *agent
	block chan struct{}
}

func newAgentEnv(t *testing.T, lim EgressLimits) *agentEnv {
	t.Helper()
	k, err := auth.NewKeys()
	if err != nil {
		t.Fatal(err)
	}
	x := &agentEnv{block: make(chan struct{})}
	t.Cleanup(func() { close(x.block) })
	r, err := New(Config{Keys: k, Egress: EgressConfig{Limits: lim,
		Resolver: nopResolver{},
		Dial: func(ctx context.Context, ip netip.Addr, port uint16) (net.Conn, error) {
			<-x.block // ignores ctx on purpose: the dial of a killed stream
			a, b := net.Pipe()
			b.Close()
			return a, nil
		}}})
	if err != nil {
		t.Fatal(err)
	}
	cls, err := r.CreateClass(ClassSpec{Name: "c", RequireID: true, Allowed: []string{"group:g"}, Egress: []string{"api.example.org:443"}})
	if err != nil {
		t.Fatal(err)
	}
	r.mu.Lock()
	defer r.mu.Unlock()
	x.e = r.classes[cls.Id].eg
	x.s = x.e.session("s1")
	x.ag = x.s.agentFor(x.e, &conn{label: "guest"})
	t.Cleanup(x.ag.stop)
	return x
}

type nopResolver struct{}

func (nopResolver) LookupAddrs(context.Context, string) ([]netip.Addr, error) {
	return []netip.Addr{netip.MustParseAddr("93.184.216.34")}, nil
}

// With every ephemeral port of the source address taken, a connection to an
// allowed name is refused as a limit, and no link is made.
func TestConnectEgressNoEphemeralPortLeft(t *testing.T) {
	x := newAgentEnv(t, EgressLimits{})
	src := netip.MustParseAddr("10.0.0.9")
	r := x.e.r
	r.mu.Lock()
	defer r.mu.Unlock()
	if _, err := x.e.gw.Resolve(context.Background(), x.s.pins, "api.example.org"); err != nil {
		t.Fatal(err)
	}
	for p := 49152; p <= 65535; p++ {
		x.e.c.listeners[lkey{src, firewall.TCP, uint16(p)}] = &listener{}
	}
	x.e.c.s.Ports["p"] = &sPort{ID: "p"} // no port security: the firewall lets it through
	cn := &conn{r: r, c: x.e.c, session: "s1", streams: map[uint32]*end{}}
	var got v1.Code
	refuse := func(c v1.Code, msg string) error { got = c; return errors.New(msg) }
	err := cn.connectEgress(1, &v1.Connect{PortId: "p", DstPort: 443}, netip.MustParseAddr("93.184.216.34"), src, refuse)
	if err == nil || got != v1.Code_CODE_LIMIT {
		t.Fatalf("got %v, code %v; want a limit refusal", err, got)
	}
	if len(cn.streams) != 0 {
		t.Fatalf("%d streams made without a source port", len(cn.streams))
	}
}

// The agent ends when its pipe dies, instead of reading nothing forever.
func TestAgentStopsWhenPipeDies(t *testing.T) {
	x := newAgentEnv(t, EgressLimits{})
	_ = x.ag.t.Close("test")
	select {
	case <-x.ag.runDone:
	case <-time.After(5 * time.Second):
		t.Fatal("the agent's read loop outlived its pipe")
	}
}

// A class without egress tells its members so.
func TestNilEgressClassProto(t *testing.T) {
	var e *egressClass
	if p := e.proto().Policy; p != "none" {
		t.Fatalf("policy %q for a class without egress", p)
	}
}

// stream registers an expected stream and has the agent accept it.
func (x *agentEnv) stream(t *testing.T, id uint32) *estream {
	t.Helper()
	x.ag.expect(id, expect{ip: netip.MustParseAddr("93.184.216.34"), names: []string{"api.example.org"}})
	x.ag.onConnect(id)
	s := x.ag.stream(id)
	if s == nil {
		t.Fatalf("stream %d was not accepted", id)
	}
	return s
}

// A CONNECT the relay never announced, or one arriving after the agent was
// stopped, creates no stream and so dials nothing.
func TestAgentRefusesUnannouncedAndLateConnect(t *testing.T) {
	x := newAgentEnv(t, EgressLimits{})
	x.ag.onConnect(999)
	if n := len(x.ag.st); n != 0 {
		t.Fatalf("%d streams after an unannounced CONNECT", n)
	}
	x.ag.expect(5, expect{ip: netip.MustParseAddr("93.184.216.34"), names: []string{"api.example.org"}})
	x.ag.stop()
	x.ag.onConnect(5)
	if n := len(x.ag.st); n != 0 {
		t.Fatalf("%d streams after a CONNECT to a stopped agent", n)
	}
}

// Bytes that arrive for a stream that is already dead are ignored: they are
// not judged as a ClientHello and do not count as a TLS refusal.
func TestAgentIgnoresDataOfDeadStream(t *testing.T) {
	x := newAgentEnv(t, EgressLimits{})
	s := x.stream(t, 7)
	s.kill()
	s.onData([]byte("GET / HTTP/1.1\r\nHost: api.example.org\r\n\r\n"))
	if n := x.e.ctr.tls.Load(); n != 0 {
		t.Fatalf("%d TLS refusals counted for a dead stream", n)
	}
	// The same bytes on a live stream are refused and counted.
	l := x.stream(t, 9)
	l.onData([]byte("GET / HTTP/1.1\r\nHost: api.example.org\r\n\r\n"))
	if n := x.e.ctr.tls.Load(); n != 1 {
		t.Fatalf("%d TLS refusals counted for a live stream, want 1", n)
	}
}

// A guest that closes before it sent a ClientHello gets its stream reset: no
// half-open stream waits for the hello timeout.
func TestAgentGuestClosedBeforeHello(t *testing.T) {
	x := newAgentEnv(t, EgressLimits{})
	s := x.stream(t, 11)
	s.guestClosed()
	if !s.isDead() {
		t.Fatal("the stream outlived the guest's close")
	}
}

func failingConn() net.Conn {
	a, b := net.Pipe()
	b.Close()
	return a
}

// A failed write to the outside resets the stream instead of dropping bytes
// silently.
func TestAgentWriteFailureResetsStream(t *testing.T) {
	x := newAgentEnv(t, EgressLimits{})
	s := x.stream(t, 13)
	s.checked.Store(true)
	s.nc = failingConn()
	s.enqueue([]byte("data"))
	go s.writeLoop()
	eventually(t, "the stream was reset", s.isDead)
}

// When the agent stops while a write waits for the class's byte rate, the
// bytes are neither counted against the day nor written.
func TestAgentStopWhileWaitingForRate(t *testing.T) {
	x := newAgentEnv(t, EgressLimits{ClassBytesPerSecond: 1})
	s := x.stream(t, 15)
	s.checked.Store(true)
	s.nc = failingConn()
	x.e.bytes.take(x.e.bytes.burst) // the bucket is empty: the write must wait
	s.enqueue([]byte("data"))
	done := make(chan struct{})
	go func() { s.writeLoop(); close(done) }()
	time.Sleep(50 * time.Millisecond)
	x.ag.stop()
	select {
	case <-done:
	case <-time.After(5 * time.Second):
		t.Fatal("the write loop outlived the agent")
	}
	if d := x.s.day; d != 0 {
		t.Fatalf("%d bytes counted for bytes never sent", d)
	}
}

func TestBucketTake(t *testing.T) {
	now := time.Unix(1000, 0)
	b := newBucket(1, 2, func() time.Time { return now })
	if !b.take(2) {
		t.Fatal("a full bucket refused its burst")
	}
	if b.take(1) {
		t.Fatal("an empty bucket gave a token")
	}
	now = now.Add(time.Second)
	if !b.take(1) {
		t.Fatal("a token was not refilled after a second")
	}
	if b.take(1) {
		t.Fatal("more than the refill was given")
	}
	now = now.Add(time.Hour)
	if b.take(3) {
		t.Fatal("a take above the burst succeeded")
	}
	if !b.take(2) {
		t.Fatal("the bucket did not refill up to its burst")
	}
}

func eventually(t *testing.T, what string, f func() bool) {
	t.Helper()
	for end := time.Now().Add(5 * time.Second); time.Now().Before(end); time.Sleep(5 * time.Millisecond) {
		if f() {
			return
		}
	}
	t.Fatalf("timed out: %s", what)
}
