// SPDX-License-Identifier: BSD-3-Clause

package relay_test

import (
	"context"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/sha256"
	"crypto/tls"
	"crypto/x509"
	"errors"
	"io"
	"math/big"
	"net"
	"net/netip"
	"os"
	"path/filepath"
	"runtime"
	"strings"
	"sync"
	"sync/atomic"
	"syscall"
	"testing"
	"time"

	"github.com/go-wasmcontainers/relay/auth"
	"github.com/go-wasmcontainers/relay/driver"
	"github.com/go-wasmcontainers/relay/egress"
	v1 "github.com/go-wasmcontainers/relay/gen/relayv1"
	"github.com/go-wasmcontainers/relay/relay"
)

var (
	apiIP   = netip.MustParseAddr("93.184.216.34")
	otherIP = netip.MustParseAddr("93.184.216.35")
)

type fakeDNS struct {
	mu   sync.Mutex
	m    map[string][]netip.Addr
	last string
	// hold, when set, is called after the answer is chosen and before it is
	// returned: a test parks a lookup in flight with it.
	hold func(name string)
}

func (f *fakeDNS) LookupAddrs(_ context.Context, name string) ([]netip.Addr, error) {
	f.mu.Lock()
	f.last = name
	a, ok := f.m[strings.TrimSuffix(name, ".")]
	hold := f.hold
	f.mu.Unlock()
	if hold != nil {
		hold(name)
	}
	if !ok {
		return nil, errors.New("NXDOMAIN")
	}
	return a, nil
}

func (f *fakeDNS) set(name string, a ...netip.Addr) {
	f.mu.Lock()
	f.m[name] = a
	f.mu.Unlock()
}

type countConn struct {
	net.Conn
	n *atomic.Int64
}

func (c countConn) Read(p []byte) (int, error) {
	n, err := c.Conn.Read(p)
	c.n.Add(int64(n))
	return n, err
}

// egEnv is a relay with one egress class and a local TLS echo server that
// stands for the whole outside.
type egEnv struct {
	*env
	dns    *fakeDNS
	srv    net.Listener
	rawIn  atomic.Int64 // bytes the outside server received
	conns  atomic.Int64 // TCP connections it accepted
	closed chan struct{}
	dialed atomic.Int64
	mode   atomic.Int32 // what the outside server does after the handshake
	hold   atomic.Pointer[chan struct{}]
	greet  atomic.Bool // the outside server writes before it is spoken to
	hrr    atomic.Bool // the outside server answers with a HelloRetryRequest
}

// helloRetryRequest is a TLS 1.3 ServerHello whose random is the fixed
// HelloRetryRequest value (RFC 8446 4.1.3).
func helloRetryRequest() []byte {
	random := sha256.Sum256([]byte("HelloRetryRequest"))
	body := append([]byte{3, 3}, random[:]...)
	body = append(body, 0, 0x13, 0x01, 0, 0, 0) // session id, suite, compression, no extensions
	hs := append([]byte{2, 0, byte(len(body) >> 8), byte(len(body))}, body...)
	return append([]byte{0x16, 3, 3, byte(len(hs) >> 8), byte(len(hs))}, hs...)
}

const (
	modeEcho = iota
	modeSink
	modeFlood
)

func testCert(t testing.TB) tls.Certificate {
	t.Helper()
	key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	tpl := &x509.Certificate{SerialNumber: big.NewInt(1), NotBefore: time.Now().Add(-time.Hour),
		NotAfter: time.Now().Add(time.Hour), DNSNames: []string{"api.example.org"}}
	der, err := x509.CreateCertificate(rand.Reader, tpl, tpl, &key.PublicKey, key)
	if err != nil {
		t.Fatal(err)
	}
	return tls.Certificate{Certificate: [][]byte{der}, PrivateKey: key}
}

func newEgEnv(t testing.TB, lim relay.EgressLimits) *egEnv {
	t.Helper()
	x := &egEnv{closed: make(chan struct{}, 256), dns: &fakeDNS{m: map[string][]netip.Addr{
		"api.example.org": {apiIP}, "other.example.org": {otherIP}, "evil.example.org": {netip.MustParseAddr("93.184.216.99")}}}}
	srv, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	x.srv = srv
	t.Cleanup(func() { srv.Close() })
	cfg := &tls.Config{Certificates: []tls.Certificate{testCert(t)}}
	go func() {
		for {
			c, err := srv.Accept()
			if err != nil {
				return
			}
			x.conns.Add(1)
			go func() {
				defer func() { x.closed <- struct{}{} }()
				defer c.Close()
				if x.greet.Load() {
					c.Write([]byte("220 the outside speaks first"))
				}
				if x.hrr.Load() {
					// Answer the first bytes with a HelloRetryRequest.
					c.Read(make([]byte, 1))
					c.Write(helloRetryRequest())
					io.Copy(io.Discard, c)
					return
				}
				tc := tls.Server(countConn{c, &x.rawIn}, cfg)
				if tc.Handshake() != nil {
					return
				}
				switch x.mode.Load() {
				case modeSink:
					io.Copy(io.Discard, tc)
				case modeFlood:
					tc.Write(make([]byte, 200000))
					io.Copy(io.Discard, tc)
				default:
					io.Copy(tc, tc)
				}
			}()
		}
	}()
	k, err := auth.NewKeys()
	if err != nil {
		t.Fatal(err)
	}
	r, err := relay.New(relay.Config{Keys: k, Egress: relay.EgressConfig{Resolver: x.dns, Limits: lim, Operator: "test operator",
		Dial: func(ctx context.Context, ip netip.Addr, port uint16) (net.Conn, error) {
			x.dialed.Add(1)
			if h := x.hold.Load(); h != nil {
				<-*h // deliberately ignores ctx: a dial that returns after the stream was killed
			}
			if x.hold.Load() != nil {
				ctx = context.Background() // the late dial of a killed stream still connects
			}
			return (&net.Dialer{}).DialContext(ctx, "tcp", srv.Addr().String())
		}}})
	if err != nil {
		t.Fatal(err)
	}
	cls, err := r.CreateClass(relay.ClassSpec{Name: "c", RequireID: true, Allowed: []string{"group:students"},
		Egress: []string{"api.example.org:443", "other.example.org:443"}})
	if err != nil {
		t.Fatal(err)
	}
	x.env = &env{t: t, r: r, class: cls}
	return x
}

// person joins with an identity in the allowed group.
func (x *egEnv) person(name string) (*driver.Session, *driver.Endpoint) {
	x.t.Helper()
	id := &relay.Identity{Issuer: "https://idp", Subject: name, Groups: []string{"students"}}
	j, err := x.r.Join(x.class.JoinCode, name, id)
	if err != nil {
		x.t.Fatal(err)
	}
	s := x.connect(j.Token)
	return s, attach(x.t, s, "web")
}

func (x *egEnv) state() *v1.EgressState {
	x.t.Helper()
	st, err := x.r.EgressState(x.class.Id)
	if err != nil {
		x.t.Fatal(err)
	}
	return st
}

func eventually(t *testing.T, what string, f func() bool) {
	t.Helper()
	for end := time.Now().Add(5 * time.Second); time.Now().Before(end); time.Sleep(10 * time.Millisecond) {
		if f() {
			return
		}
	}
	t.Fatalf("timed out: %s", what)
}

func wantErrno(t *testing.T, err error, no syscall.Errno) {
	t.Helper()
	if !errors.Is(err, no) {
		t.Fatalf("got %v, want %v", err, no)
	}
}

func resolve(t *testing.T, ep *driver.Endpoint, name string) []netip.Addr {
	t.Helper()
	// A refused name answers "no such host", the same as an unknown one:
	// the guest learns nothing from the difference.
	a, err := ep.Resolve(ctx(t), name)
	if err != nil && !strings.Contains(err.Error(), "no such host") {
		t.Fatal(err)
	}
	return a
}

func dialRaw(t *testing.T, ep *driver.Endpoint, ip netip.Addr, port uint16) (net.Conn, error) {
	t.Helper()
	return ep.Dial(ctx(t), "tcp", netip.AddrPortFrom(ip, port))
}

// dialTLS dials ip:443 and runs a TLS handshake naming serverName.
func dialTLS(t *testing.T, ep *driver.Endpoint, ip netip.Addr, serverName string) (*tls.Conn, error) {
	t.Helper()
	c, err := dialRaw(t, ep, ip, 443)
	if err != nil {
		return nil, err
	}
	tc := tls.Client(c, &tls.Config{ServerName: serverName, InsecureSkipVerify: true})
	hc, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()
	if err := tc.HandshakeContext(hc); err != nil {
		c.Close()
		return nil, err
	}
	return tc, nil
}

func echo(t *testing.T, c net.Conn, msg string) {
	t.Helper()
	c.SetDeadline(time.Now().Add(5 * time.Second))
	if _, err := c.Write([]byte(msg)); err != nil {
		t.Fatal(err)
	}
	buf := make([]byte, len(msg))
	if _, err := io.ReadFull(c, buf); err != nil || string(buf) != msg {
		t.Fatalf("echo: %q %v", buf, err)
	}
}

func TestEgressEndToEnd(t *testing.T) {
	x := newEgEnv(t, relay.EgressLimits{})
	s, ep := x.person("ann")
	st := s.Welcome().Egress
	if st == nil || st.Policy != "gateway" || st.Operator != "test operator" || !st.Logs || len(st.Allowlist) != 2 ||
		st.Allowlist[0] != "api.example.org:443" || st.Limits.StreamsPerSession != 16 || st.Limits.SessionBytesPerDay != 1<<30 {
		t.Fatalf("welcome: %v", st)
	}
	if got := resolve(t, ep, "api.example.org"); len(got) != 1 || got[0] != apiIP {
		t.Fatalf("resolve: %v", got)
	}
	c, err := dialTLS(t, ep, apiIP, "api.example.org")
	if err != nil {
		t.Fatal(err)
	}
	echo(t, c, "hello from the guest")
	if got := x.state().Counters; got.Allowed != 1 || got.ActiveStreams != 1 || got.DeniedLimit != 0 {
		t.Fatalf("counters: %v", got)
	}
	c.Close()
	eventually(t, "the stream is released", func() bool { return x.state().Counters.ActiveStreams == 0 })
	if got := x.state().Counters; got.BytesUp == 0 || got.BytesDown == 0 {
		t.Fatalf("no bytes counted: %v", got)
	}
}

func TestEgressNoPolicyNoEgress(t *testing.T) {
	// A class with no allowlist: the destination is unreachable, as before.
	e := newEnv(t, v1.Template_TEMPLATE_NEUTRON_DEFAULT, relay.Limits{})
	s := e.student("ann")
	if st := s.Welcome().Egress; st == nil || st.Policy != "none" || st.Reason == "" {
		t.Fatalf("welcome: %v", st)
	}
	ep := attach(t, s, "web")
	_, err := dialRaw(t, ep, apiIP, 443)
	wantErrno(t, err, syscall.EHOSTUNREACH)
	if got := resolve(t, ep, "api.example.org"); len(got) != 0 {
		t.Fatalf("a class with no egress resolved an outside name: %v", got)
	}
}

func TestEgressRefusedAtCreation(t *testing.T) {
	k, _ := auth.NewKeys()
	r, _ := relay.New(relay.Config{Keys: k})
	ok := "api.example.org:443"
	for name, spec := range map[string]relay.ClassSpec{
		"no identity":           {Name: "x", Allowed: []string{"group:g"}, Egress: []string{ok}},
		"no audience":           {Name: "x", RequireID: true, Egress: []string{ok}},
		"empty list":            {Name: "x", RequireID: true, Allowed: []string{"group:g"}, Egress: []string{}},
		"empty entry":           {Name: "x", RequireID: true, Allowed: []string{"group:g"}, Egress: []string{""}},
		"wildcard":              {Name: "x", RequireID: true, Allowed: []string{"group:g"}, Egress: []string{"*.example.org:443"}},
		"wildcard only":         {Name: "x", RequireID: true, Allowed: []string{"group:g"}, Egress: []string{"*"}},
		"ip":                    {Name: "x", RequireID: true, Allowed: []string{"group:g"}, Egress: []string{"93.184.216.34:443"}},
		"cidr":                  {Name: "x", RequireID: true, Allowed: []string{"group:g"}, Egress: []string{"93.184.216.0/24:443"}},
		"port 80":               {Name: "x", RequireID: true, Allowed: []string{"group:g"}, Egress: []string{"api.example.org:80"}},
		"no port":               {Name: "x", RequireID: true, Allowed: []string{"group:g"}, Egress: []string{"api.example.org"}},
		"one good one wildcard": {Name: "x", RequireID: true, Allowed: []string{"group:g"}, Egress: []string{ok, "*.example.org:443"}},
	} {
		if _, err := r.CreateClass(spec); relay.ErrKind(err) != relay.KindInvalid {
			t.Errorf("%s: got %v, want invalid", name, err)
		}
	}
	if cs := r.ListClasses(); len(cs) != 0 {
		t.Fatalf("a refused class was created: %v", cs)
	}
	good, err := r.CreateClass(relay.ClassSpec{Name: "x", RequireID: true, Allowed: []string{"group:g"}, Egress: []string{ok, ok}})
	if err != nil || len(good.Egress) != 1 {
		t.Fatalf("good class: %v %v", good, err)
	}
}

func TestEgressRefusedAtLoad(t *testing.T) {
	// The relay refuses to start egress on a stored class that skips the
	// identity requirement, whoever edited the state file.
	dir := t.TempDir()
	state := func(extra string) string {
		return `{"version":1,"relay_id":"x","classes":{"c-1":{"id":"c-1","name":"n","join_code":"AAAAAAAA","cidr":"10.42.0.0/16",` +
			`"session_bits":24,"dns_domain":"class","egress":["api.example.org:443"]` + extra + `}}}`
	}
	k, _ := auth.NewKeys()
	for name, tc := range map[string]struct {
		extra string
		ok    bool
	}{
		"no identity":     {``, false},
		"no audience":     {`,"require_identity":true`, false},
		"complete":        {`,"require_identity":true,"allowed":["group:g"]`, true},
		"stored wildcard": {`,"require_identity":true,"allowed":["group:g"],"egress":["*.example.org:443"]`, false},
	} {
		p := filepath.Join(dir, strings.ReplaceAll(name, " ", "-")+".json")
		if err := os.WriteFile(p, []byte(state(tc.extra)), 0o600); err != nil {
			t.Fatal(err)
		}
		_, err := relay.New(relay.Config{Keys: k, Store: relay.FileStore{Path: p}})
		if (err == nil) != tc.ok {
			t.Errorf("%s: err %v, want ok=%v", name, err, tc.ok)
		}
	}
}

func TestEgressNeedsIdentityToJoin(t *testing.T) {
	x := newEgEnv(t, relay.EgressLimits{})
	if _, err := x.r.Join(x.class.JoinCode, "anon", nil); relay.ErrKind(err) != relay.KindUnauthenticated {
		t.Fatalf("anonymous join: %v", err)
	}
	other := &relay.Identity{Issuer: "https://idp", Subject: "x", Groups: []string{"visitors"}}
	if _, err := x.r.Join(x.class.JoinCode, "visitor", other); relay.ErrKind(err) != relay.KindDenied {
		t.Fatalf("visitor join: %v", err)
	}
}

func TestEgressDenyTables(t *testing.T) {
	// Every row of both deny tables, by name (the answer is refused whole)
	// and by address (an address the gateway never resolved).
	x := newEgEnv(t, relay.EgressLimits{LookupsPerSecond: 1e6, ConnectsPerSecond: 1e6, ConnectBurst: 1e6})
	_, ep := x.person("ann")
	v4, v6 := egress.DeniedPrefixes()
	rows := 0
	for _, p := range append(append([]netip.Prefix(nil), v4...), v6...) {
		for _, a := range []netip.Addr{p.Addr(), lastAddr(p)} {
			x.dns.set("api.example.org", a)
			if got := resolve(t, ep, "api.example.org"); len(got) != 0 {
				t.Errorf("%v (%v) resolved: %v", p, a, got)
			}
			rows++
			if a.Is4() {
				_, err := dialRaw(t, ep, a, 443)
				if !errors.Is(err, syscall.ECONNREFUSED) {
					t.Errorf("%v dialled: %v", a, err)
				}
			}
		}
	}
	if got := x.state().Counters.DeniedPrivateRange; got < uint64(rows) {
		t.Fatalf("%d rows but only %d denials counted by the table", rows, got)
	}
	if x.dialed.Load() != 0 {
		t.Fatalf("the gateway dialled %d times for refused addresses", x.dialed.Load())
	}
}

func lastAddr(p netip.Prefix) netip.Addr {
	b := p.Addr().AsSlice()
	for i := p.Bits(); i < len(b)*8; i++ {
		b[i/8] |= 0x80 >> (i % 8)
	}
	a, _ := netip.AddrFromSlice(b)
	return a
}

func TestEgressRebinding(t *testing.T) {
	x := newEgEnv(t, relay.EgressLimits{})
	_, ep := x.person("ann")
	// A mixed answer is refused whole: the public address is not usable
	// either, so a hostile resolver cannot smuggle the private one in.
	x.dns.set("api.example.org", apiIP, netip.MustParseAddr("10.42.0.1"))
	if got := resolve(t, ep, "api.example.org"); len(got) != 0 {
		t.Fatalf("mixed answer: %v", got)
	}
	_, err := dialRaw(t, ep, apiIP, 443)
	wantErrno(t, err, syscall.ECONNREFUSED)
	// The name later answers a private address: not pinned, refused.
	x.dns.set("api.example.org", apiIP)
	resolve(t, ep, "api.example.org")
	x.dns.set("api.example.org", netip.MustParseAddr("169.254.169.254"))
	if got := resolve(t, ep, "api.example.org"); len(got) != 0 {
		t.Fatalf("rebound answer: %v", got)
	}
	_, err = dialRaw(t, ep, netip.MustParseAddr("169.254.169.254"), 443)
	wantErrno(t, err, syscall.ECONNREFUSED)
	if x.dialed.Load() != 0 {
		t.Fatal("dialled a refused address")
	}
}

func TestEgressNotAllowlisted(t *testing.T) {
	x := newEgEnv(t, relay.EgressLimits{})
	_, ep := x.person("ann")
	x.dns.set("not-listed.example.org", netip.MustParseAddr("93.184.216.50"))
	if got := resolve(t, ep, "not-listed.example.org"); len(got) != 0 {
		t.Fatalf("resolved: %v", got)
	}
	// Never resolved through the gateway, though the host exists: refused.
	_, err := dialRaw(t, ep, netip.MustParseAddr("93.184.216.50"), 443)
	wantErrno(t, err, syscall.ECONNREFUSED)
	// An IP literal resolves to itself and is no way in.
	if got := resolve(t, ep, "93.184.216.50"); len(got) != 1 {
		t.Fatalf("literal: %v", got)
	}
	_, err = dialRaw(t, ep, netip.MustParseAddr("93.184.216.50"), 443)
	wantErrno(t, err, syscall.ECONNREFUSED)
	// A pinned address of one name with the other name in the hello.
	resolve(t, ep, "api.example.org")
	if _, err := dialTLS(t, ep, apiIP, "other.example.org"); err == nil {
		t.Fatal("cross-name hello accepted")
	}
	st := x.state().Counters
	if st.DeniedNotAllowlisted < 3 || st.DeniedTlsName != 1 || st.LastDeniedHost == "" || st.LastDeniedUnix == 0 {
		t.Fatalf("counters: %v", st)
	}
}

func TestEgressPort80Refused(t *testing.T) {
	x := newEgEnv(t, relay.EgressLimits{})
	_, ep := x.person("ann")
	resolve(t, ep, "api.example.org")
	for _, port := range []uint16{80, 8443, 22, 444} {
		_, err := dialRaw(t, ep, apiIP, port)
		wantErrno(t, err, syscall.ECONNREFUSED)
	}
	if x.dialed.Load() != 0 {
		t.Fatal("dialled a refused port")
	}
}

type chunkConn struct {
	net.Conn
	n int
}

func (c chunkConn) Write(p []byte) (int, error) {
	for off := 0; off < len(p); off += c.n {
		end := min(off+c.n, len(p))
		if _, err := c.Conn.Write(p[off:end]); err != nil {
			return off, err
		}
	}
	return len(p), nil
}

func TestEgressSNI(t *testing.T) {
	x := newEgEnv(t, relay.EgressLimits{ConnectsPerSecond: 1e6})
	_, ep := x.person("ann")
	resolve(t, ep, "api.example.org")
	refused := func(name string, f func() error) {
		t.Helper()
		before := x.state().Counters.DeniedTlsName
		if err := f(); err == nil {
			t.Fatalf("%s: accepted", name)
		}
		eventually(t, name+": counted", func() bool { return x.state().Counters.DeniedTlsName == before+1 })
	}
	refused("mismatch", func() error { _, err := dialTLS(t, ep, apiIP, "evil.example.org"); return err })
	refused("missing", func() error { _, err := dialTLS(t, ep, apiIP, ""); return err })
	refused("not TLS", func() error {
		c, err := dialRaw(t, ep, apiIP, 443)
		if err != nil {
			t.Fatal(err)
		}
		defer c.Close()
		c.Write([]byte("GET / HTTP/1.1\r\nHost: api.example.org\r\n\r\n"))
		c.SetReadDeadline(time.Now().Add(5 * time.Second))
		_, err = c.Read(make([]byte, 1))
		return err
	})
	refused("oversize record", func() error {
		c, err := dialRaw(t, ep, apiIP, 443)
		if err != nil {
			t.Fatal(err)
		}
		defer c.Close()
		c.Write([]byte{0x16, 3, 1, 0x40, 0x01, 1, 0, 0, 0})
		c.SetReadDeadline(time.Now().Add(5 * time.Second))
		_, err = c.Read(make([]byte, 1))
		return err
	})
	refused("a lie about the length", func() error {
		c, err := dialRaw(t, ep, apiIP, 443)
		if err != nil {
			t.Fatal(err)
		}
		defer c.Close()
		c.Write([]byte{0x16, 3, 1, 0, 9, 1, 0, 0xff, 0xff, 0, 0, 0, 0, 0})
		c.SetReadDeadline(time.Now().Add(5 * time.Second))
		_, err = c.Read(make([]byte, 1))
		return err
	})
	// Nothing of any refused hello reached the outside server.
	eventually(t, "outside sockets closed", func() bool { return len(x.closed) >= 5 })
	if got := x.rawIn.Load(); got != 0 {
		t.Fatalf("the outside server received %d bytes from refused streams", got)
	}
}

func TestEgressSplitHelloIsReassembled(t *testing.T) {
	// A ClientHello split across TCP segments (not across TLS records) is
	// buffered up to one record and judged whole.
	x := newEgEnv(t, relay.EgressLimits{})
	_, ep := x.person("ann")
	resolve(t, ep, "api.example.org")
	c, err := dialRaw(t, ep, apiIP, 443)
	if err != nil {
		t.Fatal(err)
	}
	tc := tls.Client(chunkConn{c, 7}, &tls.Config{ServerName: "api.example.org", InsecureSkipVerify: true})
	if err := tc.Handshake(); err != nil {
		t.Fatal(err)
	}
	echo(t, tc, "split")
}

func TestEgressUDPDropped(t *testing.T) {
	x := newEgEnv(t, relay.EgressLimits{})
	_, ep := x.person("ann")
	pc, err := ep.ListenPacket(ctx(t), "udp", 0)
	if err != nil {
		t.Fatal(err)
	}
	defer pc.Close()
	for i := 0; i < 3; i++ {
		pc.WriteTo([]byte("quic"), net.UDPAddrFromAddrPort(netip.AddrPortFrom(apiIP, 443)))
	}
	eventually(t, "udp counted", func() bool { return x.state().Counters.DroppedUdp == 3 })
}

func TestEgressLimitStreamsPerSession(t *testing.T) {
	x := newEgEnv(t, relay.EgressLimits{StreamsPerSession: 2})
	_, ep := x.person("ann")
	resolve(t, ep, "api.example.org")
	a, err := dialTLS(t, ep, apiIP, "api.example.org")
	if err != nil {
		t.Fatal(err)
	}
	if _, err := dialTLS(t, ep, apiIP, "api.example.org"); err != nil {
		t.Fatal(err)
	}
	_, err = dialRaw(t, ep, apiIP, 443)
	wantErrno(t, err, syscall.ENOBUFS)
	if x.state().Counters.DeniedLimit != 1 {
		t.Fatalf("counters: %v", x.state().Counters)
	}
	// The slot comes back when a stream ends.
	a.Close()
	eventually(t, "slot released", func() bool {
		c, err := dialRaw(t, ep, apiIP, 443)
		if err == nil {
			c.Close()
		}
		return err == nil
	})
}

func TestEgressLimitConnectRate(t *testing.T) {
	x := newEgEnv(t, relay.EgressLimits{ConnectsPerSecond: 0.001, ConnectBurst: 2})
	_, ep := x.person("ann")
	// Refused attempts count too: a scan is stopped before it learns much.
	for i := 0; i < 2; i++ {
		_, err := dialRaw(t, ep, apiIP, 443)
		wantErrno(t, err, syscall.ECONNREFUSED)
	}
	_, err := dialRaw(t, ep, apiIP, 443)
	wantErrno(t, err, syscall.ENOBUFS)
}

func TestEgressLimitLookups(t *testing.T) {
	x := newEgEnv(t, relay.EgressLimits{LookupsPerSecond: 1})
	_, ep := x.person("ann")
	if got := resolve(t, ep, "api.example.org"); len(got) != 1 {
		t.Fatalf("first lookup: %v", got)
	}
	if got := resolve(t, ep, "api.example.org"); len(got) != 0 {
		t.Fatalf("second lookup in the same second: %v", got)
	}
	if x.state().Counters.DeniedLimit != 1 {
		t.Fatalf("counters: %v", x.state().Counters)
	}
}

func TestEgressLimitPerDestination(t *testing.T) {
	x := newEgEnv(t, relay.EgressLimits{StreamsPerDestination: 1})
	_, a := x.person("ann")
	_, b := x.person("bob")
	resolve(t, a, "api.example.org")
	resolve(t, b, "api.example.org")
	if _, err := dialTLS(t, a, apiIP, "api.example.org"); err != nil {
		t.Fatal(err)
	}
	_, err := dialRaw(t, b, apiIP, 443)
	wantErrno(t, err, syscall.ENOBUFS)
	// Another destination is not affected.
	resolve(t, b, "other.example.org")
	if _, err := dialTLS(t, b, otherIP, "other.example.org"); err != nil {
		t.Fatal(err)
	}
}

func TestEgressLimitBytesPerDay(t *testing.T) {
	x := newEgEnv(t, relay.EgressLimits{SessionBytesPerDay: 6000})
	_, ep := x.person("ann")
	resolve(t, ep, "api.example.org")
	c, err := dialTLS(t, ep, apiIP, "api.example.org")
	if err != nil {
		t.Fatal(err)
	}
	c.SetDeadline(time.Now().Add(5 * time.Second))
	chunk := make([]byte, 1000)
	var failed bool
	for i := 0; i < 40 && !failed; i++ {
		if _, err := c.Write(chunk); err != nil {
			failed = true
			break
		}
		if _, err := io.ReadFull(c, chunk); err != nil {
			failed = true
		}
	}
	if !failed {
		t.Fatal("40 kB went through a 6 kB day")
	}
	_, err = dialRaw(t, ep, apiIP, 443)
	wantErrno(t, err, syscall.ENOBUFS)
	// Another session has its own day.
	_, other := x.person("bob")
	resolve(t, other, "api.example.org")
	if _, err := dialTLS(t, other, apiIP, "api.example.org"); err != nil {
		t.Fatal(err)
	}
}

func readFails(c net.Conn) bool {
	c.SetReadDeadline(time.Now().Add(5 * time.Second))
	_, err := c.Read(make([]byte, 1))
	var ne net.Error
	return err != nil && !(errors.As(err, &ne) && ne.Timeout())
}

func TestEgressIdleLifetimeHelloTimeouts(t *testing.T) {
	x := newEgEnv(t, relay.EgressLimits{Idle: 200 * time.Millisecond, Lifetime: time.Hour, HelloTimeout: 150 * time.Millisecond})
	_, ep := x.person("ann")
	resolve(t, ep, "api.example.org")
	// No ClientHello in time.
	raw, err := dialRaw(t, ep, apiIP, 443)
	if err != nil {
		t.Fatal(err)
	}
	if !readFails(raw) {
		t.Fatal("a stream with no hello stayed open")
	}
	// Idle after a good hello.
	c, err := dialTLS(t, ep, apiIP, "api.example.org")
	if err != nil {
		t.Fatal(err)
	}
	if !readFails(c) {
		t.Fatal("an idle stream stayed open")
	}
	y := newEgEnv(t, relay.EgressLimits{Idle: time.Hour, Lifetime: 400 * time.Millisecond})
	_, ep = y.person("ann")
	resolve(t, ep, "api.example.org")
	c, err = dialTLS(t, ep, apiIP, "api.example.org")
	if err != nil {
		t.Fatal(err)
	}
	stop := time.Now().Add(5 * time.Second)
	for time.Now().Before(stop) {
		c.SetDeadline(time.Now().Add(time.Second))
		if _, err := c.Write([]byte("x")); err != nil {
			return
		}
		if _, err := io.ReadFull(c, make([]byte, 1)); err != nil {
			return
		}
		time.Sleep(50 * time.Millisecond)
	}
	t.Fatal("a busy stream outlived its lifetime")
}

func TestEgressKickEndsStreams(t *testing.T) {
	x := newEgEnv(t, relay.EgressLimits{})
	s, ep := x.person("ann")
	resolve(t, ep, "api.example.org")
	c, err := dialTLS(t, ep, apiIP, "api.example.org")
	if err != nil {
		t.Fatal(err)
	}
	echo(t, c, "alive")
	if err := x.r.KickSession(x.class.Id, "ann"); err != nil {
		t.Fatal(err)
	}
	select {
	case <-s.Done():
	case <-time.After(5 * time.Second):
		t.Fatal("kicked session still open")
	}
	select {
	case <-x.closed:
	case <-time.After(5 * time.Second):
		t.Fatal("the outside socket of a kicked session is still open")
	}
	eventually(t, "released", func() bool { return x.state().Counters.ActiveStreams == 0 })
}

// A kick must end every stream of the session, not only the first: one
// agent serves them all.
func TestEgressKickEndsEveryStream(t *testing.T) {
	x := newEgEnv(t, relay.EgressLimits{})
	time.Sleep(50 * time.Millisecond)
	base := runtime.NumGoroutine()
	_, ep := x.person("ann")
	resolve(t, ep, "api.example.org")
	for i := 0; i < 3; i++ {
		c, err := dialTLS(t, ep, apiIP, "api.example.org")
		if err != nil {
			t.Fatal(err)
		}
		echo(t, c, "alive")
	}
	if err := x.r.KickSession(x.class.Id, "ann"); err != nil {
		t.Fatal(err)
	}
	for i := 0; i < 3; i++ {
		select {
		case <-x.closed:
		case <-time.After(5 * time.Second):
			t.Fatalf("outside socket %d of a kicked session is still open", i)
		}
	}
	// One agent served the three streams, and it is gone: nothing of the
	// session is left running.
	eventually(t, "the session's goroutines ended", func() bool { return runtime.NumGoroutine() <= base+1 })
}

// A dial that returns after its stream was killed must not leave an open
// outside socket behind.
func TestEgressDialFinishingAfterKick(t *testing.T) {
	x := newEgEnv(t, relay.EgressLimits{})
	_, ep := x.person("ann")
	resolve(t, ep, "api.example.org")
	release := make(chan struct{})
	x.hold.Store(&release)
	done := make(chan struct{})
	go func() {
		defer close(done)
		if c, err := dialRaw(t, ep, apiIP, 443); err == nil {
			c.Close()
		}
	}()
	eventually(t, "the dial started", func() bool { return x.dialed.Load() == 1 })
	if err := x.r.KickSession(x.class.Id, "ann"); err != nil {
		t.Fatal(err)
	}
	close(release)
	select {
	case <-x.closed:
	case <-time.After(5 * time.Second):
		t.Fatal("the outside socket of a killed stream stayed open")
	}
	<-done
}

// The upload side of the day's allowance, with a server that never answers:
// the stream ends long before the 200 kB are through.
func TestEgressDayLimitOnUpload(t *testing.T) {
	x := newEgEnv(t, relay.EgressLimits{SessionBytesPerDay: 8000})
	x.mode.Store(modeSink)
	_, ep := x.person("ann")
	resolve(t, ep, "api.example.org")
	c, err := dialTLS(t, ep, apiIP, "api.example.org")
	if err != nil {
		t.Fatal(err)
	}
	c.SetDeadline(time.Now().Add(5 * time.Second))
	chunk := make([]byte, 1000)
	for i := 0; i < 200; i++ {
		if _, err := c.Write(chunk); err != nil {
			break
		}
	}
	eventually(t, "the stream was released", func() bool { return x.state().Counters.ActiveStreams == 0 })
	if got := x.rawIn.Load(); got > 30000 {
		t.Fatalf("%d bytes reached the outside through an 8 kB day", got)
	}
	if x.state().Counters.DeniedLimit == 0 {
		t.Fatal("the limit was not counted")
	}
}

// The download side: the outside floods, the guest receives about the day's
// allowance and no more.
func TestEgressDayLimitOnDownload(t *testing.T) {
	x := newEgEnv(t, relay.EgressLimits{SessionBytesPerDay: 8000})
	x.mode.Store(modeFlood)
	_, ep := x.person("ann")
	resolve(t, ep, "api.example.org")
	c, err := dialTLS(t, ep, apiIP, "api.example.org")
	if err != nil {
		t.Fatal(err)
	}
	c.SetDeadline(time.Now().Add(5 * time.Second))
	n, _ := io.Copy(io.Discard, c)
	if n >= 30000 {
		t.Fatalf("the guest received %d bytes through an 8 kB day", n)
	}
	eventually(t, "the limit was counted", func() bool { return x.state().Counters.DeniedLimit > 0 })
}

func TestEgressStateUnknownClass(t *testing.T) {
	x := newEgEnv(t, relay.EgressLimits{})
	if _, err := x.r.EgressState("no-such-class"); relay.ErrKind(err) != relay.KindNotFound {
		t.Fatalf("got %v", err)
	}
}

func TestEgressRotationEndsStreamsAndForgetsPins(t *testing.T) {
	x := newEgEnv(t, relay.EgressLimits{})
	_, ep := x.person("ann")
	resolve(t, ep, "api.example.org")
	c, err := dialTLS(t, ep, apiIP, "api.example.org")
	if err != nil {
		t.Fatal(err)
	}
	echo(t, c, "alive")
	if _, err := x.r.RotateJoinCode(x.class.Id); err != nil {
		t.Fatal(err)
	}
	if !readFails(c) {
		t.Fatal("the stream survived the rotation")
	}
	select {
	case <-x.closed:
	case <-time.After(5 * time.Second):
		t.Fatal("the outside socket survived the rotation")
	}
	// The session lives, but its pins are gone until it resolves again.
	_, err = dialRaw(t, ep, apiIP, 443)
	wantErrno(t, err, syscall.ECONNREFUSED)
	resolve(t, ep, "api.example.org")
	c, err = dialTLS(t, ep, apiIP, "api.example.org")
	if err != nil {
		t.Fatal(err)
	}
	echo(t, c, "again")
}

func TestEgressDeleteClassStopsAgents(t *testing.T) {
	x := newEgEnv(t, relay.EgressLimits{})
	_, ep := x.person("ann")
	resolve(t, ep, "api.example.org")
	if _, err := dialTLS(t, ep, apiIP, "api.example.org"); err != nil {
		t.Fatal(err)
	}
	if err := x.r.DeleteClass(x.class.Id); err != nil {
		t.Fatal(err)
	}
	select {
	case <-x.closed:
	case <-time.After(5 * time.Second):
		t.Fatal("the outside socket of a deleted class is still open")
	}
}

func TestEgressBackpressureAndBounds(t *testing.T) {
	// Many sessions hammering the gateway stay inside the bounds: refusals
	// by limit, no growth of what the relay holds. Run under GOMEMLIMIT and
	// ulimit -v by the make target.
	x := newEgEnv(t, relay.EgressLimits{StreamsPerSession: 4, ConnectsPerSecond: 1e6, ConnectBurst: 1e6, StreamsPerDestination: 20})
	const people = 8
	var wg sync.WaitGroup
	var ok, limited, other atomic.Int64
	for p := 0; p < people; p++ {
		_, ep := x.person("p" + string(rune('a'+p)))
		resolve(t, ep, "api.example.org")
		wg.Add(1)
		go func() {
			defer wg.Done()
			var held []net.Conn
			for i := 0; i < 30; i++ {
				c, err := dialRaw(t, ep, apiIP, 443)
				switch {
				case err == nil:
					ok.Add(1)
					held = append(held, c)
				case errors.Is(err, syscall.ENOBUFS):
					limited.Add(1)
				default:
					other.Add(1)
				}
			}
			for _, c := range held {
				c.Close()
			}
		}()
	}
	wg.Wait()
	if other.Load() != 0 || limited.Load() == 0 {
		t.Fatalf("ok %d limited %d other %d", ok.Load(), limited.Load(), other.Load())
	}
	// Per session 4 streams at a time, per class 20 to one destination.
	if ok.Load() > people*4+20 {
		t.Fatalf("%d streams opened, bounds are %d", ok.Load(), people*4)
	}
	eventually(t, "everything released", func() bool { return x.state().Counters.ActiveStreams == 0 })
}
