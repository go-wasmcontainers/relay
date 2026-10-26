// SPDX-License-Identifier: BSD-3-Clause

package relay_test

import (
	"bytes"
	"context"
	"errors"
	"io"
	"net"
	"net/netip"
	"strings"
	"sync"
	"syscall"
	"testing"
	"time"

	"github.com/go-wasmcontainers/relay/auth"
	"github.com/go-wasmcontainers/relay/driver"
	"github.com/go-wasmcontainers/relay/firewall"
	v1 "github.com/go-wasmcontainers/relay/gen/relayv1"
	"github.com/go-wasmcontainers/relay/relay"
)

type env struct {
	t     *testing.T
	r     *relay.Relay
	class *v1.Class
	mu    sync.Mutex
	audit []string
}

func newEnv(t *testing.T, tmpl v1.Template, lim relay.Limits) *env {
	t.Helper()
	k, err := auth.NewKeys()
	if err != nil {
		t.Fatal(err)
	}
	e := &env{t: t}
	e.r, err = relay.New(relay.Config{Keys: k, Limits: lim, Audit: func(ev string, _ map[string]string) {
		e.mu.Lock()
		e.audit = append(e.audit, ev)
		e.mu.Unlock()
	}})
	if err != nil {
		t.Fatal(err)
	}
	e.class, err = e.r.CreateClass(relay.ClassSpec{Name: "net101", Template: tmpl})
	if err != nil {
		t.Fatal(err)
	}
	return e
}

// student joins with the class code and connects a session over a pipe.
func (e *env) student(name string) *driver.Session {
	e.t.Helper()
	j, err := e.r.Join(e.class.JoinCode, name, nil)
	if err != nil {
		e.t.Fatal(err)
	}
	return e.connect(j.Token)
}

func (e *env) connect(token string) *driver.Session {
	e.t.Helper()
	cl, err := e.r.Authenticate(token)
	if err != nil {
		e.t.Fatal(err)
	}
	a, b := relay.Pipe()
	go e.r.Serve(context.Background(), b, cl)
	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()
	s, err := driver.Dial(ctx, a)
	if err != nil {
		e.t.Fatal(err)
	}
	e.t.Cleanup(func() { s.Close() })
	return s
}

func ctx(t *testing.T) context.Context {
	c, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	t.Cleanup(cancel)
	return c
}

func attach(t *testing.T, s *driver.Session, name string) *driver.Endpoint {
	t.Helper()
	ep, err := s.Attach(ctx(t), name)
	if err != nil {
		t.Fatal(err)
	}
	return ep
}

func (e *env) defaultSG() string {
	gs, err := e.r.ListSecurityGroups(e.class.Id)
	if err != nil {
		e.t.Fatal(err)
	}
	for _, g := range gs {
		if g.Name == "default" {
			return g.Id
		}
	}
	e.t.Fatal("no default group")
	return ""
}

func (e *env) rule(group string, dir v1.Direction, p v1.Protocol, port uint32) *v1.SecurityGroupRule {
	e.t.Helper()
	r, err := e.r.CreateRule(e.class.Id, group, &v1.SecurityGroupRule{Direction: dir, Protocol: p, PortRangeMin: port, PortRangeMax: port})
	if err != nil {
		e.t.Fatal(err)
	}
	return r
}

// echoServer accepts and echoes until the listener closes.
func echoServer(l net.Listener) {
	for {
		c, err := l.Accept()
		if err != nil {
			return
		}
		go func() {
			defer c.Close()
			io.Copy(c, c)
		}()
	}
}

func TestAddressesAndDNS(t *testing.T) {
	e := newEnv(t, v1.Template_TEMPLATE_ISOLATED, relay.Limits{})
	alice := e.student("Alice")
	bob := e.student("Bob")
	web := attach(t, alice, "web")
	curl := attach(t, bob, "curl")
	if web.Addr() != netip.MustParseAddr("10.42.1.2") || curl.Addr() != netip.MustParseAddr("10.42.2.2") {
		t.Fatalf("addresses %v %v", web.Addr(), curl.Addr())
	}
	if web.Port().DnsName != "web.alice.class" {
		t.Fatal(web.Port().DnsName)
	}
	// Attaching the same container again gives the same port.
	again := attach(t, alice, "web")
	if again.Port().Id != web.Port().Id {
		t.Fatal("re-attach gave a new port")
	}
	for name, want := range map[string]string{"web.alice.class": "10.42.1.2", "web.alice": "10.42.1.2", "curl": "10.42.2.2"} {
		got, err := curl.Resolve(ctx(t), name)
		if err != nil || len(got) != 1 || got[0].String() != want {
			t.Errorf("%s: %v %v", name, got, err)
		}
	}
	if _, err := curl.Resolve(ctx(t), "web"); err == nil {
		t.Error("bob's bare 'web' resolved to alice's container")
	}
}

func TestIsolatedDeniesThenRuleAllows(t *testing.T) {
	e := newEnv(t, v1.Template_TEMPLATE_ISOLATED, relay.Limits{})
	alice, bob := e.student("Alice"), e.student("Bob")
	web, curl := attach(t, alice, "web"), attach(t, bob, "curl")
	l, err := web.Listen(ctx(t), "tcp", 80)
	if err != nil {
		t.Fatal(err)
	}
	go echoServer(l)
	dst := netip.AddrPortFrom(web.Addr(), 80)

	_, err = curl.Dial(ctx(t), "tcp", dst)
	if !errors.Is(err, syscall.ECONNREFUSED) {
		t.Fatalf("isolated class: %v, want ECONNREFUSED", err)
	}
	sg := e.defaultSG()
	// Ingress alone is not enough: bob's egress goes to the teacher only.
	e.rule(sg, v1.Direction_DIRECTION_INGRESS, v1.Protocol_PROTOCOL_TCP, 80)
	if _, err := curl.Dial(ctx(t), "tcp", dst); !errors.Is(err, syscall.ECONNREFUSED) {
		t.Fatalf("egress not allowed yet: %v", err)
	}
	e.rule(sg, v1.Direction_DIRECTION_EGRESS, v1.Protocol_PROTOCOL_TCP, 80)
	c, err := curl.Dial(ctx(t), "tcp", dst)
	if err != nil {
		t.Fatal(err)
	}
	msg := bytes.Repeat([]byte("hello relay "), 20000) // 240 kB: past several windows
	go c.Write(msg)
	got := make([]byte, len(msg))
	if _, err := io.ReadFull(c, got); err != nil || !bytes.Equal(got, msg) {
		t.Fatalf("echo: %v", err)
	}
	// The listener saw the relay-assigned source address, not anything bob chose.
	if ra := c.LocalAddr().(*net.TCPAddr); ra.IP.String() != "10.42.2.2" || ra.Port < 49152 {
		t.Fatalf("source %v", ra)
	}
	c.Close()
}

func TestRuleRemovalResetsFlow(t *testing.T) {
	e := newEnv(t, v1.Template_TEMPLATE_ISOLATED, relay.Limits{})
	alice, bob := e.student("Alice"), e.student("Bob")
	web, curl := attach(t, alice, "web"), attach(t, bob, "curl")
	l, _ := web.Listen(ctx(t), "tcp", 80)
	go echoServer(l)
	sg := e.defaultSG()
	in := e.rule(sg, v1.Direction_DIRECTION_INGRESS, v1.Protocol_PROTOCOL_TCP, 80)
	e.rule(sg, v1.Direction_DIRECTION_EGRESS, v1.Protocol_PROTOCOL_TCP, 80)
	c, err := curl.Dial(ctx(t), "tcp", netip.AddrPortFrom(web.Addr(), 80))
	if err != nil {
		t.Fatal(err)
	}
	c.Write([]byte("x"))
	b := make([]byte, 1)
	if _, err := io.ReadFull(c, b); err != nil {
		t.Fatal(err)
	}
	var events []*v1.FlowEvent
	var mu sync.Mutex
	wctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	go e.r.WatchFlows(wctx, e.class.Id, "", false, 0, func(ev *v1.FlowEvent) error {
		mu.Lock()
		events = append(events, ev)
		mu.Unlock()
		return nil
	})
	time.Sleep(20 * time.Millisecond)
	if err := e.r.DeleteRule(e.class.Id, in.Id); err != nil {
		t.Fatal(err)
	}
	c.SetReadDeadline(time.Now().Add(5 * time.Second))
	_, err = c.Read(b)
	if !errors.Is(err, syscall.ECONNRESET) {
		t.Fatalf("after the rule went: %v, want ECONNRESET", err)
	}
	time.Sleep(20 * time.Millisecond)
	mu.Lock()
	defer mu.Unlock()
	found := false
	for _, ev := range events {
		if ev.Verdict == v1.Verdict_VERDICT_REVOKED && strings.Contains(ev.Reason, "revoked") {
			found = true
		}
	}
	if !found {
		t.Fatalf("no REVOKED event in %v", events)
	}
}

func TestUDPConntrack(t *testing.T) {
	e := newEnv(t, v1.Template_TEMPLATE_ISOLATED, relay.Limits{})
	alice, bob := e.student("Alice"), e.student("Bob")
	dns, client := attach(t, alice, "dns"), attach(t, bob, "client")
	srv, err := dns.ListenPacket(ctx(t), "udp", 53)
	if err != nil {
		t.Fatal(err)
	}
	sg := e.defaultSG()
	e.rule(sg, v1.Direction_DIRECTION_INGRESS, v1.Protocol_PROTOCOL_UDP, 53)
	e.rule(sg, v1.Direction_DIRECTION_EGRESS, v1.Protocol_PROTOCOL_UDP, 53)
	// No rule allows the reply (from port 53 to bob's ephemeral port, ingress
	// at bob): connection tracking must.
	go func() {
		buf := make([]byte, 100)
		for {
			n, from, err := srv.ReadFrom(buf)
			if err != nil {
				return
			}
			srv.WriteTo(append([]byte("re:"), buf[:n]...), from)
		}
	}()
	c, err := client.Dial(ctx(t), "udp", netip.AddrPortFrom(dns.Addr(), 53))
	if err != nil {
		t.Fatal(err)
	}
	c.SetReadDeadline(time.Now().Add(5 * time.Second))
	c.Write([]byte("q1"))
	buf := make([]byte, 100)
	n, err := c.Read(buf)
	if err != nil || string(buf[:n]) != "re:q1" {
		t.Fatalf("reply: %q %v", buf[:n], err)
	}
	// An unsolicited datagram from alice to bob's port is still refused.
	other, _ := dns.ListenPacket(ctx(t), "udp", 5353)
	cl := c.LocalAddr().(*net.UDPAddr)
	_ = cl
	other.WriteTo([]byte("spam"), &net.UDPAddr{IP: net.ParseIP("10.42.2.2"), Port: 49152})
	c.SetReadDeadline(time.Now().Add(200 * time.Millisecond))
	if n, err := c.Read(buf); err == nil {
		t.Fatalf("unsolicited datagram delivered: %q", buf[:n])
	}
}

func TestStatelessNeedsBothDirections(t *testing.T) {
	e := newEnv(t, v1.Template_TEMPLATE_ISOLATED, relay.Limits{})
	sl, err := e.r.CreateSecurityGroup(e.class.Id, "sl", "", true)
	if err != nil {
		t.Fatal(err)
	}
	alice, bob := e.student("Alice"), e.student("Bob")
	web, curl := attach(t, alice, "web"), attach(t, bob, "curl")
	for _, p := range []*v1.Port{web.Port(), curl.Port()} {
		if _, err := e.r.UpdatePort(e.class.Id, p.Id, []string{"sl"}, true, nil); err != nil {
			t.Fatal(err)
		}
	}
	l, _ := web.Listen(ctx(t), "tcp", 80)
	go echoServer(l)
	e.rule(sl.Id, v1.Direction_DIRECTION_INGRESS, v1.Protocol_PROTOCOL_TCP, 80)
	e.rule(sl.Id, v1.Direction_DIRECTION_EGRESS, v1.Protocol_PROTOCOL_TCP, 80)
	dst := netip.AddrPortFrom(web.Addr(), 80)
	if _, err := curl.Dial(ctx(t), "tcp", dst); !errors.Is(err, syscall.ECONNREFUSED) {
		t.Fatalf("stateless without return rules: %v", err)
	}
	if _, err := e.r.CreateRule(e.class.Id, "sl", &v1.SecurityGroupRule{Direction: v1.Direction_DIRECTION_EGRESS, Protocol: v1.Protocol_PROTOCOL_TCP}); err != nil {
		t.Fatal(err)
	}
	if _, err := e.r.CreateRule(e.class.Id, "sl", &v1.SecurityGroupRule{Direction: v1.Direction_DIRECTION_INGRESS, Protocol: v1.Protocol_PROTOCOL_TCP}); err != nil {
		t.Fatal(err)
	}
	c, err := curl.Dial(ctx(t), "tcp", dst)
	if err != nil {
		t.Fatalf("both directions allowed: %v", err)
	}
	c.Close()
}

func TestNeutronDefaultTemplate(t *testing.T) {
	e := newEnv(t, v1.Template_TEMPLATE_NEUTRON_DEFAULT, relay.Limits{})
	alice, bob := e.student("Alice"), e.student("Bob")
	web, curl := attach(t, alice, "web"), attach(t, bob, "curl")
	l, _ := web.Listen(ctx(t), "tcp", 8080)
	go echoServer(l)
	c, err := curl.Dial(ctx(t), "tcp", netip.AddrPortFrom(web.Addr(), 8080))
	if err != nil {
		t.Fatalf("same default group: %v", err)
	}
	c.Close()
	ex, err := e.r.ExplainFlow(e.class.Id, "bob/curl", "alice/web", firewall.TCP, 8080)
	if err != nil || ex.Verdict != v1.Verdict_VERDICT_ALLOW || ex.IngressRuleId == "" {
		t.Fatalf("explain: %v %v", ex, err)
	}
}

func TestTeacherSession(t *testing.T) {
	e := newEnv(t, v1.Template_TEMPLATE_ISOLATED, relay.Limits{})
	j, err := e.r.TeacherSession(e.class.Id)
	if err != nil {
		t.Fatal(err)
	}
	teacher := e.connect(j.Token)
	srv := attach(t, teacher, "shared")
	if srv.Addr() != netip.MustParseAddr("10.42.0.2") || srv.Port().DnsName != "shared.teacher.class" {
		t.Fatal(srv.Addr(), srv.Port().DnsName)
	}
	l, _ := srv.Listen(ctx(t), "tcp", 443)
	go echoServer(l)
	// Isolated: students may reach the teacher's subnet once the teacher's
	// port has an ingress rule.
	sg, _ := e.r.CreateSecurityGroup(e.class.Id, "public", "", false)
	e.rule(sg.Id, v1.Direction_DIRECTION_INGRESS, v1.Protocol_PROTOCOL_TCP, 443)
	if _, err := e.r.UpdatePort(e.class.Id, "teacher/shared", []string{"default", "public"}, true, nil); err != nil {
		t.Fatal(err)
	}
	bob := e.student("Bob")
	curl := attach(t, bob, "curl")
	c, err := curl.Dial(ctx(t), "tcp", netip.AddrPortFrom(srv.Addr(), 443))
	if err != nil {
		t.Fatalf("student to teacher: %v", err)
	}
	c.Close()
}

func TestSpoofing(t *testing.T) {
	e := newEnv(t, v1.Template_TEMPLATE_NEUTRON_DEFAULT, relay.Limits{})
	alice, bob := e.student("Alice"), e.student("Bob")
	web := attach(t, alice, "web")
	curl := attach(t, bob, "curl")
	// Bob forges an endpoint with alice's port id: the relay must refuse
	// every use of a port that is not his.
	forged := driver.ForgeEndpoint(bob, web.Port())
	if _, err := forged.Listen(ctx(t), "tcp", 81); err == nil {
		t.Fatal("bob listened on alice's port")
	}
	if _, err := forged.Dial(ctx(t), "tcp", netip.AddrPortFrom(curl.Addr(), 1)); err == nil {
		t.Fatal("bob dialled from alice's port")
	}
	// A datagram from a source port bob never bound is dropped.
	srv, _ := web.ListenPacket(ctx(t), "udp", 53)
	srv.SetReadDeadline(time.Now().Add(200 * time.Millisecond))
	driver.SendRaw(curl, 53, netip.AddrPortFrom(web.Addr(), 53), []byte("spoofed source port"))
	if _, _, err := srv.ReadFrom(make([]byte, 64)); err == nil {
		t.Fatal("datagram with an unbound source port delivered")
	}
}

func TestKickEndsSession(t *testing.T) {
	e := newEnv(t, v1.Template_TEMPLATE_ISOLATED, relay.Limits{})
	j, _ := e.r.Join(e.class.JoinCode, "Mallory", nil)
	s := e.connect(j.Token)
	attach(t, s, "x")
	if err := e.r.KickSession(e.class.Id, "mallory"); err != nil {
		t.Fatal(err)
	}
	select {
	case <-s.Done():
	case <-time.After(5 * time.Second):
		t.Fatal("kicked session still open")
	}
	if _, err := e.r.Authenticate(j.Token); err == nil {
		t.Fatal("kicked session's token still valid")
	}
	if ports, _ := e.r.ListPorts(e.class.Id, ""); len(ports) != 0 {
		t.Fatalf("ports left: %v", ports)
	}
}

func TestQuotas(t *testing.T) {
	e := newEnv(t, v1.Template_TEMPLATE_NEUTRON_DEFAULT, relay.Limits{MaxPorts: 2, MaxListeners: 1, MaxStreams: 2})
	s := e.student("Alice")
	a := attach(t, s, "a")
	attach(t, s, "b")
	if _, err := s.Attach(ctx(t), "c"); !errors.Is(err, syscall.ENOBUFS) {
		t.Fatalf("third port: %v", err)
	}
	l, err := a.Listen(ctx(t), "tcp", 80)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := a.Listen(ctx(t), "tcp", 81); !errors.Is(err, syscall.ENOBUFS) {
		t.Fatalf("second listener: %v", err)
	}
	if _, err := a.Listen(ctx(t), "tcp", 80); err == nil {
		t.Fatal("same port twice")
	}
	go echoServer(l)
	bob := e.student("Bob")
	b := attach(t, bob, "b")
	c1, err := b.Dial(ctx(t), "tcp", netip.AddrPortFrom(a.Addr(), 80))
	if err != nil {
		t.Fatal(err)
	}
	c2, err := b.Dial(ctx(t), "tcp", netip.AddrPortFrom(a.Addr(), 80))
	if err != nil {
		t.Fatal(err)
	}
	if _, err := b.Dial(ctx(t), "tcp", netip.AddrPortFrom(a.Addr(), 80)); !errors.Is(err, syscall.ENOBUFS) {
		t.Fatalf("third stream: %v", err)
	}
	c1.Close()
	c2.Close()
}

func TestRateLimit(t *testing.T) {
	// 64 KiB/s with a 16 KiB burst: 160 KiB takes about 2.25 s.
	e := newEnv(t, v1.Template_TEMPLATE_NEUTRON_DEFAULT, relay.Limits{BytesPerSecond: 64 << 10, BurstBytes: 16 << 10})
	alice, bob := e.student("Alice"), e.student("Bob")
	sink, src := attach(t, alice, "sink"), attach(t, bob, "src")
	l, _ := sink.Listen(ctx(t), "tcp", 9)
	got := make(chan int, 1)
	go func() {
		c, err := l.Accept()
		if err != nil {
			return
		}
		n, _ := io.Copy(io.Discard, c)
		got <- int(n)
	}()
	c, err := src.Dial(ctx(t), "tcp", netip.AddrPortFrom(sink.Addr(), 9))
	if err != nil {
		t.Fatal(err)
	}
	start := time.Now()
	c.Write(make([]byte, 160<<10))
	c.Close()
	n := <-got
	el := time.Since(start)
	if n != 160<<10 {
		t.Fatalf("%d bytes", n)
	}
	if el < 1500*time.Millisecond {
		t.Fatalf("160 KiB at 64 KiB/s took %v: not limited", el)
	}
}

func TestProtocolViolationCloses(t *testing.T) {
	e := newEnv(t, v1.Template_TEMPLATE_ISOLATED, relay.Limits{})
	j, _ := e.r.Join(e.class.JoinCode, "Eve", nil)
	cl, _ := e.r.Authenticate(j.Token)
	a, b := relay.Pipe()
	done := make(chan error, 1)
	go func() { done <- e.r.Serve(context.Background(), b, cl) }()
	s, err := driver.Dial(ctx(t), a)
	if err != nil {
		t.Fatal(err)
	}
	// A message that is not a frame.
	a.WriteMessage(ctx(t), []byte{1, 2, 3})
	select {
	case <-done:
	case <-time.After(5 * time.Second):
		t.Fatal("relay kept a connection that sent garbage")
	}
	<-s.Done()
}

func TestWrongVersion(t *testing.T) {
	e := newEnv(t, v1.Template_TEMPLATE_ISOLATED, relay.Limits{})
	j, _ := e.r.Join(e.class.JoinCode, "Eve", nil)
	cl, _ := e.r.Authenticate(j.Token)
	a, b := relay.Pipe()
	go e.r.Serve(context.Background(), b, cl)
	if err := driver.HelloVersion(ctx(t), a, 2); err == nil || !strings.Contains(err.Error(), "version") {
		t.Fatalf("version 2: %v", err)
	}
}

func TestReconnectKeepsAddress(t *testing.T) {
	e := newEnv(t, v1.Template_TEMPLATE_ISOLATED, relay.Limits{})
	j, _ := e.r.Join(e.class.JoinCode, "Alice", nil)
	s1 := e.connect(j.Token)
	a1 := attach(t, s1, "web")
	s2 := e.connect(j.Token) // the browser reloads
	select {
	case <-s1.Done():
	case <-time.After(5 * time.Second):
		t.Fatal("the old connection was not replaced")
	}
	a2 := attach(t, s2, "web")
	if a1.Addr() != a2.Addr() {
		t.Fatalf("address changed on reconnect: %v -> %v", a1.Addr(), a2.Addr())
	}
}

func TestJoinAndIdentity(t *testing.T) {
	k, _ := auth.NewKeys()
	r, _ := relay.New(relay.Config{Keys: k})
	cls, err := r.CreateClass(relay.ClassSpec{Name: "x", RequireID: true, Allowed: []string{"group:students", "email:prof@example.org"}})
	if err != nil {
		t.Fatal(err)
	}
	if _, err := r.Join(cls.JoinCode, "Anon", nil); relay.ErrKind(err) != relay.KindUnauthenticated {
		t.Fatalf("no identity: %v", err)
	}
	stranger := &relay.Identity{Issuer: "https://idp", Subject: "s1"}
	if _, err := r.Join(cls.JoinCode, "Stranger", stranger); relay.ErrKind(err) != relay.KindDenied {
		t.Fatalf("not on the list: %v", err)
	}
	st := &relay.Identity{Issuer: "https://idp", Subject: "s2", Groups: []string{"students"}}
	j1, err := r.Join(cls.JoinCode, "Stu", st)
	if err != nil {
		t.Fatal(err)
	}
	j2, err := r.Join(strings.ToLower(cls.JoinCode), "Stu again", st)
	if err != nil || j2.Session.Id != j1.Session.Id {
		t.Fatalf("one identity got two sessions: %v %v", j2, err)
	}
	if _, err := r.Join("0000000000", "X", st); relay.ErrKind(err) != relay.KindDenied {
		t.Fatalf("wrong code: %v", err)
	}
	// Refresh needs the same identity.
	if _, err := r.Refresh(j1.Token, stranger); err == nil {
		t.Fatal("refresh with another identity")
	}
	if _, err := r.Refresh(j1.Token, st); err != nil {
		t.Fatal(err)
	}
	// Rotating the code stops new joins only.
	if _, err := r.RotateJoinCode(cls.Id); err != nil {
		t.Fatal(err)
	}
	if _, err := r.Join(cls.JoinCode, "Late", st); err == nil {
		t.Fatal("old code still admits")
	}
	if _, err := r.Authenticate(j1.Token); err != nil {
		t.Fatal("rotation ended an existing session")
	}
}

func TestPersistence(t *testing.T) {
	k, _ := auth.NewKeys()
	store := relay.FileStore{Path: t.TempDir() + "/state.json"}
	r1, err := relay.New(relay.Config{Keys: k, Store: store})
	if err != nil {
		t.Fatal(err)
	}
	cls, _ := r1.CreateClass(relay.ClassSpec{Name: "p"})
	j, _ := r1.Join(cls.JoinCode, "Alice", nil)
	sg, _ := r1.CreateSecurityGroup(cls.Id, "web", "", false)
	r1.CreateRule(cls.Id, "web", &v1.SecurityGroupRule{Direction: v1.Direction_DIRECTION_INGRESS, Protocol: v1.Protocol_PROTOCOL_TCP, PortRangeMin: 80})
	// Restart.
	r2, err := relay.New(relay.Config{Keys: k, Store: store})
	if err != nil {
		t.Fatal(err)
	}
	if _, err := r2.Authenticate(j.Token); err != nil {
		t.Fatalf("token after restart: %v", err)
	}
	gs, _ := r2.ListSecurityGroups(cls.Id)
	var found bool
	for _, g := range gs {
		if g.Id == sg.Id && len(g.Rules) == 1 && g.Rules[0].PortRangeMax == 80 {
			found = true
		}
	}
	if !found {
		t.Fatalf("groups after restart: %v", gs)
	}
	if _, err := r2.Join(cls.JoinCode, "Bob", nil); err != nil {
		t.Fatalf("join code after restart: %v", err)
	}
}

func TestValidation(t *testing.T) {
	k, _ := auth.NewKeys()
	r, _ := relay.New(relay.Config{Keys: k, MaxGroups: 2, MaxRules: 2})
	for _, spec := range []relay.ClassSpec{{Name: ""}, {Name: "x", CIDR: "10.42.0.1/16"}, {Name: "x", CIDR: "fc00::/7"},
		{Name: "x", SessionBits: 16}, {Name: "x", DNSDomain: "Bad_Domain"}, {Name: "x", Allowed: []string{"uid:x"}}} {
		if _, err := r.CreateClass(spec); err == nil {
			t.Errorf("%+v accepted", spec)
		}
	}
	cls, _ := r.CreateClass(relay.ClassSpec{Name: "x", CIDR: "192.168.50.0/24", SessionBits: 28})
	if cls.Network.Cidr != "192.168.50.0/24" {
		t.Fatal(cls.Network)
	}
	if _, err := r.CreateSecurityGroup(cls.Id, "Bad Name", "", false); err == nil {
		t.Error("bad group name")
	}
	if _, err := r.CreateSecurityGroup(cls.Id, "g2", "", false); err != nil {
		t.Fatal(err)
	}
	if _, err := r.CreateSecurityGroup(cls.Id, "g3", "", false); relay.ErrKind(err) != relay.KindLimit {
		t.Errorf("group quota: %v", err)
	}
	// The isolated default has 1 rule; the quota is 2.
	if _, err := r.CreateRule(cls.Id, "g2", &v1.SecurityGroupRule{Direction: v1.Direction_DIRECTION_INGRESS}); err != nil {
		t.Fatal(err)
	}
	if _, err := r.CreateRule(cls.Id, "g2", &v1.SecurityGroupRule{Direction: v1.Direction_DIRECTION_EGRESS}); relay.ErrKind(err) != relay.KindLimit {
		t.Errorf("rule quota: %v", err)
	}
	if err := r.DeleteSecurityGroup(cls.Id, "default"); err == nil {
		t.Error("deleted the default group")
	}
	for _, bad := range []*v1.SecurityGroupRule{
		{Direction: 0},
		{Direction: v1.Direction_DIRECTION_INGRESS, Protocol: v1.Protocol_PROTOCOL_TCP, PortRangeMin: 9, PortRangeMax: 8},
		{Direction: v1.Direction_DIRECTION_INGRESS, Ethertype: "IPv6"},
		{Direction: v1.Direction_DIRECTION_INGRESS, Remote: &v1.SecurityGroupRule_RemoteGroupId{RemoteGroupId: "nope"}},
		{Direction: v1.Direction_DIRECTION_INGRESS, Remote: &v1.SecurityGroupRule_RemoteIpPrefix{RemoteIpPrefix: "x"}},
	} {
		if _, err := r.CreateRule(cls.Id, "default", bad); err == nil {
			t.Errorf("rule %v accepted", bad)
		}
	}
}
