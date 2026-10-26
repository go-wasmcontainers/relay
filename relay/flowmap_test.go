// SPDX-License-Identifier: BSD-3-Clause

package relay_test

import (
	"context"
	"errors"
	"io"
	"net/netip"
	"strings"
	"syscall"
	"testing"
	"time"

	v1 "github.com/go-wasmcontainers/relay/gen/relayv1"
	"github.com/go-wasmcontainers/relay/relay"
)

func findEdge(u *v1.FlowMapUpdate, port uint32) *v1.MapEdge {
	for _, e := range u.Edges {
		if e.Port == port {
			return e
		}
	}
	return nil
}

func TestFlowMap(t *testing.T) {
	e := newEnv(t, v1.Template_TEMPLATE_ISOLATED, relay.Limits{})
	alice, bob, carol := e.student("Alice"), e.student("Bob"), e.student("Carol")
	web, curl := attach(t, alice, "web"), attach(t, bob, "curl")
	other := attach(t, carol, "x")
	l, _ := web.Listen(ctx(t), "tcp", 80)
	go echoServer(l)
	sg := e.defaultSG()
	e.rule(sg, v1.Direction_DIRECTION_INGRESS, v1.Protocol_PROTOCOL_TCP, 80)
	e.rule(sg, v1.Direction_DIRECTION_EGRESS, v1.Protocol_PROTOCOL_TCP, 80)

	w, err := e.r.WatchMap(e.class.Id, "")
	if err != nil {
		t.Fatal(err)
	}
	defer w.Close()
	first, err := w.Next(context.Background())
	if err != nil {
		t.Fatal(err)
	}
	if len(first.Clusters) != 3 || len(first.Nodes) != 3 || len(first.Edges) != 0 {
		t.Fatalf("empty class map: %d clusters %d nodes %d edges", len(first.Clusters), len(first.Nodes), len(first.Edges))
	}

	c, err := curl.Dial(ctx(t), "tcp", netip.AddrPortFrom(web.Addr(), 80))
	if err != nil {
		t.Fatal(err)
	}
	c.Write(make([]byte, 5000))
	io.ReadFull(c, make([]byte, 5000))
	// A refused flow: carol to alice on 22.
	if _, err := other.Dial(ctx(t), "tcp", netip.AddrPortFrom(web.Addr(), 22)); !errors.Is(err, syscall.ECONNREFUSED) {
		t.Fatal(err)
	}
	time.Sleep(10 * time.Millisecond)
	u, _ := w.Next(context.Background())
	web80 := findEdge(u, 80)
	if web80 == nil || web80.Open != 1 || web80.Opened != 1 || web80.Bytes < 10000 || web80.EgressRuleId == "" {
		t.Fatalf("live edge: %+v", web80)
	}
	if web80.BytesPerSecond <= 0 {
		t.Fatalf("no rate on a live edge: %+v", web80)
	}
	ssh := findEdge(u, 22)
	if ssh == nil || ssh.Denied != 1 || !ssh.DeniedRecently || !strings.Contains(ssh.LastReason, "no egress rule") {
		t.Fatalf("denied edge: %+v", ssh)
	}
	if len(u.Events) < 2 {
		t.Fatalf("events: %v", u.Events)
	}
	c.Close()
	time.Sleep(20 * time.Millisecond)
	u, _ = w.Next(context.Background())
	if e := findEdge(u, 80); e == nil || e.Open != 0 || e.Bytes < 10000 {
		t.Fatalf("closed edge keeps its bytes: %+v", e)
	}

	// A student's view: their own flows and the peers they reach only.
	sw, err := e.r.WatchMap(e.class.Id, bob.Welcome().Session.Id)
	if err != nil {
		t.Fatal(err)
	}
	defer sw.Close()
	su, _ := sw.Next(context.Background())
	if findEdge(su, 22) != nil {
		t.Fatal("bob sees carol's refused flow")
	}
	if findEdge(su, 80) == nil {
		t.Fatal("bob does not see his own flow")
	}
	for _, n := range su.Nodes {
		if n.Label == "x" {
			t.Fatal("bob sees carol's container")
		}
	}

	if _, err := e.r.WatchMap("nope", ""); err == nil {
		t.Fatal("watch of an unknown class")
	}
	cctx, cancel := context.WithCancel(context.Background())
	cancel()
	if _, err := w.Next(cctx); err == nil {
		t.Fatal("next after cancel")
	}
}

func TestFlowMapUDP(t *testing.T) {
	e := newEnv(t, v1.Template_TEMPLATE_NEUTRON_DEFAULT, relay.Limits{})
	alice, bob := e.student("Alice"), e.student("Bob")
	dns, client := attach(t, alice, "dns"), attach(t, bob, "client")
	srv, _ := dns.ListenPacket(ctx(t), "udp", 53)
	go func() {
		buf := make([]byte, 100)
		for {
			n, from, err := srv.ReadFrom(buf)
			if err != nil {
				return
			}
			srv.WriteTo(buf[:n], from)
		}
	}()
	w, _ := e.r.WatchMap(e.class.Id, "")
	defer w.Close()
	c, _ := client.Dial(ctx(t), "udp", netip.AddrPortFrom(dns.Addr(), 53))
	c.SetReadDeadline(time.Now().Add(5 * time.Second))
	for range 3 {
		c.Write(make([]byte, 100))
		c.Read(make([]byte, 100))
	}
	u, _ := w.Next(context.Background())
	d := findEdge(u, 53)
	// 3 requests and 3 replies, all on the one forward edge.
	if d == nil || d.Bytes != 600 || d.Protocol != v1.Protocol_PROTOCOL_UDP {
		t.Fatalf("udp edge: %+v (edges %v)", d, u.Edges)
	}
}

func TestMapTicket(t *testing.T) {
	e := newEnv(t, v1.Template_TEMPLATE_ISOLATED, relay.Limits{})
	tok, exp, err := e.r.MapTicket(e.class.Id)
	if err != nil || exp.Before(time.Now().Add(11*time.Hour)) {
		t.Fatal(err, exp)
	}
	cls, err := e.r.VerifyMapTicket(tok)
	if err != nil || cls != e.class.Id {
		t.Fatal(cls, err)
	}
	// A map ticket is not a session token, and a session token is not a ticket.
	if _, err := e.r.Authenticate(tok); err == nil {
		t.Fatal("a map ticket authenticated as a session")
	}
	j, _ := e.r.Join(e.class.JoinCode, "Alice", nil)
	if _, err := e.r.VerifyMapTicket(j.Token); err == nil {
		t.Fatal("a session token passed as a map ticket")
	}
	if _, _, err := e.r.MapTicket("nope"); err == nil {
		t.Fatal("ticket for an unknown class")
	}
	if err := e.r.DeleteClass(e.class.Id); err != nil {
		t.Fatal(err)
	}
	if _, err := e.r.VerifyMapTicket(tok); err == nil {
		t.Fatal("ticket of a deleted class")
	}
}
