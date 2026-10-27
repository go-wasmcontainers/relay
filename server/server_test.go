// SPDX-License-Identifier: BSD-3-Clause

package server_test

import (
	"context"
	"errors"
	"io"
	"net/http"
	"net/http/httptest"
	"net/netip"
	"strings"
	"testing"
	"time"

	"connectrpc.com/connect/v2"
	"connectrpc.com/connect/v2/connecthttp"

	"github.com/go-wasmcontainers/relay/auth"
	"github.com/go-wasmcontainers/relay/driver"
	v1 "github.com/go-wasmcontainers/relay/gen/relayv1"
	"github.com/go-wasmcontainers/relay/gen/relayv1/relayv1connect"
	"github.com/go-wasmcontainers/relay/relay"
	"github.com/go-wasmcontainers/relay/server"
)

type headerRT struct {
	base http.RoundTripper
	h    http.Header
}

func (h headerRT) RoundTrip(r *http.Request) (*http.Response, error) {
	r = r.Clone(r.Context())
	for k, v := range h.h {
		r.Header[k] = v
	}
	return h.base.RoundTrip(r)
}

func withHeader(c *http.Client, k, v string) *http.Client {
	return &http.Client{Transport: headerRT{base: c.Transport, h: http.Header{k: {v}}}}
}

type rig struct {
	r      *relay.Relay
	pub    *httptest.Server
	adm    *httptest.Server
	token  string
	admin  *http.Client
	public *http.Client
}

func newRig(t *testing.T, cfg server.Config) *rig {
	t.Helper()
	k, _ := auth.NewKeys()
	r, err := relay.New(relay.Config{Keys: k})
	if err != nil {
		t.Fatal(err)
	}
	tok, _ := auth.RandomToken()
	cfg.Relay, cfg.AdminToken = r, tok
	s, err := server.New(cfg)
	if err != nil {
		t.Fatal(err)
	}
	g := &rig{r: r, token: tok}
	g.pub = httptest.NewTLSServer(s.Public())
	g.adm = httptest.NewTLSServer(s.Admin())
	t.Cleanup(func() { g.pub.Close(); g.adm.Close() })
	g.admin = withHeader(g.adm.Client(), "Authorization", "Bearer "+tok)
	g.public = g.pub.Client()
	return g
}

func classClient(c *http.Client, base string) relayv1connect.ClassServiceClient {
	return relayv1connect.NewClassServiceClient(connect.NewClient(connecthttp.NewTransport(c, base)))
}

func joinClient(c *http.Client, base string) relayv1connect.JoinServiceClient {
	return relayv1connect.NewJoinServiceClient(connect.NewClient(connecthttp.NewTransport(c, base)))
}

func sgClient(c *http.Client, base string) relayv1connect.SecurityGroupServiceClient {
	return relayv1connect.NewSecurityGroupServiceClient(connect.NewClient(connecthttp.NewTransport(c, base)))
}

func flowClient(c *http.Client, base string) relayv1connect.FlowLogServiceClient {
	return relayv1connect.NewFlowLogServiceClient(connect.NewClient(connecthttp.NewTransport(c, base)))
}

func portClient(c *http.Client, base string) relayv1connect.PortServiceClient {
	return relayv1connect.NewPortServiceClient(connect.NewClient(connecthttp.NewTransport(c, base)))
}

func tctx(t *testing.T) context.Context {
	c, cancel := context.WithTimeout(context.Background(), 15*time.Second)
	t.Cleanup(cancel)
	return c
}

func wsURL(s *httptest.Server) string { return "wss" + strings.TrimPrefix(s.URL, "https") + "/v1/data" }

func TestEndToEnd(t *testing.T) {
	g := newRig(t, server.Config{})
	ctx := tctx(t)
	cls, err := classClient(g.admin, g.adm.URL).CreateClass(ctx, &v1.CreateClassRequest{Name: "lab", Template: v1.Template_TEMPLATE_NEUTRON_DEFAULT})
	if err != nil {
		t.Fatal(err)
	}
	join := joinClient(g.public, g.pub.URL)
	ja, err := join.Join(ctx, &v1.JoinRequest{JoinCode: cls.JoinCode, DisplayName: "Alice"})
	if err != nil {
		t.Fatal(err)
	}
	jb, err := join.Join(ctx, &v1.JoinRequest{JoinCode: cls.JoinCode, DisplayName: "Bob"})
	if err != nil {
		t.Fatal(err)
	}
	if ja.Class.JoinCode != "" {
		t.Fatal("a student was shown the join code")
	}

	// Flow log, as the teacher sees it.
	events := make(chan *v1.FlowEvent, 16)
	st, err := flowClient(g.admin, g.adm.URL).WatchFlows(ctx, &v1.WatchFlowsRequest{ClassId: cls.Id})
	if err != nil {
		t.Fatal(err)
	}
	go func() {
		for {
			e, err := st.Receive()
			if err != nil {
				return
			}
			events <- e
		}
	}()
	// Mark the web rule as logged so the allow is reported.
	if _, err := sgClient(g.admin, g.adm.URL).CreateRule(ctx, &v1.CreateRuleRequest{ClassId: cls.Id, Group: "default",
		Rule: &v1.SecurityGroupRule{Direction: v1.Direction_DIRECTION_INGRESS, Protocol: v1.Protocol_PROTOCOL_TCP, PortRangeMin: 80, Log: true}}); err != nil {
		t.Fatal(err)
	}

	sa, err := driver.DialWebSocket(ctx, wsURL(g.pub), ja.SessionToken, g.public)
	if err != nil {
		t.Fatal(err)
	}
	defer sa.Close()
	sb, err := driver.DialWebSocket(ctx, wsURL(g.pub), jb.SessionToken, g.public)
	if err != nil {
		t.Fatal(err)
	}
	defer sb.Close()
	web, err := sa.Attach(ctx, "web")
	if err != nil {
		t.Fatal(err)
	}
	curl, err := sb.Attach(ctx, "curl")
	if err != nil {
		t.Fatal(err)
	}
	l, err := web.Listen(ctx, "tcp", 80)
	if err != nil {
		t.Fatal(err)
	}
	go func() {
		c, err := l.Accept()
		if err != nil {
			return
		}
		io.Copy(c, c)
		c.Close()
	}()
	c, err := curl.Dial(ctx, "tcp", netip.AddrPortFrom(web.Addr(), 80))
	if err != nil {
		t.Fatal(err)
	}
	c.Write([]byte("GET / HTTP/1.0\r\n\r\n"))
	buf := make([]byte, 18)
	if _, err := io.ReadFull(c, buf); err != nil || string(buf) != "GET / HTTP/1.0\r\n\r\n" {
		t.Fatalf("%q %v", buf, err)
	}
	select {
	case e := <-events:
		if e.Verdict != v1.Verdict_VERDICT_ALLOW || !strings.HasPrefix(e.Dst, "10.42.1.2:80") {
			t.Fatalf("event %v", e)
		}
	case <-time.After(5 * time.Second):
		t.Fatal("no flow event")
	}

	// A student's own view: ports of their own only.
	stud := withHeader(g.public, "Wctr-Session", jb.SessionToken)
	ps, err := portClient(stud, g.pub.URL).ListPorts(ctx, &v1.ListPortsRequest{ClassId: cls.Id})
	if err != nil || len(ps.Ports) != 1 || ps.Ports[0].Container != "curl" {
		t.Fatalf("student ports: %v %v", ps, err)
	}
	// A student cannot change rules, even with the admin token, on the
	// public listener.
	pubAdmin := withHeader(g.public, "Authorization", "Bearer "+g.token)
	if _, err := sgClient(pubAdmin, g.pub.URL).CreateRule(ctx, &v1.CreateRuleRequest{ClassId: cls.Id, Group: "default",
		Rule: &v1.SecurityGroupRule{Direction: v1.Direction_DIRECTION_INGRESS}}); connect.CodeOf(err) != connect.CodePermissionDenied {
		t.Fatalf("admin token on the public listener: %v", err)
	}
	// The class service is not even mounted there.
	if _, err := classClient(pubAdmin, g.pub.URL).ListClasses(ctx, &v1.ListClassesRequest{}); connect.CodeOf(err) != connect.CodeUnimplemented && connect.CodeOf(err) != connect.CodeNotFound {
		t.Fatalf("class service on the public listener: %v", err)
	}
}

func TestAdminNeedsToken(t *testing.T) {
	g := newRig(t, server.Config{})
	ctx := tctx(t)
	if _, err := classClient(g.adm.Client(), g.adm.URL).ListClasses(ctx, &v1.ListClassesRequest{}); err == nil {
		t.Fatal("admin without a token")
	}
	bad := withHeader(g.adm.Client(), "Authorization", "Bearer nope")
	if _, err := classClient(bad, g.adm.URL).ListClasses(ctx, &v1.ListClassesRequest{}); err == nil {
		t.Fatal("admin with a wrong token")
	}
	if _, err := classClient(g.admin, g.adm.URL).ListClasses(ctx, &v1.ListClassesRequest{}); err != nil {
		t.Fatal(err)
	}
}

func TestUpgradeRefusedWithoutToken(t *testing.T) {
	g := newRig(t, server.Config{})
	ctx := tctx(t)
	if _, err := driver.DialWebSocket(ctx, wsURL(g.pub), "v1.bogus.token", g.public); err == nil {
		t.Fatal("upgrade with a bogus token")
	}
	req, _ := http.NewRequest("GET", g.pub.URL+"/v1/data", nil)
	resp, err := g.public.Do(req)
	if err != nil {
		t.Fatal(err)
	}
	resp.Body.Close()
	if resp.StatusCode != http.StatusUnauthorized {
		t.Fatalf("no token: %d", resp.StatusCode)
	}
}

func TestOriginChecked(t *testing.T) {
	g := newRig(t, server.Config{AllowedOrigins: []string{"https://go-wasmcontainers.github.io"}})
	ctx := tctx(t)
	cls, _ := classClient(g.admin, g.adm.URL).CreateClass(ctx, &v1.CreateClassRequest{Name: "o"})
	j, _ := joinClient(g.public, g.pub.URL).Join(ctx, &v1.JoinRequest{JoinCode: cls.JoinCode, DisplayName: "A"})
	for _, o := range []string{"https://evil.example", "http://go-wasmcontainers.github.io",
		"https://go-wasmcontainers.github.io.evil.example", "null"} {
		evil := withHeader(g.public, "Origin", o)
		if _, err := driver.DialWebSocket(ctx, wsURL(g.pub), j.SessionToken, evil); err == nil {
			t.Fatalf("origin %s opened the data channel", o)
		}
	}
	for _, o := range []string{"https://go-wasmcontainers.github.io", "https://" + strings.TrimPrefix(g.pub.URL, "https://")} {
		good := withHeader(g.public, "Origin", o)
		s, err := driver.DialWebSocket(ctx, wsURL(g.pub), j.SessionToken, good)
		if err != nil {
			t.Fatalf("allowed origin %s: %v", o, err)
		}
		s.Close()
	}
	// No Origin at all: a client without a browser.
	s, err := driver.DialWebSocket(ctx, wsURL(g.pub), j.SessionToken, g.public)
	if err != nil {
		t.Fatalf("no origin: %v", err)
	}
	s.Close()
}

func TestJoinRateLimited(t *testing.T) {
	g := newRig(t, server.Config{PreAuthPerMinute: 3})
	ctx := tctx(t)
	join := joinClient(g.public, g.pub.URL)
	var last error
	for range 5 {
		_, last = join.Join(ctx, &v1.JoinRequest{JoinCode: "0000000000", DisplayName: "X"})
	}
	if connect.CodeOf(last) != connect.CodeResourceExhausted {
		t.Fatalf("5 joins at 3/min: %v", last)
	}
}

func TestAllowedHosts(t *testing.T) {
	g := newRig(t, server.Config{AllowedHosts: []string{"relay.example"}})
	resp, err := g.public.Get(g.pub.URL + "/v1/info")
	if err != nil {
		t.Fatal(err)
	}
	resp.Body.Close()
	if resp.StatusCode != http.StatusMisdirectedRequest {
		t.Fatalf("unknown Host served: %d", resp.StatusCode)
	}
}

func TestInfo(t *testing.T) {
	g := newRig(t, server.Config{TLSMode: "internal"})
	resp, err := g.public.Get(g.pub.URL + "/v1/info")
	if err != nil {
		t.Fatal(err)
	}
	b, _ := io.ReadAll(resp.Body)
	resp.Body.Close()
	if !strings.Contains(string(b), `"tls":"internal"`) || resp.Header.Get("X-Content-Type-Options") != "nosniff" {
		t.Fatalf("%s %v", b, resp.Header)
	}
}

func TestRequireIdentityNeedsIssuer(t *testing.T) {
	g := newRig(t, server.Config{})
	_, err := classClient(g.admin, g.adm.URL).CreateClass(tctx(t), &v1.CreateClassRequest{Name: "x", RequireIdentity: true})
	if connect.CodeOf(err) != connect.CodeFailedPrecondition {
		t.Fatalf("%v", err)
	}
	var ce *connect.Error
	if !errors.As(err, &ce) {
		t.Fatal(err)
	}
}
