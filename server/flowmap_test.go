// SPDX-License-Identifier: BSD-3-Clause

package server_test

import (
	"io"
	"net/http"
	"strings"
	"testing"

	"connectrpc.com/connect/v2"
	"connectrpc.com/connect/v2/connecthttp"

	v1 "github.com/go-wasmcontainers/relay/gen/relayv1"
	"github.com/go-wasmcontainers/relay/gen/relayv1/relayv1connect"
	"github.com/go-wasmcontainers/relay/server"
)

func mapClient(c *http.Client, base string) relayv1connect.FlowMapServiceClient {
	return relayv1connect.NewFlowMapServiceClient(connect.NewClient(connecthttp.NewTransport(c, base)))
}

func TestWatchFlowMapAccess(t *testing.T) {
	g := newRig(t, server.Config{})
	ctx := tctx(t)
	cls, _ := classClient(g.admin, g.adm.URL).CreateClass(ctx, &v1.CreateClassRequest{Name: "map"})
	other, _ := classClient(g.admin, g.adm.URL).CreateClass(ctx, &v1.CreateClassRequest{Name: "other"})

	first := func(c *http.Client, base, class string) (*v1.FlowMapUpdate, error) {
		st, err := flowClient(c, base).WatchFlowMap(ctx, &v1.WatchFlowMapRequest{ClassId: class, TickMs: 100})
		if err != nil {
			return nil, err
		}
		defer st.Close()
		return st.Receive()
	}
	// No credential on the public listener.
	if _, err := first(g.public, g.pub.URL, cls.Id); connect.CodeOf(err) != connect.CodeUnauthenticated {
		t.Fatalf("anonymous: %v", err)
	}
	// The teacher's ticket, from the admin API, works on the public listener
	// for that class only, and grants nothing else.
	if _, err := mapClient(g.public, g.pub.URL).FlowMapTicket(ctx, &v1.FlowMapTicketRequest{ClassId: cls.Id}); err == nil {
		t.Fatal("a ticket from the public listener")
	}
	tk, err := mapClient(g.admin, g.adm.URL).FlowMapTicket(ctx, &v1.FlowMapTicketRequest{ClassId: cls.Id})
	if err != nil {
		t.Fatal(err)
	}
	withTicket := withHeader(g.public, "Wctr-Map-Ticket", tk.Ticket)
	u, err := first(withTicket, g.pub.URL, cls.Id)
	if err != nil || u.Seq != 1 {
		t.Fatalf("ticket: %v %v", u, err)
	}
	if _, err := first(withTicket, g.pub.URL, other.Id); connect.CodeOf(err) != connect.CodePermissionDenied {
		t.Fatalf("ticket for another class: %v", err)
	}
	if _, err := sgClient(withTicket, g.pub.URL).ListSecurityGroups(ctx, &v1.ListSecurityGroupsRequest{ClassId: cls.Id}); err == nil {
		t.Fatal("a map ticket read the security groups")
	}
	// A student's session: their own view.
	j, _ := joinClient(g.public, g.pub.URL).Join(ctx, &v1.JoinRequest{JoinCode: cls.JoinCode, DisplayName: "A"})
	stud := withHeader(g.public, "Wctr-Session", j.SessionToken)
	if _, err := first(stud, g.pub.URL, cls.Id); err != nil {
		t.Fatalf("student view: %v", err)
	}
	if _, err := first(stud, g.pub.URL, other.Id); connect.CodeOf(err) != connect.CodePermissionDenied {
		t.Fatalf("student, other class: %v", err)
	}
	// The admin listener, directly.
	if _, err := first(g.admin, g.adm.URL, cls.Id); err != nil {
		t.Fatal(err)
	}
	if _, err := first(g.admin, g.adm.URL, "nope"); connect.CodeOf(err) != connect.CodeNotFound {
		t.Fatalf("unknown class: %v", err)
	}
}

func TestFlowMapPageHeaders(t *testing.T) {
	g := newRig(t, server.Config{})
	for path, want := range map[string]string{"/flowmap/": "<canvas id=\"screen\"", "/flowmap/flowmap.js": "wctrFlowmapConfig",
		"/flowmap/wasm_exec.js": "Go", "/flowmap/flowmap.css": "canvas"} {
		resp, err := g.public.Get(g.pub.URL + path)
		if err != nil {
			t.Fatal(err)
		}
		b, _ := io.ReadAll(resp.Body)
		resp.Body.Close()
		if resp.StatusCode != 200 || !strings.Contains(string(b), want) {
			t.Fatalf("%s: %d %q", path, resp.StatusCode, b[:min(len(b), 80)])
		}
		csp := resp.Header.Get("Content-Security-Policy")
		if !strings.Contains(csp, "script-src 'self' 'wasm-unsafe-eval'") || strings.Contains(csp, "unsafe-inline") ||
			!strings.Contains(csp, "frame-ancestors 'none'") {
			t.Fatalf("%s: CSP %q", path, csp)
		}
	}
	resp, _ := g.public.Get(g.pub.URL + "/flowmap/flowmap.wasm")
	resp.Body.Close()
	if server.FlowMapBuilt {
		if resp.StatusCode != 200 || resp.Header.Get("Content-Type") != "application/wasm" {
			t.Fatalf("wasm: %d %s", resp.StatusCode, resp.Header.Get("Content-Type"))
		}
	} else if resp.StatusCode != http.StatusNotFound {
		t.Fatalf("no-flowmap build served a wasm: %d", resp.StatusCode)
	}
	resp, _ = g.public.Get(g.pub.URL + "/flowmap/flowmap.wasm.gz")
	resp.Body.Close()
	if resp.StatusCode != http.StatusNotFound {
		t.Fatal("the .gz is served directly")
	}
}
