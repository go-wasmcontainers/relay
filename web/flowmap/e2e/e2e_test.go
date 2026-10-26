// SPDX-License-Identifier: BSD-3-Clause

//go:build e2e

// Package e2e drives the flow-map page in real browsers (Playwright, Chromium
// and Firefox) against an in-process relay with real flows, and asserts what
// the page's view model says (window.wctrFlowmapState), not pixels.
//
//	go run ./internal/buildflowmap                     (repository root)
//	cd web/flowmap && go test -tags 'e2e flowmap' ./e2e
//
// PLAYWRIGHT_DRIVER_PATH / PLAYWRIGHT_NODEJS_PATH as playwright-go needs them;
// E2E_BROWSERS (default "chromium,firefox") picks the browsers.
package e2e

import (
	"context"
	"encoding/json"
	"io"
	"net"
	"net/http"
	"net/http/httptest"
	"net/netip"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"connectrpc.com/connect/v2"
	"connectrpc.com/connect/v2/connecthttp"
	"github.com/playwright-community/playwright-go"

	"github.com/go-wasmcontainers/relay/auth"
	"github.com/go-wasmcontainers/relay/driver"
	v1 "github.com/go-wasmcontainers/relay/gen/relayv1"
	"github.com/go-wasmcontainers/relay/gen/relayv1/relayv1connect"
	"github.com/go-wasmcontainers/relay/relay"
	"github.com/go-wasmcontainers/relay/server"
	"github.com/go-wasmcontainers/relay/web/flowmap"
)

type bearer struct {
	base http.RoundTripper
	tok  string
}

func (b bearer) RoundTrip(r *http.Request) (*http.Response, error) {
	r = r.Clone(r.Context())
	r.Header.Set("Authorization", "Bearer "+b.tok)
	return b.base.RoundTrip(r)
}

func TestFlowMapInBrowsers(t *testing.T) {
	if !server.FlowMapBuilt {
		t.Fatal("build with -tags flowmap (after go run ./internal/buildflowmap)")
	}
	k, _ := auth.NewKeys()
	r, err := relay.New(relay.Config{Keys: k})
	if err != nil {
		t.Fatal(err)
	}
	tok, _ := auth.RandomToken()
	srv, err := server.New(server.Config{Relay: r, AdminToken: tok})
	if err != nil {
		t.Fatal(err)
	}
	pub := httptest.NewServer(srv.Public())
	defer pub.Close()
	adm := httptest.NewServer(srv.Admin())
	defer adm.Close()
	ctx, cancel := context.WithTimeout(context.Background(), 4*time.Minute)
	defer cancel()

	admin := &http.Client{Transport: bearer{http.DefaultTransport, tok}}
	cc := connect.NewClient(connecthttp.NewTransport(admin, adm.URL))
	cls, err := relayv1connect.NewClassServiceClient(cc).CreateClass(ctx, &v1.CreateClassRequest{Name: "e2e"})
	if err != nil {
		t.Fatal(err)
	}
	sgs := relayv1connect.NewSecurityGroupServiceClient(cc)
	for _, d := range []v1.Direction{v1.Direction_DIRECTION_INGRESS, v1.Direction_DIRECTION_EGRESS} {
		if _, err := sgs.CreateRule(ctx, &v1.CreateRuleRequest{ClassId: cls.Id, Group: "default",
			Rule: &v1.SecurityGroupRule{Direction: d, Protocol: v1.Protocol_PROTOCOL_TCP, PortRangeMin: 80}}); err != nil {
			t.Fatal(err)
		}
	}
	ticket, err := relayv1connect.NewFlowMapServiceClient(cc).FlowMapTicket(ctx, &v1.FlowMapTicketRequest{ClassId: cls.Id})
	if err != nil {
		t.Fatal(err)
	}

	// Two students: alice serves on 80, bob connects (allowed) and tries 22
	// (refused), again and again so the page sees live traffic and refusals.
	join := relayv1connect.NewJoinServiceClient(connect.NewClient(connecthttp.NewTransport(http.DefaultClient, pub.URL)))
	ws := "ws" + strings.TrimPrefix(pub.URL, "http") + "/v1/data"
	session := func(name string) *driver.Session {
		j, err := join.Join(ctx, &v1.JoinRequest{JoinCode: cls.JoinCode, DisplayName: name})
		if err != nil {
			t.Fatal(err)
		}
		s, err := driver.DialWebSocket(ctx, ws, j.SessionToken, http.DefaultClient)
		if err != nil {
			t.Fatal(err)
		}
		t.Cleanup(func() { s.Close() })
		return s
	}
	alice, bob := session("Alice"), session("Bob")
	web, _ := alice.Attach(ctx, "web")
	curl, _ := bob.Attach(ctx, "curl")
	l, err := web.Listen(ctx, "tcp", 80)
	if err != nil {
		t.Fatal(err)
	}
	go func() {
		for {
			c, err := l.Accept()
			if err != nil {
				return
			}
			go func(c net.Conn) { io.Copy(c, c); c.Close() }(c)
		}
	}()
	go func() {
		for ctx.Err() == nil {
			if c, err := curl.Dial(ctx, "tcp", netip.AddrPortFrom(web.Addr(), 80)); err == nil {
				c.Write(make([]byte, 4096))
				io.ReadFull(c, make([]byte, 4096))
				c.Close()
			}
			curl.Dial(ctx, "tcp", netip.AddrPortFrom(web.Addr(), 22))
			time.Sleep(200 * time.Millisecond)
		}
	}()

	if err := playwright.Install(&playwright.RunOptions{SkipInstallBrowsers: true}); err != nil {
		t.Fatal(err)
	}
	pw, err := playwright.Run()
	if err != nil {
		t.Fatal(err)
	}
	defer pw.Stop()
	browsers := os.Getenv("E2E_BROWSERS")
	if browsers == "" {
		browsers = "chromium,firefox"
	}
	for _, name := range strings.Split(browsers, ",") {
		t.Run(name, func(t *testing.T) {
			var bt playwright.BrowserType
			switch name {
			case "chromium":
				bt = pw.Chromium
			case "firefox":
				bt = pw.Firefox
			default:
				t.Fatalf("browser %q", name)
			}
			b, err := bt.Launch()
			if err != nil {
				t.Fatal(err)
			}
			defer b.Close()
			page, err := b.NewPage(playwright.BrowserNewPageOptions{Viewport: &playwright.Size{Width: 1280, Height: 720}})
			if err != nil {
				t.Fatal(err)
			}
			var cspErrors []string
			page.On("console", func(m playwright.ConsoleMessage) {
				if strings.Contains(m.Text(), "Content Security Policy") || strings.Contains(m.Text(), "Content-Security-Policy") {
					cspErrors = append(cspErrors, m.Text())
				}
			})
			start := time.Now()
			if _, err := page.Goto(pub.URL + "/flowmap/#class=" + cls.Id + "&ticket=" + ticket.Ticket); err != nil {
				t.Fatal(err)
			}
			state := func() flowmap.State {
				v, err := page.Evaluate("() => globalThis.wctrFlowmapState || ''")
				if err != nil {
					t.Fatal(err)
				}
				var s flowmap.State
				if str, _ := v.(string); str != "" {
					_ = json.Unmarshal([]byte(str), &s)
				}
				return s
			}
			var s flowmap.State
			var firstEdge time.Duration
			deadline := time.Now().Add(60 * time.Second)
			for time.Now().Before(deadline) {
				s = state()
				if firstEdge == 0 && len(s.Edges) > 0 {
					firstEdge = time.Since(start)
				}
				if hasEdge(s.Edges, "bob/curl -> alice/web tcp/80") && len(s.Denied) > 0 {
					break
				}
				time.Sleep(100 * time.Millisecond)
			}
			if !hasEdge(s.Edges, "bob/curl -> alice/web tcp/80") {
				t.Fatalf("the allowed flow never appeared: %+v", s)
			}
			if len(s.Denied) == 0 || !strings.Contains(s.Denied[0], "tcp/22") || !strings.Contains(s.Denied[0], "no ") {
				t.Fatalf("the refused flow is not shown as refused, with its reason: %+v", s)
			}
			if !strings.Contains(s.Status, "containers") || len(s.Clusters) != 2 {
				t.Fatalf("status/clusters: %+v", s)
			}
			// The filter box (HTML, outside the canvas) reaches the view model.
			if err := page.Locator("#filter").Fill("alice"); err != nil {
				t.Fatal(err)
			}
			time.Sleep(300 * time.Millisecond)
			if f := state().Filter; f != "alice" {
				t.Fatalf("filter: %q", f)
			}
			// The URL bar no longer shows the ticket.
			if strings.Contains(page.URL(), "ticket=") {
				t.Fatal("the ticket stayed in the address bar")
			}
			if len(cspErrors) > 0 {
				t.Fatalf("CSP violations: %v", cspErrors)
			}
			t.Logf("%s: first edge on screen %v after navigation", name, firstEdge)
			if dir := os.Getenv("E2E_SHOT_DIR"); dir != "" {
				shot(t, page, dir, name)
			}
		})
	}
}

// shot saves a screenshot for a person to look at, OUTSIDE every repository:
// a directory inside a git work tree is refused.
func shot(t *testing.T, page playwright.Page, dir, name string) {
	abs, err := filepath.Abs(dir)
	if err != nil {
		t.Fatal(err)
	}
	for d := abs; ; d = filepath.Dir(d) {
		if _, err := os.Stat(filepath.Join(d, ".git")); err == nil {
			t.Fatalf("E2E_SHOT_DIR %s is inside the work tree %s: screenshots never go in a repository", abs, d)
		}
		if filepath.Dir(d) == d {
			break
		}
	}
	if err := os.MkdirAll(abs, 0o700); err != nil {
		t.Fatal(err)
	}
	p := filepath.Join(abs, "flowmap-"+name+".png")
	if _, err := page.Screenshot(playwright.PageScreenshotOptions{Path: &p}); err != nil {
		t.Fatal(err)
	}
	t.Logf("screenshot: %s", p)
}

func hasEdge(edges []string, want string) bool {
	for _, e := range edges {
		if e == want {
			return true
		}
	}
	return false
}
