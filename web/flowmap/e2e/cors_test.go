// SPDX-License-Identifier: BSD-3-Clause

//go:build e2e

package e2e

import (
	"context"
	"net/http"
	"net/http/httptest"
	"os"
	"strings"
	"testing"
	"time"

	"connectrpc.com/connect/v2"
	"connectrpc.com/connect/v2/connecthttp"
	"github.com/mxschmitt/playwright-go"

	"github.com/go-wasmcontainers/relay/auth"
	v1 "github.com/go-wasmcontainers/relay/gen/relayv1"
	"github.com/go-wasmcontainers/relay/gen/relayv1/relayv1connect"
	"github.com/go-wasmcontainers/relay/relay"
	"github.com/go-wasmcontainers/relay/server"
)

// joinScript is what the playground's engine worker does with Connect-Web: a
// Connect unary call over JSON with the headers Connect-Web sets (User-Agent
// among them, which Firefox puts in the preflight), then the data WebSocket
// with the session token as a subprotocol. It returns "ok", or the step that
// failed.
const joinScript = `async ([relay, code]) => {
	let tok;
	try {
		const r = await fetch(relay + "/wasmcontainers.relay.v1.JoinService/Join", {
			method: "POST",
			headers: {"Content-Type": "application/json", "Connect-Protocol-Version": "1",
				"Connect-Timeout-Ms": "10000", "User-Agent": "connect-es/2.0.0"},
			body: JSON.stringify({joinCode: code, displayName: "Browser"}),
		});
		if (!r.ok) return "join status " + r.status;
		tok = (await r.json()).sessionToken;
	} catch (e) { return "join fetch: " + e; }
	return await new Promise((resolve) => {
		const ws = new WebSocket(relay.replace(/^http/, "ws") + "/v1/data", ["wctr-relay.v1", "bearer." + tok]);
		ws.onopen = () => { ws.close(); resolve("ok"); };
		ws.onerror = () => resolve("websocket refused");
		setTimeout(() => resolve("websocket timeout"), 10000);
	});
}`

// wsScript opens the data WebSocket with a token obtained elsewhere: what a
// hostile page would try once it had one.
const wsScript = `async ([relay, tok]) => await new Promise((resolve) => {
	const ws = new WebSocket(relay.replace(/^http/, "ws") + "/v1/data", ["wctr-relay.v1", "bearer." + tok]);
	ws.onopen = () => { ws.close(); resolve("ok"); };
	ws.onerror = () => resolve("websocket refused");
	setTimeout(() => resolve("websocket timeout"), 10000);
})`

func TestCORSInBrowsers(t *testing.T) {
	page := http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "text/html; charset=utf-8")
		w.Write([]byte("<!doctype html><title>page</title>"))
	})
	allowed := httptest.NewServer(page)
	defer allowed.Close()
	foreign := httptest.NewServer(page)
	defer foreign.Close()

	k, _ := auth.NewKeys()
	r, err := relay.New(relay.Config{Keys: k})
	if err != nil {
		t.Fatal(err)
	}
	tok, _ := auth.RandomToken()
	srv, err := server.New(server.Config{Relay: r, AdminToken: tok, AllowedOrigins: []string{allowed.URL}})
	if err != nil {
		t.Fatal(err)
	}
	pub := httptest.NewServer(srv.Public())
	defer pub.Close()
	adm := httptest.NewServer(srv.Admin())
	defer adm.Close()
	ctx, cancel := context.WithTimeout(context.Background(), 3*time.Minute)
	defer cancel()
	admin := &http.Client{Transport: bearer{http.DefaultTransport, tok}}
	cls, err := relayv1connect.NewClassServiceClient(connect.NewClient(connecthttp.NewTransport(admin, adm.URL))).
		CreateClass(ctx, &v1.CreateClassRequest{Name: "cors"})
	if err != nil {
		t.Fatal(err)
	}
	join := relayv1connect.NewJoinServiceClient(connect.NewClient(connecthttp.NewTransport(http.DefaultClient, pub.URL)))

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
			bt := map[string]playwright.BrowserType{"chromium": pw.Chromium, "firefox": pw.Firefox}[name]
			if bt == nil {
				t.Fatalf("browser %q", name)
			}
			b, err := bt.Launch()
			if err != nil {
				t.Fatal(err)
			}
			defer b.Close()
			run := func(origin, script string, arg []any) string {
				p, err := b.NewPage()
				if err != nil {
					t.Fatal(err)
				}
				defer p.Close()
				if _, err := p.Goto(origin + "/"); err != nil {
					t.Fatal(err)
				}
				v, err := p.Evaluate(script, arg)
				if err != nil {
					t.Fatal(err)
				}
				s, _ := v.(string)
				return s
			}
			if got := run(allowed.URL, joinScript, []any{pub.URL, cls.JoinCode}); got != "ok" {
				t.Fatalf("listed origin: %s", got)
			}
			if got := run(foreign.URL, joinScript, []any{pub.URL, cls.JoinCode}); !strings.HasPrefix(got, "join fetch") {
				t.Fatalf("unlisted origin joined: %s", got)
			}
			// A stolen token does not open the data channel from an unlisted
			// origin (cross-site WebSocket hijacking).
			j, err := join.Join(ctx, &v1.JoinRequest{JoinCode: cls.JoinCode, DisplayName: "Stolen"})
			if err != nil {
				t.Fatal(err)
			}
			if got := run(foreign.URL, wsScript, []any{pub.URL, j.SessionToken}); got != "websocket refused" {
				t.Fatalf("unlisted origin, data channel: %s", got)
			}
		})
	}
}
