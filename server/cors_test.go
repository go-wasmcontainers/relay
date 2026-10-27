// SPDX-License-Identifier: BSD-3-Clause

package server_test

import (
	"net/http"
	"slices"
	"strings"
	"testing"

	v1 "github.com/go-wasmcontainers/relay/gen/relayv1"
	"github.com/go-wasmcontainers/relay/server"
)

const playground = "https://go-wasmcontainers.github.io"

const joinPath = "/wasmcontainers.relay.v1.JoinService/Join"

func preflight(t *testing.T, c *http.Client, url, origin, method, headers string) *http.Response {
	t.Helper()
	req, _ := http.NewRequest(http.MethodOptions, url, nil)
	req.Header.Set("Origin", origin)
	req.Header.Set("Access-Control-Request-Method", method)
	if headers != "" {
		req.Header.Set("Access-Control-Request-Headers", headers)
	}
	resp, err := c.Do(req)
	if err != nil {
		t.Fatal(err)
	}
	resp.Body.Close()
	return resp
}

func splitList(v string) []string {
	var out []string
	for _, p := range strings.Split(v, ",") {
		out = append(out, strings.ToLower(strings.TrimSpace(p)))
	}
	return out
}

func TestCORSPreflightAllowed(t *testing.T) {
	g := newRig(t, server.Config{AllowedOrigins: []string{playground}})
	// What Firefox sends for a Connect-Web unary call with a session.
	want := "content-type,connect-protocol-version,connect-timeout-ms,user-agent,authorization,wctr-session"
	for _, path := range []string{joinPath, "/wasmcontainers.relay.v1.JoinService/RefreshSession",
		"/wasmcontainers.relay.v1.FlowLogService/WatchFlowMap"} {
		resp := preflight(t, g.public, g.pub.URL+path, playground, "POST", want)
		if resp.StatusCode != http.StatusNoContent {
			t.Fatalf("%s: preflight %d", path, resp.StatusCode)
		}
		h := resp.Header
		if h.Get("Access-Control-Allow-Origin") != playground {
			t.Fatalf("%s: Allow-Origin %q", path, h.Get("Access-Control-Allow-Origin"))
		}
		if h.Get("Access-Control-Allow-Credentials") != "" {
			t.Fatal("credentials mode enabled")
		}
		allowed := splitList(h.Get("Access-Control-Allow-Headers"))
		for _, w := range splitList(want) {
			if !slices.Contains(allowed, w) {
				t.Fatalf("%s: header %s not allowed: %v", path, w, allowed)
			}
		}
		if m := splitList(h.Get("Access-Control-Allow-Methods")); !slices.Equal(m, []string{"get", "post"}) {
			t.Fatalf("methods %v", m)
		}
		if h.Get("Access-Control-Max-Age") != "7200" {
			t.Fatalf("max-age %q", h.Get("Access-Control-Max-Age"))
		}
		if !slices.Contains(h.Values("Vary"), "Origin") {
			t.Fatalf("no Vary: Origin: %v", h.Values("Vary"))
		}
	}
}

func TestCORSPreflightRefused(t *testing.T) {
	g := newRig(t, server.Config{AllowedOrigins: []string{playground}})
	cases := []struct{ name, path, origin, method string }{
		{"foreign origin", joinPath, "https://evil.example", "POST"},
		{"scheme differs", joinPath, "http://go-wasmcontainers.github.io", "POST"},
		{"suffix", joinPath, "https://go-wasmcontainers.github.io.evil.example", "POST"},
		{"null origin", joinPath, "null", "POST"},
		{"method", joinPath, playground, "DELETE"},
		{"not a browser RPC", "/wasmcontainers.relay.v1.SecurityGroupService/ListRules", playground, "POST"},
	}
	for _, c := range cases {
		resp := preflight(t, g.public, g.pub.URL+c.path, c.origin, c.method, "content-type")
		if resp.StatusCode != http.StatusForbidden || resp.Header.Get("Access-Control-Allow-Origin") != "" {
			t.Fatalf("%s: %d %q", c.name, resp.StatusCode, resp.Header.Get("Access-Control-Allow-Origin"))
		}
	}
}

func TestCORSDefaultIsSameOriginOnly(t *testing.T) {
	g := newRig(t, server.Config{})
	if resp := preflight(t, g.public, g.pub.URL+joinPath, playground, "POST", "content-type"); resp.StatusCode != http.StatusForbidden {
		t.Fatalf("no allowlist, foreign origin: %d", resp.StatusCode)
	}
	if resp := preflight(t, g.public, g.pub.URL+joinPath, g.pub.URL, "POST", "content-type"); resp.StatusCode != http.StatusNoContent {
		t.Fatalf("own origin: %d", resp.StatusCode)
	}
}

func TestCORSActualResponse(t *testing.T) {
	g := newRig(t, server.Config{AllowedOrigins: []string{playground}})
	ctx := tctx(t)
	cls, _ := classClient(g.admin, g.adm.URL).CreateClass(ctx, &v1.CreateClassRequest{Name: "c"})
	body := `{"joinCode":"` + cls.JoinCode + `","displayName":"A"}`
	for _, c := range []struct {
		origin string
		allow  bool
	}{{playground, true}, {"https://evil.example", false}} {
		req, _ := http.NewRequest("POST", g.pub.URL+joinPath, strings.NewReader(body))
		req.Header.Set("Content-Type", "application/json")
		req.Header.Set("Origin", c.origin)
		resp, err := g.public.Do(req)
		if err != nil {
			t.Fatal(err)
		}
		resp.Body.Close()
		got := resp.Header.Get("Access-Control-Allow-Origin")
		if c.allow && (got != playground || !strings.Contains(resp.Header.Get("Access-Control-Expose-Headers"), "Grpc-Status")) {
			t.Fatalf("allowed origin: %d %v", resp.StatusCode, resp.Header)
		}
		if !c.allow && got != "" {
			t.Fatalf("foreign origin got Allow-Origin %q", got)
		}
	}
}

func TestCORSAdminListenerHasNone(t *testing.T) {
	g := newRig(t, server.Config{AllowedOrigins: []string{playground}})
	resp := preflight(t, g.admin, g.adm.URL+"/wasmcontainers.relay.v1.ClassService/ListClasses", playground, "POST", "content-type,authorization")
	if resp.Header.Get("Access-Control-Allow-Origin") != "" || resp.StatusCode == http.StatusNoContent {
		t.Fatalf("admin answered a preflight: %d %v", resp.StatusCode, resp.Header)
	}
	resp = preflight(t, g.admin, g.adm.URL+joinPath, playground, "POST", "content-type")
	if resp.Header.Get("Access-Control-Allow-Origin") != "" {
		t.Fatalf("admin Join answered a preflight: %v", resp.Header)
	}
}

func TestCORSOriginValidation(t *testing.T) {
	for _, o := range []string{"*", "https://*.github.io", "go-wasmcontainers.github.io", "https://x.example/path",
		"ftp://x.example", "https://u@x.example", "https://x.example?q"} {
		if _, err := server.New(server.Config{Relay: newRig(t, server.Config{}).r, AllowedOrigins: []string{o}}); err == nil {
			t.Fatalf("origin %q accepted", o)
		}
	}
	if n, err := server.NormalizeOrigin("HTTPS://Go-WasmContainers.GitHub.io/"); err != nil || n != playground {
		t.Fatalf("%q %v", n, err)
	}
}
