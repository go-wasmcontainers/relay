// SPDX-License-Identifier: BSD-3-Clause

package cli

import (
	"bytes"
	"context"
	"crypto/tls"
	"io"
	"net/http"
	"net/netip"
	"os"
	"path/filepath"
	"regexp"
	"strings"
	"testing"
	"time"

	"connectrpc.com/connect/v2"
	"connectrpc.com/connect/v2/connecthttp"

	"github.com/go-wasmcontainers/relay/driver"
	v1 "github.com/go-wasmcontainers/relay/gen/relayv1"
	"github.com/go-wasmcontainers/relay/gen/relayv1/relayv1connect"
	"github.com/go-wasmcontainers/relay/tlsca"
)

func run(t *testing.T, ctx context.Context, args ...string) (string, error) {
	t.Helper()
	var out, errb bytes.Buffer
	root := RootCmd()
	root.SetArgs(args)
	root.SetOut(&out)
	root.SetErr(&errb)
	err := root.ExecuteContext(ctx)
	return out.String(), err
}

func mustRun(t *testing.T, args ...string) string {
	t.Helper()
	ctx, cancel := context.WithTimeout(context.Background(), 20*time.Second)
	defer cancel()
	out, err := run(t, ctx, args...)
	if err != nil {
		t.Fatalf("%v: %v", args, err)
	}
	return out
}

// shortDir: a Unix socket path must stay under ~104 bytes on macOS.
func shortDir(t *testing.T) string {
	d, err := os.MkdirTemp("", "wr")
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { os.RemoveAll(d) })
	return d
}

func TestAcceptance(t *testing.T) {
	sd := filepath.Join(shortDir(t), "s")
	st := "--state-dir=" + sd
	out := mustRun(t, "init", st, "--name", "localhost", "--ip", "127.0.0.1")
	if !strings.Contains(out, "internal CA created") {
		t.Fatal(out)
	}
	if fi, err := os.Stat(filepath.Join(sd, "admin.token")); err != nil || fi.Mode().Perm() != 0o600 {
		t.Fatalf("admin token: %v %v", fi.Mode(), err)
	}

	ready := make(chan string, 1)
	serveReady = ready
	defer func() { serveReady = nil }()
	sctx, stop := context.WithCancel(context.Background())
	served := make(chan error, 1)
	go func() {
		_, err := run(t, sctx, "serve", st, "--listen", "127.0.0.1:0", "--tls", "internal")
		served <- err
	}()
	var addr string
	select {
	case addr = <-ready:
	case err := <-served:
		t.Fatalf("serve: %v", err)
	case <-time.After(10 * time.Second):
		t.Fatal("serve did not start")
	}
	defer func() {
		stop()
		<-served
	}()

	out = mustRun(t, "class", "create", "lab", st, "--template", "neutron")
	code := regexp.MustCompile(`join code ([0-9A-Z]{5}-[0-9A-Z]{5})`).FindStringSubmatch(out)
	id := regexp.MustCompile(`\((c-[0-9a-f]+)\)`).FindStringSubmatch(out)
	if code == nil || id == nil {
		t.Fatalf("class create: %q", out)
	}
	cls := "--class=" + id[1]
	if out := mustRun(t, "class", "list", st); !strings.Contains(out, "lab") {
		t.Fatal(out)
	}
	mustRun(t, "sg", "create", "web", st, cls)
	ruleID := strings.TrimSpace(mustRun(t, "rule", "add", "web", st, cls, "--ingress", "--proto", "tcp", "--port", "80"))
	if !strings.HasPrefix(ruleID, "r-") {
		t.Fatal(ruleID)
	}
	if out := mustRun(t, "sg", "list", st, cls); !strings.Contains(out, "ingress") || !strings.Contains(out, "80") {
		t.Fatal(out)
	}

	// Students, over wss, trusting the internal CA.
	ca, err := tlsca.Load(filepath.Join(sd, "ca"))
	if err != nil {
		t.Fatal(err)
	}
	hc := &http.Client{Transport: &http.Transport{TLSClientConfig: &tls.Config{RootCAs: ca.Pool()}}}
	base := "https://" + addr
	join := relayv1connect.NewJoinServiceClient(connect.NewClient(connecthttp.NewTransport(hc, base)))
	ctx, cancel := context.WithTimeout(context.Background(), 20*time.Second)
	defer cancel()
	ja, err := join.Join(ctx, &v1.JoinRequest{JoinCode: code[1], DisplayName: "Alice"})
	if err != nil {
		t.Fatal(err)
	}
	jb, err := join.Join(ctx, &v1.JoinRequest{JoinCode: code[1], DisplayName: "Bob"})
	if err != nil {
		t.Fatal(err)
	}
	ws := "wss://" + addr + "/v1/data"
	sa, err := driver.DialWebSocket(ctx, ws, ja.SessionToken, hc)
	if err != nil {
		t.Fatal(err)
	}
	defer sa.Close()
	sb, err := driver.DialWebSocket(ctx, ws, jb.SessionToken, hc)
	if err != nil {
		t.Fatal(err)
	}
	defer sb.Close()
	web, _ := sa.Attach(ctx, "web")
	curl, _ := sb.Attach(ctx, "curl")
	l, err := web.Listen(ctx, "tcp", 80)
	if err != nil {
		t.Fatal(err)
	}
	go func() {
		c, err := l.Accept()
		if err == nil {
			io.Copy(c, c)
			c.Close()
		}
	}()
	mustRun(t, "port", "set", "alice/web", st, cls, "--sg", "default,web")
	c, err := curl.Dial(ctx, "tcp", netip.AddrPortFrom(web.Addr(), 80))
	if err != nil {
		t.Fatal(err)
	}
	c.Write([]byte("ping"))
	b := make([]byte, 4)
	if _, err := io.ReadFull(c, b); err != nil || string(b) != "ping" {
		t.Fatalf("%q %v", b, err)
	}
	c.Close()

	if out := mustRun(t, "explain", st, cls, "bob/curl", "alice/web", "tcp/80"); !strings.Contains(out, "ALLOW") {
		t.Fatal(out)
	}
	if out := mustRun(t, "flows", st, cls); !strings.Contains(out, "10.42.1.2:80") {
		t.Fatalf("flows: %q", out)
	}
	if out := mustRun(t, "port", "list", st, cls); !strings.Contains(out, "web.alice.class") {
		t.Fatal(out)
	}
	if out := mustRun(t, "class", "sessions", st, id[1]); !strings.Contains(out, "alice") {
		t.Fatal(out)
	}
	if out := mustRun(t, "ca", "export", st); !strings.Contains(out, "BEGIN CERTIFICATE") {
		t.Fatal(out)
	}
	tokFile := filepath.Join(shortDir(t), "teacher.token")
	if out := mustRun(t, "teacher-session", st, cls, "--out", tokFile); !strings.Contains(out, "teacher") {
		t.Fatal(out)
	}
	mustRun(t, "rule", "delete", ruleID, st, cls)
	mustRun(t, "class", "kick", id[1], "bob", st)
	mustRun(t, "class", "rotate-code", id[1], st)
	mustRun(t, "class", "delete", id[1], st)
}

func TestRefusals(t *testing.T) {
	sd := filepath.Join(shortDir(t), "s")
	ctx := context.Background()
	if _, err := run(t, ctx, "serve", "--state-dir="+sd, "--tls", "off", "--listen", "0.0.0.0:0"); err == nil {
		t.Fatal("--tls off on a public address")
	}
	if _, err := run(t, ctx, "rule", "add", "x", "--state-dir="+sd); err == nil {
		t.Fatal("rule add without a direction")
	}
	if _, err := run(t, ctx, "class", "list", "--server", "http://example.org"); err == nil {
		t.Fatal("cleartext remote admin")
	}
	if _, err := run(t, ctx, "class", "list", "--server", "https://example.org"); err == nil || !strings.Contains(err.Error(), "token-file") {
		t.Fatalf("remote admin without a token file: %v", err)
	}
	if _, err := run(t, ctx, "teacher-session", "--state-dir="+sd); err == nil {
		t.Fatal("teacher-session without --out")
	}
	out, err := run(t, ctx, "version")
	if err != nil || !strings.Contains(out, "wctr-relay") {
		t.Fatal(out, err)
	}
	var o, e bytes.Buffer
	if Main([]string{"nope"}, &o, &e) != 1 || !strings.Contains(e.String(), "wctr-relay:") {
		t.Fatal(e.String())
	}
}
