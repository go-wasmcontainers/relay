// SPDX-License-Identifier: BSD-3-Clause

package cli

import (
	"context"
	"crypto/tls"
	"crypto/x509"
	"errors"
	"fmt"
	"log"
	"net"
	"net/http"
	"net/netip"
	"os"
	"os/signal"
	"path/filepath"
	"strings"
	"syscall"
	"time"

	"github.com/go-authn/oidc"
	"github.com/go-authn/servercert"
	"github.com/spf13/cobra"

	"github.com/go-wasmcontainers/relay/internal/statedir"
	"github.com/go-wasmcontainers/relay/relay"
	"github.com/go-wasmcontainers/relay/server"
	"github.com/go-wasmcontainers/relay/tlsca"
)

type serveFlags struct {
	listen, adminListen      string
	tlsMode                  string
	certFile, keyFile        string
	acmeDomains              []string
	acmeEmail, acmeDirectory string
	acmeCache                string
	eabKID, eabHMACFile      string
	acmeHTTP                 string
	origins, hosts           []string
	oidcIssuer, oidcAudience string
	oidcType, teacherGroup   string
	auditRetention           time.Duration
	sessionTTL               time.Duration
	relayID                  string
}

// serveReady, when set (tests), receives the public listener's address.
var serveReady chan<- string

func serveCmd(g *globals) *cobra.Command {
	f := &serveFlags{}
	cmd := &cobra.Command{
		Use:   "serve",
		Short: "Run the relay",
		Long: "Run the relay: the data plane (wss://<listen>/v1/data) and the control API for students on --listen,\n" +
			"the admin API on the state directory's Unix socket (and on --admin-listen if given).\n\n" +
			"TLS (--tls): internal (the state directory's CA, see init --name/--ip), files (--cert/--key, reloaded on\n" +
			"change), acme (--acme-domain, through go-authn/servercert: tls-alpn-01, http-01 with --acme-http, or a CA\n" +
			"with pre-validated domains such as GÉANT TCS with --eab-*), or off (only on a loopback address, behind a\n" +
			"TLS proxy such as Caddy).",
		Args: cobra.NoArgs,
		RunE: func(cmd *cobra.Command, _ []string) error { return serve(cmd, g, f) },
	}
	fl := cmd.Flags()
	fl.StringVar(&f.listen, "listen", ":8443", "address students reach")
	fl.StringVar(&f.adminListen, "admin-listen", "", "also serve the admin API here (TLS; admin token or OIDC teacher role)")
	fl.StringVar(&f.tlsMode, "tls", "internal", "internal, files, acme or off")
	fl.StringVar(&f.certFile, "cert", "", "certificate chain (--tls files)")
	fl.StringVar(&f.keyFile, "key", "", "private key (--tls files)")
	fl.StringSliceVar(&f.acmeDomains, "acme-domain", nil, "name to obtain a certificate for (--tls acme; repeatable)")
	fl.StringVar(&f.acmeEmail, "acme-email", "", "ACME account contact")
	fl.StringVar(&f.acmeDirectory, "acme-directory", "", "ACME directory URL (default Let's Encrypt)")
	fl.StringVar(&f.acmeCache, "acme-cache", "", "ACME cache directory (default <state>/acme)")
	fl.StringVar(&f.eabKID, "eab-kid", "", "External Account Binding key id")
	fl.StringVar(&f.eabHMACFile, "eab-hmac-file", "", "file holding the EAB HMAC key (0600)")
	fl.StringVar(&f.acmeHTTP, "acme-http", "", "also answer http-01 on this address (e.g. :80)")
	fl.StringArrayVar(&f.origins, "cors-origin", nil,
		"browser origin allowed besides the relay's own, e.g. https://go-wasmcontainers.github.io (repeatable; never *): CORS on Join, RefreshSession and the flow views, and the data WebSocket's Origin check")
	fl.StringSliceVar(&f.hosts, "host", nil, "Host names (or addresses) served; others are refused (DNS rebinding)")
	fl.StringVar(&f.oidcIssuer, "oidc-issuer", "", "OpenID Connect issuer whose tokens identify people")
	fl.StringVar(&f.oidcAudience, "oidc-audience", "", "audience the tokens must name (this relay's client id)")
	fl.StringVar(&f.oidcType, "oidc-type", "", `token "typ" to require ("at+jwt" for access tokens)`)
	fl.StringVar(&f.teacherGroup, "teacher-group", "", "groups-claim value that grants the teacher role on --admin-listen")
	fl.DurationVar(&f.auditRetention, "audit-retention", 30*24*time.Hour, "audit log retention")
	fl.DurationVar(&f.sessionTTL, "session-ttl", 12*time.Hour, "session token lifetime")
	fl.StringVar(&f.relayID, "relay-id", "", "this relay's id (default: the host name)")
	return cmd
}

func isLoopbackListen(addr string) bool {
	host, _, err := net.SplitHostPort(addr)
	if err != nil {
		return false
	}
	if host == "localhost" {
		return true
	}
	a, err := netip.ParseAddr(host)
	return err == nil && a.IsLoopback()
}

func publicTLS(d statedir.Dir, f *serveFlags, logf func(string, ...any)) (*tls.Config, http.Handler, error) {
	switch f.tlsMode {
	case "off":
		if !isLoopbackListen(f.listen) {
			return nil, nil, errors.New("--tls off is only allowed on a loopback --listen (behind a TLS proxy)")
		}
		return nil, nil, nil
	case "internal":
		ca, err := tlsca.Load(d.CA())
		if err != nil {
			return nil, nil, fmt.Errorf("internal CA: %w (run: wctr-relay init --name <name> --ip <address>)", err)
		}
		return ca.TLSConfig(), nil, nil
	case "files":
		src, err := servercert.New(servercert.Config{CertFile: abs(f.certFile), KeyFile: abs(f.keyFile), OnError: func(err error) { logf("tls: %v", err) }})
		if err != nil {
			return nil, nil, err
		}
		return src.TLSConfig(), nil, nil
	case "acme":
		cache := f.acmeCache
		if cache == "" {
			cache = filepath.Join(string(d), "acme")
		}
		src, err := servercert.New(servercert.Config{ACME: &servercert.ACME{DirectoryURL: f.acmeDirectory, Email: f.acmeEmail,
			Domains: f.acmeDomains, CacheDir: abs(cache), EABKeyID: f.eabKID, EABHMACKeyFile: abs(f.eabHMACFile),
			HTTPChallenge: f.acmeHTTP != ""}, OnError: func(err error) { logf("acme: %v", err) }})
		if err != nil {
			return nil, nil, err
		}
		var h http.Handler
		if f.acmeHTTP != "" {
			h = src.HTTPHandler(nil)
		}
		go func() {
			ctx, cancel := context.WithTimeout(context.Background(), 5*time.Minute)
			defer cancel()
			if err := src.Prefetch(ctx); err != nil {
				logf("acme prefetch: %v", err)
			}
		}()
		return src.TLSConfig(), h, nil
	}
	return nil, nil, fmt.Errorf("--tls %q: internal, files, acme or off", f.tlsMode)
}

func abs(p string) string {
	if p == "" {
		return ""
	}
	a, err := filepath.Abs(p)
	if err != nil {
		return p
	}
	return a
}

func serve(cmd *cobra.Command, g *globals, f *serveFlags) error {
	d, err := g.dir()
	if err != nil {
		return err
	}
	if err := d.Ensure(); err != nil {
		return err
	}
	logger := log.New(cmd.ErrOrStderr(), "wctr-relay ", log.LstdFlags)
	logf := logger.Printf
	keys, err := d.Keys()
	if err != nil {
		return fmt.Errorf("%w (run: wctr-relay init)", err)
	}
	adminToken, err := d.AdminToken()
	if err != nil {
		return err
	}
	audit, err := d.OpenAudit(f.auditRetention, time.Now())
	if err != nil {
		return err
	}
	defer audit.Close()
	id := f.relayID
	if id == "" {
		id, _ = os.Hostname()
	}
	r, err := relay.New(relay.Config{RelayID: id, Store: relay.FileStore{Path: d.State()}, Keys: keys,
		SessionTTL: f.sessionTTL, Audit: audit.Write})
	if err != nil {
		return err
	}
	ctx, stop := signal.NotifyContext(cmd.Context(), os.Interrupt, syscall.SIGTERM)
	defer stop()
	var verifier *oidc.Verifier
	if f.oidcIssuer != "" {
		if f.oidcAudience == "" {
			return errors.New("--oidc-issuer needs --oidc-audience")
		}
		verifier, err = oidc.New(ctx, oidc.Config{Issuer: f.oidcIssuer, Audience: f.oidcAudience, Type: f.oidcType})
		if err != nil {
			return fmt.Errorf("oidc: %w", err)
		}
	}
	tlsCfg, acmeHTTP, err := publicTLS(d, f, logf)
	if err != nil {
		return err
	}
	var hosts []string
	for _, h := range f.hosts {
		hosts = append(hosts, strings.ToLower(h))
	}
	srv, err := server.New(server.Config{Relay: r, AdminToken: adminToken, OIDC: verifier, TeacherGroup: f.teacherGroup,
		AllowedOrigins: f.origins, AllowedHosts: hosts, TLSMode: f.tlsMode, Logf: logf})
	if err != nil {
		return err
	}
	server.Version = Version

	// Admin socket: 0600, bound without a window (see listenAdmin).
	sock, err := g.adminSocket()
	if err != nil {
		return err
	}
	ul, err := listenAdmin(sock)
	if err != nil {
		return err
	}
	defer os.Remove(sock)

	pl, err := net.Listen("tcp", f.listen)
	if err != nil {
		ul.Close()
		return err
	}
	hs := func(h http.Handler) *http.Server {
		return &http.Server{Handler: h, ReadHeaderTimeout: 5 * time.Second, IdleTimeout: 120 * time.Second,
			MaxHeaderBytes: 16 << 10, ErrorLog: logger}
	}
	pub := hs(srv.Public())
	adm := hs(srv.AdminTrusted())
	errc := make(chan error, 4)
	go func() { errc <- adm.Serve(ul) }()
	if tlsCfg != nil {
		tlsCfg.NextProtos = append(tlsCfg.NextProtos, "h2", "http/1.1")
		go func() { errc <- pub.Serve(tls.NewListener(pl, tlsCfg)) }()
	} else {
		go func() { errc <- pub.Serve(pl) }()
	}
	var extra []*http.Server
	if f.adminListen != "" {
		if tlsCfg == nil && !isLoopbackListen(f.adminListen) {
			return errors.New("--admin-listen without TLS is only allowed on loopback")
		}
		al, err := net.Listen("tcp", f.adminListen)
		if err != nil {
			return err
		}
		a2 := hs(srv.Admin())
		extra = append(extra, a2)
		if tlsCfg != nil {
			go func() { errc <- a2.Serve(tls.NewListener(al, tlsCfg)) }()
		} else {
			go func() { errc <- a2.Serve(al) }()
		}
	}
	if acmeHTTP != nil {
		h := hs(acmeHTTP)
		extra = append(extra, h)
		go func() { errc <- listenAndServe(h, f.acmeHTTP) }()
	}
	logf("listening on %s (tls %s), admin socket %s", pl.Addr(), f.tlsMode, sock)
	if serveReady != nil {
		serveReady <- pl.Addr().String()
	}
	select {
	case <-ctx.Done():
	case err := <-errc:
		if err != nil && !errors.Is(err, http.ErrServerClosed) {
			logf("serve: %v", err)
		}
	}
	sctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()
	for _, s := range append([]*http.Server{pub, adm}, extra...) {
		s.Shutdown(sctx)
	}
	return nil
}

func listenAndServe(s *http.Server, addr string) error {
	l, err := net.Listen("tcp", addr)
	if err != nil {
		return err
	}
	return s.Serve(l)
}

func loadPool(path string) (*x509.CertPool, error) {
	b, err := os.ReadFile(path)
	if err != nil {
		return nil, err
	}
	p := x509.NewCertPool()
	if !p.AppendCertsFromPEM(b) {
		return nil, errors.New(path + ": no PEM certificate")
	}
	return p, nil
}

func initCA(d statedir.Dir, names []string, ips []netip.Addr) error {
	return tlsca.Init(d.CA(), names, ips)
}
