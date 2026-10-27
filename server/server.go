// SPDX-License-Identifier: BSD-3-Clause

// Package server puts the relay on the network: the data plane as a
// WebSocket at /v1/data, the control API as Connect handlers (gRPC,
// gRPC-Web and the Connect protocol on one handler), and /v1/info.
//
// Two handlers, never one: Public is what students reach (the LAN, or the
// internet); it never grants the admin role, whatever credential arrives.
// Admin is mounted on the Unix socket and loopback, or on a separate
// --admin-listen, and requires the admin token or the OpenID Connect
// teacher role.
package server

import (
	"context"
	"encoding/json"
	"errors"
	"net"
	"net/http"
	"strings"
	"sync"
	"time"

	"connectrpc.com/connect/v2"
	"connectrpc.com/connect/v2/connecthttp"
	"github.com/coder/websocket"
	"github.com/go-authn/oidc"

	"github.com/go-wasmcontainers/relay/auth"
	"github.com/go-wasmcontainers/relay/frame"
	"github.com/go-wasmcontainers/relay/gen/relayv1/relayv1connect"
	"github.com/go-wasmcontainers/relay/relay"
)

// Version is the relay's release, reported by /v1/info.
var Version = "devel"

// Config configures the HTTP side of a relay.
type Config struct {
	Relay *relay.Relay
	// AdminToken is the teacher's admin credential (Admin handler only).
	AdminToken string
	// OIDC, when set, verifies OpenID Connect tokens: on Join and
	// RefreshSession (the identity), and on the Admin handler with the
	// TeacherGroup.
	OIDC         *oidc.Verifier
	TeacherGroup string
	// AllowedOrigins are the browser origins (scheme://host[:port], e.g.
	// "https://go-wasmcontainers.github.io") allowed besides the relay's own:
	// CORS on the public RPCs a page needs (Join, RefreshSession, the flow
	// views) and the Origin check of the data WebSocket. Never "*"; empty
	// means same-origin only.
	AllowedOrigins []string
	// AllowedHosts, when set, are the only Host headers served (DNS
	// rebinding); ports are ignored.
	AllowedHosts []string
	// PreAuthPerMinute bounds Join calls and WebSocket upgrades per source
	// address (default 30); MaxHandshakes bounds concurrent upgrades still
	// waiting for their HELLO (default 32).
	PreAuthPerMinute int
	MaxHandshakes    int
	// TLSMode is reported by /v1/info ("acme", "files", "internal", "off").
	TLSMode string
	Logf    func(format string, args ...any)
}

// Server serves one relay.
type Server struct {
	cfg     Config
	ipl     *ipLimiter
	hand    chan struct{}
	origins []string // normalised AllowedOrigins
}

// New checks cfg and returns a Server.
func New(cfg Config) (*Server, error) {
	if cfg.Relay == nil {
		return nil, errors.New("server: no relay")
	}
	if cfg.PreAuthPerMinute == 0 {
		cfg.PreAuthPerMinute = 30
	}
	if cfg.MaxHandshakes == 0 {
		cfg.MaxHandshakes = 32
	}
	if cfg.Logf == nil {
		cfg.Logf = func(string, ...any) {}
	}
	origins := make([]string, 0, len(cfg.AllowedOrigins))
	for _, o := range cfg.AllowedOrigins {
		n, err := NormalizeOrigin(o)
		if err != nil {
			return nil, err
		}
		origins = append(origins, n)
	}
	return &Server{cfg: cfg, ipl: newIPLimiter(float64(cfg.PreAuthPerMinute)/60, float64(cfg.PreAuthPerMinute)),
		hand: make(chan struct{}, cfg.MaxHandshakes), origins: origins}, nil
}

// ---------------------------------------------------------------- principals

type principalKey struct{}

// Principal is who is calling, as the handler established it.
type Principal struct {
	Admin    bool
	Session  *auth.Claims    // a student's (or the teacher's) session token
	Identity *relay.Identity // an OpenID Connect identity
	MapClass string          // a flow-map ticket's class: WatchFlowMap on it, nothing else
}

func principal(ctx context.Context) *Principal {
	p, _ := ctx.Value(principalKey{}).(*Principal)
	if p == nil {
		return &Principal{}
	}
	return p
}

func bearer(r *http.Request) string {
	h := r.Header.Get("Authorization")
	if len(h) > 7 && strings.EqualFold(h[:7], "bearer ") {
		return strings.TrimSpace(h[7:])
	}
	return ""
}

// sessionHeader carries a session token on control calls (the
// Authorization header may hold the OIDC token at the same time).
const sessionHeader = "Wctr-Session"

// mapTicketHeader carries a flow-map ticket (FlowMapService.FlowMapTicket).
const mapTicketHeader = "Wctr-Map-Ticket"

func (s *Server) identity(ctx context.Context, raw string) *relay.Identity {
	if s.cfg.OIDC == nil || raw == "" {
		return nil
	}
	tok, err := s.cfg.OIDC.Verify(ctx, raw)
	if err != nil {
		s.cfg.Logf("oidc: %v", err)
		return nil
	}
	id := &relay.Identity{Issuer: tok.Issuer(), Subject: tok.Subject(), Groups: tok.Groups()}
	if tok.EmailVerified() {
		id.Email = tok.Email()
	}
	return id
}

// ------------------------------------------------------------------ handlers

// Public is the handler students reach.
func (s *Server) Public() http.Handler {
	mux := http.NewServeMux()
	mux.HandleFunc("GET /v1/info", s.info)
	mux.HandleFunc("GET /v1/data", s.data)
	mux.Handle("GET /flowmap/", flowMapPage())
	cs := connect.NewServer()
	svc := &services{s: s}
	relayv1connect.RegisterJoinServiceHandler(cs, svc)
	relayv1connect.RegisterPortServiceHandler(cs, svc)
	relayv1connect.RegisterFlowLogServiceHandler(cs, svc)
	relayv1connect.RegisterSecurityGroupServiceHandler(cs, svc)
	connecthttp.Mount(mux, cs, connecthttp.WithReadMaxBytes(1<<20))
	return s.guard(s.cors(mux), false)
}

// Admin is the handler for the teacher: Unix socket, loopback, or a
// separate admin listener.
func (s *Server) Admin() http.Handler {
	return s.adminHandler(false)
}

// AdminTrusted is Admin for a listener whose callers are trusted by
// construction (a Unix socket only its owner can open): no token needed.
func (s *Server) AdminTrusted() http.Handler {
	return s.adminHandler(true)
}

func (s *Server) adminHandler(trusted bool) http.Handler {
	mux := http.NewServeMux()
	mux.HandleFunc("GET /v1/info", s.info)
	cs := connect.NewServer()
	svc := &services{s: s}
	relayv1connect.RegisterClassServiceHandler(cs, svc)
	relayv1connect.RegisterFlowMapServiceHandler(cs, svc)
	relayv1connect.RegisterJoinServiceHandler(cs, svc)
	relayv1connect.RegisterPortServiceHandler(cs, svc)
	relayv1connect.RegisterFlowLogServiceHandler(cs, svc)
	relayv1connect.RegisterSecurityGroupServiceHandler(cs, svc)
	connecthttp.Mount(mux, cs, connecthttp.WithReadMaxBytes(1<<20))
	h := http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		p := &Principal{}
		if trusted {
			p.Admin = true
		} else if tok := bearer(r); tok != "" {
			if s.cfg.AdminToken != "" && auth.Equal(tok, s.cfg.AdminToken) {
				p.Admin = true
			} else if id := s.identity(r.Context(), tok); id != nil && s.cfg.TeacherGroup != "" && contains(id.Groups, s.cfg.TeacherGroup) {
				p.Admin, p.Identity = true, id
			}
		}
		if !p.Admin && r.URL.Path != "/v1/info" {
			http.Error(w, "unauthenticated", http.StatusUnauthorized)
			return
		}
		mux.ServeHTTP(w, r.WithContext(context.WithValue(r.Context(), principalKey{}, p)))
	})
	return s.guard(h, true)
}

func contains(list []string, v string) bool {
	for _, x := range list {
		if x == v {
			return true
		}
	}
	return false
}

// guard applies the Host check, security headers and, on the public
// handler, the student principal.
func (s *Server) guard(h http.Handler, admin bool) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if len(s.cfg.AllowedHosts) > 0 {
			host := r.Host
			if hh, _, err := net.SplitHostPort(host); err == nil {
				host = hh
			}
			if !contains(s.cfg.AllowedHosts, strings.ToLower(host)) {
				http.Error(w, "unknown host", http.StatusMisdirectedRequest)
				return
			}
		}
		hd := w.Header()
		hd.Set("X-Content-Type-Options", "nosniff")
		hd.Set("Referrer-Policy", "no-referrer")
		hd.Set("Cross-Origin-Resource-Policy", "same-origin")
		ctx := context.WithValue(r.Context(), requestKey{}, r)
		if !admin {
			p := &Principal{}
			if tok := r.Header.Get(sessionHeader); tok != "" {
				if cl, err := s.cfg.Relay.Authenticate(tok); err == nil {
					p.Session = &cl
				}
			}
			if tok := r.Header.Get(mapTicketHeader); tok != "" {
				if cls, err := s.cfg.Relay.VerifyMapTicket(tok); err == nil {
					p.MapClass = cls
				}
			}
			ctx = context.WithValue(ctx, principalKey{}, p)
		}
		h.ServeHTTP(w, r.WithContext(ctx))
	})
}

func (s *Server) info(w http.ResponseWriter, r *http.Request) {
	w.Header().Set("Content-Type", "application/json")
	w.Header().Set("Cache-Control", "no-store")
	_ = json.NewEncoder(w).Encode(map[string]any{
		"name": "wctr-relay", "version": Version, "protocol": frame.Version, "tls": s.cfg.TLSMode,
	})
}

// --------------------------------------------------------------- data plane

// TokenFromSubprotocols finds the session token a client offered as a
// "bearer.<token>" subprotocol.
func TokenFromSubprotocols(h http.Header) string {
	for _, v := range h.Values("Sec-WebSocket-Protocol") {
		for _, p := range strings.Split(v, ",") {
			p = strings.TrimSpace(p)
			if strings.HasPrefix(p, frame.BearerPrefix) {
				return p[len(frame.BearerPrefix):]
			}
		}
	}
	return ""
}

func clientIP(r *http.Request) string {
	host, _, err := net.SplitHostPort(r.RemoteAddr)
	if err != nil {
		return r.RemoteAddr
	}
	return host
}

func (s *Server) data(w http.ResponseWriter, r *http.Request) {
	// Cross-site WebSocket hijacking: a browser always sends Origin on an
	// upgrade; only the allowlist and the relay's own origin may open it.
	// Clients without a browser send none.
	if o := r.Header.Get("Origin"); o != "" && !s.originAllowed(r, o) {
		http.Error(w, "origin not allowed", http.StatusForbidden)
		return
	}
	if !s.ipl.allow(clientIP(r)) {
		http.Error(w, "slow down", http.StatusTooManyRequests)
		return
	}
	// Authenticate before the upgrade and before any per-session state.
	cl, err := s.cfg.Relay.Authenticate(TokenFromSubprotocols(r.Header))
	if err != nil {
		http.Error(w, "unauthenticated", http.StatusUnauthorized)
		return
	}
	select {
	case s.hand <- struct{}{}:
	default:
		http.Error(w, "busy", http.StatusServiceUnavailable)
		return
	}
	released := false
	release := func() {
		if !released {
			released = true
			<-s.hand
		}
	}
	defer release()
	// The Origin was checked above against exact origins (coder/websocket's
	// patterns are path.Match globs, which an IPv6 "[::1]" host breaks).
	c, err := websocket.Accept(w, r, &websocket.AcceptOptions{Subprotocols: []string{frame.Subprotocol}, InsecureSkipVerify: true})
	if err != nil {
		return
	}
	if c.Subprotocol() != frame.Subprotocol {
		c.Close(websocket.StatusPolicyViolation, "subprotocol "+frame.Subprotocol+" required")
		return
	}
	c.SetReadLimit(frame.MaxFrame)
	t := &wsTransport{c: c, onFirstRead: release}
	_ = s.cfg.Relay.Serve(r.Context(), t, cl)
}

// wsTransport adapts a WebSocket to relay.Transport.
type wsTransport struct {
	c           *websocket.Conn
	onFirstRead func()
	once        sync.Once
}

func (t *wsTransport) ReadMessage(ctx context.Context) ([]byte, error) {
	typ, b, err := t.c.Read(ctx)
	if t.onFirstRead != nil {
		t.once.Do(t.onFirstRead)
	}
	if err != nil {
		return nil, err
	}
	if typ != websocket.MessageBinary {
		return nil, errors.New("text message on the data channel")
	}
	return b, nil
}

func (t *wsTransport) WriteMessage(ctx context.Context, b []byte) error {
	ctx, cancel := context.WithTimeout(ctx, 30*time.Second)
	defer cancel()
	return t.c.Write(ctx, websocket.MessageBinary, b)
}

func (t *wsTransport) Close(reason string) error {
	if len(reason) > 120 {
		reason = reason[:120]
	}
	return t.c.Close(websocket.StatusNormalClosure, reason)
}

// ------------------------------------------------------------- IP limiter

type ipLimiter struct {
	mu    sync.Mutex
	rate  float64
	burst float64
	m     map[string]*ipBucket
}

type ipBucket struct {
	tokens float64
	last   time.Time
}

func newIPLimiter(rate, burst float64) *ipLimiter {
	return &ipLimiter{rate: rate, burst: burst, m: map[string]*ipBucket{}}
}

func (l *ipLimiter) allow(ip string) bool {
	l.mu.Lock()
	defer l.mu.Unlock()
	now := time.Now()
	if len(l.m) > 65536 {
		for k, b := range l.m {
			if now.Sub(b.last) > time.Minute {
				delete(l.m, k)
			}
		}
	}
	b := l.m[ip]
	if b == nil {
		b = &ipBucket{tokens: l.burst, last: now}
		l.m[ip] = b
	}
	b.tokens += now.Sub(b.last).Seconds() * l.rate
	if b.tokens > l.burst {
		b.tokens = l.burst
	}
	b.last = now
	if b.tokens < 1 {
		return false
	}
	b.tokens--
	return true
}
