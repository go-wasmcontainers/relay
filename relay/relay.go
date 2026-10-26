// SPDX-License-Identifier: BSD-3-Clause

// Package relay is the classroom relay's core, independent of any network
// transport: classes, sessions, ports and their addresses and DNS names,
// security groups enforced on every flow, connection tracking, the flow log,
// and the data plane that brokers streams and datagrams between sessions.
//
// A transport (package server: a WebSocket; tests: an in-memory pipe) hands
// Serve an authenticated connection; everything after that is frames
// (package frame).
package relay

import (
	"crypto/rand"
	"crypto/sha256"
	"encoding/hex"
	"errors"
	"fmt"
	"net/netip"
	"slices"
	"strconv"
	"strings"
	"sync"
	"time"

	"github.com/go-wasmcontainers/relay/auth"
	"github.com/go-wasmcontainers/relay/firewall"
	v1 "github.com/go-wasmcontainers/relay/gen/relayv1"
)

// Limits bounds what one session may use. Zero fields take the defaults.
type Limits struct {
	MaxStreams      int     // open streams per session (256)
	MaxListeners    int     // listening sockets per session (64)
	MaxPorts        int     // containers attached per session (10)
	MaxPending      int     // connects awaiting an answer per session (32)
	StreamWindow    uint32  // initial credit per stream direction (64 KiB)
	BytesPerSecond  float64 // sustained data rate per session (2 MiB/s)
	BurstBytes      float64 // (8 MiB)
	FramesPerSecond float64 // (2000)
	BurstFrames     float64 // (4000)
	MaxQueue        int     // bytes queued to one slow connection before it is closed (4 MiB)
	MaxDatagram     int     // UDP payload (8 KiB)
}

func (l Limits) withDefaults() Limits {
	def := func(v *int, d int) {
		if *v == 0 {
			*v = d
		}
	}
	deff := func(v *float64, d float64) {
		if *v == 0 {
			*v = d
		}
	}
	def(&l.MaxStreams, 256)
	def(&l.MaxListeners, 64)
	def(&l.MaxPorts, 10)
	def(&l.MaxPending, 32)
	if l.StreamWindow == 0 {
		l.StreamWindow = 64 << 10
	}
	deff(&l.BytesPerSecond, 2<<20)
	deff(&l.BurstBytes, 8<<20)
	deff(&l.FramesPerSecond, 2000)
	deff(&l.BurstFrames, 4000)
	def(&l.MaxQueue, 4<<20)
	def(&l.MaxDatagram, 8<<10)
	return l
}

// Identity is what an OpenID Connect token said about a person, as the
// server verified it. Only a pseudonymous hash of Issuer and Subject is
// kept; Email and Groups are used at the moment of the check and dropped.
type Identity struct {
	Issuer, Subject string
	Email           string // verified only; empty otherwise
	Groups          []string
}

func (id *Identity) hash() string {
	if id == nil || id.Subject == "" {
		return ""
	}
	h := sha256.Sum256([]byte(id.Issuer + "\x00" + id.Subject))
	return hex.EncodeToString(h[:16])
}

// Config configures a Relay.
type Config struct {
	RelayID    string
	Store      Store
	Keys       *auth.Keys
	Limits     Limits
	SessionTTL time.Duration // session token lifetime (12 h)
	UDPIdle    time.Duration // connection-tracking idle timeout for UDP (30 s)
	Now        func() time.Time
	// Audit, if set, receives login, rule and membership changes.
	Audit func(event string, fields map[string]string)
	// MaxClasses bounds the classes one relay holds (64).
	MaxClasses int
	// Quotas per class (Neutron's security_group and security_group_rule).
	MaxGroups, MaxRules int
}

// Error is a control-plane error with a kind the API maps to a status.
type Error struct {
	Kind Kind
	Msg  string
}

// Kind classifies an Error.
type Kind int

const (
	KindInvalid Kind = iota + 1
	KindNotFound
	KindExists
	KindDenied
	KindLimit
	KindUnauthenticated
)

func (e *Error) Error() string { return e.Msg }

func errf(k Kind, format string, a ...any) error {
	return &Error{Kind: k, Msg: fmt.Sprintf(format, a...)}
}

// ErrKind returns the kind of err, or 0.
func ErrKind(err error) Kind {
	var e *Error
	if errors.As(err, &e) {
		return e.Kind
	}
	return 0
}

// Relay is the core. All methods are safe for concurrent use.
type Relay struct {
	cfg    Config
	limits Limits

	mu      sync.Mutex
	st      *State
	classes map[string]*class
	codes   map[string]string // join code -> class id
}

// New loads the control plane from cfg.Store (or starts empty).
func New(cfg Config) (*Relay, error) {
	if cfg.Keys == nil {
		return nil, errors.New("relay: no signing keys")
	}
	if cfg.Store == nil {
		cfg.Store = &MemStore{}
	}
	if cfg.Now == nil {
		cfg.Now = time.Now
	}
	if cfg.SessionTTL == 0 {
		cfg.SessionTTL = 12 * time.Hour
	}
	if cfg.UDPIdle == 0 {
		cfg.UDPIdle = 30 * time.Second
	}
	if cfg.MaxClasses == 0 {
		cfg.MaxClasses = 64
	}
	if cfg.MaxGroups == 0 {
		cfg.MaxGroups = 50
	}
	if cfg.MaxRules == 0 {
		cfg.MaxRules = 500
	}
	if cfg.RelayID == "" {
		cfg.RelayID = "relay-1"
	}
	r := &Relay{cfg: cfg, limits: cfg.Limits.withDefaults(), classes: map[string]*class{}, codes: map[string]string{}}
	st, err := cfg.Store.Load()
	if err != nil {
		return nil, err
	}
	if st == nil {
		st = &State{Version: 1, RelayID: cfg.RelayID, Classes: map[string]*sClass{}}
	}
	if st.Classes == nil {
		st.Classes = map[string]*sClass{}
	}
	r.st = st
	for _, sc := range st.Classes {
		c, err := newClass(r, sc)
		if err != nil {
			return nil, fmt.Errorf("relay: class %s: %w", sc.ID, err)
		}
		r.classes[sc.ID] = c
		r.codes[sc.JoinCode] = sc.ID
	}
	return r, nil
}

// Limits is what the relay enforces per session.
func (r *Relay) Limits() Limits { return r.limits }

func (r *Relay) save() error { return r.cfg.Store.Save(r.st) }

func (r *Relay) audit(event string, kv ...string) {
	if r.cfg.Audit == nil {
		return
	}
	m := map[string]string{}
	for i := 0; i+1 < len(kv); i += 2 {
		m[kv[i]] = kv[i+1]
	}
	r.cfg.Audit(event, m)
}

func randomID(prefix string) string {
	var b [8]byte
	_, _ = rand.Read(b[:])
	return prefix + hex.EncodeToString(b[:])
}

// ------------------------------------------------------------------ classes

// ClassSpec is what CreateClass needs.
type ClassSpec struct {
	Name        string
	CIDR        string // default 10.42.0.0/16
	SessionBits int    // default 24
	DNSDomain   string // default "class"
	Template    v1.Template
	Allowed     []string
	RequireID   bool
}

// CreateClass makes a class with its network, its join code and its default
// security group (isolated, or Neutron's default).
func (r *Relay) CreateClass(spec ClassSpec) (*v1.Class, error) {
	if spec.Name == "" || len(spec.Name) > 100 {
		return nil, errf(KindInvalid, "a class needs a name of 1 to 100 bytes")
	}
	if spec.CIDR == "" {
		spec.CIDR = "10.42.0.0/16"
	}
	if spec.SessionBits == 0 {
		spec.SessionBits = 24
	}
	if spec.DNSDomain == "" {
		spec.DNSDomain = "class"
	}
	if err := checkDomain(spec.DNSDomain); err != nil {
		return nil, err
	}
	pfx, err := netip.ParsePrefix(spec.CIDR)
	if err != nil || !pfx.Addr().Is4() || pfx.Masked() != pfx {
		return nil, errf(KindInvalid, "network %q: want an IPv4 network such as 10.42.0.0/16", spec.CIDR)
	}
	if spec.SessionBits <= pfx.Bits() || spec.SessionBits > 29 {
		return nil, errf(KindInvalid, "session subnets /%d must be longer than the class network /%d and at most /29", spec.SessionBits, pfx.Bits())
	}
	for _, a := range spec.Allowed {
		if err := checkAllowed(a); err != nil {
			return nil, err
		}
	}
	code, err := auth.NewJoinCode()
	if err != nil {
		return nil, err
	}
	r.mu.Lock()
	defer r.mu.Unlock()
	if len(r.classes) >= r.cfg.MaxClasses {
		return nil, errf(KindLimit, "this relay holds %d classes already", len(r.classes))
	}
	sc := &sClass{
		ID: randomID("c-"), Name: spec.Name, JoinCode: code, CIDR: pfx.String(), SessionBits: spec.SessionBits,
		DNSDomain: spec.DNSDomain, Template: int(spec.Template), Allowed: spec.Allowed, RequireID: spec.RequireID,
		Created: r.cfg.Now().Unix(), Epoch: 1, Groups: map[string]*sGroup{}, Sessions: map[string]*sSess{}, Ports: map[string]*sPort{},
	}
	// The default group, after the template.
	g := &sGroup{ID: sc.newID("sg-"), Name: "default", Stateful: true}
	teacherNet := subnet(pfx, spec.SessionBits, 0)
	switch spec.Template {
	case v1.Template_TEMPLATE_NEUTRON_DEFAULT:
		g.Description = "Neutron's default: all egress, ingress from the same group"
		g.Rules = []sRule{
			{ID: sc.newID("r-"), Direction: uint8(firewall.Egress)},
			{ID: sc.newID("r-"), Direction: uint8(firewall.Ingress), RemoteGroup: g.ID},
		}
	default:
		g.Description = "isolated: no ingress, egress to the teacher's subnet only"
		g.Rules = []sRule{
			{ID: sc.newID("r-"), Direction: uint8(firewall.Egress), RemotePrefix: teacherNet.String(), Description: "to the teacher"},
		}
	}
	sc.Groups[g.ID] = g
	sc.DefaultSG = g.ID
	c, err := newClass(r, sc)
	if err != nil {
		return nil, err
	}
	r.st.Classes[sc.ID] = sc
	r.classes[sc.ID] = c
	r.codes[code] = sc.ID
	if err := r.save(); err != nil {
		delete(r.st.Classes, sc.ID)
		delete(r.classes, sc.ID)
		delete(r.codes, code)
		return nil, err
	}
	r.audit("class.create", "class", sc.ID, "name", sc.Name)
	return c.proto(true), nil
}

func checkDomain(d string) error {
	if len(d) > 63 {
		return errf(KindInvalid, "dns domain too long")
	}
	for _, l := range strings.Split(d, ".") {
		if l == "" || l[0] == '-' || l[len(l)-1] == '-' {
			return errf(KindInvalid, "dns domain %q: bad label", d)
		}
		for _, ch := range l {
			if !(ch >= 'a' && ch <= 'z' || ch >= '0' && ch <= '9' || ch == '-') {
				return errf(KindInvalid, "dns domain %q: lower-case letters, digits and hyphens only", d)
			}
		}
	}
	return nil
}

func checkAllowed(a string) error {
	kind, val, ok := strings.Cut(a, ":")
	if !ok || val == "" || len(a) > 256 {
		return errf(KindInvalid, "allowed entry %q: want sub:<subject>, email:<address> or group:<group>", a)
	}
	switch kind {
	case "sub", "email", "group":
		return nil
	}
	return errf(KindInvalid, "allowed entry %q: want sub:, email: or group:", a)
}

func (sc *sClass) newID(prefix string) string {
	sc.NextID++
	return prefix + strconv.FormatUint(sc.NextID, 10)
}

// subnet is the n-th /bits subnet of pfx.
func subnet(pfx netip.Prefix, bits, n int) netip.Prefix {
	a := pfx.Addr().As4()
	base := uint32(a[0])<<24 | uint32(a[1])<<16 | uint32(a[2])<<8 | uint32(a[3])
	base += uint32(n) << (32 - bits)
	return netip.PrefixFrom(netip.AddrFrom4([4]byte{byte(base >> 24), byte(base >> 16), byte(base >> 8), byte(base)}), bits)
}

// host is the h-th address of a subnet.
func host(sn netip.Prefix, h int) netip.Addr {
	a := sn.Addr().As4()
	v := uint32(a[0])<<24 | uint32(a[1])<<16 | uint32(a[2])<<8 | uint32(a[3])
	v += uint32(h)
	return netip.AddrFrom4([4]byte{byte(v >> 24), byte(v >> 16), byte(v >> 8), byte(v)})
}

// GetClass returns a class; withCode shows the join code (teacher only).
func (r *Relay) GetClass(id string, withCode bool) (*v1.Class, error) {
	r.mu.Lock()
	defer r.mu.Unlock()
	c, ok := r.classes[id]
	if !ok {
		return nil, errf(KindNotFound, "no class %s", id)
	}
	return c.proto(withCode), nil
}

// ListClasses lists every class, oldest first.
func (r *Relay) ListClasses() []*v1.Class {
	r.mu.Lock()
	defer r.mu.Unlock()
	var out []*v1.Class
	for _, c := range r.classes {
		out = append(out, c.proto(true))
	}
	slices.SortFunc(out, func(a, b *v1.Class) int {
		if a.CreatedUnix != b.CreatedUnix {
			return int(a.CreatedUnix - b.CreatedUnix)
		}
		return strings.Compare(a.Id, b.Id)
	})
	return out
}

// DeleteClass ends every session of the class and forgets it, identities
// included.
func (r *Relay) DeleteClass(id string) error {
	r.mu.Lock()
	c, ok := r.classes[id]
	if !ok {
		r.mu.Unlock()
		return errf(KindNotFound, "no class %s", id)
	}
	conns := c.allConns()
	delete(r.classes, id)
	delete(r.codes, c.s.JoinCode)
	delete(r.st.Classes, id)
	err := r.save()
	r.mu.Unlock()
	for _, cn := range conns {
		cn.goAway(v1.Code_CODE_UNAUTHENTICATED, "the class was deleted")
	}
	c.closeSubs()
	r.audit("class.delete", "class", id)
	return err
}

// RotateJoinCode draws a new join code; the old one stops admitting anyone.
// Existing sessions are not affected (KickSession ends one).
func (r *Relay) RotateJoinCode(id string) (*v1.Class, error) {
	code, err := auth.NewJoinCode()
	if err != nil {
		return nil, err
	}
	r.mu.Lock()
	defer r.mu.Unlock()
	c, ok := r.classes[id]
	if !ok {
		return nil, errf(KindNotFound, "no class %s", id)
	}
	delete(r.codes, c.s.JoinCode)
	c.s.JoinCode = code
	r.codes[code] = id
	if err := r.save(); err != nil {
		return nil, err
	}
	r.audit("class.rotate_code", "class", id)
	return c.proto(true), nil
}

// ------------------------------------------------------------------ sessions

// Joined is what Join and TeacherSession return.
type Joined struct {
	Token   string
	Expires time.Time
	Session *v1.Session
	Class   *v1.Class
}

// Join admits a student with a class's join code. With an identity, the
// class's allowed list is checked and one identity gets one session per
// class (joining again returns it). A class that requires an identity
// refuses a join without one.
func (r *Relay) Join(code, display string, id *Identity) (*Joined, error) {
	norm, err := auth.NormalizeJoinCode(code)
	if err != nil {
		return nil, errf(KindDenied, "unknown join code")
	}
	display = auth.CleanDisplayName(display)
	if display == "" {
		return nil, errf(KindInvalid, "a display name is needed")
	}
	r.mu.Lock()
	defer r.mu.Unlock()
	cid, ok := r.codes[norm]
	if !ok {
		return nil, errf(KindDenied, "unknown join code")
	}
	c := r.classes[cid]
	if c.s.RequireID && (id == nil || id.Subject == "") {
		return nil, errf(KindUnauthenticated, "this class needs you to log in")
	}
	if id != nil && len(c.s.Allowed) > 0 && !allowed(c.s.Allowed, id) {
		r.audit("session.refused", "class", cid, "identity", id.hash())
		return nil, errf(KindDenied, "you are not on this class's list")
	}
	var s *sSess
	if h := id.hash(); h != "" {
		for _, x := range c.s.Sessions {
			if x.Identity == h && !x.Teacher {
				s = x
				break
			}
		}
	}
	if s == nil {
		s, err = c.addSession(display, false, id.hash())
		if err != nil {
			return nil, err
		}
		if err := r.save(); err != nil {
			delete(c.s.Sessions, s.ID)
			return nil, err
		}
	}
	r.audit("session.join", "class", cid, "session", s.ID, "label", s.Label, "identity", s.Identity)
	return r.issue(c, s)
}

func allowed(list []string, id *Identity) bool {
	for _, a := range list {
		kind, val, _ := strings.Cut(a, ":")
		switch kind {
		case "sub":
			if val == id.Subject {
				return true
			}
		case "email":
			if id.Email != "" && strings.EqualFold(val, id.Email) {
				return true
			}
		case "group":
			if slices.Contains(id.Groups, val) {
				return true
			}
		}
	}
	return false
}

// TeacherSession is the teacher's own session in a class (subnet 0, label
// "teacher"), so the teacher's containers can publish shared services.
func (r *Relay) TeacherSession(classID string) (*Joined, error) {
	r.mu.Lock()
	defer r.mu.Unlock()
	c, ok := r.classes[classID]
	if !ok {
		return nil, errf(KindNotFound, "no class %s", classID)
	}
	var s *sSess
	for _, x := range c.s.Sessions {
		if x.Teacher {
			s = x
		}
	}
	if s == nil {
		var err error
		if s, err = c.addSession("teacher", true, ""); err != nil {
			return nil, err
		}
		if err := r.save(); err != nil {
			return nil, err
		}
	}
	return r.issue(c, s)
}

func (r *Relay) issue(c *class, s *sSess) (*Joined, error) {
	exp := r.cfg.Now().Add(r.cfg.SessionTTL)
	tok, err := r.cfg.Keys.Sign(auth.Claims{Expiry: exp, Class: c.s.ID, Session: s.ID})
	if err != nil {
		return nil, err
	}
	return &Joined{Token: tok, Expires: exp, Session: c.sessionProto(s), Class: c.proto(false)}, nil
}

// Authenticate checks a session token: signature, expiry, and that its
// session still exists (a kicked session's tokens stop working at once).
func (r *Relay) Authenticate(tok string) (auth.Claims, error) {
	cl, err := r.cfg.Keys.Verify(tok, r.cfg.Now())
	if err != nil {
		return auth.Claims{}, errf(KindUnauthenticated, "unauthenticated")
	}
	r.mu.Lock()
	defer r.mu.Unlock()
	c, ok := r.classes[cl.Class]
	if !ok {
		return auth.Claims{}, errf(KindUnauthenticated, "unauthenticated")
	}
	if _, ok := c.s.Sessions[cl.Session]; !ok {
		return auth.Claims{}, errf(KindUnauthenticated, "unauthenticated")
	}
	return cl, nil
}

// Refresh exchanges a valid session token for a new one. With an identity,
// it must be the session's.
func (r *Relay) Refresh(tok string, id *Identity) (*Joined, error) {
	cl, err := r.Authenticate(tok)
	if err != nil {
		return nil, err
	}
	r.mu.Lock()
	defer r.mu.Unlock()
	c, ok := r.classes[cl.Class]
	if !ok {
		return nil, errf(KindUnauthenticated, "unauthenticated")
	}
	s := c.s.Sessions[cl.Session]
	if s == nil {
		return nil, errf(KindUnauthenticated, "unauthenticated")
	}
	if s.Identity != "" && s.Identity != id.hash() {
		return nil, errf(KindUnauthenticated, "unauthenticated")
	}
	if c.s.RequireID && s.Identity == "" && !s.Teacher {
		return nil, errf(KindUnauthenticated, "unauthenticated")
	}
	return r.issue(c, s)
}

// ListSessions lists a class's sessions.
func (r *Relay) ListSessions(classID string) ([]*v1.Session, error) {
	r.mu.Lock()
	defer r.mu.Unlock()
	c, ok := r.classes[classID]
	if !ok {
		return nil, errf(KindNotFound, "no class %s", classID)
	}
	var out []*v1.Session
	for _, s := range c.s.Sessions {
		out = append(out, c.sessionProto(s))
	}
	slices.SortFunc(out, func(a, b *v1.Session) int { return strings.Compare(a.Subnet, b.Subnet) })
	return out, nil
}

// KickSession ends a session: its connection closes, its ports go, its
// tokens stop working.
func (r *Relay) KickSession(classID, who string) error {
	r.mu.Lock()
	c, ok := r.classes[classID]
	if !ok {
		r.mu.Unlock()
		return errf(KindNotFound, "no class %s", classID)
	}
	s := c.findSession(who)
	if s == nil {
		r.mu.Unlock()
		return errf(KindNotFound, "no session %s", who)
	}
	cn := c.conns[s.ID]
	for id, p := range c.s.Ports {
		if p.Session == s.ID {
			c.removePort(id)
		}
	}
	delete(c.s.Sessions, s.ID)
	delete(c.conns, s.ID)
	err := r.save()
	r.mu.Unlock()
	if cn != nil {
		cn.goAway(v1.Code_CODE_UNAUTHENTICATED, "removed from the class by the teacher")
	}
	r.audit("session.kick", "class", classID, "session", s.ID)
	return err
}
