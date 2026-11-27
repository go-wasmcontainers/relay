// SPDX-License-Identifier: BSD-3-Clause

package egress

import (
	"context"
	"errors"
	"fmt"
	"net/netip"
	"sync"
	"syscall"
	"time"
)

// Pin limits (threat model section 6, rule 3; proposals to be measured, D11).
const (
	MaxPins = 256
	PinTTL  = 5 * time.Minute
)

// Refusals. Each is a policy verdict (ECONNREFUSED in the guest) except
// ErrLimit, which is CODE_LIMIT (ENOBUFS).
var (
	ErrNotAllowlisted = errors.New("egress: destination is not allowlisted")
	ErrNotPinned      = errors.New("egress: address was not resolved by the gateway for this session")
	ErrPort           = errors.New("egress: only port 443 is reachable")
	ErrNoAddress      = errors.New("egress: the name has no usable IPv4 address")
	ErrLimit          = errors.New("egress: limit reached")
	ErrServerName     = errors.New("egress: the TLS server name is not the allowlisted name")
)

// DeniedError is an answer or address refused by the deny table.
type DeniedError struct {
	Addr   netip.Addr
	Reason string
}

func (e *DeniedError) Error() string { return "egress: " + e.Addr.String() + " refused: " + e.Reason }

// Resolver is the outside lookup. It must return every address of the name;
// the gateway judges them.
type Resolver interface {
	LookupAddrs(ctx context.Context, name string) ([]netip.Addr, error)
}

// Gateway is the policy of one egress-enabled class. Safe for concurrent
// use; it keeps no per-session state (that is Pins).
type Gateway struct {
	Allow    *Allowlist
	Resolver Resolver
	Now      func() time.Time
	// Extra are operator-supplied prefixes that are never dialled either
	// (the relay's own addresses, the class CIDR, internal ranges).
	Extra []netip.Prefix
}

// NewGateway checks its inputs: a non-empty allowlist and a resolver.
func NewGateway(a *Allowlist, r Resolver, extra []netip.Prefix) (*Gateway, error) {
	if a == nil || len(a.list) == 0 {
		return nil, errors.New("egress: no allowlist")
	}
	if r == nil {
		return nil, errors.New("egress: no resolver")
	}
	return &Gateway{Allow: a, Resolver: r, Now: time.Now, Extra: append([]netip.Prefix(nil), extra...)}, nil
}

func (g *Gateway) now() time.Time {
	if g.Now != nil {
		return g.Now()
	}
	return time.Now()
}

func (g *Gateway) deny(a netip.Addr) string {
	if r := Denied(a); r != "" {
		return r
	}
	u := a.Unmap()
	for _, p := range g.Extra {
		if p.Contains(u) {
			return "operator-denied range " + p.String()
		}
	}
	return ""
}

// Resolve is rule 1 and 2 of the threat model: only an exact allowlisted
// name is looked up outside, and if any address of the answer is not
// globally reachable the whole answer is refused (a mixed answer is the
// signature of DNS rebinding). The vetted IPv4 addresses are pinned for the
// session and returned; IPv6 answers are vetted but not used in v1 (D7).
func (g *Gateway) Resolve(ctx context.Context, p *Pins, name string) ([]netip.Addr, error) {
	name = Normalize(name)
	if !g.Allow.Has(name, Port) {
		return nil, ErrNotAllowlisted
	}
	addrs, err := g.Resolver.LookupAddrs(ctx, name)
	if err != nil {
		return nil, err
	}
	var v4 []netip.Addr
	for _, a := range addrs {
		if r := g.deny(a); r != "" {
			return nil, &DeniedError{Addr: a, Reason: r}
		}
		if u := a.Unmap(); u.Is4() {
			v4 = append(v4, u)
		}
	}
	if len(v4) == 0 {
		return nil, ErrNoAddress
	}
	for _, a := range v4 {
		if err := p.pin(a, name, g.now()); err != nil {
			return nil, err
		}
	}
	return v4, nil
}

// Authorize is rule 3 and 5: a CONNECT to an address outside the class is
// allowed only on port 443 and only for an address this session resolved
// through the gateway; the address is vetted again. It returns the name the
// address was pinned for, which the TLS server name must equal.
func (g *Gateway) Authorize(p *Pins, ip netip.Addr, port uint16) (name string, err error) {
	if port != Port {
		return "", ErrPort
	}
	ip = ip.Unmap()
	if r := g.deny(ip); r != "" {
		return "", &DeniedError{Addr: ip, Reason: r}
	}
	name, ok := p.lookup(ip, g.now())
	if !ok {
		return "", ErrNotPinned
	}
	if !g.Allow.Has(name, port) {
		return "", ErrNotAllowlisted
	}
	return name, nil
}

// CheckHello is rule D4: the ClientHello in record must name the pinned
// name. ErrNeedMore means the caller should buffer more of the first record.
func CheckHello(pinned string, record []byte) error {
	sni, err := ClientHelloSNI(record)
	if err != nil {
		return err
	}
	if Normalize(sni) != pinned {
		return ErrServerName
	}
	return nil
}

// Control is a net.Dialer Control hook: the last check at connect(2) time,
// defence in depth for rule 4 (the gateway dials the literal it pinned).
func (g *Gateway) Control(network, address string, _ syscall.RawConn) error {
	ap, err := netip.ParseAddrPort(address)
	if err != nil {
		return fmt.Errorf("egress: dial %q: not a literal address", address)
	}
	if ap.Port() != Port {
		return ErrPort
	}
	if r := g.deny(ap.Addr()); r != "" {
		return &DeniedError{Addr: ap.Addr(), Reason: r}
	}
	return nil
}

// Pins is one session's vetted addresses: ip -> (name, expiry), bounded.
type Pins struct {
	mu sync.Mutex
	m  map[netip.Addr]pin
}

type pin struct {
	name    string
	expires time.Time
}

// NewPins returns an empty table.
func NewPins() *Pins { return &Pins{m: map[netip.Addr]pin{}} }

func (p *Pins) pin(a netip.Addr, name string, now time.Time) error {
	p.mu.Lock()
	defer p.mu.Unlock()
	if _, ok := p.m[a]; !ok && len(p.m) >= MaxPins {
		for k, v := range p.m {
			if !now.Before(v.expires) {
				delete(p.m, k)
			}
		}
		if len(p.m) >= MaxPins {
			return ErrLimit
		}
	}
	p.m[a] = pin{name: name, expires: now.Add(PinTTL)}
	return nil
}

func (p *Pins) lookup(a netip.Addr, now time.Time) (string, bool) {
	p.mu.Lock()
	defer p.mu.Unlock()
	v, ok := p.m[a]
	if !ok || !now.Before(v.expires) {
		delete(p.m, a)
		return "", false
	}
	return v.name, true
}

// Len is the number of pins held (expired ones included until touched).
func (p *Pins) Len() int {
	p.mu.Lock()
	defer p.mu.Unlock()
	return len(p.m)
}
