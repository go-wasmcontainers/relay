// SPDX-License-Identifier: BSD-3-Clause

package egress

import (
	"context"
	"errors"
	"fmt"
	"net/netip"
	"slices"
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
	ErrStale          = errors.New("egress: the lookup began before the session's pins were cleared")
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
	// The generation is read before the lookup: a Clear while it runs (a
	// rotated join code, a removed member) makes the answer stale.
	gen := p.Generation()
	// Rooted: a relative name would walk the host's resolv.conf search
	// domains and could answer for another name.
	addrs, err := g.Resolver.LookupAddrs(ctx, name+".")
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
		if err := p.pinGen(a, name, g.now(), &gen); err != nil {
			return nil, err
		}
	}
	return v4, nil
}

// Authorize is rule 3 and 5: a CONNECT to an address outside the class is
// allowed only on port 443 and only for an address this session resolved
// through the gateway; the address is vetted again. It returns the name the
// address was pinned for (sorted; several allowlisted names may share an
// address), one of which the TLS server name must equal. Using a pin
// refreshes it.
func (g *Gateway) Authorize(p *Pins, ip netip.Addr, port uint16) (names []string, err error) {
	if port != Port {
		return nil, ErrPort
	}
	ip = ip.Unmap()
	if r := g.deny(ip); r != "" {
		return nil, &DeniedError{Addr: ip, Reason: r}
	}
	pinned := p.lookup(ip, g.now())
	if len(pinned) == 0 {
		return nil, ErrNotPinned
	}
	for _, n := range pinned {
		if g.Allow.Has(n, port) {
			names = append(names, n)
		}
	}
	if len(names) == 0 {
		return nil, ErrNotAllowlisted
	}
	return names, nil
}

// CheckHello is rule D4: the ClientHello in record must name one of the
// pinned names. ErrNeedMore means the caller should buffer more of the first
// record.
func CheckHello(pinned []string, record []byte) error {
	sni, err := ClientHelloSNI(record)
	if err != nil {
		return err
	}
	if !slices.Contains(pinned, Normalize(sni)) {
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

// Pins is one session's vetted addresses: ip -> {name -> expiry}, bounded.
// Several allowlisted names may share an address (CDNs), so an address holds
// a set of names; the bound counts (address, name) pairs.
type Pins struct {
	mu  sync.Mutex
	m   map[netip.Addr]map[string]time.Time
	n   int
	gen uint64
}

// NewPins returns an empty table.
func NewPins() *Pins { return &Pins{m: map[netip.Addr]map[string]time.Time{}} }

// Generation counts Clear calls. A lookup that began in an earlier
// generation must not pin: see PinIf.
func (p *Pins) Generation() uint64 {
	p.mu.Lock()
	defer p.mu.Unlock()
	return p.gen
}

func (p *Pins) pin(a netip.Addr, name string, now time.Time) error {
	return p.pinGen(a, name, now, nil)
}

// pinGen pins unless gen is set and no longer the table's generation.
func (p *Pins) pinGen(a netip.Addr, name string, now time.Time, gen *uint64) error {
	p.mu.Lock()
	defer p.mu.Unlock()
	if gen != nil && *gen != p.gen {
		return ErrStale
	}
	names := p.m[a]
	if _, ok := names[name]; !ok && p.n >= MaxPins {
		p.sweep(now)
		if p.n >= MaxPins {
			return ErrLimit
		}
		names = p.m[a]
	}
	if names == nil {
		names = map[string]time.Time{}
		p.m[a] = names
	}
	if _, ok := names[name]; !ok {
		p.n++
	}
	names[name] = now.Add(PinTTL)
	return nil
}

// sweep drops every expired pair. p.mu held.
func (p *Pins) sweep(now time.Time) {
	for a, names := range p.m {
		for n, exp := range names {
			if !now.Before(exp) {
				delete(names, n)
				p.n--
			}
		}
		if len(names) == 0 {
			delete(p.m, a)
		}
	}
}

// lookup returns the names pinned to a, sorted, and refreshes each one's
// expiry: a pin lives while the session keeps using the address.
func (p *Pins) lookup(a netip.Addr, now time.Time) []string {
	p.mu.Lock()
	defer p.mu.Unlock()
	names := p.m[a]
	var out []string
	for n, exp := range names {
		if !now.Before(exp) {
			delete(names, n)
			p.n--
			continue
		}
		names[n] = now.Add(PinTTL)
		out = append(out, n)
	}
	if len(names) == 0 {
		delete(p.m, a)
	}
	slices.Sort(out)
	return out
}

// Clear forgets every pin and starts a new generation: the session must
// resolve again, and a lookup already in flight cannot pin afterwards.
func (p *Pins) Clear() {
	p.mu.Lock()
	defer p.mu.Unlock()
	clear(p.m)
	p.n = 0
	p.gen++
}

// Len is the number of (address, name) pins held (expired ones included
// until touched).
func (p *Pins) Len() int {
	p.mu.Lock()
	defer p.mu.Unlock()
	return p.n
}
