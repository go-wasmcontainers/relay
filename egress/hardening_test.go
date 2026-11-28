// SPDX-License-Identifier: BSD-3-Clause

package egress

import (
	"context"
	"crypto/sha256"
	"errors"
	"net/netip"
	"testing"
	"time"
)

// Review findings of PR 19, each held by a test that failed first.

func newGWNames(t *testing.T, r *fakeResolver, names ...string) (*Gateway, *Pins, *time.Time) {
	t.Helper()
	var spec []string
	for _, n := range names {
		spec = append(spec, n+":443")
	}
	al, err := ParseAllowlist(spec)
	if err != nil {
		t.Fatal(err)
	}
	g, err := NewGateway(al, r, nil)
	if err != nil {
		t.Fatal(err)
	}
	now := time.Unix(1000, 0)
	g.Now = func() time.Time { return now }
	return g, NewPins(), &now
}

// D4: encrypted_client_hello (0xfe0d) is refused whatever the outer name.
func TestECHIsRefusedEvenWithThePinnedOuterName(t *testing.T) {
	for _, body := range [][]byte{make([]byte, 64), nil} {
		h := hello(sniExt("api.example.com"), ext(0xfe0d, body))
		if err := CheckHello([]string{"api.example.com"}, h); !errors.Is(err, ErrECH) {
			t.Fatalf("ech with the pinned outer name: %v", err)
		}
		// Order must not matter.
		h = hello(ext(0xfe0d, body), sniExt("api.example.com"))
		if _, err := ClientHelloSNI(h); !errors.Is(err, ErrECH) {
			t.Fatalf("ech first: %v", err)
		}
	}
}

// RFC 8446 4.2: no two extensions of one type.
func TestDuplicateExtensionsAreRefused(t *testing.T) {
	other := ext(0, []byte{0, 4, 1, 0, 1, 'x'})
	if _, err := ClientHelloSNI(hello(sniExt("api.example.com"), other)); !errors.Is(err, ErrMultiSNI) {
		t.Errorf("second server_name with a non host_name entry: %v", err)
	}
	if _, err := ClientHelloSNI(hello(other, sniExt("api.example.com"))); !errors.Is(err, ErrMultiSNI) {
		t.Errorf("same, other order: %v", err)
	}
	if _, err := ClientHelloSNI(hello(ext(10, []byte{0, 2, 0, 23}), sniExt("api.example.com"), ext(10, []byte{0, 2, 0, 24}))); !errors.Is(err, ErrBadHello) {
		t.Errorf("duplicate supported_groups: %v", err)
	}
}

// The host_name bytes are letters, digits, hyphen, dot and underscore, and
// nothing else: every byte value is judged.
func TestServerNameBytes(t *testing.T) {
	for c := 0; c < 256; c++ {
		ok := c >= 'a' && c <= 'z' || c >= 'A' && c <= 'Z' || c >= '0' && c <= '9' || c == '-' || c == '.' || c == '_'
		b := []byte("a.b")
		b[1] = byte(c)
		got, err := ClientHelloSNI(hello(sniExt(string(b))))
		if ok && (err != nil || got != string(b)) {
			t.Errorf("byte %#x refused: %v", c, err)
		}
		if !ok && !errors.Is(err, ErrBadHello) {
			t.Errorf("byte %#x accepted: %q %v", c, got, err)
		}
	}
}

// CDNs share addresses: two allowlisted names on one IP both keep their pin.
func TestSharedAddressKeepsEveryName(t *testing.T) {
	ip := ips("93.184.216.34")
	r := &fakeResolver{answers: map[string][]netip.Addr{"a.example.com": ip, "b.example.com": ip}}
	al, _ := ParseAllowlist([]string{"a.example.com:443", "b.example.com:443"})
	g, _ := NewGateway(al, r, nil)
	p := NewPins()
	for _, n := range []string{"a.example.com", "b.example.com"} {
		if _, err := g.Resolve(context.Background(), p, n); err != nil {
			t.Fatal(err)
		}
	}
	names, err := g.Authorize(p, ip[0], 443)
	if err != nil || len(names) != 2 || names[0] != "a.example.com" || names[1] != "b.example.com" {
		t.Fatalf("names = %v, %v", names, err)
	}
	for _, n := range []string{"a.example.com", "b.example.com"} {
		if err := CheckHello(names, hello(sniExt(n))); err != nil {
			t.Errorf("%s: %v", n, err)
		}
	}
	if err := CheckHello(names, hello(sniExt("c.example.com"))); !errors.Is(err, ErrServerName) {
		t.Errorf("unpinned name: %v", err)
	}
	if p.Len() != 2 {
		t.Errorf("Len = %d, want 2 (one per address and name)", p.Len())
	}
}

// Pins are refreshed by use and expire without it, name by name.
func TestPinsRefreshOnUseAndExpirePerName(t *testing.T) {
	ip := ips("93.184.216.34")
	r := &fakeResolver{answers: map[string][]netip.Addr{"a.example.com": ip, "b.example.com": ip}}
	g, p, now := newGWNames(t, r, "a.example.com", "b.example.com")
	if _, err := g.Resolve(context.Background(), p, "a.example.com"); err != nil {
		t.Fatal(err)
	}
	*now = now.Add(PinTTL - time.Second)
	if _, err := g.Resolve(context.Background(), p, "b.example.com"); err != nil {
		t.Fatal(err)
	}
	// a is 1 s from expiry: using the address refreshes it.
	if names, err := g.Authorize(p, ip[0], 443); err != nil || len(names) != 2 {
		t.Fatalf("%v %v", names, err)
	}
	*now = now.Add(2 * time.Second) // past a's original expiry, inside b's
	names, err := g.Authorize(p, ip[0], 443)
	if err != nil || len(names) != 2 {
		t.Fatalf("a was not refreshed by use: %v %v", names, err)
	}
	*now = now.Add(PinTTL + time.Second) // nothing used it for a whole TTL
	if _, err := g.Authorize(p, ip[0], 443); !errors.Is(err, ErrNotPinned) {
		t.Fatalf("expired: %v", err)
	}
	if p.Len() != 0 {
		t.Fatalf("expired pins are kept: %d", p.Len())
	}
}

func TestPinLimitCountsNamesAndAddresses(t *testing.T) {
	p := NewPins()
	now := time.Unix(1000, 0)
	for i := 0; i < MaxPins; i++ {
		if err := p.pin(netip.MustParseAddr("93.184.0.1"), "n"+string(rune('a'+i%26))+string(rune('a'+i/26)), now); err != nil {
			t.Fatalf("pin %d: %v", i, err)
		}
	}
	if err := p.pin(netip.MustParseAddr("93.184.0.1"), "zzz", now); !errors.Is(err, ErrLimit) {
		t.Fatalf("over the bound: %v", err)
	}
	// Re-pinning a held pair is not a new entry.
	if err := p.pin(netip.MustParseAddr("93.184.0.1"), "naa", now); err != nil {
		t.Fatalf("refresh of a held pin: %v", err)
	}
}

type clearingResolver struct {
	p   *Pins
	ans []netip.Addr
}

func (c clearingResolver) LookupAddrs(context.Context, string) ([]netip.Addr, error) {
	c.p.Clear() // a join-code rotation or a removal lands while the lookup runs
	return c.ans, nil
}

// A lookup in flight when the pins are cleared cannot pin afterwards.
func TestLookupInFlightCannotPinAfterClear(t *testing.T) {
	p := NewPins()
	al, _ := ParseAllowlist([]string{"api.example.com:443"})
	g, _ := NewGateway(al, clearingResolver{p, ips("93.184.216.34")}, nil)
	if _, err := g.Resolve(context.Background(), p, "api.example.com"); !errors.Is(err, ErrStale) {
		t.Fatalf("stale lookup: %v", err)
	}
	if p.Len() != 0 {
		t.Fatalf("%d pins from a stale lookup", p.Len())
	}
	if _, err := g.Authorize(p, netip.MustParseAddr("93.184.216.34"), 443); !errors.Is(err, ErrNotPinned) {
		t.Fatalf("authorize: %v", err)
	}
}

// A relative name would walk the host's resolv.conf search domains: the
// lookup name is rooted.
func TestLookupNameIsRooted(t *testing.T) {
	r := &fakeResolver{answers: map[string][]netip.Addr{"api.example.com": ips("93.184.216.34")}}
	g, p, _ := newGW(t, r)
	if _, err := g.Resolve(context.Background(), p, "API.example.com"); err != nil {
		t.Fatal(err)
	}
	if len(r.calls) != 1 || r.calls[0] != "api.example.com." {
		t.Fatalf("lookup names = %q, want the rooted name", r.calls)
	}
}

func helloRetry() []byte {
	b := make([]byte, 5+4+2+32)
	b[0], b[1], b[2] = 0x16, 3, 3
	b[3], b[4] = 0, byte(len(b)-5)
	b[5] = 2 // ServerHello
	copy(b[11:], helloRetryRandom[:])
	return b
}

// RFC 8446 4.1.3: a ServerHello with the fixed random is a HelloRetryRequest.
func TestIsHelloRetryRequest(t *testing.T) {
	if sha256.Sum256([]byte("HelloRetryRequest")) != helloRetryRandom {
		t.Fatal("the constant is not SHA-256(\"HelloRetryRequest\")")
	}
	hrr := helloRetry()
	if got, decided := IsHelloRetryRequest(hrr); !got || !decided {
		t.Errorf("hrr = %v %v", got, decided)
	}
	if got, decided := IsHelloRetryRequest(hrr[:42]); got || decided {
		t.Errorf("42 bytes decide nothing: %v %v", got, decided)
	}
	sh := helloRetry()
	sh[20] ^= 1
	if got, decided := IsHelloRetryRequest(sh); got || !decided {
		t.Errorf("an ordinary ServerHello: %v %v", got, decided)
	}
	if got, decided := IsHelloRetryRequest([]byte{0x17, 3, 3}); got || !decided {
		t.Errorf("application data: %v %v", got, decided)
	}
	if got, decided := IsHelloRetryRequest([]byte{0x16, 3, 3, 0, 4, 14, 0, 0, 0}); got || !decided {
		t.Errorf("a non-ServerHello handshake: %v %v", got, decided)
	}
	if _, decided := IsHelloRetryRequest(nil); decided {
		t.Error("nothing decides nothing")
	}
}

// Addresses outside both IANA registries that alias private space.
func TestIPv6AliasesOfPrivateSpaceAreRefused(t *testing.T) {
	for _, s := range []string{"::127.0.0.1", "::10.0.0.1", "::a9fe:a9fe", "fec0::1", "feff:ffff::1", "::2", "::ffff:0:0", "::"} {
		if Denied(netip.MustParseAddr(s)) == "" {
			t.Errorf("%s is not refused", s)
		}
	}
	if Denied(netip.MustParseAddr("2606:4700:4700::1111")) != "" {
		t.Error("a global address is refused")
	}
}
