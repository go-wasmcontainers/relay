// SPDX-License-Identifier: BSD-3-Clause

package egress

import (
	"context"
	"errors"
	"net/netip"
	"strings"
	"testing"
	"time"
)

// firstLast returns the first and last address of a prefix.
func firstLast(p netip.Prefix) (netip.Addr, netip.Addr) {
	first := p.Masked().Addr()
	last := first
	b := last.AsSlice()
	for i := p.Bits(); i < len(b)*8; i++ {
		b[i/8] |= 0x80 >> (i % 8)
	}
	l, _ := netip.AddrFromSlice(b)
	return first, l
}

// One refusal test per row of both deny tables: the first and the last
// address of every prefix.
func TestEveryDeniedRangeIsRefused(t *testing.T) {
	v4, v6 := DeniedPrefixes()
	if len(v4) != 16 || len(v6) != 14 {
		t.Fatalf("tables changed: %d IPv4 rows, %d IPv6 rows; update the tests with them", len(v4), len(v6))
	}
	for _, p := range append(v4, v6...) {
		f, l := firstLast(p)
		for _, a := range []netip.Addr{f, l} {
			if Denied(a) == "" {
				t.Errorf("%v (in %v) is not refused", a, p)
			}
		}
	}
}

func TestDeniedNamedRows(t *testing.T) {
	for _, s := range []string{
		// the rows the threat model names, one address each
		"0.0.0.0", "0.255.255.255", "10.1.2.3", "100.64.0.1", "100.127.255.255", "127.0.0.1", "127.255.255.254",
		"169.254.169.254", "172.16.0.1", "172.31.255.255", "192.0.0.1", "192.0.0.9", "192.0.2.1", "192.88.99.1", "192.168.1.1",
		"198.18.0.1", "198.19.255.255", "198.51.100.1", "203.0.113.1", "224.0.0.1", "239.255.255.255", "240.0.0.1",
		"255.255.255.255",
		"::", "::1", "64:ff9b:1::1", "100::1", "2001::1", "2001:1::1", "2001:db8::1", "3fff::1", "5f00::1",
		"fc00::1", "fd12:3456::1", "fe80::1", "ff02::1", "ff0e::1",
		// IPv4 inside IPv6: mapped, NAT64, 6to4, Teredo
		"::ffff:10.0.0.1", "::ffff:127.0.0.1", "::ffff:169.254.169.254", "::ffff:192.168.0.1", "::ffff:224.0.0.1",
		"64:ff9b::a00:1", "64:ff9b::7f00:1", "64:ff9b::808:808",
		"2002:a00:1::1", "2002:7f00:1::", "2002:808:808::1",
		"2001:0:4136:e378:8000:63bf:3fff:fdd2",
	} {
		if Denied(netip.MustParseAddr(s)) == "" {
			t.Errorf("%s is not refused", s)
		}
	}
	if Denied(netip.MustParseAddr("fe80::1%eth0")) == "" {
		t.Error("a zone is not refused")
	}
	if Denied(netip.Addr{}) == "" {
		t.Error("the zero address is not refused")
	}
}

func TestGlobalAddressesPass(t *testing.T) {
	for _, s := range []string{"1.1.1.1", "8.8.8.8", "93.184.216.34", "172.15.255.255", "172.32.0.0", "100.63.255.255",
		"100.128.0.0", "192.0.3.1", "198.17.255.255", "198.20.0.0", "223.255.255.255", "11.0.0.1", "126.255.255.255",
		"2606:4700:4700::1111", "2a00:1450::1", "::ffff:8.8.8.8"} {
		if r := Denied(netip.MustParseAddr(s)); r != "" {
			t.Errorf("%s refused: %s", s, r)
		}
	}
}

func TestAllowlistRefusals(t *testing.T) {
	for _, bad := range [][]string{
		nil, {}, {""}, {"*"}, {"*:443"}, {"*.example.com:443"}, {"0.0.0.0/0"}, {"::/0"}, {"::/0:443"}, {"10.0.0.0/8:443"},
		{"example.com"}, {"example.com:80"}, {"example.com:25"}, {"example.com:465"}, {"example.com:587"},
		{"example.com:8443"}, {"example.com:0"}, {"example.com:0443"}, {"example.com:99999"}, {"example.com:"}, {":443"},
		{"com:443"}, {"localhost:443"}, {"93.184.216.34:443"}, {"[::1]:443"}, {"1.2.3.4.5:443"}, {"Example.COM:443"},
		{"exa mple.com:443"}, {"example..com:443"}, {"-a.example.com:443"}, {"a_b.example.com:443"},
		{"example.com/path:443"}, {"user@example.com:443"}, {"bücher.example:443"}, {"example.com.:443"},
		{"example.com:443", "*"}, {"example.com:443", ""},
	} {
		if a, err := ParseAllowlist(bad); err == nil {
			t.Errorf("%q accepted: %v", bad, a.Hosts())
		}
	}
	many := make([]string, MaxAllowlist+1)
	for i := range many {
		many[i] = "h" + strings.Repeat("a", i%5) + string(rune('a'+i%26)) + string(rune('a'+i/26%26)) + ".example.com:443"
	}
	if _, err := ParseAllowlist(many); err == nil {
		t.Error("an oversize allowlist accepted")
	}
}

func TestAllowlistAccepts(t *testing.T) {
	a, err := ParseAllowlist([]string{"api.example.com:443", "b.example.org:443", "api.example.com:443"})
	if err != nil {
		t.Fatal(err)
	}
	if h := a.Hosts(); len(h) != 2 || h[0].String() != "api.example.com:443" {
		t.Fatalf("hosts %v", h)
	}
	if !a.Has("API.Example.com.", 443) || a.Has("api.example.com", 80) || a.Has("example.com", 443) || a.Has("x.api.example.com", 443) {
		t.Error("Has is not exact")
	}
	var none *Allowlist
	if none.Has("api.example.com", 443) {
		t.Error("a nil allowlist allows")
	}
}

type fakeResolver struct {
	answers map[string][]netip.Addr
	calls   []string
	err     error
}

func (f *fakeResolver) LookupAddrs(_ context.Context, name string) ([]netip.Addr, error) {
	f.calls = append(f.calls, name)
	return f.answers[name], f.err
}

func ips(s ...string) []netip.Addr {
	var out []netip.Addr
	for _, x := range s {
		out = append(out, netip.MustParseAddr(x))
	}
	return out
}

func newGW(t *testing.T, r *fakeResolver) (*Gateway, *Pins, *time.Time) {
	t.Helper()
	al, err := ParseAllowlist([]string{"api.example.com:443"})
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

func TestNewGatewayRefusesNoAllowlist(t *testing.T) {
	if _, err := NewGateway(nil, &fakeResolver{}, nil); err == nil {
		t.Error("nil allowlist accepted")
	}
	if _, err := NewGateway(&Allowlist{}, &fakeResolver{}, nil); err == nil {
		t.Error("empty allowlist accepted")
	}
	al, _ := ParseAllowlist([]string{"a.example.com:443"})
	if _, err := NewGateway(al, nil, nil); err == nil {
		t.Error("no resolver accepted")
	}
}

func TestResolveOnlyAllowlistedNames(t *testing.T) {
	r := &fakeResolver{answers: map[string][]netip.Addr{"evil.example.net": ips("8.8.8.8")}}
	g, p, _ := newGW(t, r)
	if _, err := g.Resolve(context.Background(), p, "evil.example.net"); !errors.Is(err, ErrNotAllowlisted) {
		t.Fatalf("err = %v", err)
	}
	if len(r.calls) != 0 {
		t.Fatalf("a name that is not allowlisted was looked up outside: %v", r.calls)
	}
}

// DNS rebinding: a mixed answer is refused whole, nothing is pinned, and a
// public answer is pinned and then dialled as a literal.
func TestResolveRebinding(t *testing.T) {
	for name, answer := range map[string][]string{
		"private only":   {"10.0.0.5"},
		"public+private": {"93.184.216.34", "10.0.0.5"},
		"private+public": {"169.254.169.254", "93.184.216.34"},
		"public+v6 ULA":  {"93.184.216.34", "fd00::1"},
		"mapped private": {"::ffff:127.0.0.1"},
		"loopback":       {"127.0.0.1"},
	} {
		r := &fakeResolver{answers: map[string][]netip.Addr{"api.example.com": ips(answer...)}}
		g, p, _ := newGW(t, r)
		_, err := g.Resolve(context.Background(), p, "api.example.com")
		var de *DeniedError
		if !errors.As(err, &de) {
			t.Errorf("%s: err = %v", name, err)
		}
		if p.Len() != 0 {
			t.Errorf("%s: %d addresses pinned from a refused answer", name, p.Len())
		}
	}
}

func TestResolvePinsAndAuthorize(t *testing.T) {
	r := &fakeResolver{answers: map[string][]netip.Addr{"api.example.com": ips("93.184.216.34", "2606:2800:220:1::1")}}
	g, p, now := newGW(t, r)
	got, err := g.Resolve(context.Background(), p, "API.example.com.")
	if err != nil || len(got) != 1 || got[0] != netip.MustParseAddr("93.184.216.34") {
		t.Fatalf("resolve = %v, %v", got, err)
	}
	ip := got[0]
	if name, err := g.Authorize(p, ip, 443); err != nil || name != "api.example.com" {
		t.Fatalf("authorize = %q, %v", name, err)
	}
	// Port 80 is refused, so is any other.
	for _, port := range []uint16{80, 25, 8443, 0} {
		if _, err := g.Authorize(p, ip, port); !errors.Is(err, ErrPort) {
			t.Errorf("port %d: %v", port, err)
		}
	}
	// A bare IP the session never resolved is refused, allowlisted or not.
	if _, err := g.Authorize(p, netip.MustParseAddr("93.184.216.35"), 443); !errors.Is(err, ErrNotPinned) {
		t.Errorf("unpinned: %v", err)
	}
	// Another session's pins do not help.
	if _, err := g.Authorize(NewPins(), ip, 443); !errors.Is(err, ErrNotPinned) {
		t.Errorf("other session: %v", err)
	}
	// A private address is refused even when somebody pinned it.
	p.pin(netip.MustParseAddr("10.0.0.1"), "api.example.com", g.now())
	var de *DeniedError
	if _, err := g.Authorize(p, netip.MustParseAddr("10.0.0.1"), 443); !errors.As(err, &de) {
		t.Errorf("private pin: %v", err)
	}
	// The pin expires, failing closed.
	*now = now.Add(PinTTL)
	if _, err := g.Authorize(p, ip, 443); !errors.Is(err, ErrNotPinned) {
		t.Errorf("expired: %v", err)
	}
}

func TestPinsAreBounded(t *testing.T) {
	g, p, now := newGW(t, &fakeResolver{})
	for i := 0; i < MaxPins; i++ {
		if err := p.pin(netip.AddrFrom4([4]byte{93, 184, byte(i >> 8), byte(i)}), "api.example.com", g.now()); err != nil {
			t.Fatal(err)
		}
	}
	if err := p.pin(netip.MustParseAddr("8.8.8.8"), "api.example.com", g.now()); !errors.Is(err, ErrLimit) {
		t.Fatalf("pin %d: %v", MaxPins+1, err)
	}
	if p.Len() != MaxPins {
		t.Fatalf("len %d", p.Len())
	}
	*now = now.Add(PinTTL)
	if err := p.pin(netip.MustParseAddr("8.8.8.8"), "api.example.com", g.now()); err != nil {
		t.Fatalf("after expiry: %v", err)
	}
}

func TestExtraPrefixesAndControl(t *testing.T) {
	al, _ := ParseAllowlist([]string{"api.example.com:443"})
	g, _ := NewGateway(al, &fakeResolver{answers: map[string][]netip.Addr{"api.example.com": ips("93.184.216.34")}},
		[]netip.Prefix{netip.MustParsePrefix("93.184.216.0/24")})
	if _, err := g.Resolve(context.Background(), NewPins(), "api.example.com"); err == nil {
		t.Error("an operator-denied range resolved")
	}
	g2, _, _ := newGW(t, &fakeResolver{})
	for _, bad := range []string{"10.0.0.1:443", "127.0.0.1:443", "[::1]:443", "93.184.216.34:80", "example.com:443", "[::ffff:10.0.0.1]:443"} {
		if err := g2.Control("tcp", bad, nil); err == nil {
			t.Errorf("control accepted %s", bad)
		}
	}
	if err := g2.Control("tcp4", "93.184.216.34:443", nil); err != nil {
		t.Errorf("control refused a public literal: %v", err)
	}
}

// -------------------------------------------------------------------- SNI

func ext(typ int, body []byte) []byte {
	return append([]byte{byte(typ >> 8), byte(typ), byte(len(body) >> 8), byte(len(body))}, body...)
}

func sniExt(names ...string) []byte {
	var list []byte
	for _, n := range names {
		list = append(list, 0, byte(len(n)>>8), byte(len(n)))
		list = append(list, n...)
	}
	return ext(0, append([]byte{byte(len(list) >> 8), byte(len(list))}, list...))
}

// hello builds one TLS record holding a ClientHello with the extensions.
func hello(exts ...[]byte) []byte {
	var e []byte
	for _, x := range exts {
		e = append(e, x...)
	}
	body := []byte{3, 3}
	body = append(body, make([]byte, 32)...)
	body = append(body, 0)                // session id
	body = append(body, 0, 2, 0x13, 0x01) // one cipher suite
	body = append(body, 1, 0)             // null compression
	body = append(body, byte(len(e)>>8), byte(len(e)))
	body = append(body, e...)
	hs := append([]byte{1, byte(len(body) >> 16), byte(len(body) >> 8), byte(len(body))}, body...)
	return append([]byte{0x16, 3, 1, byte(len(hs) >> 8), byte(len(hs))}, hs...)
}

func TestClientHelloSNI(t *testing.T) {
	ok := hello(ext(10, []byte{0, 2, 0, 23}), sniExt("api.example.com"))
	if n, err := ClientHelloSNI(ok); err != nil || n != "api.example.com" {
		t.Fatalf("sni = %q, %v", n, err)
	}
	if err := CheckHello("api.example.com", ok); err != nil {
		t.Fatalf("match: %v", err)
	}
	if err := CheckHello("other.example.com", ok); !errors.Is(err, ErrServerName) {
		t.Fatalf("mismatch: %v", err)
	}
	if err := CheckHello("api.example.com", hello(sniExt("API.Example.COM"))); err != nil {
		t.Fatalf("case: %v", err)
	}
	// Missing SNI, no extensions at all.
	if _, err := ClientHelloSNI(hello(ext(10, []byte{0, 2, 0, 23}))); !errors.Is(err, ErrNoSNI) {
		t.Errorf("no sni: %v", err)
	}
	if _, err := ClientHelloSNI(hello()); !errors.Is(err, ErrNoSNI) {
		t.Errorf("no extensions: %v", err)
	}
	// Two names, two extensions.
	if _, err := ClientHelloSNI(hello(sniExt("a.example.com", "b.example.com"))); !errors.Is(err, ErrMultiSNI) {
		t.Errorf("two names: %v", err)
	}
	if _, err := ClientHelloSNI(hello(sniExt("a.example.com"), sniExt("a.example.com"))); !errors.Is(err, ErrMultiSNI) {
		t.Errorf("two extensions: %v", err)
	}
	// Non-TLS: HTTP, SSLv2-style, a wrong content type, a non-hello handshake.
	for _, b := range [][]byte{
		[]byte("GET / HTTP/1.1\r\nHost: api.example.com\r\n\r\n"),
		{0x80, 0x2e, 1, 0, 2, 0, 0, 0},
		{0x17, 3, 3, 0, 5, 1, 2, 3, 4, 5},
		{0x16, 3, 3, 0, 4, 2, 0, 0, 0}, // ServerHello type
		{0x16, 2, 0, 0, 4, 1, 0, 0, 0},
	} {
		if _, err := ClientHelloSNI(b); !errors.Is(err, ErrNotTLS) {
			t.Errorf("%q: %v", b, err)
		}
	}
	// Oversize record header, and an empty one.
	if _, err := ClientHelloSNI([]byte{0x16, 3, 1, 0x40, 0x01, 1}); !errors.Is(err, ErrOversize) {
		t.Errorf("oversize: %v", err)
	}
	if _, err := ClientHelloSNI([]byte{0x16, 3, 1, 0, 0}); !errors.Is(err, ErrOversize) {
		t.Errorf("empty: %v", err)
	}
	// Split across records: the handshake length says more than the record holds.
	split := append([]byte(nil), ok...)
	split[6], split[7], split[8] = 0, 0xff, 0xff
	if _, err := ClientHelloSNI(split); !errors.Is(err, ErrSplitHello) {
		t.Errorf("split: %v", err)
	}
	// Short buffers want more, never a verdict, never a panic.
	for i := 0; i < len(ok); i++ {
		if _, err := ClientHelloSNI(ok[:i]); !errors.Is(err, ErrNeedMore) {
			t.Fatalf("prefix %d: %v", i, err)
		}
	}
	// Trailing bytes after the record are not read.
	if n, err := ClientHelloSNI(append(append([]byte(nil), ok...), 0xde, 0xad)); err != nil || n != "api.example.com" {
		t.Errorf("trailing: %q %v", n, err)
	}
	// A name with a control byte or a NUL.
	if _, err := ClientHelloSNI(hello(sniExt("a\x00b.example.com"))); !errors.Is(err, ErrBadHello) {
		t.Errorf("nul: %v", err)
	}
	// An extensions block whose length lies.
	lie := append([]byte(nil), ok...)
	lie[len(lie)-len(sniExt("api.example.com"))-2+1]++ // not asserting where; any corruption must not panic
	_, _ = ClientHelloSNI(lie)
}

// ECH shows only an outer name (the public name); it is refused unless that
// is the pinned name (D4).
func TestECHOuterNameIsRefused(t *testing.T) {
	ech := hello(sniExt("public.cdn.example"), ext(0xfe0d, make([]byte, 64)))
	if err := CheckHello("api.example.com", ech); !errors.Is(err, ErrServerName) {
		t.Fatalf("ech: %v", err)
	}
}

func FuzzClientHelloSNI(f *testing.F) {
	f.Add(hello(sniExt("api.example.com")))
	f.Add(hello(ext(10, []byte{0, 2, 0, 23}), sniExt("a.b.example.com")))
	f.Add([]byte("GET / HTTP/1.1\r\n\r\n"))
	f.Add([]byte{0x16, 3, 1, 0, 0})
	f.Add([]byte{})
	f.Fuzz(func(t *testing.T, b []byte) {
		name, err := ClientHelloSNI(b)
		if err != nil {
			if name != "" {
				t.Fatalf("name %q with error %v", name, err)
			}
			return
		}
		if name == "" || len(name) > MaxRecord {
			t.Fatalf("bad name %q", name)
		}
		for i := 0; i < len(name); i++ {
			if name[i] <= ' ' || name[i] >= 0x7f {
				t.Fatalf("name %q holds byte %#x", name, name[i])
			}
		}
	})
}

func FuzzParseAllowlist(f *testing.F) {
	for _, s := range []string{"api.example.com:443", "*", "0.0.0.0/0", "::/0", "example.com:80", "", "a.b:443", "1.2.3.4:443", "ex\x00.com:443"} {
		f.Add(s)
	}
	f.Fuzz(func(t *testing.T, s string) {
		a, err := ParseAllowlist([]string{s})
		if err != nil {
			return
		}
		for _, d := range a.Hosts() {
			if d.Port != Port {
				t.Fatalf("port %d from %q", d.Port, s)
			}
			if strings.ContainsAny(d.Host, "*/ ,:[]@") || len(d.Host) == 0 {
				t.Fatalf("host %q from %q", d.Host, s)
			}
			if _, err := netip.ParseAddr(d.Host); err == nil {
				t.Fatalf("IP literal %q accepted", s)
			}
			if d.Host != Normalize(d.Host) {
				t.Fatalf("host %q not normal", d.Host)
			}
		}
	})
}
