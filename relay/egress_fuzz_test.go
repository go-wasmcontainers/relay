// SPDX-License-Identifier: BSD-3-Clause

package relay_test

import (
	"context"
	"fmt"
	"net/netip"
	"sync/atomic"
	"testing"
	"time"

	"github.com/go-wasmcontainers/relay/egress"
	"github.com/go-wasmcontainers/relay/relay"
)

// fuzzTB lets the shared helpers run inside a fuzz target, where *testing.F
// refuses Helper and Cleanup: once live, both are no-ops.
type fuzzTB struct {
	testing.TB
	live atomic.Bool
}

func (b *fuzzTB) Helper() {}
func (b *fuzzTB) Fatal(args ...any) {
	if !b.live.Load() {
		b.TB.Fatal(args...)
	}
	panic(fmt.Sprint(args...))
}
func (b *fuzzTB) Fatalf(format string, args ...any) {
	if !b.live.Load() {
		b.TB.Fatalf(format, args...)
	}
	panic(fmt.Sprintf(format, args...))
}
func (b *fuzzTB) Cleanup(fn func()) {
	if !b.live.Load() {
		b.TB.Cleanup(fn)
	}
}

// FuzzServeEgress drives the outside paths (RESOLVE of any name, CONNECT to
// any address and port, any first bytes) of a class with egress. The relay must
// not panic or hang, and the outside server must see nothing unless the first
// bytes are a ClientHello naming the allowlisted host the guest resolved.
func FuzzServeEgress(f *testing.F) {
	f.Add("api.example.org", "93.184.216.34", uint32(443), clientHello(f, "api.example.org"))
	f.Add("evil.example.org", "93.184.216.99", uint32(443), []byte("GET / HTTP/1.1\r\n\r\n"))
	f.Add("a..b", "::ffff:127.0.0.1", uint32(0), []byte{0x16, 3, 1, 0, 0})
	f.Add("\xff\x00", "not-an-ip", uint32(70000), []byte{})
	// One environment (one listener) per fuzzing process: a fresh one per input
	// exhausts the ephemeral ports.
	tb := &fuzzTB{TB: f}
	// One session too (a class holds 255), with the rate limits out of the way.
	x := newEgEnv(tb, relay.EgressLimits{ConnectsPerSecond: 1e6, ConnectBurst: 1e6, LookupsPerSecond: 1e6,
		StreamsPerSession: 1 << 20, StreamsPerDestination: 1 << 20})
	_, ep := x.person("fuzz")
	tb.live.Store(true)
	f.Fuzz(func(t *testing.T, name, dst string, port uint32, payload []byte) {
		if len(payload) > 1<<15 {
			payload = payload[:1<<15]
		}
		before := x.rawIn.Load()
		ctx, cancel := context.WithTimeout(context.Background(), 3*time.Second)
		defer cancel()
		ep.Resolve(ctx, name)
		ep.Resolve(ctx, "api.example.org")
		ip, err := netip.ParseAddr(dst)
		if err != nil {
			return
		}
		c, err := ep.Dial(ctx, "tcp", netip.AddrPortFrom(ip, uint16(port)))
		if err != nil {
			return
		}
		defer c.Close()
		c.Write(payload)
		c.SetReadDeadline(time.Now().Add(100 * time.Millisecond))
		c.Read(make([]byte, 1))
		if x.rawIn.Load() != before {
			if sni, err := egress.ClientHelloSNI(payload); err != nil || sni != "api.example.org" {
				t.Fatalf("the outside server received bytes for first bytes %x (sni %q, %v)", payload, sni, err)
			}
		}
	})
}
