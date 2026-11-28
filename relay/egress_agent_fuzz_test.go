// SPDX-License-Identifier: BSD-3-Clause

package relay

import (
	"crypto/tls"
	"io"
	"net"
	"testing"

	"github.com/go-wasmcontainers/relay/egress"
)

func seedHello(f *testing.F, name string) []byte {
	a, b := net.Pipe()
	defer b.Close()
	go func() {
		_ = tls.Client(a, &tls.Config{ServerName: name, InsecureSkipVerify: true}).Handshake()
		a.Close()
	}()
	hdr := make([]byte, 5)
	if _, err := io.ReadFull(b, hdr); err != nil {
		f.Fatal(err)
	}
	body := make([]byte, int(hdr[3])<<8|int(hdr[4]))
	if _, err := io.ReadFull(b, body); err != nil {
		f.Fatal(err)
	}
	return append(hdr, body...)
}

// FuzzAgentOnData feeds the guest's bytes to a stream in arbitrary pieces. The
// reassembly must never panic, and nothing may be queued for the outside
// before the bytes read so far are a ClientHello naming the pinned host.
func FuzzAgentOnData(f *testing.F) {
	hello := seedHello(f, "api.example.org")
	f.Add(hello, uint8(0))
	f.Add(hello, uint8(7))
	f.Add(seedHello(f, "evil.example.org"), uint8(3))
	f.Add([]byte("GET / HTTP/1.1\r\n\r\n"), uint8(1))
	f.Add([]byte{0x16, 3, 1, 0xff, 0xff}, uint8(2))
	f.Fuzz(func(t *testing.T, payload []byte, cut uint8) {
		if len(payload) > 1<<16 {
			payload = payload[:1<<16]
		}
		x := newAgentEnv(t, EgressLimits{})
		s := x.stream(t, 21)
		step := int(cut)%32 + 1
		for off := 0; off < len(payload); off += step {
			end := min(off+step, len(payload))
			s.onData(payload[off:end])
			s.qmu.Lock()
			queued := len(s.qbuf)
			s.qmu.Unlock()
			if queued > 0 && !s.checked.Load() {
				t.Fatalf("%d bytes queued for the outside before the hello was checked: %x", queued, payload[:end])
			}
		}
		if s.checked.Load() {
			// It passed: the whole first record must name the pinned host.
			first := payload
			for end := 1; end <= len(payload); end++ {
				if egress.CheckHello([]string{"api.example.org"}, payload[:end]) == nil {
					first = payload[:end]
					break
				}
			}
			if err := egress.CheckHello([]string{"api.example.org"}, first); err != nil {
				t.Fatalf("the stream went live on bytes that are not a hello for the pinned host: %x (%v)", payload, err)
			}
		}
	})
}
