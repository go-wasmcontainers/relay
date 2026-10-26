// SPDX-License-Identifier: BSD-3-Clause

package driver

import (
	"context"
	"fmt"
	"net/netip"

	"google.golang.org/protobuf/proto"

	"github.com/go-wasmcontainers/relay/frame"
	v1 "github.com/go-wasmcontainers/relay/gen/relayv1"
)

// The functions below build what a hostile client would send. They exist so
// that the relay's tests can check it refuses them; an engine has no use for
// them.

// ForgeEndpoint is an endpoint of s that names port p, whoever owns it.
func ForgeEndpoint(s *Session, p *v1.Port) *Endpoint {
	a, _ := netip.ParseAddr(p.GetIp())
	return &Endpoint{s: s, port: p, addr: a}
}

// SendRaw sends a datagram claiming any source port.
func SendRaw(e *Endpoint, srcPort uint16, to netip.AddrPort, payload []byte) error {
	_, err := e.send(srcPort, to, payload)
	return err
}

// HelloVersion opens a session announcing another protocol version and
// returns the relay's refusal.
func HelloVersion(ctx context.Context, t Transport, version uint32) error {
	hello, _ := proto.Marshal(&v1.Hello{Version: version})
	b, _ := frame.Encode(frame.Frame{Type: frame.TypeHello, Payload: hello})
	if err := t.WriteMessage(ctx, b); err != nil {
		return err
	}
	msg, err := t.ReadMessage(ctx)
	if err != nil {
		return err
	}
	f, err := frame.Decode(msg)
	if err != nil {
		return err
	}
	if f.Type != frame.TypeGoAway {
		return nil
	}
	var r v1.Result
	_ = proto.Unmarshal(f.Payload, &r)
	return fmt.Errorf("refused (%v): %s", r.Code, r.Message)
}
