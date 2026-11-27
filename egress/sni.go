// SPDX-License-Identifier: BSD-3-Clause

package egress

import (
	"errors"
)

// MaxRecord bounds the first TLS record the gateway parses (RFC 8446 5.1:
// a record fragment is at most 2^14 bytes; the relay's frame payload bound
// is the same order).
const MaxRecord = 16 << 10

// Errors of ClientHelloSNI. NeedMore is not a refusal: the record is not
// complete yet.
var (
	ErrNeedMore   = errors.New("egress: the first TLS record is not complete yet")
	ErrNotTLS     = errors.New("egress: the first bytes are not a TLS handshake record")
	ErrOversize   = errors.New("egress: the first TLS record is over the bound")
	ErrNoSNI      = errors.New("egress: the ClientHello has no server name")
	ErrBadHello   = errors.New("egress: malformed ClientHello")
	ErrSplitHello = errors.New("egress: a ClientHello split across records is refused")
	ErrMultiSNI   = errors.New("egress: more than one server name")
)

type reader struct {
	b []byte
}

func (r *reader) take(n int) ([]byte, bool) {
	if n < 0 || n > len(r.b) {
		return nil, false
	}
	out := r.b[:n]
	r.b = r.b[n:]
	return out, true
}

func (r *reader) u8() (int, bool) {
	b, ok := r.take(1)
	if !ok {
		return 0, false
	}
	return int(b[0]), true
}

func (r *reader) u16() (int, bool) {
	b, ok := r.take(2)
	if !ok {
		return 0, false
	}
	return int(b[0])<<8 | int(b[1]), true
}

// ClientHelloSNI returns the host_name of the server_name extension (RFC 6066
// 3) of the ClientHello at the start of b, which must hold one whole TLS
// record (RFC 8446 5.1). It never reads past b and allocates only the name.
// A ClientHello whose handshake message does not fit the first record is
// refused (ErrSplitHello), as is anything that is not a handshake record
// (ErrNotTLS), a record over MaxRecord (ErrOversize) and a hello with no
// server name or two (ErrNoSNI, ErrMultiSNI). A hello using Encrypted Client
// Hello carries only its outer name, which is what this returns (decision
// D4: the caller compares it to the pinned name, so ECH is refused when the
// outer name differs and the inner name is unreachable by design).
func ClientHelloSNI(b []byte) (string, error) {
	if len(b) < 5 {
		return "", ErrNeedMore
	}
	if b[0] != 0x16 || b[1] != 3 || b[2] > 4 {
		return "", ErrNotTLS
	}
	n := int(b[3])<<8 | int(b[4])
	if n > MaxRecord || n == 0 {
		return "", ErrOversize
	}
	if len(b) < 5+n {
		return "", ErrNeedMore
	}
	r := &reader{b: b[5 : 5+n]}
	if t, ok := r.u8(); !ok || t != 1 {
		return "", ErrNotTLS // not a ClientHello
	}
	l3, ok := r.take(3)
	if !ok {
		return "", ErrBadHello
	}
	hl := int(l3[0])<<16 | int(l3[1])<<8 | int(l3[2])
	if hl > len(r.b) {
		return "", ErrSplitHello
	}
	r.b = r.b[:hl]
	if _, ok := r.take(2 + 32); !ok { // legacy_version, random
		return "", ErrBadHello
	}
	sl, ok := r.u8()
	if !ok {
		return "", ErrBadHello
	}
	if _, ok := r.take(sl); !ok { // legacy_session_id
		return "", ErrBadHello
	}
	cl, ok := r.u16()
	if !ok {
		return "", ErrBadHello
	}
	if _, ok := r.take(cl); !ok { // cipher_suites
		return "", ErrBadHello
	}
	ml, ok := r.u8()
	if !ok {
		return "", ErrBadHello
	}
	if _, ok := r.take(ml); !ok { // compression_methods
		return "", ErrBadHello
	}
	el, ok := r.u16()
	if !ok || el != len(r.b) {
		return "", ErrBadHello
	}
	name := ""
	for len(r.b) > 0 {
		typ, ok := r.u16()
		if !ok {
			return "", ErrBadHello
		}
		xl, ok := r.u16()
		if !ok {
			return "", ErrBadHello
		}
		xb, ok := r.take(xl)
		if !ok {
			return "", ErrBadHello
		}
		if typ != 0 {
			continue
		}
		if name != "" {
			return "", ErrMultiSNI
		}
		x := &reader{b: xb}
		ll, ok := x.u16()
		if !ok || ll != len(x.b) {
			return "", ErrBadHello
		}
		for len(x.b) > 0 {
			nt, ok := x.u8()
			if !ok {
				return "", ErrBadHello
			}
			nl, ok := x.u16()
			if !ok {
				return "", ErrBadHello
			}
			nb, ok := x.take(nl)
			if !ok {
				return "", ErrBadHello
			}
			if nt != 0 {
				continue
			}
			if name != "" || len(nb) == 0 {
				return "", ErrMultiSNI
			}
			for _, c := range nb {
				if c <= ' ' || c >= 0x7f {
					return "", ErrBadHello
				}
			}
			name = string(nb)
		}
	}
	if name == "" {
		return "", ErrNoSNI
	}
	return name, nil
}
