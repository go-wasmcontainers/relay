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

// reader is a sticky-error cursor: after one read past the end every read
// returns zero and bad stays set, so a parser checks bad once per structure.
type reader struct {
	b   []byte
	bad bool
}

func (r *reader) take(n int) []byte {
	if r.bad || n > len(r.b) {
		r.bad, r.b = true, nil
		return nil
	}
	out := r.b[:n]
	r.b = r.b[n:]
	return out
}

func (r *reader) u8() int {
	if b := r.take(1); b != nil {
		return int(b[0])
	}
	return 0
}

func (r *reader) u16() int {
	if b := r.take(2); b != nil {
		return int(b[0])<<8 | int(b[1])
	}
	return 0
}

func (r *reader) u24() int {
	if b := r.take(3); b != nil {
		return int(b[0])<<16 | int(b[1])<<8 | int(b[2])
	}
	return 0
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
	if r.u8() != 1 {
		return "", ErrNotTLS // not a ClientHello
	}
	hl := r.u24()
	if hl > len(r.b) {
		return "", ErrSplitHello
	}
	r.b = r.b[:hl]
	r.take(2 + 32)  // legacy_version, random
	r.take(r.u8())  // legacy_session_id
	r.take(r.u16()) // cipher_suites
	r.take(r.u8())  // compression_methods
	el := r.u16()
	if r.bad || el != len(r.b) {
		return "", ErrBadHello
	}
	name := ""
	for len(r.b) > 0 {
		typ := r.u16()
		xb := r.take(r.u16())
		if r.bad {
			return "", ErrBadHello
		}
		if typ != 0 {
			continue
		}
		x := &reader{b: xb}
		ll := x.u16()
		if x.bad || ll != len(x.b) {
			return "", ErrBadHello
		}
		for len(x.b) > 0 {
			nt := x.u8()
			nb := x.take(x.u16())
			if x.bad || len(nb) == 0 {
				return "", ErrBadHello
			}
			if nt != 0 {
				continue
			}
			if name != "" {
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
