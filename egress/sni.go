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
	ErrECH        = errors.New("egress: Encrypted Client Hello is refused")
)

// extECH is the encrypted_client_hello extension type (draft-ietf-tls-esni).
// The gateway cannot see the inner name, so a hello carrying it is refused
// whatever its outer name (decision D4).
const extECH = 0xfe0d

// hostByte reports whether c may appear in a host_name: letters, digits,
// hyphen, dot and underscore (RFC 6066 3 wants an ASCII DNS name without a
// trailing dot; anything else is not a name the allowlist could hold).
func hostByte(c byte) bool {
	switch {
	case c >= 'a' && c <= 'z', c >= 'A' && c <= 'Z', c >= '0' && c <= '9':
		return true
	}
	return c == '-' || c == '.' || c == '_'
}

// helloRetryRandom is the fixed ServerHello.random of a HelloRetryRequest,
// the SHA-256 of "HelloRetryRequest" (RFC 8446 4.1.3).
var helloRetryRandom = [32]byte{
	0xCF, 0x21, 0xAD, 0x74, 0xE5, 0x9A, 0x61, 0x11, 0xBE, 0x1D, 0x8C, 0x02, 0x1E, 0x65, 0xB8, 0x91,
	0xC2, 0xA2, 0x11, 0x16, 0x7A, 0xBB, 0x8C, 0x5E, 0x07, 0x9E, 0x09, 0xE2, 0xC8, 0xA8, 0x33, 0x9C,
}

// IsHelloRetryRequest reports whether b, the first bytes the server sent,
// open with a HelloRetryRequest. A HelloRetryRequest makes the client send a
// second ClientHello the gateway never saw, so the relay refuses it
// (decision D4). decided is false while b is too short to tell: the first
// 43 bytes are needed (record header, handshake header, version, random).
func IsHelloRetryRequest(b []byte) (hrr, decided bool) {
	if len(b) == 0 {
		return false, false
	}
	if b[0] != 0x16 {
		return false, true
	}
	if len(b) > 5 && b[5] != 2 {
		return false, true
	}
	if len(b) < 11+32 {
		return false, false
	}
	return string(b[11:11+32]) == string(helloRetryRandom[:]), true
}

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
// server name or two (ErrNoSNI, ErrMultiSNI), a repeated extension type (RFC
// 8446 4.2) and a hello using Encrypted Client Hello (ErrECH, decision D4:
// the inner name is unreachable by design, so whatever the outer name says
// proves nothing).
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
	// seen holds one bit per extension type: RFC 8446 4.2 forbids two
	// extensions of one type in a ClientHello.
	var seen [1 << 13]byte
	for len(r.b) > 0 {
		typ := r.u16()
		xb := r.take(r.u16())
		if r.bad {
			return "", ErrBadHello
		}
		if typ == extECH {
			return "", ErrECH
		}
		if seen[typ>>3]&(1<<(typ&7)) != 0 {
			if typ == 0 {
				return "", ErrMultiSNI
			}
			return "", ErrBadHello
		}
		seen[typ>>3] |= 1 << (typ & 7)
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
				if !hostByte(c) {
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
