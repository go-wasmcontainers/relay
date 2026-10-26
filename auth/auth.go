// SPDX-License-Identifier: BSD-3-Clause

// Package auth holds the relay's own credentials: the teacher's admin token,
// a class's join code, and the session tokens the relay signs for students.
//
// A session token is
//
//	"v1." + base64url(claims) + "." + base64url(Ed25519 signature over "v1." + base64url(claims))
//
// where claims is a fixed binary layout (no JSON, no algorithm field: there
// is exactly one algorithm, so there is nothing to confuse):
//
//	u8   key id
//	i64  expiry, unix seconds, big endian
//	u8   len, class id
//	u8   len, session id
//
// The token is checked against the relay's clock only.
package auth

import (
	"bytes"
	"crypto/ed25519"
	"crypto/rand"
	"crypto/subtle"
	"encoding/base64"
	"encoding/binary"
	"errors"
	"fmt"
	"strings"
	"time"
	"unicode"
)

var b64 = base64.RawURLEncoding

// MaxTokenLen bounds what ParseToken will look at.
const MaxTokenLen = 512

// Claims are what a session token says.
type Claims struct {
	KeyID   uint8
	Expiry  time.Time
	Class   string
	Session string
}

// Errors from Verify. A client is told only "unauthenticated"; these are for
// the relay's log.
var (
	ErrMalformed = errors.New("auth: malformed token")
	ErrSignature = errors.New("auth: bad signature")
	ErrExpired   = errors.New("auth: token expired")
	ErrKey       = errors.New("auth: unknown key id")
)

// Keys signs and verifies session tokens. Keys are identified by a one-byte
// id so they can be rotated (the replicated store, later, distributes them).
type Keys struct {
	Current uint8
	Private map[uint8]ed25519.PrivateKey
}

// NewKeys makes a key set with one fresh key, id 1.
func NewKeys() (*Keys, error) {
	_, priv, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		return nil, err
	}
	return &Keys{Current: 1, Private: map[uint8]ed25519.PrivateKey{1: priv}}, nil
}

// Sign issues a token for c (its KeyID is set to the current key).
func (k *Keys) Sign(c Claims) (string, error) {
	priv, ok := k.Private[k.Current]
	if !ok {
		return "", ErrKey
	}
	if len(c.Class) > 64 || len(c.Session) > 64 {
		return "", errors.New("auth: id longer than 64 bytes")
	}
	c.KeyID = k.Current
	var buf bytes.Buffer
	buf.WriteByte(c.KeyID)
	var e [8]byte
	binary.BigEndian.PutUint64(e[:], uint64(c.Expiry.Unix()))
	buf.Write(e[:])
	buf.WriteByte(byte(len(c.Class)))
	buf.WriteString(c.Class)
	buf.WriteByte(byte(len(c.Session)))
	buf.WriteString(c.Session)
	head := "v1." + b64.EncodeToString(buf.Bytes())
	sig := ed25519.Sign(priv, []byte(head))
	return head + "." + b64.EncodeToString(sig), nil
}

// Verify checks a token's form, signature and expiry at now.
func (k *Keys) Verify(tok string, now time.Time) (Claims, error) {
	c, head, sig, err := ParseToken(tok)
	if err != nil {
		return Claims{}, err
	}
	priv, ok := k.Private[c.KeyID]
	if !ok {
		return Claims{}, ErrKey
	}
	if !ed25519.Verify(priv.Public().(ed25519.PublicKey), []byte(head), sig) {
		return Claims{}, ErrSignature
	}
	if !now.Before(c.Expiry) {
		return Claims{}, ErrExpired
	}
	return c, nil
}

// ParseToken splits and decodes a token without checking its signature.
// head is the signed part.
func ParseToken(tok string) (c Claims, head string, sig []byte, err error) {
	if len(tok) > MaxTokenLen || !strings.HasPrefix(tok, "v1.") {
		return Claims{}, "", nil, ErrMalformed
	}
	rest := tok[3:]
	body, s, ok := strings.Cut(rest, ".")
	if !ok || strings.Contains(s, ".") {
		return Claims{}, "", nil, ErrMalformed
	}
	raw, err := b64.Strict().DecodeString(body)
	if err != nil {
		return Claims{}, "", nil, ErrMalformed
	}
	sig, err = b64.Strict().DecodeString(s)
	if err != nil || len(sig) != ed25519.SignatureSize {
		return Claims{}, "", nil, ErrMalformed
	}
	// Canonical spelling only: one token, one string.
	if b64.EncodeToString(raw) != body || b64.EncodeToString(sig) != s {
		return Claims{}, "", nil, ErrMalformed
	}
	if len(raw) < 1+8+1 {
		return Claims{}, "", nil, ErrMalformed
	}
	c.KeyID = raw[0]
	exp := int64(binary.BigEndian.Uint64(raw[1:9]))
	if exp < 0 || exp > 253402300799 { // year 9999
		return Claims{}, "", nil, ErrMalformed
	}
	c.Expiry = time.Unix(exp, 0)
	p := raw[9:]
	cls, p, ok := lenPrefixed(p)
	if !ok {
		return Claims{}, "", nil, ErrMalformed
	}
	ses, p, ok := lenPrefixed(p)
	if !ok || len(p) != 0 {
		return Claims{}, "", nil, ErrMalformed
	}
	c.Class, c.Session = cls, ses
	return c, "v1." + body, sig, nil
}

func lenPrefixed(p []byte) (string, []byte, bool) {
	if len(p) < 1 {
		return "", nil, false
	}
	n := int(p[0])
	if len(p) < 1+n || n > 64 {
		return "", nil, false
	}
	return string(p[1 : 1+n]), p[1+n:], true
}

// RandomToken is 32 random bytes, base64url: the admin token.
func RandomToken() (string, error) {
	var b [32]byte
	if _, err := rand.Read(b[:]); err != nil {
		return "", err
	}
	return b64.EncodeToString(b[:]), nil
}

// Equal compares two secrets in constant time.
func Equal(a, b string) bool {
	return subtle.ConstantTimeCompare([]byte(a), []byte(b)) == 1
}

// codeAlphabet is Crockford's base32: no I, L, O, U, so a code read aloud or
// copied from a projector is not mistaken.
const codeAlphabet = "0123456789ABCDEFGHJKMNPQRSTVWXYZ"

// CodeLen is a join code's length: 10 symbols of 5 bits, 50 bits.
const CodeLen = 10

// NewJoinCode draws a join code.
func NewJoinCode() (string, error) {
	var b [CodeLen]byte
	if _, err := rand.Read(b[:]); err != nil {
		return "", err
	}
	for i := range b {
		b[i] = codeAlphabet[b[i]&31]
	}
	return string(b[:]), nil
}

// NormalizeJoinCode reads a typed code: case-insensitive, spaces and dashes
// ignored, and the look-alikes Crockford maps (O->0, I/L->1).
func NormalizeJoinCode(s string) (string, error) {
	if len(s) > 64 {
		return "", errors.New("join code too long")
	}
	var out []byte
	for _, r := range strings.ToUpper(s) {
		switch {
		case r == ' ' || r == '-':
			continue
		case r == 'O':
			r = '0'
		case r == 'I' || r == 'L':
			r = '1'
		}
		if r > unicode.MaxASCII || !strings.ContainsRune(codeAlphabet, r) {
			return "", fmt.Errorf("join code: %q is not a code symbol", r)
		}
		out = append(out, byte(r))
	}
	if len(out) != CodeLen {
		return "", fmt.Errorf("join code: want %d symbols", CodeLen)
	}
	return string(out), nil
}

// Label derives a DNS label from a display name: lower-case ASCII letters and
// digits, hyphens between words, at most 20 bytes, never empty (it falls back
// to "student"). Collisions are the caller's to resolve.
func Label(display string) string {
	var b []byte
	dash := false
	for _, r := range strings.ToLower(display) {
		switch {
		case r >= 'a' && r <= 'z', r >= '0' && r <= '9':
			if dash && len(b) > 0 {
				b = append(b, '-')
			}
			dash = false
			b = append(b, byte(r))
		default:
			dash = true
		}
		if len(b) >= 20 {
			break
		}
	}
	if len(b) > 20 {
		b = b[:20]
	}
	for len(b) > 0 && b[len(b)-1] == '-' {
		b = b[:len(b)-1]
	}
	if len(b) == 0 || (b[0] >= '0' && b[0] <= '9') {
		b = append([]byte("s-"), b...)
		if len(b) == 2 {
			return "student"
		}
	}
	return string(b)
}

// CleanDisplayName bounds and strips a display name: at most 40 runes, no
// control or format characters, trimmed. It is data, escaped wherever shown.
func CleanDisplayName(s string) string {
	var out []rune
	for _, r := range s {
		if unicode.IsControl(r) || unicode.Is(unicode.Cf, r) {
			continue
		}
		out = append(out, r)
		if len(out) == 40 {
			break
		}
	}
	return strings.TrimSpace(string(out))
}
