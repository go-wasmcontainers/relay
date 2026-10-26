// SPDX-License-Identifier: BSD-3-Clause

package frame

import (
	"bytes"
	"encoding/binary"
	"errors"
	"testing"
)

func TestRoundTrip(t *testing.T) {
	for _, f := range []Frame{
		{Type: TypeHello, Stream: 0, Payload: []byte("x")},
		{Type: TypeData, Stream: 7, Payload: bytes.Repeat([]byte{0xAB}, MaxPayload)},
		{Type: TypeClose, Stream: 1<<32 - 1},
		{Type: TypeWindow, Stream: 3, Payload: Credit(65536)},
	} {
		b, err := Encode(f)
		if err != nil {
			t.Fatal(err)
		}
		if len(b) != HeaderSize+len(f.Payload) {
			t.Fatalf("%v: %d bytes", f.Type, len(b))
		}
		g, err := Decode(b)
		if err != nil {
			t.Fatalf("%v: %v", f.Type, err)
		}
		if g.Type != f.Type || g.Stream != f.Stream || !bytes.Equal(g.Payload, f.Payload) {
			t.Fatalf("round trip: %+v != %+v", g, f)
		}
	}
}

func TestDecodeRefuses(t *testing.T) {
	ok, _ := Encode(Frame{Type: TypeData, Stream: 1, Payload: []byte("abc")})
	big := make([]byte, HeaderSize+MaxPayload+1)
	big[0] = byte(TypeData)
	binary.BigEndian.PutUint32(big[6:], MaxPayload+1)
	lie := append([]byte(nil), ok...)
	binary.BigEndian.PutUint32(lie[6:], 2)
	unknown := append([]byte(nil), ok...)
	unknown[0] = byte(typeEnd)
	zero := append([]byte(nil), ok...)
	zero[0] = 0
	flags := append([]byte(nil), ok...)
	flags[1] = 1
	for name, c := range map[string]struct {
		msg  []byte
		want error
	}{
		"short":    {ok[:HeaderSize-1], ErrShort},
		"too big":  {big, ErrTooLarge},
		"length":   {lie, ErrLength},
		"trailing": {append(append([]byte(nil), ok...), 0), ErrLength},
		"unknown":  {unknown, ErrUnknownType},
		"zero":     {zero, ErrUnknownType},
		"flags":    {flags, ErrFlags},
	} {
		if _, err := Decode(c.msg); !errors.Is(err, c.want) {
			t.Errorf("%s: %v, want %v", name, err, c.want)
		}
	}
}

func TestEncodeRefuses(t *testing.T) {
	if _, err := Encode(Frame{Type: TypeData, Payload: make([]byte, MaxPayload+1)}); !errors.Is(err, ErrTooLarge) {
		t.Fatal(err)
	}
	if _, err := Encode(Frame{Type: 200}); !errors.Is(err, ErrUnknownType) {
		t.Fatal(err)
	}
}

func TestCredit(t *testing.T) {
	n, err := ParseCredit(Credit(12345))
	if err != nil || n != 12345 {
		t.Fatal(n, err)
	}
	if _, err := ParseCredit([]byte{1, 2, 3}); err == nil {
		t.Fatal("3 bytes accepted")
	}
}

func TestTypeNames(t *testing.T) {
	if len(typeNames) != int(typeEnd) {
		t.Fatalf("%d names for %d types", len(typeNames), typeEnd)
	}
	if TypeGoAway.String() != "GOAWAY" || Type(99).String() != "TYPE(99)" {
		t.Fatal(TypeGoAway.String(), Type(99).String())
	}
}

// FuzzDecode: any message either decodes to a frame that re-encodes to the
// same bytes, or is refused; nothing panics and the payload stays bounded.
func FuzzDecode(f *testing.F) {
	for _, s := range []Frame{{Type: TypeHello, Payload: []byte{8, 1}}, {Type: TypeData, Stream: 9, Payload: []byte("hello")},
		{Type: TypeWindow, Stream: 2, Payload: Credit(1)}} {
		b, _ := Encode(s)
		f.Add(b)
	}
	f.Add([]byte{})
	f.Add(make([]byte, HeaderSize))
	f.Fuzz(func(t *testing.T, msg []byte) {
		fr, err := Decode(msg)
		if err != nil {
			return
		}
		if len(fr.Payload) > MaxPayload {
			t.Fatalf("payload of %d bytes", len(fr.Payload))
		}
		b, err := Encode(fr)
		if err != nil {
			t.Fatalf("decoded frame does not encode: %v", err)
		}
		if !bytes.Equal(b, msg) {
			t.Fatalf("re-encoding differs")
		}
	})
}
