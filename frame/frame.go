// SPDX-License-Identifier: BSD-3-Clause

// Package frame is the relay's data-plane wire format, version 1.
//
// One WebSocket per browser carries binary messages; each message is exactly
// one frame:
//
//	0      1      2              6              10
//	+------+------+--------------+--------------+------------------+
//	| type | flags| stream id    | length       | payload ...      |
//	| u8   | u8   | u32 BE       | u32 BE       | length bytes     |
//	+------+------+--------------+--------------+------------------+
//
// length must equal the number of payload bytes that follow, and be at most
// MaxPayload. Control frames carry a protobuf message (package relayv1);
// DATA carries raw bytes; WINDOW carries a u32 BE credit.
//
// Stream ids: the client allocates odd ids, the relay even ids, so the two
// never collide (as HTTP/2 does). Id 0 is the connection itself. Request
// frames (ATTACH, LISTEN, RESOLVE, ...) use the stream id as a request id and
// are answered with the same id.
package frame

import (
	"encoding/binary"
	"errors"
	"fmt"
)

// Version is the protocol version this package speaks. A peer that sends
// another major version is refused (relayv1.Code_CODE_VERSION).
const Version = 1

// Subprotocol is the WebSocket subprotocol of version 1. The session token
// travels as a second subprotocol, BearerPrefix + token, so that it is
// checked before the upgrade (a browser cannot set an Authorization header
// on a WebSocket) and never appears in a URL.
const (
	Subprotocol  = "wctr-relay.v1"
	BearerPrefix = "bearer."
)

const (
	// HeaderSize is the fixed header length.
	HeaderSize = 10
	// MaxPayload bounds every frame's payload: 16 KiB.
	MaxPayload = 16 << 10
	// MaxFrame is the largest message a peer may send; a WebSocket read
	// limit is set to it.
	MaxFrame = HeaderSize + MaxPayload
)

// Type is a frame type.
type Type uint8

// Frame types. The numbering is part of the protocol: never renumber.
const (
	TypeInvalid   Type = 0
	TypeHello     Type = 1  // client: relayv1.Hello (first frame)
	TypeWelcome   Type = 2  // relay: relayv1.Welcome
	TypeAttach    Type = 3  // client request: relayv1.Attach
	TypeAttached  Type = 4  // relay reply: relayv1.Attached
	TypeDetach    Type = 5  // client: relayv1.Detach
	TypeListen    Type = 6  // client request: relayv1.Listen
	TypeListening Type = 7  // relay reply: relayv1.Listening
	TypeUnlisten  Type = 8  // client: relayv1.Unlisten
	TypeConnect   Type = 9  // client: relayv1.Connect; relay to listener: relayv1.Incoming
	TypeAccept    Type = 10 // listener: empty; relay to caller: relayv1.Accepted
	TypeRefuse    Type = 11 // relayv1.Result
	TypeData      Type = 12 // raw bytes
	TypeWindow    Type = 13 // u32 BE credit
	TypeClose     Type = 14 // empty: this side will send no more on the stream
	TypeReset     Type = 15 // relayv1.Result: the stream is gone
	TypeDatagram  Type = 16 // relayv1.Datagram
	TypeResolve   Type = 17 // client request: relayv1.Resolve
	TypeResolved  Type = 18 // relay reply: relayv1.Resolved
	TypeResult    Type = 19 // relay reply to a request that failed: relayv1.Result
	TypeReauth    Type = 20 // client: relayv1.Hello with a new session token
	TypeGoAway    Type = 21 // relay: relayv1.Result, then the connection closes
	typeEnd       Type = 22
)

var typeNames = [...]string{"INVALID", "HELLO", "WELCOME", "ATTACH", "ATTACHED", "DETACH",
	"LISTEN", "LISTENING", "UNLISTEN", "CONNECT", "ACCEPT", "REFUSE", "DATA", "WINDOW",
	"CLOSE", "RESET", "DATAGRAM", "RESOLVE", "RESOLVED", "RESULT", "REAUTH", "GOAWAY"}

func (t Type) String() string {
	if t < typeEnd {
		return typeNames[t]
	}
	return fmt.Sprintf("TYPE(%d)", uint8(t))
}

// Known reports whether t is a frame type of this version.
func (t Type) Known() bool { return t > TypeInvalid && t < typeEnd }

// Frame is one decoded frame. Payload aliases the buffer it was decoded
// from: copy it to keep it past the next read.
type Frame struct {
	Type    Type
	Flags   uint8
	Stream  uint32
	Payload []byte
}

// Errors returned by Decode. Every one of them is a protocol violation: the
// relay answers it by closing the connection.
var (
	ErrShort       = errors.New("frame: shorter than its header")
	ErrTooLarge    = errors.New("frame: payload larger than 16 KiB")
	ErrLength      = errors.New("frame: length field disagrees with the message")
	ErrUnknownType = errors.New("frame: unknown type")
	ErrFlags       = errors.New("frame: reserved flags set")
)

// Decode parses one message into a frame. It never allocates: Payload is a
// sub-slice of msg.
func Decode(msg []byte) (Frame, error) {
	if len(msg) < HeaderSize {
		return Frame{}, ErrShort
	}
	f := Frame{
		Type:   Type(msg[0]),
		Flags:  msg[1],
		Stream: binary.BigEndian.Uint32(msg[2:6]),
	}
	n := binary.BigEndian.Uint32(msg[6:10])
	if n > MaxPayload {
		return Frame{}, ErrTooLarge
	}
	if uint64(n) != uint64(len(msg)-HeaderSize) {
		return Frame{}, ErrLength
	}
	if !f.Type.Known() {
		return Frame{}, ErrUnknownType
	}
	if f.Flags != 0 {
		return Frame{}, ErrFlags
	}
	f.Payload = msg[HeaderSize:]
	return f, nil
}

// Append encodes f onto dst and returns the extended slice.
func Append(dst []byte, f Frame) ([]byte, error) {
	if len(f.Payload) > MaxPayload {
		return dst, ErrTooLarge
	}
	if !f.Type.Known() {
		return dst, ErrUnknownType
	}
	var h [HeaderSize]byte
	h[0] = byte(f.Type)
	h[1] = f.Flags
	binary.BigEndian.PutUint32(h[2:6], f.Stream)
	binary.BigEndian.PutUint32(h[6:10], uint32(len(f.Payload)))
	dst = append(dst, h[:]...)
	return append(dst, f.Payload...), nil
}

// Encode is Append onto a new slice.
func Encode(f Frame) ([]byte, error) {
	return Append(make([]byte, 0, HeaderSize+len(f.Payload)), f)
}

// Credit is the payload of a WINDOW frame.
func Credit(n uint32) []byte {
	var b [4]byte
	binary.BigEndian.PutUint32(b[:], n)
	return b[:]
}

// ParseCredit reads a WINDOW frame's payload.
func ParseCredit(p []byte) (uint32, error) {
	if len(p) != 4 {
		return 0, ErrLength
	}
	return binary.BigEndian.Uint32(p), nil
}

// ClientStream reports whether id was allocated by the client (odd).
func ClientStream(id uint32) bool { return id&1 == 1 }
