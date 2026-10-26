# The engine's NetworkDriver contract

What [go-wasmcontainers/engine](https://github.com/go-wasmcontainers/engine)
implements so that its containers reach a class network through the relay.
The relay side exists (package `driver` of this repository); the engine side is
the engine's to write. Design:
<https://go-wasmcontainers.github.io/docs/main/design/classroom-network/>.

## The Go interface (in the engine)

```go
// Package netdriver (engine). A NetworkDriver gives containers endpoints
// on a network. The engine maps the WasmEdge socket host functions of
// wasi_snapshot_preview1 (sock_open, sock_bind, sock_listen, sock_accept via
// the listener, sock_connect, sock_recv_from, sock_send_to,
// sock_getaddrinfo, sock_shutdown, sock_getlocaladdr, sock_getpeeraddr) onto
// an Endpoint.
type NetworkDriver interface {
	// Attach gives container (a DNS label: [a-z0-9-]{1,63}) an endpoint.
	// Attaching the same name again returns the same address.
	Attach(ctx context.Context, container string) (Endpoint, error)
	Close() error
}

type Endpoint interface {
	Addr() netip.Addr
	// Listen: SOCK_STREAM bind+listen. port 0 picks an ephemeral port
	// (49152-65535); the returned listener's Addr says which.
	Listen(ctx context.Context, network string, port uint16) (net.Listener, error) // "tcp"
	// Dial: SOCK_STREAM connect, or a connected SOCK_DGRAM socket.
	Dial(ctx context.Context, network string, addr netip.AddrPort) (net.Conn, error) // "tcp", "udp"
	// ListenPacket: SOCK_DGRAM bind.
	ListenPacket(ctx context.Context, network string, port uint16) (net.PacketConn, error) // "udp"
	// Resolve: sock_getaddrinfo. Names: "<container>" (same session),
	// "<container>.<student>", "<container>.<student>.<domain>", or an IP
	// literal.
	Resolve(ctx context.Context, name string) ([]netip.Addr, error)
	Detach() error
}
```

`*driver.Endpoint` has exactly these methods (its `Listen` returns
`*driver.Listener` and `ListenPacket` `*driver.PacketConn`, which implement
`net.Listener` and `net.PacketConn`); a two-line adapter makes it the engine's
interface. `driver.Session` is one connection: `driver.DialWebSocket(ctx,
"wss://<relay>/v1/data", sessionToken, httpClient)` natively, the same call in
the browser (`GOOS=js`: the page's WebSocket does the handshake), or
`driver.Dial(ctx, transport)` over any message transport. `Session.Attach`
returns the endpoint.

### Errors → errno

Every refusal unwraps to a `syscall.Errno`, which the host function returns:

| relay answer | errno |
| --- | --- |
| no listener, or the firewall said no | `ECONNREFUSED` |
| no container has the address | `EHOSTUNREACH` |
| the peer went away, the rule was removed, the session ended | `ECONNRESET` |
| port already bound | `EADDRINUSE` |
| a quota or a rate limit | `ENOBUFS` |
| a name that does not resolve | `*net.DNSError` with `IsNotFound` (`EAI_NONAME`) |

### Behaviour the engine relies on

- Addresses are assigned by the relay; the engine never chooses one.
- A connect blocks until the listener's side accepts or refuses (10 s at
  most), as a TCP handshake would.
- Streams are flow-controlled end to end (64 KiB window per direction): a
  container that stops reading slows its peer, it does not fill memory.
- `Close` on a stream sends a close (the peer reads EOF); `CloseWrite`
  half-closes.
- UDP datagrams are at most 8 KiB; a full receive queue (256 datagrams)
  drops, as a socket buffer would.
- A reconnect of the same session (page reload) keeps every address; open
  streams are reset; listeners must be re-registered (the engine re-runs its
  `Listen` calls).
- Before the session token expires (`Welcome.token_expires_unix`), call
  `JoinService.RefreshSession` and `Session.Reauth(newToken)`; no flow drops.

## The wire protocol (version 1)

One binary WebSocket message per frame, subprotocol `wctr-relay.v1`, session
token as a second offered subprotocol `bearer.<token>` (checked before the
upgrade; never in a URL):

```text
 0      1      2              6              10
 +------+------+--------------+--------------+------------------+
 | type | flags| stream id    | length       | payload          |
 | u8   | 0    | u32 BE       | u32 BE       | <= 16 KiB        |
 +------+------+--------------+--------------+------------------+
```

| type | name | direction | payload (protobuf `wasmcontainers.relay.v1`) |
| --- | --- | --- | --- |
| 1 | HELLO | client, first frame | `Hello{version: 1}` |
| 2 | WELCOME | relay | `Welcome` (session, network, limits, relay id, epoch, token expiry) |
| 3/4 | ATTACH / ATTACHED | request / reply | `Attach{container}` / `Attached{port}` |
| 5 | DETACH | client | `Detach{port_id}` |
| 6/7 | LISTEN / LISTENING | request / reply | `Listen{port_id, protocol, port}` / `Listening{port}` |
| 8 | UNLISTEN | client | `Unlisten` |
| 9 | CONNECT | client (odd id) / relay to listener (even id) | `Connect{port_id, dst_ip, dst_port}` / `Incoming{port_id, listen_port, src_ip, src_port}` |
| 10 | ACCEPT | listener / relay to caller | empty / `Accepted{src_ip, src_port}` |
| 11 | REFUSE | either | `Result` |
| 12 | DATA | either | raw bytes, within the stream's credit |
| 13 | WINDOW | either | u32 BE credit returned |
| 14 | CLOSE | either | empty |
| 15 | RESET | either | `Result` |
| 16 | DATAGRAM | either, stream 0 | `Datagram{port_id, src_port, dst_ip, dst_port, payload}` (the relay fills `src_ip`) |
| 17/18 | RESOLVE / RESOLVED | request / reply | `Resolve{name}` / `Resolved{ips}` |
| 19 | RESULT | reply to a failed request | `Result{code, message}` |
| 20 | REAUTH | client | `Hello{session_token}` |
| 21 | GOAWAY | relay, then close | `Result` |

The client allocates odd stream ids, the relay even ones; a request's stream
id is its request id. A frame that does not decode, a `DATA` beyond the
window, or a frame out of place is a protocol violation: `GOAWAY` and close.
`frame.Version` is 1; a `HELLO` with another version gets `GOAWAY`
`CODE_VERSION`.

## Tests the engine can reuse

`relay.Pipe()` and `relay.Relay.Serve` run a relay in the same process as two
engines; see `relay/relay_test.go` for the pattern (two sessions, a listener,
a dial, rules allowing and denying).
