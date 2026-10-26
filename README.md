# relay

[![Docs](https://img.shields.io/badge/docs-hugo%20%2B%20hextra-0079A8)](https://go-wasmcontainers.github.io/docs/latest/relay/)
[![License: BSD-3-Clause](https://img.shields.io/badge/license-BSD--3--Clause-blue)](LICENSE)
[![CI](https://github.com/go-wasmcontainers/relay/actions/workflows/ci.yml/badge.svg)](https://github.com/go-wasmcontainers/relay/actions/workflows/ci.yml)
[![Go Reference](https://pkg.go.dev/badge/github.com/go-wasmcontainers/relay.svg)](https://pkg.go.dev/github.com/go-wasmcontainers/relay)
![status](https://img.shields.io/badge/status-M--relay--2-green)

**The classroom relay and firewall for WASI containers**, in pure Go
(`CGO_ENABLED=0`). Every student's browser (or engine) opens one secure
WebSocket to `wctr-relay`, on the teacher's laptop or on a server; the relay
brokers the containers' connections and datagrams between students, gives
each container an address and a DNS name, and checks **every flow** against
**security groups modelled on OpenStack Neutron**: default deny, allow-only
rules, enforced at both ends, stateful by connection tracking, with a flow
log. The teacher manages it through a **gRPC control API** (connect-go: gRPC,
gRPC-Web and the Connect protocol on one handler) and the `wctr-relay`
command. Documentation: <https://go-wasmcontainers.github.io/docs/latest/relay/>;
design: <https://go-wasmcontainers.github.io/docs/latest/design/classroom-network/>.

> **Status: M-relay-1 and M-relay-2.** The relay core, the data plane, the
> firewall, the control API, the CLI, TLS (internal CA, files, ACME) and
> OpenID Connect verification are written and tested natively. The browser
> path inside the engine, the live flow map and high availability are later
> milestones; see [Limitations](#limitations).

## Quick start (teacher)

```console
$ go install github.com/go-wasmcontainers/relay/cmd/wctr-relay@latest
$ wctr-relay init --name relay.local --ip 192.168.1.10   # state dir, admin token, internal CA
$ wctr-relay serve --listen :8443 &
$ wctr-relay class create "Networking 101"
class     Networking 101 (c-…)
join code 7KQ2M-X9D4P
network   10.42.0.0/16, /24 per session, domain .class
template  isolated
$ wctr-relay sg create web --class c-…
$ wctr-relay rule add web --class c-… --ingress --proto tcp --port 80
$ wctr-relay rule add default --class c-… --egress --proto tcp --port 80
$ wctr-relay port set alice/web --class c-… --sg default,web
$ wctr-relay flows --class c-… --follow
```

`init --name/--ip` creates the internal CA: install `ca.crt` (printed by
`wctr-relay ca export`) on the class's machines, or use a publicly trusted
certificate (`--tls acme` or `--tls files`). Students join with the code;
each gets a subnet (`10.42.<n>.0/24`), each container an address and the
name `<container>.<student>.class`. A new class starts **isolated** (no
ingress; egress to the teacher's subnet only): opening flows is the lab.
`--template neutron` gives Neutron's default group instead (all egress,
ingress from the same group). The sequence above is what `TestAcceptance`
(`internal/cli`) runs against a real `serve`.

## Commands

| Command | What |
| --- | --- |
| `init [--name N] [--ip A]` | state directory (`0700`): admin token, signing keys, internal CA for those names |
| `serve` | run the relay (flags below) |
| `class create NAME [--cidr --session-bits --domain --template --allow --require-identity]` | a class and its join code |
| `class list`, `delete`, `rotate-code`, `sessions`, `kick` | manage classes and sessions |
| `sg list`, `sg create NAME [--stateless]`, `sg delete` | security groups |
| `rule add GROUP --ingress\|--egress [--proto --port --remote-ip\|--remote-group]`, `rule delete ID` | rules (allow only); deleting one resets the flows only it allowed |
| `port list [--student]`, `port set PORT [--sg a,b] [--port-security on\|off]` | ports (containers) |
| `flows [--follow] [--deny-only] [--student]` | the flow log |
| `explain SRC DST PROTO/PORT` | what the firewall would decide, and which rules |
| `ca export`, `fingerprint`, `rotate` | the internal CA's root |
| `teacher-session --out FILE` | a session for the teacher's own containers (subnet 0, label `teacher`) |

`serve` flags: `--listen` (`:8443`); `--tls internal|files|acme|off`;
`--cert`/`--key` (files, reloaded on change); `--acme-domain`, `--acme-email`,
`--acme-directory`, `--eab-kid`, `--eab-hmac-file`, `--acme-http` (ACME
through [go-authn/servercert](https://github.com/go-authn/servercert)); `off`
only on loopback, behind a proxy such as Caddy; `--origin` (other origins
allowed to open the data channel, default the GitHub Pages playground);
`--host` (Host names served); `--oidc-issuer`, `--oidc-audience`,
`--oidc-type`, `--teacher-group` (OpenID Connect through
[go-authn/oidc](https://github.com/go-authn/oidc)); `--admin-listen` (admin
API on TCP with TLS); `--session-ttl`; `--audit-retention`. The admin API is
on the state directory's Unix socket (`0600`); the CLI uses it, or
`--server https://… --token-file FILE`.

## Packages

| Package | What it does |
| --- | --- |
| `frame` | the data-plane wire format v1: 10-byte header, 16 KiB payload bound |
| `firewall` | the Neutron-style model and its evaluation (both ends, remote prefix and group, stateful and stateless, ICMP type and code) |
| `auth` | session tokens (Ed25519, fixed layout, one algorithm), join codes, DNS labels |
| `relay` | the core: classes, sessions, ports, addresses, DNS, the stream and datagram broker, credit flow control, connection tracking, revocation, quotas, rate limits, flow log, `Store` (a file now, replicated later) |
| `driver` | the client an engine uses: `Session`, `Endpoint` with `Listen`, `Dial`, `ListenPacket`, `Resolve` returning `net` types; builds for `js/wasm` |
| `server` | the WebSocket data plane and the Connect handlers; public and admin handlers; OpenID Connect; pre-authentication limits |
| `tlsca` | the internal, name-constrained CA |
| `cmd/wctr-relay`, `internal/cli` | the cobra command line |

The contract the engine implements is in [docs/NETWORKDRIVER.md](docs/NETWORKDRIVER.md).

## Security

- **Identity is the relay's**: it assigns every address and port; a frame
  naming a port the session does not own is refused; a datagram from a source
  port the sender has not bound is dropped (`TestSpoofing`).
- **Authenticate before upgrading**: the session token travels as a WebSocket
  subprotocol (`bearer.<token>`), is checked before the upgrade and before any
  per-session state, and is never in a URL. Per-IP limits on joins and
  upgrades, a cap on concurrent handshakes, `ReadHeaderTimeout`,
  `MaxHeaderBytes`.
- **Two handlers**: the public one never grants the admin role (the admin
  token is refused there, `TestEndToEnd`); the admin API is on a `0600` Unix
  socket, or `--admin-listen` with the token or the OIDC teacher role.
- **Bounds**: 16 KiB frames, 64 KiB stream windows, per-session streams,
  listeners, ports, pending connects, bytes/s and frames/s, a 4 MiB send queue
  after which a slow reader is closed; per-class quotas on groups and rules
  (Neutron's `security_group` and `security_group_rule`).
- **Origin and Host** checks on the data channel (foreign pages, DNS rebinding).
- **Secrets** (admin token, signing keys, CA key, EAB key, state file) are
  `0600` files, refused if group- or world-readable, never on a command line.
- **Privacy**: per student, a display name, a derived label and, with OpenID
  Connect, a pseudonymous hash of issuer and subject; deleting a class deletes
  them. The audit log keeps 30 days by default.
- **Fuzzed** in CI: the frame decoder, the token parser, join codes, labels,
  CLI rule specs, and the relay fed arbitrary frames (`FuzzServe`).
  `govulncheck` runs on every change.

## Performance

The benchmarks are committed (`go test -run '^$' -bench . -cpu 1 ./relay`):
one stream's throughput against a direct loopback TCP connection
(`BenchmarkDirectTCP`), a 64-byte round trip, and 40 sessions echoing at once.
**No numbers are published yet**: the measuring machine was loaded (1-minute
load above 12) when this release was cut, which makes ratios meaningless.
They are an open item.

## Limitations

- The engine does not use the driver yet (its `NetworkDriver` is the engine's
  to write); the browser path, the playground served by the relay, join-flow
  detection and WebTransport are later milestones (M-relay-3 and -4).
- No live flow map page yet (M-relay-2b), no ICMP (M-relay-5), no IPv6.
- One relay per class: high availability (Raft, epoch leases) is M-relay-HA.
- servercert has no DNS-01 yet ([go-authn/servercert#16](https://github.com/go-authn/servercert/issues/16)),
  so a LAN-only relay with a public name needs a CA with pre-validated domains
  (GÉANT TCS) or `--tls files`.
- `wctr-relay login` (the OpenID Connect loopback login for the teacher) is
  not written; a remote admin uses `--token-file`.

## License

BSD 3-Clause, see [LICENSE](LICENSE).
