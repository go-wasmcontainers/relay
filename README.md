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

> **Status: M-relay-1, M-relay-2 and M-relay-2b.** The relay core, the data
> plane, the firewall, the control API, the CLI, TLS (internal CA, files,
> ACME), OpenID Connect verification and the live flow map are written and
> tested (natively, and the flow map in Chromium and Firefox). The browser
> path inside the engine and high availability are later milestones; see
> [Limitations](#limitations).

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

## The live flow map

```console
$ wctr-relay flowmap --class c-… --url https://relay.local:8443
https://relay.local:8443/flowmap/#class=c-…&ticket=v1.…
```

Open the link (on the projector): every student is a box holding their
containers, coloured by security group; every flow is a line whose width
follows its throughput; a **refused flow flashes as a dashed red line**, and
its row in the event log says which rule was missing. Click a container or a
flow for its details (address, groups, the rules that allowed it, counters);
the filter box dims everything else. The page is a Go WebAssembly
application on [go-widgets](https://github.com/go-widgets/toolkit)'
`GraphView`, served by the relay itself under a strict Content-Security-Policy
(`script-src 'self' 'wasm-unsafe-eval'`, nothing from elsewhere), fed by the
`FlowLogService.WatchFlowMap` server stream (Connect protocol): one
aggregated update per tick (4 Hz), coalesced for a slow reader, capped at
400 containers and 2 000 flows.

The link's ticket (in the fragment, never sent to a server, removed from the
address bar on load) allows watching that class's map and nothing else, for
12 hours. A student can open their own view, with their session token: only
the flows that touch their own containers.

The page's WebAssembly is about 20 MB (4.9 MB gzipped, as embedded), so it is not committed: the binaries
attached to each [release](https://github.com/go-wasmcontainers/relay/releases)
carry it (built with `-tags flowmap`). From source:
`go run ./internal/buildflowmap && go install -tags flowmap ./cmd/wctr-relay`.
A plain `go install` serves the page, which then says the map is missing.

## Commands

| Command | What |
| --- | --- |
| `init [--name N] [--ip A]` | state directory (`0700`): admin token, signing keys, internal CA for those names |
| `serve` | run the relay (flags below) |
| `class create NAME [--cidr --session-bits --domain --template --allow --require-identity --egress]` | a class and its join code; `--egress host:443` (repeatable) opens [outbound egress](#outbound-egress) |
| `class list`, `delete`, `rotate-code`, `sessions`, `kick` | manage classes and sessions |
| `sg list`, `sg create NAME [--stateless]`, `sg delete` | security groups |
| `rule add GROUP --ingress\|--egress [--proto --port --remote-ip\|--remote-group]`, `rule delete ID` | rules (allow only); deleting one resets the flows only it allowed |
| `port list [--student]`, `port set PORT [--sg a,b] [--port-security on\|off]` | ports (containers) |
| `flows [--follow] [--deny-only] [--student]` | the flow log |
| `explain SRC DST PROTO/PORT` | what the firewall would decide, and which rules |
| `ca export`, `fingerprint`, `rotate` | the internal CA's root |
| `teacher-session --out FILE` | a session for the teacher's own containers (subnet 0, label `teacher`) |
| `flowmap --class C --url https://…` | the link to the class's live flow map, with a read-only 12-hour ticket |

`serve` flags: `--listen` (`:8443`); `--tls internal|files|acme|off`;
`--cert`/`--key` (files, reloaded on change); `--acme-domain`, `--acme-email`,
`--acme-directory`, `--eab-kid`, `--eab-hmac-file`, `--acme-http` (ACME
through [go-authn/servercert](https://github.com/go-authn/servercert)); `off`
only on loopback, behind a proxy such as Caddy; `--cors-origin
https://go-wasmcontainers.github.io` (repeatable; a browser origin allowed
besides the relay's own: CORS on Join, RefreshSession, WatchFlowMap,
WatchFlows and ListPorts, and the Origin check of the data WebSocket against
cross-site hijacking; never `*`, no credentials mode, preflights cached 2
hours; default none, so a page served from elsewhere, such as the GitHub
Pages playground, must be listed; the admin listener has no CORS);
`--host` (Host names served); `--oidc-issuer`, `--oidc-audience`,
`--oidc-type`, `--teacher-group` (OpenID Connect through
[go-authn/oidc](https://github.com/go-authn/oidc)); `--admin-listen` (admin
API on TCP with TLS); `--session-ttl`; `--audit-retention`;
`--egress-operator` (the name shown to students as the party that sees their
outbound destinations; default the relay's ID). The admin API is
on the state directory's Unix socket (`0600`), or the path given with
`--admin-socket` (to `serve` and to the CLI alike; a Unix socket path holds
at most 103 bytes on macOS and 107 on Linux, and a longer one is refused with
that reason); the CLI uses it, or `--server https://… --token-file FILE`.

## Packages

| Package | What it does |
| --- | --- |
| `frame` | the data-plane wire format v1: 10-byte header, 16 KiB payload bound |
| `firewall` | the Neutron-style model and its evaluation (both ends, remote prefix and group, stateful and stateless, ICMP type and code) |
| `auth` | session tokens (Ed25519, fixed layout, one algorithm), join codes, DNS labels |
| `relay` | the core: classes, sessions, ports, addresses, DNS, the stream and datagram broker, credit flow control, connection tracking, revocation, quotas, rate limits, flow log, `Store` (a file now, replicated later) |
| `driver` | the client an engine uses: `Session`, `Endpoint` with `Listen`, `Dial`, `ListenPacket`, `Resolve` returning `net` types; builds for `js/wasm` |
| `server` | the WebSocket data plane and the Connect handlers; public and admin handlers; OpenID Connect; pre-authentication limits |
| `egress` | the outbound gateway's policy: the allowlist, the deny tables, the resolve-and-pin step, the TLS ClientHello check; pure, no sockets |
| `tlsca` | the internal, name-constrained CA |
| `cmd/wctr-relay`, `internal/cli` | the cobra command line |
| `web/flowmap` (own module) | the flow-map page: view model, scene (go-widgets `GraphView`, `LogView`), its WebAssembly main, browser tests |
| `internal/buildflowmap` | builds the page's WebAssembly for `-tags flowmap` |

The contract the engine implements is in [docs/NETWORKDRIVER.md](docs/NETWORKDRIVER.md).

## Outbound egress

A class can let its containers reach a short list of public hosts. The relay
is the only gateway: nothing else in the class has a route out.

```sh
wctr-relay class create lab --require-identity --allow group:students \
    --egress api.example.org:443 --egress pypi.org:443
```

- **Needs identity and an audience.** `--egress` is refused unless the class
  has `--require-identity` and a non-empty `--allow`; a stored class that
  lost either is refused when the relay starts. No flag waives this.
- **Exact `host:443` entries.** No wildcard, no IP, no CIDR, no port other
  than 443, and an empty list is an error, not "everything".
- **Resolve, then pin.** The guest asks for a name; the relay resolves it
  outside, refuses the whole answer if any address is in a deny table
  (loopback, RFC 1918, link-local and the cloud metadata address, CGNAT,
  multicast, reserved, IPv4-embedding IPv6 prefixes, the class's own CIDR),
  and pins the addresses to that session for 5 minutes. A connection to any
  other address is refused, so DNS rebinding and IP literals get nowhere.
- **SNI must match.** The first TLS record is buffered (at most 16 KiB) and
  its server name must equal the pinned name; missing, mismatched, split
  across records, oversize or non-TLS streams are reset and counted. Nothing
  of a refused stream reaches the outside.
- **TCP only.** UDP and QUIC are dropped and counted. No IPv6 egress, though
  the IPv6 deny table ships and is tested.
- **Limits**, per session unless stated: 16 concurrent streams, 2 new
  connections per second (burst 20), 1 GiB per day, 8 lookups per second, 5
  minutes idle, 1 hour lifetime; per destination 64 streams across the class;
  8 MiB/s across the class. Over a limit the guest sees `ENOBUFS`
  (`CODE_LIMIT`); a policy refusal is `ECONNREFUSED` (`CODE_REFUSED`). A
  refusal after the stream was accepted (an SNI mismatch) shows up as
  `ECONNRESET`.
- **Ends with the session.** A kick, a join-code rotation or deleting the
  class closes the live egress streams and forgets the pins.
- **Logged, and said so.** Destinations are written to the flow log and kept
  for the audit retention (30 days by default). Every student's Welcome
  carries the operator's name, the allowlist, the limits and the counters, so
  the UI can say who sees what.
- **Personal egress** is running your own relay with a one-person class:
  you are the operator, and the list is yours.

Caveat: egress is for names you trust to be reached by every student of the
class; the relay is the audit point, not a content filter.

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
  CLI rule specs, the egress allowlist parser and ClientHello reader, and the
  relay fed arbitrary frames (`FuzzServe`).
  `govulncheck` runs on every change.

## Performance

The benchmarks are committed (`go test -run '^$' -bench . -cpu 1 ./relay`):
one stream's throughput against a direct loopback TCP connection
(`BenchmarkDirectTCP`), a 64-byte round trip, and 40 sessions echoing at once.
The flow map adds `BenchmarkSceneFrame` (`web/flowmap`: one update applied
and one 1920×1080 frame drawn, 40 students, 200 containers, 1 000 flows) and
the browser test logs the time from navigation to the first flow on screen
(184 ms in Chromium on the development machine). **No benchmark numbers are
published yet**: the measuring machine was loaded (1-minute
load above 12) when this release was cut, which makes ratios meaningless.
They are an open item.

## Limitations

- The engine does not use the driver yet (its `NetworkDriver` is the engine's
  to write); the browser path, the playground served by the relay, join-flow
  detection and WebTransport are later milestones (M-relay-3 and -4).
- No ICMP (M-relay-5), no IPv6 (and no IPv6 egress). The flow map has no pause/replay yet (the
  relay keeps the last 1 000 events; the page shows the last 200).
- One relay per class: high availability (Raft, epoch leases) is M-relay-HA.
- servercert has no DNS-01 yet ([go-authn/servercert#16](https://github.com/go-authn/servercert/issues/16)),
  so a LAN-only relay with a public name needs a CA with pre-validated domains
  (GÉANT TCS) or `--tls files`.
- `wctr-relay login` (the OpenID Connect loopback login for the teacher) is
  not written; a remote admin uses `--token-file`.

## License

BSD 3-Clause, see [LICENSE](LICENSE).
