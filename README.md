# pcapnet

Go networking over gopacket/PCAP: direct UDP datagrams and TCP connections carried
by **PCAT — Packet Capture and Allocation Transport**.

PCAT assigns virtual IPv4 addresses to clients and serves their TCP connections
through one shared gVisor stack. Choose an unencrypted channel, server-authenticated
DTLS, or mutually authenticated DTLS (mDTLS). Direct UDP needs no gVisor stack.

## Features

- `net.Conn` / `net.PacketConn` for direct physical UDP, with optional magic-header framing.
- UDP magic-header capture across all ports, with read-only and replying APIs.
- TCP `Dial` / `Listen`, automatic client allocation, and concurrent peers.
- Optional [DTLS adapter](dtlstransport/README.md) for direct datagrams or PCAT, using Pion DTLS 1.2.
- Configurable virtual subnets, MTUs, deadlines, and session limits.
- Automatic Ethernet-device selection and optional host UDP port reservation.
- Pluggable packet/datagram transports and an in-memory backend for tests.

## Requirements

Use the Go toolchain specified in [go.mod](go.mod), CGO, a C compiler, and libpcap
development headers/libraries. Live PCAP requires an Ethernet capture driver and
capture/injection privileges. Loopback and non-Ethernet capture are unsupported.
Run peers on different hosts or suitably configured network namespaces.

```sh
go get github.com/MeHungr/pcapnet
```

## Quick start

Build the [TCP examples](examples/README.md) as a normal user, then run them with
capture/injection privileges:

```sh
go build -o /tmp/pcapnet-tcp-server ./examples/tcp-server
go build -o /tmp/pcapnet-tcp-client ./examples/tcp-client
```

```sh
# Server host
SERVER_IP=192.0.2.2
sudo /tmp/pcapnet-tcp-server -local-ip "$SERVER_IP" -subnet 10.200.0.0/24
```

```sh
# Client host
SERVER_IP=192.0.2.2
sudo /tmp/pcapnet-tcp-client -peer "${SERVER_IP}:45001" -message hello
```

This starts an **unencrypted** tunnel. Add `-dtls` and operator-supplied certificate
flags for [DTLS](examples/README.md#dtls) or
[mDTLS](examples/README.md#mutual-dtls). Secure setup never falls back to plaintext.
Virtual addresses exist inside gVisor; no host addresses or routes are installed.

## Examples

| Program | Purpose |
| --- | --- |
| [udp-client](examples/udp-client/main.go) | Send a physical UDP datagram and read its echo |
| [udp-server](examples/udp-server/main.go) | Echo physical UDP datagrams |
| [udp-capture](examples/udp-capture/main.go) | Observe a configurable UDP payload prefix across all ports |
| [udp-capture-server](examples/udp-capture-server/main.go) | Echo matching datagrams from the port each client contacted |
| [tcp-client](examples/tcp-client/main.go) | Allocate a PCAT address and exchange TCP data |
| [tcp-server](examples/tcp-server/main.go) | Accept concurrent TCP connections from PCAT peers |

See the [example guide](examples/README.md) for plain, DTLS, mDTLS, and concurrent
client commands. All programs support `-h` and `-device`; fixed-port clients and
servers also support `-reserve-port`.

## API overview

| API | Role |
| --- | --- |
| `DialUDP` / `ListenUDP` | Direct physical UDP; interoperates with ordinary UDP peers |
| `CaptureUDP` / `UDPCapture.Receive` | Read-only UDP prefix capture on all ports of one local IPv4 address |
| `ListenUDPCapture` / `UDPCaptureServer` | Receive matching bodies across nonzero ports and reply from the contacted port |
| `DialPCAPStack` / `ListenPCAPTCP` | Plain PCAT client stack / shared TCP server |
| `DialStack` / `NewTCPServer` | Allocate and run TCP over a supplied plain or secure endpoint |
| `DatagramEndpoint` / `Peer` | Message transport and per-connection identity |
| `PacketTransport` / `NewVirtualStackWithTransport` | Complete inner IP packets and gVisor attachment |
| `NewMemoryPair` | In-memory packet transport |
| `NewPCAPTransport` | Lower-level fixed-peer raw encapsulation, outside the PCAT session protocol |

`Config` supplies `VirtualIP`, `PeerSubnet` (`netip.Prefix`), and inner `MTU`.
`ServerConfig` controls the address pool, server IP, MTU, lease timeout, and peer
limit. `UDPConfig` describes the physical endpoint; listeners require `LocalIP`
and a nonzero port. Direct UDP does not allocate ephemeral ports.

Set `UDPConfig.MagicHeader` to prepend a binary prefix on `Write`/`WriteTo` and
match/remove it on `Read`/`ReadFrom`. Empty means ordinary UDP. Both endpoints
use the same prefix; `UDPConn.MaxDatagramSize()` accounts for its MTU overhead.
The dialed connection receives replies on its source port without a second
listener. Servers use `ReadFrom` and reply to the returned address with `WriteTo`.
See the [magic-header round trip](examples/README.md#magic-header-udp).

For encrypted direct datagrams, wrap UDP with `NewPlainUDPEndpoint` and then
`dtlstransport.Dial` / `Listen`. Exchange bodies with `SendTo` / `ReceiveFrom`;
no virtual stack or allocation is required. The
[UDP DTLS examples](examples/README.md#dtls-for-direct-udp) support server
certificate verification and optional required client certificates (mDTLS).
The importing application supplies credentials and authorization policy.

`CaptureUDP` takes `UDPCaptureConfig{LocalIP, DeviceName, MagicHeader}`. The
nonempty binary header matches at payload byte zero; `Receive(ctx)` returns the
full payload and both endpoint addresses. Close the capture when finished.
Capture never binds ports or sends packets; host socket delivery and possible
ICMP responses remain under host control. Its bounded queue drops new packets
when full. See the [capture example](examples/udp-capture/main.go).

`ListenUDPCapture` takes the same capture configuration and returns a server
with `Receive(ctx)` and `Reply(ctx, request, body)`. Receive removes the header;
Reply prepends it and reverses the request's address/port tuple. It uses one
persistent capture/injection handle without reserving ports. See the
[all-port echo example](examples/README.md#udp-capture-server).

Successful stack attachment transfers transport ownership. `DialStack` owns its
endpoint on entry and cleans it up on any failure. Close the owning stack/server
to release its endpoints and workers; inspect `VirtualStack.Err()` for terminal
and cleanup errors. Detailed contracts and defaults are in
[architecture](docs/architecture.md) and the source API comments.

## Protocol and security

The [PCAT specification](docs/protocol/README.md) defines the common session
format and all three channel profiles, including packet and handshake diagrams:

- [Unencrypted channel](docs/protocol/plain.md)
- [DTLS channel](docs/protocol/dtls.md)
- [mDTLS channel](docs/protocol/mdtls.md)

Session messages use `PCAT`; secure routing envelopes use `PCDT`. Previous
experimental markers are intentionally rejected. Peers must use matching builds
and channel profiles.

Plain PCAT provides no authentication, encryption, or replay protection. DTLS
verifies the server; mDTLS also requires a trusted client certificate. Applications
supply credentials, trust policy, and certificate renewal. Application TLS/mTLS
over returned TCP connections remains an independent service-level choice.

## Network limits

Device selection follows the client route or the interface owning the server's
`LocalIP`; `DeviceName` overrides it. Host UDP reservation defaults to **off**.
Enabling it binds a normal host socket visible in `ss`, but PCAP still performs
all packet I/O. Processes sharing one physical UDP port must leave reservation off.

Physical networking supports IPv4 unicast and up to two ingress VLAN tags. IPv6,
wildcard/all-interface listeners, outer fragmentation, path MTU discovery, NAT
traversal, and address migration are not implemented. Inner MTU defaults to 1200.
At physical MTU 1500, the maximum inner packet is 1448 bytes for plain PCAT and
1387 for secure PCAT. Jumbo secure records also respect the pinned DTLS library's
[receive limit](docs/protocol/dtls.md#mtu).

## Development

```sh
go build ./...
go test -race -timeout=30s ./...
go vet ./...
```

The suite includes simulated Ethernet, allocation, concurrent TCP, certificate
verification, replay/tampering, cancellation, and cleanup regressions.
[Testing documentation](docs/testing.md) covers optional live capture tests and
their environment variables. Live two-host driver behavior requires separate
verification. See the [maintenance review](docs/maintenance-review.md) for the
resource-handling changes and validation scope.
