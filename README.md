# pcapnet

Standalone Go library for a gVisor TCP/IPv4 stack over a UDP tunnel implemented
with gopacket and PCAP. All package source, tests, route lookup, and ARP helpers
are in this repository's root. It has no dependency on the former `pkg/network`
or `pkg/pcapconn` packages. There is no command-line executable yet.

The module retains `github.com/MeHungr/doodlebob/pkg/pcapnet` so existing imports
continue to work. This is a local repository; no remote or hosted module has been
created. If published at a different path, update `go.mod` and the example import.

## Repository layout

| Files | Responsibility |
| --- | --- |
| `stack.go`, `dial.go`, `listen.go`, `lifecycle.go` | gVisor stack and TCP lifecycle |
| `bridge.go`, `transport.go`, `memory.go` | Packet bridge and transport abstraction |
| `pcap*.go`, `packet.go`, `mtu.go` | PCAP setup, UDP tunnel, validation and MTU |
| `route.go`, `arp.go` | Local route lookup and ARP resolution |
| `*_test.go` | Unit, integration, example, and opt-in live tests |
| `IMPLEMENTATION.md` | Implementation history and consolidation notes |

Build and check the complete standalone module from this directory:

```sh
go build ./...
go test -race -timeout=30s ./...
go vet ./...
```


`pcapnet` runs a gVisor TCP/IPv4 stack and carries its packets through a
`PacketTransport`. `PCAPTransport` sends and captures Ethernet frames using
`gopacket/pcap`. Each outer IPv4/UDP datagram contains one complete inner IPv4
packet. `MemoryTransport` provides the same packet interface for local testing.

```text
application net.Conn
  → gVisor TCP / virtual IPv4
  → packet bridge
  → Ethernet / physical IPv4 / UDP / inner IPv4 packet
  → peer PCAP transport and bridge
  → peer gVisor TCP / application
```

`pcapconn` sends TCP/IP packets directly over Ethernet using the host identity.
This package instead connects two independent virtual endpoints through UDP.
Virtual IPs do not need to be assigned to host interfaces or routed by the host;
gVisor routes only its configured peer through its own channel endpoint. The host's physical
route determines the capture interface, physical source address, and next hop.

## Requirements and scope

Build with the Go version in the repository's `go.mod`, CGO enabled, a C compiler,
and libpcap development headers/libraries. Runtime capture and injection require
an Ethernet capture device and privileges granted by the platform's capture
driver. Linux live-test instructions below use root inside isolated namespaces.
Capture names that differ from OS interface names are matched using the route
source address; other platforms and capture drivers still need live validation.

The initial transport supports a fixed physical IPv4 peer and inner IPv4 TCP.
It has no encryption, authentication, peer discovery, keepalive, NAT traversal,
outer fragment reassembly, or path MTU discovery. Tuple filtering does not
establish peer identity. Traffic remains subject to the host/network firewall.
The package does not change firewall rules or install host routes.

Ingress supports Ethernet frames with zero, one, or two 802.1Q/802.1ad VLAN tags.
Egress generates untagged Ethernet frames. Loopback/non-Ethernet devices are not
supported. Physical routes and next-hop MACs are resolved at setup; route or
neighbor changes require recreating the transport.

## Configure both endpoints

For two hosts with physical addresses `192.0.2.1` and `192.0.2.2`, configure:

| Setting | Endpoint A | Endpoint B |
| --- | --- | --- |
| Capture device | A's route-selected Ethernet device | B's route-selected Ethernet device |
| Outer local UDP port | `45000` | `45001` |
| Outer peer | `192.0.2.2:45001` | `192.0.2.1:45000` |
| Virtual IP | `10.200.0.1` | `10.200.0.2` |
| Peer virtual IP | `10.200.0.2` | `10.200.0.1` |
| Inner MTU | `1200` | `1200` |

The physical source IP is selected by the host route to the physical peer. The
configured capture device must match that route. ARP resolves either the peer
itself for a direct route or the gateway for a routed peer, with a five-second
setup timeout bounded by the caller's context.

Use `PCAPConfig` for the physical endpoint and `Config` for gVisor. The legacy
`Config.DeviceName` field is retained for compatibility and is not used to open
PCAP; set `PCAPConfig.DeviceName` instead.

`PCAPConfig.MTU` and `Config.MTU` both default to `1200` when zero and must agree
at attachment. Inner MTU includes the entire inner IP header and payload. With
standard outer IPv4/UDP headers:

```text
maximum inner MTU = physical IP MTU - 20 - 8
1500-byte physical MTU → at most 1472 inner bytes
```

The package checks the local interface MTU. Choose an inner MTU suitable for the
whole path; smaller downstream MTUs are not discovered automatically. Outer
IPv4 packets set Don't Fragment, and outer fragments are rejected on receive.

## Optional host UDP reservation

`PCAPConfig.ReserveUDPPort` defaults to `false`. When true, setup binds a normal
host UDP socket to the route source IP and `LocalPort`. This prevents ordinary
bind collisions and host closed-port ICMP responses. It is visible in tools
such as `ss -uan`, with process attribution from `ss -uanp` when permitted.
The reservation socket is held until transport closure and does not perform
tunnel packet I/O.

When false, no reservation socket is created. Other host applications may bind
the port, and the host may emit ICMP port-unreachable replies to incoming UDP.
PCAP still performs capture/injection. A future Cobra command can assign its
boolean flag directly to `ReserveUDPPort`; this package adds no CLI flags.

## Construct and use a stack

See [example_test.go](example_test.go) for a compiled example of both configurations
and ownership handling. The core sequence is:

```go
transport, err := pcapnet.NewPCAPTransport(ctx, physicalConfig)
if err != nil {
    return err
}
v, err := pcapnet.NewVirtualStackWithTransport(virtualConfig, transport)
if err != nil {
    // Failed attachment leaves ownership with the caller.
    return errors.Join(err, transport.Close())
}
defer v.Close() // Owns the transport and both packet workers.
```

On one endpoint, create a virtual TCP listener with `v.Listen(6767)` and accept
connections. On its peer, use `v.Dial(ctx, "10.200.0.2", 6767)`. These return
standard `net.Listener` and `net.Conn` interfaces with connection deadlines.
Dial contexts affect the handshake, not the established connection's lifetime.
The `NewPCAPTransport` context affects setup, not the resulting transport.

After successful attachment, do not share the transport with another stack,
close it separately, or read/write `v.Link` directly. `NewVirtualStack` remains
available for callers that manage their own channel endpoint packet processing.

## Shutdown and errors

Packet worker failure records its cause, rejects new dial/listen operations,
cancels pending handshakes, and closes existing TCP endpoints automatically.
`Close()` waits for worker and gVisor cleanup and retains its existing void
signature. Query `Err()` for the worker failure and any resource cleanup errors:

```go
v.Close()
if err := v.Err(); err != nil {
    return err
}
```

`Err()` is safe during shutdown; calling `Close()` first obtains the completed
cleanup result. Normal shutdown cancellation is not an error. Immediate
transport failure can begin shutdown before the attachment constructor returns.

Stack closure stops workers immediately; keep the stack alive while application
protocols finish exchanging data. It does not promise to drain queued TCP data
or finish graceful TCP teardown before stopping the transport.

PCAP receive calls use a 100 ms capture timeout and check cancellation between
native calls. Injection already executing in a native driver cannot be canceled.
A stalled driver can delay shutdown; live tests must verify the target driver's
behavior. Handles are never freed while transport I/O still uses them.

## Automated tests

From the module root:

```sh
go test -race -timeout=30s ./...
go vet ./...
```

The normal suite includes a full two-stack tunnel test with simulated Ethernet
capture/injection, real gopacket serialization, real libpcap BPF filtering, and
both production bridges. It exchanges 1-byte, 1201-byte, and 128 KiB messages,
checks MTU limits and unrelated-traffic filtering, and covers reservation on/off.
Unit tests cover malformed packets, checksums, cancellation, ownership, failure
propagation, cleanup errors, and blocked TCP operations.

If the environment disallows socket creation, only the real loopback reservation
bind/collision test skips on permission errors. These tests do not establish
that a live capture driver works.

## Opt-in live tests

Live tests have build tag `pcaplive` and additionally require `PCAPNET_LIVE=1`.
Without that variable they skip, even when compiled with the tag. Once enabled,
invalid settings or unavailable devices fail rather than silently skipping.

| Variable | Purpose |
| --- | --- |
| `PCAPNET_DEVICE` | Physical Ethernet capture device |
| `PCAPNET_LOCAL_PORT` | Nonzero outer UDP local port |
| `PCAPNET_PEER` | Peer physical IPv4 address and UDP port |
| `PCAPNET_VIRTUAL_IP` | Local gVisor IPv4 address |
| `PCAPNET_PEER_VIRTUAL_IP` | Peer gVisor IPv4 address |
| `PCAPNET_ROLE` | `server` or `client` for the echo test |
| `PCAPNET_RESERVE_UDP` | Optional boolean, default `false` |
| `PCAPNET_MTU` | Optional inner MTU, default `1200` |

`TestLivePCAPTCPEcho` runs on two hosts or separate network namespaces. Start the
server first and wait for its listening log. The client verifies a 64 KiB echo.
The server can remain alive until its 20-second deadline if the client closes
its stack before TCP FIN reaches the server; that idle timeout is accepted only
when the expected number of bytes has been echoed.

`TestLivePCAPReceiveCancellation` checks cancellation with the selected real
capture driver, then closes the transport during an active capture call and
requires the pending receive to unblock. Run it without concurrent echo traffic.
Both tests need an outer test timeout to bound misbehaving native drivers.

### Linux namespace example

Build a test executable from the module root before changing network namespaces:

```sh
go test -tags=pcaplive -c -o /tmp/pcapnet-live.test .
```

Create two namespaces and a dedicated Ethernet link on a test machine:

```sh
sudo ip netns add pcapnet-a
sudo ip netns add pcapnet-b
sudo ip link add pcap-a type veth peer name pcap-b
sudo ip link set pcap-a netns pcapnet-a
sudo ip link set pcap-b netns pcapnet-b
sudo ip -n pcapnet-a addr add 192.0.2.1/24 dev pcap-a
sudo ip -n pcapnet-b addr add 192.0.2.2/24 dev pcap-b
sudo ip -n pcapnet-a link set lo up
sudo ip -n pcapnet-b link set lo up
sudo ip -n pcapnet-a link set pcap-a up
sudo ip -n pcapnet-b link set pcap-b up
```

In the server terminal:

```sh
sudo ip netns exec pcapnet-b env \
  PCAPNET_LIVE=1 PCAPNET_ROLE=server PCAPNET_DEVICE=pcap-b \
  PCAPNET_LOCAL_PORT=45001 PCAPNET_PEER=192.0.2.1:45000 \
  PCAPNET_VIRTUAL_IP=10.200.0.2 PCAPNET_PEER_VIRTUAL_IP=10.200.0.1 \
  PCAPNET_RESERVE_UDP=true \
  /tmp/pcapnet-live.test -test.v -test.timeout=40s \
  -test.run '^TestLivePCAPTCPEcho$'
```

After the listening log, run in the client terminal:

```sh
sudo ip netns exec pcapnet-a env \
  PCAPNET_LIVE=1 PCAPNET_ROLE=client PCAPNET_DEVICE=pcap-a \
  PCAPNET_LOCAL_PORT=45000 PCAPNET_PEER=192.0.2.2:45001 \
  PCAPNET_VIRTUAL_IP=10.200.0.1 PCAPNET_PEER_VIRTUAL_IP=10.200.0.2 \
  PCAPNET_RESERVE_UDP=true \
  /tmp/pcapnet-live.test -test.v -test.timeout=40s \
  -test.run '^TestLivePCAPTCPEcho$'
```

Repeat both commands with `PCAPNET_RESERVE_UDP=false` to check unreserved operation.
Once echo testing stops, reuse either endpoint's environment with
`-test.run '^TestLivePCAPReceiveCancellation$'` for the driver cancellation test.
These commands can also be adapted to two real hosts by changing the capture
names and physical endpoints to their route-selected Ethernet interfaces.

After both test processes exit, remove the namespaces (which also removes their
veth devices):

```sh
sudo ip netns del pcapnet-a
sudo ip netns del pcapnet-b
rm /tmp/pcapnet-live.test
```

The namespace commands are instructions for a privileged test environment;
normal package tests do not create interfaces or modify network configuration.

## Verification of this extraction

The complete standalone module builds, its tests pass with the race detector,
and `go vet` passes with the live-test build tag enabled. The opt-in live tests
compile but were not run against a real capture device. The real UDP socket
reservation test skips in the restricted extraction environment. No sibling
package or missing legacy isolator implementation is needed by this module.
