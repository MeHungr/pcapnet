# pcapnet

Go networking library built on gopacket/PCAP:

- **Direct UDP:** exchange datagrams with physical IPv4 peers through `net.Conn`
  and `net.PacketConn`, without creating a gVisor stack.
- **Tunneled TCP:** use gVisor TCP/IPv4 connections over a fixed-peer UDP tunnel.

```go
import "github.com/MeHungr/pcapnet"
```

## Requirements

Use the Go version specified in [go.mod](go.mod), CGO, a C compiler, and libpcap development
headers/libraries. Live networking requires an Ethernet capture driver and
capture/injection privileges. Loopback and non-Ethernet capture are unsupported.

## Examples

| Protocol | Client | Server |
| --- | --- | --- |
| Direct UDP | [udp-client](examples/udp-client/main.go) | [udp-server](examples/udp-server/main.go) |
| Tunneled TCP | [tcp-client](examples/tcp-client/main.go) | [tcp-server](examples/tcp-server/main.go) |

Both servers echo traffic until Ctrl+C. All four commands support `-device` for
an explicit capture-device override and `-reserve-port` to enable optional host
UDP reservation. Use `-h` to list flags.

### UDP echo

`SERVER_IP` is an IPv4 address assigned to the server's Ethernet interface. The
client's interface and source IP are selected from its route to that address.
Run the server first, with capture/injection privileges:

```sh
# Server host
SERVER_IP=192.0.2.2
go run ./examples/udp-server -local "${SERVER_IP}:45001"
```

```sh
# Client host
SERVER_IP=192.0.2.2
go run ./examples/udp-client -peer "${SERVER_IP}:45001" -message "hello"
```

These examples also work with ordinary UDP peers; no tunnel or virtual addresses
are required. The client uses local port `45000` unless `-local-port` overrides it.

### TCP echo over a UDP tunnel

Both hosts run pcapnet. `CLIENT_IP` and `SERVER_IP` are their physical IPv4
addresses. Virtual addresses belong to gVisor and do not need to be assigned to
host interfaces.

```sh
# Server host
CLIENT_IP=192.0.2.1
go run ./examples/tcp-server -peer "${CLIENT_IP}:45000"
```

```sh
# Client host
SERVER_IP=192.0.2.2
go run ./examples/tcp-client -peer "${SERVER_IP}:45001" -message "hello"
```

| Setting                    | TCP client default | TCP server default |
| -------------------------- | ------------------ | ------------------ |
| Outer UDP local port       | `45000`            | `45001`            |
| Local virtual IPv4 address | `10.200.0.1`       | `10.200.0.2`       |
| Peer virtual IPv4 address  | `10.200.0.2`       | `10.200.0.1`       |
| Virtual TCP port           | `6767`             | `6767`             |
| Inner MTU                  | `1200`             | `1200`             |

`-local-port`, `-virtual-ip`, `-peer-virtual-ip`, and `-tcp-port` override the
corresponding settings. Peer settings must agree on both hosts. An ordinary
physical TCP listener cannot serve this encapsulated connection.

## API

### Direct UDP

[UDPConfig](udp.go) specifies the local physical endpoint:

- `DialUDP(ctx, cfg, peer)` returns a connected `*UDPConn`. Use `Read` and `Write`.
- `ListenUDP(ctx, cfg)` returns an unconnected `*UDPConn`. Use `ReadFrom` and
  `WriteTo`; UDP has no `Accept` operation.
- `LocalIP` is required for listening and optional for dialing. `LocalPort`
  must be nonzero; ephemeral allocation is not provided.

`UDPConn` implements `net.Conn` and `net.PacketConn`. `ReadFrom` works in either
mode; `WriteTo` takes a `*net.UDPAddr` and is rejected on connected endpoints.
Local/remote addresses, mutable read/write deadlines, `Close`, and `Err` are
provided. Setup contexts affect initialization, not the endpoint's lifetime.

Reads preserve datagram boundaries, including empty datagrams. A short buffer
discards the unread tail. The receive queue holds 256 datagrams and drops new
arrivals when full. UDP adds no retransmission, ordering, or ICMP error delivery.
Listener replies must route through the selected source IP/MAC. Listener ARP
cache entries expire after 30 seconds and are bounded to 64 neighbors; connected
endpoints retain their setup route/MAC until recreated.

### Tunneled TCP

[PCAPConfig](pcap_config.go) configures the physical UDP tunnel;
[Config](config.go) configures the virtual IPv4 pair and inner MTU.

1. `NewPCAPTransport(ctx, cfg)` opens capture/injection and resolves the peer route
   and next-hop MAC.
2. `NewVirtualStackWithTransport(virtualCfg, transport)` attaches the tunnel.
   Success transfers transport ownership to the stack; failure leaves cleanup
   with the caller.
3. `v.Dial(ctx, peerVirtualIP, port)` returns a `net.Conn`; `v.Listen(port)` returns
   a `net.Listener`.
4. `v.Close()` closes endpoints, joins workers, and releases resources. Inspect
   `v.Err()` afterward for terminal and cleanup errors.

The [TCP client](examples/tcp-client/main.go) shows both attachment cleanup paths;
the [TCP server](examples/tcp-server/main.go) shows listening, accepting, and
serving connections. Dial contexts bound handshakes. Connection deadlines bound
subsequent I/O. Keep the stack alive while application data and TCP teardown are
in progress; stack closure does not drain queued traffic.

`NewMemoryPair` provides in-memory packet transport. `NewVirtualStack` creates an
unattached stack for callers managing `Link` directly. After transport attachment,
leave `Link` processing and transport ownership to the stack. The legacy
`Config.DeviceName` field is unused; overrides belong in `PCAPConfig.DeviceName`.

## Capture-device selection

`DeviceName` is optional in both physical endpoint configurations:

- TCP tunnel setup and UDP dialing use the route to the physical peer.
- UDP listening uses the interface owning `LocalIP`, on one interface/address.
- An explicit name must match the chosen interface or source IP.

Automatic selection prefers an exact OS interface-name match, then a unique
source-IP match for capture drivers with different names, such as Npcap. Missing
or ambiguous matches return errors. Invalid explicit overrides never fall back.
There is no global default-device or listen-on-all-interfaces mode.

## Optional UDP port reservation

`ReserveUDPPort` defaults to `false` for both TCP tunnels and direct UDP.
Disabling it binds no host UDP reservation socket; PCAP still captures and injects
packets. Device selection and dialing never enable reservation automatically.

Enabling it binds a normal host UDP socket to the local address/port, preventing
ordinary bind collisions and host closed-port ICMP replies. That socket appears
in tools such as `ss -uan` and can be attributed to the process with `ss -uanp`
when permitted. Without reservation, other applications can bind the port and
the host may generate ICMP port-unreachable replies. Reservation sockets do not
perform application packet I/O.

## MTU and network scope

| Mode       | MTU configuration                                                   | Maximum at physical MTU 1500  |
| ---------- | ------------------------------------------------------------------- | ----------------------------- |
| Direct UDP | `UDPConfig.MTU`: physical IPv4 MTU cap; zero uses interface MTU     | 1472-byte application payload |
| TCP tunnel | `PCAPConfig.MTU` and `Config.MTU`: matching inner MTU; default 1200 | 1472-byte inner IPv4 packet   |

IPv4 and UDP headers consume 28 bytes. Oversized direct writes return
`ErrDatagramTooLarge`. Choose MTUs suitable for the whole path: path MTU discovery
and fragmentation/reassembly are not implemented. Incoming IP options count
against the direct UDP MTU. Outer packets set Don't Fragment.

Physical networking supports IPv4 unicast with untagged Ethernet egress. Capture
accepts up to two 802.1Q/802.1ad VLAN tags. Wildcard binds, IPv6, multicast,
broadcast, NAT traversal, encryption, and authentication are unsupported. Tuple
filtering does not authenticate peers. The package does not change firewall
rules or install host routes.

## Deadlines, shutdown, and errors

Direct UDP errors wrap `net.ErrClosed` for closed operations and
`os.ErrDeadlineExceeded` for timeouts. Terminal capture/injection failures close
the endpoint; `Err()` and `Close()` preserve terminal and cleanup causes.

TCP worker failure rejects new operations, cancels pending handshakes, and closes
existing endpoints. `VirtualStack.Close()` waits for gVisor and transport cleanup;
`VirtualStack.Err()` reports errors. Normal shutdown cancellation is not a failure.

Receive loops check cancellation between native reads, using a 100 ms capture
timeout. Native route/injection calls cannot be interrupted and a stalled driver
can delay shutdown. Handles remain open until active native operations finish.

## Build and test

```sh
go build ./...
go test -race -timeout=30s ./...
go vet ./...
```

The suite covers wire parsing/checksums, device selection, ownership, deadlines,
MTUs, failures, and closure. Simulated Ethernet integration tests use real BPF
filtering and serialization for TCP tunnel and direct UDP echo, with reservation
both enabled and disabled. The loopback socket reservation test skips on explicit
socket-permission errors.

### Live capture tests

[Live tests](pcap_live_test.go) require the `pcaplive` build tag, `PCAPNET_LIVE=1`,
configured Ethernet peers, and capture/injection privileges. Without opt-in they
skip. Enabled tests fail on invalid settings or setup errors.

| Variable                                        | Purpose                                               |
| ----------------------------------------------- | ----------------------------------------------------- |
| `PCAPNET_DEVICE`                                | Optional capture device override                      |
| `PCAPNET_LOCAL_PORT`, `PCAPNET_PEER`            | Local UDP port and physical peer IPv4:port            |
| `PCAPNET_VIRTUAL_IP`, `PCAPNET_PEER_VIRTUAL_IP` | Virtual addresses for TCP/shared test settings        |
| `PCAPNET_ROLE`                                  | `server` or `client`                                  |
| `PCAPNET_RESERVE_UDP`                           | Optional boolean; default false                       |
| `PCAPNET_MTU`                                   | Optional tunnel inner MTU; default 1200               |
| `PCAPNET_UDP_MODE`                              | Direct UDP test backend: `pcap` (default) or `kernel` |

Start the server before the client, using reciprocal endpoint settings on two
hosts or network namespaces. Select one of these tests with `-run`:

- `TestLivePCAPTCPEcho`: 64 KiB echo through the TCP tunnel.
- `TestLivePCAPReceiveCancellation`: real-driver receive cancellation and closure.
- `TestLiveDirectUDPEcho`: direct UDP echo; select different backends on the two
  hosts to check interoperability with ordinary kernel UDP sockets. Shared test
  settings still require virtual addresses, although direct UDP does not use them.

```sh
go test -tags=pcaplive -run '^TestLivePCAPTCPEcho$' -v -timeout=40s .
```

Run driver cancellation tests separately from echo traffic. Simulated tests do
not establish live driver compatibility.