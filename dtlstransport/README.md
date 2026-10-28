# dtlstransport

Optional DTLS 1.2 and mutual-DTLS adapter for
[pcapnet / PCAT](../README.md), built on
[Pion DTLS v3.1.15](https://github.com/pion/dtls/tree/v3.1.15).

The adapter encrypts arbitrary application datagrams without gVisor or PCAT
allocation. It can also carry complete PCAT session messages: allocation fields,
tokens, keepalives, and inner TCP/IP packets. Core pcapnet does not import DTLS.
The importing application chooses the endpoint and supplies credentials and policy.

## Features

- Certificate-verified server authentication and optional required client authentication.
- ECDHE / AES-128-GCM, required Extended Master Secret, and replay rejection.
- Independent connections for clients sharing one physical UDP endpoint.
- Detached authentication snapshots, exact-peer retirement, and PCAT/TCP lifecycle propagation.
- Bounded handshake slots and queues, mutable deadlines, and joined shutdown.
- No skip-verification option and no automatic plaintext fallback.

## Usage

1. Open PCAP UDP with `pcapnet.DialUDP` or `pcapnet.ListenUDP`.
2. Wrap it with `pcapnet.NewPlainUDPEndpoint` for raw datagram delivery.
3. Use `dtlstransport.Dial` or `dtlstransport.Listen` to create a secure endpoint.
4. Exchange application datagrams with `SendTo(ctx, body, peer)` and
   `ReceiveFrom(ctx)`, or pass it to `pcapnet.DialStack` / `pcapnet.NewTCPServer`
   for allocated TCP.

For direct datagrams, the client sends to `endpoint.Peer()`. The server replies
using the complete `Peer` returned by `ReceiveFrom`, preserving the authenticated
connection identity. Close the secure endpoint to release its raw UDP endpoint.
No second listener is needed to receive replies. See the runnable
[UDP client](../examples/udp-client/secure.go) and
[UDP server](../examples/udp-server/secure.go), and the
[direct UDP DTLS commands](../examples/README.md#dtls-for-direct-udp).

Clients use the authenticated handle returned by `endpoint.Peer()` when calling
`DialStack`; a physical address alone cannot identify a secure connection.
The complete [TCP client](../examples/tcp-client/main.go) and
[TCP server](../examples/tcp-server/main.go) show credential loading,
initialization, and cleanup. Runnable commands are in the
[DTLS](../examples/README.md#dtls) and [mDTLS](../examples/README.md#mutual-dtls)
example guide.

### All-port capture servers

Open `pcapnet.ListenUDPCapture`, wrap it with
`pcapnet.NewPlainUDPCaptureEndpoint`, and pass the result to `dtlstransport.Listen`.
Set `ServerConfig.RequireClientCertificate` and `ClientCAs` for mDTLS. The raw
adapter transfers ownership of the capture server; closing the secure endpoint
closes all layers. See the [complete example](../examples/udp-capture-server/secure.go)
and [mDTLS commands](../examples/README.md#mutual-dtls-on-all-ports).

The capture endpoint includes the contacted local address in `Peer.LocalAddrPort`.
DTLS route keys include that metadata, and authenticated handles preserve it.
Reply with the complete handle from `ReceiveFrom`; this selects both the secure
connection and the UDP source port. Clients sharing a physical source tuple can
contact different local ports without crossing connections. No per-port listener
or unbounded reply-address map is created. Local metadata does not add wire bytes
or change the routing envelope. The configured magic prefix remains outside DTLS.

## API overview

| API | Role |
| --- | --- |
| `Dial(ctx, raw, peer, ClientConfig)` | Verify the server and return a secure client endpoint |
| `Listen(raw, ServerConfig)` | Serve independent secure peers on a supplied raw endpoint |
| `Endpoint.Peer()` | Client's exact authenticated server handle; listeners learn handles from receives |
| `Endpoint.SendTo` / `ReceiveFrom` | Exchange complete application datagrams using exact peer handles |
| `Endpoint.MaxDatagramSize()` | Application body capacity after routing and DTLS overhead |
| `Endpoint.PeerInfo(peer)` | Caller-owned `pcapnet.PeerInformation` snapshot for an active exact handle |
| `Endpoint.PeerDone(peer)` | Broadcast invalidation channel for that DTLS connection |
| `Endpoint.DisconnectPeer(ctx, peer)` | Retire only that peer and wait for DTLS cleanup; stale handles are harmless |
| `Endpoint.Close()` | Close all peers, workers, and the owned raw endpoint |
| `PeerInfo` | Existing `Authorize` callback input; distinct from the active metadata lookup method |

`Endpoint` implements `pcapnet.DatagramEndpoint` plus the optional
`PeerInfoProvider`, `PeerLifecycle`, and `PeerDisconnecter` interfaces. Existing
datagram implementations do not need these extensions. For accepted inner TCP
metadata and cleanup completion, use `TCPServer.AcceptWithPeer` and
`TCPServer.DisconnectPeer` as described in the
[core API overview](../README.md#api-overview).

## Configuration

| Setting | Meaning |
| --- | --- |
| Client `ServerName` | Required DNS name or IP SAN to verify on the server certificate |
| Client `RootCAs` | Trusted server issuers; nil selects system roots |
| Client `Certificates` | Optional client chain and key for mDTLS |
| Server `Certificates` | Required server chain and key |
| Server `RequireClientCertificate` | Require and verify a client chain |
| Server `ClientCAs` | Trusted client issuers; nil selects system roots |
| `Authorize` | Additional application policy after ordinary certificate validation |
| `Limits.MaxPeers` | Active connections plus pending handshakes; default 128 |
| `Limits.HandshakeTimeout` | Default 10 seconds |
| `Limits.IdleTimeout` | Default five minutes; successful sends and receives count |

Configuration must remain immutable while in use. Callbacks must honor their
context and must not synchronously call endpoint `Close`, which joins their
worker. Malformed chains and mismatched private keys fail before raw endpoint
ownership transfers.

Applications create, store, rotate, and protect credentials. The examples read
operator-supplied PEM files; the adapter creates no certificates or credential
files. See the [mDTLS trust and credential specification](../docs/protocol/mdtls.md#trust-and-authorization).

## Ownership and errors

`Listen` takes raw endpoint ownership on success. `Dial` leaves it caller-owned
on initial validation errors; once handshake dispatch starts it owns the endpoint,
including rollback. Setup errors preserve cleanup causes. `DialStack` takes its
supplied secure endpoint on entry and closes it on every setup failure.

`Close` cancels and joins handshakes, readers, and owned deadline watchers, closes
all connections and the raw endpoint, and discards buffered plaintext. Repeated
and concurrent closes are safe. A failed/idle server peer is isolated; a raw
endpoint failure closes the adapter. Plaintext already returned to the application
is application-owned and is not erased by closing the transport.

## Peer metadata and targeted disconnection

`Endpoint.PeerInfo(peer)` returns detached presented certificates, verified
chains, the actual selected local certificate, and authentication flags.
`PeerDone(peer)` broadcasts DTLS connection retirement, and `DisconnectPeer(ctx, peer)` retires
one exact handle without stopping other clients. PCAT observes retirement through
the optional core lifecycle interface. For complete inner TCP cleanup, use
`TCPServer.DisconnectPeer`. Cancellation bounds the cleanup wait, not retirement;
cleanup continues if the caller's context expires. Read failure, idle expiry,
received close notification, and explicit retirement propagate through lifecycle
channels without waiting for PCAT allocation timeout.

Server-only DTLS encrypts traffic but does not certificate-authenticate clients.
`PeerCertificateAuthenticated` is false on that server, while the client reports
verified server authentication. mDTLS servers report verified client chains.
`LocalCertificates` records the actual selected chain, not every configured
certificate; it is empty on clients whose certificate was not requested.

Lookups of stale handles return `pcapnet.ErrPeerNotFound`; retained metadata is
historical after its `Done` closes. Full connection IDs remain mandatory even
when reconnecting clients share an address. See the
[peer lifecycle guide](../docs/peer-lifecycle.md) for mode distinctions, snapshot
ownership, cancellation, generation isolation, and callback rules.

## Protocol

| Profile | Specification and packet diagram |
| --- | --- |
| DTLS: server authenticated, clients anonymous | [DTLS profile](../docs/protocol/dtls.md) |
| mDTLS: server and clients authenticated | [mDTLS profile](../docs/protocol/mdtls.md) |

Both use the `PCDT` routing envelope. Direct use encrypts application datagrams;
PCAT profiles encrypt session messages.
This extra envelope separates simultaneous initial handshakes at the same UDP
address; it is not a credential. Both peers must implement it, so a bare OpenSSL
or DTLS socket is not directly compatible. Routing IDs, outer metadata, and some
DTLS 1.2 handshake information remain visible. DTLS 1.3, migration, and NAT
rebinding are not supported.

The adapter subtracts 61 bytes from the raw datagram capacity for routing and
DTLS protection, and caps encrypted datagrams at the library's 8192-byte receive
limit. When used with PCAT, the session layer subtracts another 24 bytes. At
physical IPv4 MTU 1500, the maximum inner packet is 1387 bytes; the examples use 1200.

An optional `UDPConfig.MagicHeader` precedes the routing envelope on the wire:

```text
UDP payload: [ optional magic ][ PCDT envelope ][ DTLS-protected application datagram ]
```

Both endpoints must configure the same magic header. It remains outside DTLS
encryption; it provides filtering, not authentication. With no additional magic,
`CaptureUDP` can select secure traffic using the `PCDT` prefix. Direct DTLS has
no PCAT assignment or session header; use `Endpoint.MaxDatagramSize()` for its
application payload limit.

## Tests

```sh
go test -race -timeout=30s ./dtlstransport
```

Tests use in-memory datagram delivery and temporary test identities; they cover
standalone DTLS/mDTLS datagram echo, concurrent allocated TCP, invalid credentials,
authorization, replay/tampering, reconnect isolation, jumbo MTUs, cancellation,
rollback, and shutdown. Peer regressions also cover snapshot ownership, selected
certificates, targeted revocation of multiple TCP connections, shared physical
tuples, idle expiry, and stale buffered plaintext after reconnection. They do not
replace live PCAP interoperability testing.
