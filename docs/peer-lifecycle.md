# Peer metadata and lifecycle

## TCP acceptance

`TCPServer.AcceptWithPeer()` returns `(net.Conn, Peer, error)`. The SYN's PCAT
allocation generation fixes the handle, including `ConnectionID` and optional
`LocalAddrPort`. Every TCP connection in that allocation has the same peer. The
returned connection also implements `PeerConnection.Peer()`; this value remains
historical after closure. It is never reconstructed from a later virtual-IP map.
Existing `Accept()` keeps its signature and uses the same listener.

The [TCP server example](../examples/tcp-server/main.go) shows complete setup and
acceptance. Standard `VirtualStack.Listen` remains a general TCP listener; use
`TCPServer` for these generation-bound peer APIs.

## API reference

| API | Result or completion scope |
| --- | --- |
| `TCPServer.Accept()` | Existing `net.Listener` acceptance; returned connections also implement `PeerConnection` |
| `TCPServer.AcceptWithPeer()` | `(net.Conn, Peer, error)` with the SYN's original allocation binding |
| `PeerConnection.Peer()` | Immutable originating handle, including after connection closure |
| `TCPServer.PeerInfo(peer)` | `PeerInformation` for an active admitted exact peer |
| `dtlstransport.Endpoint.PeerInfo(peer)` | `PeerInformation` for an active exact DTLS connection |
| `TCPServer.PeerDone(peer)` | Retirement channel for an active matching PCAT allocation |
| `dtlstransport.Endpoint.PeerDone(peer)` | Retirement channel for the exact DTLS connection |
| `TCPServer.DisconnectPeer(ctx, peer)` | Retire all matching allocations and the secure peer; wait for PCAT/TCP and DTLS cleanup |
| `dtlstransport.Endpoint.DisconnectPeer(ctx, peer)` | Retire the secure peer; wait for DTLS cleanup; PCAT observers perform their cleanup independently |
| `ErrPeerNotFound` | No current metadata/lifecycle entry for that exact handle |

`dtlstransport.PeerInfo` remains the existing authorization callback input type;
`pcapnet.PeerInformation` is the detached active-lookup result. Neither type
replaces application identity or authorization policy.

## Authentication evidence

`dtlstransport.Endpoint.PeerInfo(peer)` and `TCPServer.PeerInfo(peer)` require the
complete exact handle. `PeerInformation` contains detached, caller-owned copies:

| Field | Meaning |
| --- | --- |
| `Peer` | Exact handle to which all evidence belongs |
| `Encrypted` | DTLS encryption was negotiated; not a sensor identity claim |
| `PeerCertificateAuthenticated` | The remote peer's certificate chain was verified |
| `ClientCertificateAuthenticated` | Client-certificate authentication participated in this handshake |
| `Certificates` | Presented peer chain, leaf first |
| `VerifiedChains` | The chains returned by normal Pion/X.509 verification at handshake time |
| `LocalCertificates` | The actual selected local chain; no private key; empty if no local certificate was sent |
| `EstablishedAt` | Time the authenticated handle was created |
| `Done` | Broadcast retirement signal; retained evidence becomes historical when closed |

On a server, server-only DTLS reports an anonymous client with both certificate
flags false and no verified client chains. On a client, the gateway certificate
is verified; a configured client certificate is not reported as selected unless
the server requested it. The client-certificate flag records the negotiated
certificate proof, not the remote application's authorization decision. mDTLS
servers verify the client chain. Raw mode reports no encryption or cryptographic
authentication, with no certificate evidence. Raw endpoint `Done` describes only
the endpoint lifetime; raw UDP cannot detect remote reconnection or termination.
`TCPServer` supplies an allocation-lifetime `Done` for raw peer snapshots.

| Observing side and mode | Encrypted | Remote certificate verified | Client-certificate proof |
| --- | --- | --- | --- |
| Raw, either side | No | No | No |
| DTLS server observing client | Yes | No | No |
| DTLS client observing server | Yes | Yes | No |
| mDTLS server observing client | Yes | Yes | Yes |
| mDTLS client observing server | Yes | Yes | Yes |

Applications bind sensor UUIDs, SANs, fingerprints, and registry authorization to
verified evidence. Certificates being present alone is not proof of verification.
The adapter does not implement sensor UUID policy, certificate renewal, or active
certificate expiry/revocation policy. Applications can schedule targeted retirement
from the actual selected certificates and verified paths. Multiple verified paths
are verification results, not a claim that every alternative path was required.

Every lookup reparses owned DER, including nested verified chains; modifying a
snapshot or an authorization callback's certificate objects cannot alter retained
evidence. Active lookups after retirement return `ErrPeerNotFound`. Previously
returned snapshots and their closed `Done` channels may be retained as historical
records; they never establish that a replacement is active.

## Disconnection and notifications

Core optional interfaces keep pcapnet independent of Pion:

- `PeerInfoProvider.PeerInfo(peer)` supplies authentication evidence.
- `PeerLifecycle.PeerDone(peer)` returns an exact-peer retirement channel.
- `PeerDisconnecter.DisconnectPeer(ctx, peer)` retires one exact handle.

`dtlstransport.Endpoint` implements all three. `ServerTransport` and
`ClientTransport` observe lifecycle channels automatically. DTLS read failure,
close notification, idle expiry, explicit disconnection, and endpoint shutdown
invalidate PCAT/TCP without waiting for the allocation timeout. Stale secure
handles are never matched by physical address alone, including after reconnection.

`Endpoint.DisconnectPeer` invalidates the peer before waiting for its DTLS workers.
`TCPServer.DisconnectPeer` additionally invalidates all that peer's allocations
and waits for associated TCP/generation cleanup. Use the server method when its
completion must include inner TCP teardown. Both are concurrency-safe and
idempotent; a stale handle cannot select its replacement. `ctx` bounds waiting.
If it expires after retirement, cleanup continues and invalidation is permanent.
Native PCAP calls already executing still depend on the driver's return behavior.

`TCPServer.PeerDone` exposes invalidation of an active matching PCAT allocation.
If a peer owns several allocations, use the DTLS endpoint's `PeerDone` to observe
their shared secure connection; targeted disconnection retires all its allocations. Connection read/write
operations also fail on abort, including blocked operations. The endpoint's
`PeerDone` observes the DTLS connection itself; a PCAT lease can expire while its
DTLS connection remains established. A raw handle has no authenticated connection
generation, so raw disconnection retires current leases but cannot identify remote
reconnections or revoke an identity cryptographically.

| Returned signal | Lifetime observed |
| --- | --- |
| DTLS `PeerDone` / secure `PeerInformation.Done` | Exact DTLS connection |
| `TCPServer.PeerDone` | Matching PCAT allocation generation |
| Raw `TCPServer.PeerInfo(...).Done` | Matching PCAT allocation generation |
| Raw `PlainUDPEndpoint.PeerInfo(...).Done` | Local UDP endpoint; no remote-liveness claim |

Notifications use closed channels, not callbacks. Multiple observers can wait
independently without consuming each other's events; no unsubscribe or callback
shutdown protocol is required. Existing `Authorize` callbacks run before handle
publication, must honor their context, and must not synchronously close their own
endpoint. Reject admission by returning an error; active metadata lookup is not
available for a handle still undergoing authorization.

## Generation isolation and resource bounds

The shared TCP server stamps inbound packets with a non-reused, process-local
allocation mark. A bounded gVisor forwarder captures that generation before a
handshake starts; completed connections carry it into the accept queue. Retired
queued accepts are closed and skipped. Queued ingress retains its allocation
token and is checked again at stack injection. Established TCP output carries its
original mark, so a retired endpoint cannot send using a reassigned IP lease.
These marks and peer handles add no wire fields.

Retirement removes tokens and marks immediately. It quarantines the virtual IP
until pending handshakes, exact TCP endpoint workers, managed connections, and a
FIFO egress barrier finish. This includes unmarked initial SYN-ACKs already
queued before the endpoint acquired its mark. Only then may the address be
reassigned. Delayed cleanup releases an address only if the allocation pointer
still matches. Slow cleanup consumes its existing allocation slot; it cannot
create an unbounded set of retiring generations or block unrelated peers' I/O.

The listener bounds pending handshakes and queued accepts to 256 each. Allocation
marks are 32-bit and never reused within one server; exhaustion rejects further
allocations rather than wrapping. No metadata tombstone map grows across
reconnections. DTLS retirement allows a best-effort `close_notify` write with a
100 ms deadline; delivery can still fail on loss or an unavailable raw link.
Remote silence is detected by configured idle timeouts, not instantly.

See [testing](testing.md) for regression scope and live-capture limitations.
