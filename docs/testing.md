# Building and testing

## Local checks

Use the Go version in [go.mod](../go.mod), CGO, and libpcap development headers.

```sh
go build ./...
go test -race -timeout=30s ./...
go vet ./...
```

The default suite requires no successful live capture. Tests cover frame lengths,
checksums, BPF filtering, device selection, optional reservation, direct UDP,
magic-header send/receive framing, passive capture, all-port capture replies,
virtual TCP, PCAT allocation, and certificate-verified DTLS/mDTLS. In-memory
networks exercise independent clients sharing a physical address, failed
handshakes, authorization, replay/tampering, reconnection, deadlines, and shutdown.
Simulated Ethernet integration tests use real serialization and compiled BPF,
including magic-header echo with reservation both enabled and disabled. Framing
tests verify binary prefixes, header-only datagrams, byte counts, MTU boundaries,
configuration/buffer ownership, and rejection of incorrect prefixes. Capture-server
tests verify reversed reply tuples, concurrent source-port isolation, nonzero-port
validation, cancellation, cleanup, and echo accepted by a dialed UDP client.
Capture-endpoint tests verify local-port metadata reaches the DTLS boundary and
selects the correct Ethernet reply tuple. DTLS tests run concurrent mDTLS
handshakes from one physical source tuple to different local ports, reject
missing/untrusted client certificates and altered peer handles, and verify
header-only/maximum-size echoes and ownership cleanup using simulated delivery.
The host socket reservation test skips explicit socket-permission errors.

Resource regressions verify autonomous cleanup after terminal session failure,
setup/cleanup error preservation, drained queues, cleared allocations, invalid
credential rejection before ownership transfer, and canceled blocked sends.
Jumbo-MTU tests verify the pinned DTLS library's receive-buffer limit.

Peer lifecycle regressions cover multiple TCP connections per peer, secure peers
sharing a physical tuple, immutable authentication snapshots in server-only/mutual
modes, raw authentication reporting, selected local certificates, targeted
revocation, blocked reads/writes, idle-expiry propagation, stale queued accepts,
forced `/30` virtual-IP reuse, delayed cleanup, cancellable disconnect waits,
rejection of dequeued ingress/marked egress from a retired generation,
incomplete-handshake revocation, and stale decrypted plaintext after reconnection.
These use real DTLS and gVisor over simulated delivery, without capture privileges.

| Regression source | Coverage |
| --- | --- |
| [Core peer tests](../tcp_peer_test.go) | Generation-bound accepts, queued accepts and `/30` reuse, delayed cleanup, canceled waits, incomplete handshakes, raw authentication metadata |
| [DTLS peer tests](../dtlstransport/peer_test.go) | Immutable evidence, selected certificates, shared-tuple peers, targeted revocation, blocked I/O, idle expiry, historical snapshots, buffered plaintext across reconnection |

The [API reference](peer-lifecycle.md#api-reference) distinguishes DTLS cleanup
completion from full PCAT/TCP cleanup and the lifetimes observed by each signal.

## Live tests

[Live capture tests](../pcap_live_test.go) require the `pcaplive` build tag and
`PCAPNET_LIVE=1`. Without opt-in they skip. Configure Ethernet peers and capture/
injection privileges on two hosts or network namespaces. Start the server first.

| Variable | Meaning |
| --- | --- |
| `PCAPNET_DEVICE` | Optional capture-device override |
| `PCAPNET_LOCAL_PORT` | Local physical UDP port |
| `PCAPNET_PEER` | Physical peer IPv4:port |
| `PCAPNET_VIRTUAL_IP` | Local virtual IPv4 address |
| `PCAPNET_PEER_VIRTUAL_IP` | Peer virtual IPv4 address |
| `PCAPNET_ROLE` | `server` or `client` |
| `PCAPNET_RESERVE_UDP` | Optional boolean; default false |
| `PCAPNET_MTU` | Optional inner MTU; default 1200 |
| `PCAPNET_UDP_MODE` | Direct UDP backend: `pcap` (default) or `kernel` |

The two hosts use reciprocal addresses/ports. Shared settings still require
virtual addresses for the direct UDP test even though direct UDP does not use
those addresses.

```sh
go test -tags=pcaplive -run '^TestLivePCAPTCPEcho$' -v -timeout=40s .
```

Available tests:

- `TestLivePCAPTCPEcho`: 64 KiB echo through lower-level fixed-peer encapsulation.
- `TestLivePCAPReceiveCancellation`: native receive cancellation and closure.
- `TestLiveDirectUDPEcho`: physical UDP interoperability; different backend modes
  on the hosts test PCAP against ordinary kernel UDP.

These live tests do not exercise PCAT allocation or secure PCAT framing. Use the
[plain, DTLS, and mDTLS example programs](../examples/README.md) for live PCAT
checks, including concurrent clients. Run driver cancellation tests separately
from echo traffic. Passing in-memory tests does not establish driver compatibility
or replace two-host verification.
