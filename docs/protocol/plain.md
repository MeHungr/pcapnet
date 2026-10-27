# Unencrypted channel profile v1

This profile carries the [session protocol](session-v1.md) directly in UDP. It
provides address allocation, framing, and peer separation, without cryptographic
confidentiality, authentication, integrity protection, or replay protection.

## Datagram layout

```text
Ethernet II [optional ingress VLAN tags]
└── Outer IPv4 header (20 B on egress)
    └── UDP header (8 B)
        └── Session message
            ├── PCAT header (24 B)
            └── Type-specific payload
                ├── Request / rejection / keepalive: empty
                ├── Assignment: 30 B
                └── Data: complete inner IPv4 packet
```

```text
UDP payload offset
 0           4   5   6       8                                  24
 +-----------+---+---+-------+-----------------------------------+
 | "PCAT"    | 1 | T | 0, 0  | Request ID or token (16 B)         |
 +-----------+---+---+-------+-----------------------------------+
24
 | Assignment fields or inner IPv4 packet, if applicable ...    |
```

`T` is the [session message type](session-v1.md#common-header). One UDP payload
MUST contain one complete session message. Source/destination ports are deployment
configuration; 45000 and 45001 are example defaults, not registered protocol
ports. Multiple client processes can share a physical tuple because allocation
request IDs and assigned tokens distinguish their traffic.

## Physical packet requirements

The reference PCAP backend emits Ethernet II carrying unfragmented IPv4/UDP with
Don't Fragment set and valid IPv4/UDP checksums. It captures untagged frames and
up to two ingress 802.1Q/802.1ad tags. IPv6, multicast, broadcast destinations,
and fragmented outer IPv4 datagrams are unsupported. IPv4 options are accepted
on ingress when consistent with the physical MTU and framing checks.

Receivers MUST validate outer packet lengths and IPv4 checksums, and validate UDP
checksums when present. An IPv4 UDP checksum of zero is permitted. Truncated or
malformed frames MUST be discarded before session processing.

The selected local address and capture interface determine the host source MAC
and IP. Replies must route through that same local endpoint; ARP resolves the
peer or next-hop gateway. PCAP capture/injection requires operating-system
privileges. Host UDP port reservation is optional and does not carry packet I/O.

## Peer binding

A peer is its outer UDP source IP/port. `Peer.ConnectionID` is zero. The server
binds each assignment to that physical endpoint and checks its token and inner
addresses before delivering data. These are routing checks, not proof of sender
identity: an observer can read tokens and an attacker may forge UDP traffic.

The reference backend does not migrate a session to a new physical endpoint.
Clients changing addresses or ports establish a new allocation. A client cannot
use an opaque secure connection handle through `PlainUDPEndpoint`; it is rejected
rather than silently treated as a plain destination.

## MTU

For physical IPv4 MTU `M`, without IP options:

```text
maximum inner packet = M - 20 (IPv4) - 8 (UDP) - 24 (session)
```

At MTU 1500 this is **1448 bytes**. A request, rejection, or keepalive uses a
24-byte UDP payload; an assignment uses 54 bytes. Ethernet/VLAN headers are outside
the IPv4 MTU. The reference inner MTU defaults to 1200. Operators must choose an
MTU suitable for the entire path; outer fragmentation and path MTU discovery are
not implemented.

## Operation

Use `ListenPCAPTCP` and `DialPCAPStack`, or compose `NewPlainUDPEndpoint` with
`NewTCPServer` and `DialStack`. See the [plain TCP example](../../examples/README.md#plain-tcp).

For confidentiality or peer authentication use the [DTLS](dtls.md) or
[mDTLS](mdtls.md) profile. Mode selection is explicit; this profile does not
upgrade itself or negotiate a secure transport.
