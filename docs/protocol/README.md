# PCAT protocol, version 1

**PCAT** means **Packet Capture and Allocation Transport**. This is the project's
version 1 implementation specification, not an IETF standard. Session messages
use the `PCAT` marker; secure routing envelopes use `PCDT`. The earlier development
markers are intentionally unsupported.

PCAT carries complete inner IPv4 packets over UDP. A server assigns
virtual addresses to clients and directs replies to their sessions. The reference
implementation serves TCP through one shared gVisor stack; virtual addresses do
not configure the host's networking stack.

## Specifications

| Document | Scope | Packet diagram |
| --- | --- | --- |
| [Session format](session-v1.md) | Allocation, data, keepalives, leases, validation | Common header and assignment |
| [Unencrypted channel](plain.md) | Session messages directly in UDP | Ethernet / IPv4 / UDP / session |
| [DTLS channel](dtls.md) | Server-authenticated DTLS 1.2 | Routing header / DTLS / encrypted session |
| [mDTLS channel](mdtls.md) | DTLS 1.2 with required client authentication | Same record layout, mutual-authentication handshake |

The three channel profiles use the same session messages. DTLS and mDTLS have
identical application-record layouts; mDTLS is an authentication policy, not a
separate encryption algorithm or packet type. Profiles are selected out of band.
There is no mode negotiation or fallback from secure to plain operation.

## Terminology and conformance

**MUST**, **MUST NOT**, **SHOULD**, and **MAY** express requirements of this project
specification. An implementation conforms to a profile by implementing its rules
and the common session specification. Defaults and implementation limits are
identified separately from wire requirements.

- **Physical endpoint:** outer UDP IP address and port.
- **Virtual address:** inner IPv4 address allocated to a client.
- **Request ID:** client-generated identifier for allocation retries.
- **Session token:** server-generated identifier carried in session messages.
- **Routing ID:** public client-generated identifier used to route DTLS records.
- **Connection ID:** local API handle for a verified DTLS connection; never a
  session-wire field. It is unrelated to the standardized DTLS CID extension.
- **Peer:** physical endpoint plus any connection identity established by the
  selected channel profile.

Identifiers are opaque byte strings, not integers or credentials in themselves.
The unencrypted profile supplies no authenticated identity. DTLS authenticates the
server; mDTLS authenticates both endpoints. Application authorization remains a
separate decision after certificate verification.

## Scope

The physical backend supports IPv4 unicast over Ethernet. It does not implement
NAT traversal, address migration, multicast, or a full VPN router. Direct
`DialUDP`/`ListenUDP` application traffic and the lower-level fixed-peer
`NewPCAPTransport` format do not use this session protocol. An ordinary UDP echo
server or a bare DTLS socket cannot substitute for a tunnel peer.

For ownership and concurrency contracts, see [architecture](../architecture.md).
For runnable programs, see [examples](../../examples/README.md).
