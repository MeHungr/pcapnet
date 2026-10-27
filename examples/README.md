# Examples

Runnable capture, clients, and echo servers for pcapnet and the PCAT protocol.

| Program | Connection type |
| --- | --- |
| [udp-capture](udp-capture/main.go) | Read-only UDP prefix capture across all local ports |
| [udp-client](udp-client/main.go), [udp-server](udp-server/main.go) | Direct physical UDP; ordinary UDP peers work |
| [tcp-client](tcp-client/main.go), [tcp-server](tcp-server/main.go) | PCAT TCP with plain, DTLS, or mDTLS channels |

## Build and prerequisites

Use the repository's Go version, CGO, and libpcap headers/libraries. Build from the
repository root as a normal user; run the binaries with capture/injection
privileges. Use two hosts or configured network namespaces with Ethernet routes.

```sh
go build -o /tmp/pcapnet-udp-capture ./examples/udp-capture
go build -o /tmp/pcapnet-udp-server ./examples/udp-server
go build -o /tmp/pcapnet-udp-client ./examples/udp-client
go build -o /tmp/pcapnet-tcp-server ./examples/tcp-server
go build -o /tmp/pcapnet-tcp-client ./examples/tcp-client
```

Each command supports `-h` and `-device` to override device selection. Clients
and echo servers also support `-reserve-port` for optional host UDP reservation.
Servers and capture run until Ctrl+C.
Addresses below are variables to replace with the server's Ethernet IPv4 address.

## Direct UDP

```sh
# Server host
SERVER_IP=192.0.2.2
sudo /tmp/pcapnet-udp-server -local "${SERVER_IP}:45001"
```

```sh
# Client host
SERVER_IP=192.0.2.2
sudo /tmp/pcapnet-udp-client -peer "${SERVER_IP}:45001" -message hello
```

Direct UDP creates no gVisor stack and sends no PCAT allocation messages.

## Magic-header UDP

```sh
# Server host
SERVER_IP=192.0.2.2
MAGIC=MYPROTO
sudo /tmp/pcapnet-udp-server -local "${SERVER_IP}:45001" -magic "$MAGIC"
```

```sh
# Client host
SERVER_IP=192.0.2.2
MAGIC=MYPROTO
sudo /tmp/pcapnet-udp-client -peer "${SERVER_IP}:45001" -magic "$MAGIC" -message hello
```

`Write`/`WriteTo` prepend the header. `Read`/`ReadFrom` deliver only matching
bodies, with the header removed. The client reads replies on the same connection;
the server replies to the address returned by `ReadFrom`. Header bytes count
toward the MTU, but are excluded from read/write byte counts. The Go API accepts
arbitrary binary headers through `UDPConfig.MagicHeader`; empty disables framing.

## Read-only UDP capture

```sh
LOCAL_IP=192.0.2.2
sudo /tmp/pcapnet-udp-capture -local-ip "$LOCAL_IP" -magic PCAT
# Binary prefix instead of a literal string:
sudo /tmp/pcapnet-udp-capture -local-ip "$LOCAL_IP" -magic-hex 00ff50434154
```

Matches the payload prefix on every UDP destination port at `LOCAL_IP` and prints
source, destination, and complete payload in hexadecimal. It reserves no ports
and sends no replies. Host socket delivery and ICMP responses are unaffected.
`PCAT` selects plain session messages; `PCDT` selects secure routing envelopes.
Matching a magic header does not authenticate the sender or decrypt DTLS.
To observe the framed UDP example, use `-magic MYPROTO`. Capture preserves the
header in its output; application connections strip it before delivery.

## Plain TCP

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

The server assigns a virtual client address automatically. Defaults are server
virtual IP `10.200.0.2`, virtual subnet `10.200.0.0/24`, virtual TCP port `6767`,
inner MTU `1200`, and outer UDP ports `45000` (client) / `45001` (server). Server
`-virtual-ip`, `-subnet`, and `-max-peers` control allocation; both programs accept
`-tcp-port` and `-local-port`. Plain PCAT is unencrypted and unauthenticated.

## DTLS

Supply a server certificate/key and a trusted CA bundle. `SERVER_NAME` must match
a DNS name or IP SAN in the server certificate. The programs do not create keys.

```sh
# Server host
SERVER_IP=192.0.2.2
SERVER_CERT=server.pem
SERVER_KEY=server-key.pem
sudo /tmp/pcapnet-tcp-server -local-ip "$SERVER_IP" -dtls \
  -cert "$SERVER_CERT" -key "$SERVER_KEY"
```

```sh
# Client host
SERVER_IP=192.0.2.2
SERVER_NAME=tunnel.example
SERVER_CA=server-ca.pem
sudo /tmp/pcapnet-tcp-client -peer "${SERVER_IP}:45001" -dtls \
  -ca "$SERVER_CA" -server-name "$SERVER_NAME" -message hello
```

Clients verify the server. The server accepts anonymous clients in this mode.
Omitting client `-ca` selects system roots, not disabled verification. A failed
secure setup never retries as plaintext.

## Mutual DTLS

Require trusted client certificates on the server and supply a distinct client
certificate/key on each client. Server and client issuing CAs can differ.

```sh
# Server host
SERVER_IP=192.0.2.2
SERVER_CERT=server.pem
SERVER_KEY=server-key.pem
CLIENT_CA=client-ca.pem
sudo /tmp/pcapnet-tcp-server -local-ip "$SERVER_IP" -dtls \
  -cert "$SERVER_CERT" -key "$SERVER_KEY" \
  -require-client-cert -ca "$CLIENT_CA"
```

```sh
# Client host
SERVER_IP=192.0.2.2
SERVER_NAME=tunnel.example
SERVER_CA=server-ca.pem
CLIENT_CERT=client.pem
CLIENT_KEY=client-key.pem
sudo /tmp/pcapnet-tcp-client -peer "${SERVER_IP}:45001" -dtls \
  -ca "$SERVER_CA" -server-name "$SERVER_NAME" \
  -cert "$CLIENT_CERT" -key "$CLIENT_KEY" -message hello
```

Both endpoints verify their peer's certificate. Credential provisioning and
rotation belong to the importing application or deployment tooling. See the
[mDTLS specification](../docs/protocol/mdtls.md) for trust and packet details.

## Concurrent clients

One server can serve independent client processes sharing a physical UDP endpoint.
Keep `-reserve-port` disabled for processes sharing the same local port:

```sh
SERVER_IP=192.0.2.2
sudo -v
for i in {1..5}; do
  sudo /tmp/pcapnet-tcp-client -peer "${SERVER_IP}:45001" -message "hello-$i" &
done
wait
```

For a secure server, use the matching DTLS or mDTLS flags on every invocation.
Within an importing application, a single client stack can also call `Dial`
concurrently to share one allocation among multiple TCP connections.

## Troubleshooting

| Symptom | Check |
| --- | --- |
| Capture permission error | Run the built binary with the platform's capture/injection privileges |
| `sudo: go: command not found` | Build as a normal user, then run the binary with `sudo` |
| Ethernet/MTU error | Check the route; a peer IP on the same host usually selects loopback |
| Certificate verification failure | Verify issuer trust, validity, SAN, and client-authentication policy |
| Allocation or connection timeout | Confirm peer reachability, matching channel profiles, ports, pool capacity, and MTU |

PCAT uses `PCAT` session and `PCDT` secure-routing markers. Earlier experimental
builds are incompatible and must be rebuilt on both hosts.
