// Package pcapnet provides tunneled TCP/IPv4 and direct Ethernet/IPv4 UDP.
// DialUDP and ListenUDP exchange application datagrams with physical peers
// through PCAP without creating a gVisor stack or tunnel. UDPConn implements
// net.Conn and net.PacketConn with packet boundaries and mutable deadlines.
// UDPConfig.MagicHeader optionally prepends a payload prefix on writes and
// matches/removes it on reads; a dialed connection also receives peer replies.
// CaptureUDP observes a configurable UDP payload prefix across all ports at one
// local IPv4 address, without reserving ports or providing a send operation.
// ListenUDPCapture provides an all-port server that removes magic headers on
// receive and restores them on replies from the port each client contacted.
//
// PCAT (Packet Capture and Allocation Transport) carries TCP over UDP sessions.
// TCP uses a gVisor stack with pluggable packet transport. DialPCAPStack
// allocates a client address; ListenPCAPTCP serves multiple clients through one
// shared stack. DatagramEndpoint separates session allocation from delivery;
// PlainUDPEndpoint provides unencrypted PCAP UDP; the optional dtlstransport
// subpackage adds DTLS without importing it into the core package.
// NewVirtualStackWithTransport connects the stack to a PacketTransport and owns
// its workers and transport until shutdown. NewMemoryPair connects stacks in
// memory; NewPCAPTransport encapsulates inner IPv4 packets in Ethernet/IPv4/UDP
// frames exchanged with a fixed physical peer through packet capture/injection.
//
// Virtual addresses belong to gVisor and need not be assigned to the host OS.
// The physical route selects the host source address and next-hop MAC. Optional
// host UDP port reservation is controlled by the physical endpoint config.
// Empty DeviceName selects capture from the peer route or UDP listener LocalIP;
// explicit overrides are validated. Ambiguous or non-Ethernet selection fails.
//
// A packet worker failure shuts down its owning stack. Close waits for resource
// cleanup, and Err reports terminal failures and cleanup errors. Live PCAP use
// requires an Ethernet capture driver and capture/injection privileges.
package pcapnet
