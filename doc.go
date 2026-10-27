// Package pcapnet provides tunneled TCP/IPv4 and direct Ethernet/IPv4 UDP.
// DialUDP and ListenUDP exchange application datagrams with physical peers
// through PCAP without creating a gVisor stack or tunnel. UDPConn implements
// net.Conn and net.PacketConn with packet boundaries and mutable deadlines.
//
// TCP uses a gVisor stack with pluggable packet transport.
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
