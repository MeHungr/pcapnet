// Package pcapnet provides a gVisor TCP/IPv4 stack with pluggable packet transport.
// NewVirtualStackWithTransport connects the stack to a PacketTransport and owns
// its workers and transport until shutdown. NewMemoryPair connects stacks in
// memory; NewPCAPTransport encapsulates inner IPv4 packets in Ethernet/IPv4/UDP
// frames exchanged with a fixed physical peer through packet capture/injection.
//
// Virtual addresses belong to gVisor and need not be assigned to the host OS.
// The physical route selects the host source address and next-hop MAC. Optional
// host UDP port reservation is controlled by PCAPConfig.ReserveUDPPort.
//
// A packet worker failure shuts down its owning stack. Close waits for resource
// cleanup, and Err reports terminal failures and cleanup errors. Live PCAP use
// requires an Ethernet capture driver and capture/injection privileges.
package pcapnet
