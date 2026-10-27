package pcapnet

import (
	"context"
	"fmt"
	"sync"

	"gvisor.dev/gvisor/pkg/tcpip"
	"gvisor.dev/gvisor/pkg/tcpip/link/channel"
	"gvisor.dev/gvisor/pkg/tcpip/network/ipv4"
	"gvisor.dev/gvisor/pkg/tcpip/stack"
	"gvisor.dev/gvisor/pkg/tcpip/transport/tcp"
)

// virtualNICID sets the ID of the virtual NIC
const virtualNICID tcpip.NICID = 1

// A VirtualStack represents the TCP/IP stack from gVisor
type VirtualStack struct {
	Stack *stack.Stack      // The TCP/IP stack
	Link  *channel.Endpoint // The link layer endpoint

	config Config        // The configuration of the stack
	bridge *packetBridge // Optional transport and its packet-processing workers

	mu        sync.Mutex         // Protects the stack's lifecycle state
	closing   bool               // Indicates that shutdown has begun
	closeOnce sync.Once          // Ensures shutdown executes once
	closeCtx  context.Context    // Context canceled during shutdown
	cancel    context.CancelFunc // Cancels pending stack operations
	err       error              // Terminal worker and resource cleanup errors

	activeDials sync.WaitGroup // Tracks TCP dial operations

	conns     map[*managedConn]struct{}     // Active TCP connections
	listeners map[*managedListener]struct{} // Active TCP listeners
}

// NewVirtualStack initializes a VirtualStack without attaching a transport.
// Callers using Link directly remain responsible for moving its packets.
func NewVirtualStack(cfg Config) (*VirtualStack, error) {
	// Attempt to normalize the Config.
	cfg, err := cfg.normalize()
	if err != nil {
		return nil, err
	}

	localAddr := tcpip.AddrFrom4(cfg.VirtualIP.As4())
	peerAddr := tcpip.AddrFrom4(cfg.PeerVirtualIP.As4())

	// Create an in-memory link layer network endpoint.
	link := channel.New(
		256,     // Size
		cfg.MTU, // MTU
		"",      // Link Address
	)

	// Initialize the TCP/IP stack.
	s := stack.New(stack.Options{
		NetworkProtocols: []stack.NetworkProtocolFactory{
			ipv4.NewProtocol,
		},
		TransportProtocols: []stack.TransportProtocolFactory{
			tcp.NewProtocol,
		},
	})

	// Register the in-memory NIC.
	if err := s.CreateNIC(virtualNICID, link); err != nil {
		s.Close()
		link.Close()
		s.Wait()
		return nil, fmt.Errorf("create gVisor NIC: %v", err)
	}

	// Assign the virtual IPv4 address.
	protocolAddr := tcpip.ProtocolAddress{
		Protocol: ipv4.ProtocolNumber, // IPv4
		AddressWithPrefix: tcpip.AddressWithPrefix{
			Address:   localAddr, // Local virtual IP
			PrefixLen: 32,        // CIDR /32
		},
	}

	// Attempt to add the address to the TCP/IP stack.
	if err := s.AddProtocolAddress(
		virtualNICID,              // ID
		protocolAddr,              // Protocol + Address
		stack.AddressProperties{}, // Properties
	); err != nil {
		s.Close()
		link.Close()
		s.Wait()
		return nil, fmt.Errorf("configure gVisor address: %v", err)
	}

	// Route packets for the peer through the in-memory NIC.
	peerSubnet, err := tcpip.NewSubnet(
		peerAddr, // Address
		tcpip.MaskFromBytes([]byte{255, 255, 255, 255}), // Subnet mask (/32)
	)
	if err != nil {
		s.Close()
		link.Close()
		s.Wait()
		return nil, fmt.Errorf("create peer subnet: %v", err)
	}

	// Add the peer's subnet to the route table
	s.SetRouteTable([]tcpip.Route{
		{
			Destination: peerSubnet,
			NIC:         virtualNICID,
		},
	})

	// Create a context to control the lifetime of the virtual stack.
	closeCtx, cancel := context.WithCancel(context.Background())

	// Initialize and return the managed virtual stack.
	return &VirtualStack{
		Stack:     s,
		Link:      link,
		config:    cfg,
		closeCtx:  closeCtx,
		cancel:    cancel,
		conns:     make(map[*managedConn]struct{}),
		listeners: make(map[*managedListener]struct{}),
	}, nil
}
