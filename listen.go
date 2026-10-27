package pcapnet

import (
	"fmt"
	"net"

	"gvisor.dev/gvisor/pkg/tcpip"
	"gvisor.dev/gvisor/pkg/tcpip/adapters/gonet"
	"gvisor.dev/gvisor/pkg/tcpip/network/ipv4"
)

// Listen creates a TCP listener on the VirtualStack's
// configured IPv4 address and the specified TCP port.
//
// The listener is automatically closed when the VirtualStack closes.
func (v *VirtualStack) Listen(port int) (net.Listener, error) {
	// Verify that the virtual stack is initialized.
	if v == nil || v.Stack == nil {
		return nil, fmt.Errorf("virtual stack is not initialized")
	}

	// Validate the TCP listening port.
	if port < 1 || port > 65535 {
		return nil, fmt.Errorf("listening port must be between 1 and 65535")
	}

	// Acquire the lifecycle lock.
	v.mu.Lock()
	defer v.mu.Unlock()

	// Reject new listeners after shutdown begins.
	if v.closing {
		return nil, ErrClosed
	}

	// Convert the virtual IPv4 address into a gVisor address.
	localIP := tcpip.AddrFrom4(v.config.VirtualIP.As4())

	// Construct the local TCP endpoint.
	localAddr := tcpip.FullAddress{
		NIC:  virtualNICID, // Virtual NIC
		Addr: localIP,      // Local virtual IP
		Port: uint16(port), // Listening port
	}

	// Create a TCP listener through gVisor.
	listener, err := gonet.ListenTCP(
		v.Stack,             // TCP/IP stack
		localAddr,           // Local TCP endpoint
		ipv4.ProtocolNumber, // IPv4 protocol
	)
	if err != nil {
		return nil, fmt.Errorf("gVisor TCP listen failed: %w", err)
	}

	// Wrap the listener to track its lifetime.
	managed := &managedListener{
		Listener: listener,
		owner:    v,
	}

	// Register the listener with the VirtualStack.
	v.listeners[managed] = struct{}{}

	return managed, nil
}
